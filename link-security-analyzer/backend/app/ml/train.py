"""Train ML models for phishing detection.

Trains LogisticRegression, RandomForest, and LightGBM (if available).
Uses GroupKFold on TRAIN split to avoid domain leakage.
Picks best model on VAL split.
Calibrates probabilities (isotonic/Platt).
Saves model + metadata to model_b.joblib.

Leakage avoidance (spec section 11):
1. Path artefact: Default model uses host-level features only (FEATURE_COLUMNS_HOST_ONLY).
   Second variant with path features trained separately, labelled "optimistic".
2. Feed-identity: Check feature importances for suspicious dominance (single feature >0.7).
3. Domain leakage: GroupKFold/GroupShuffleSplit by registrable_domain.
4. Time leakage: Not applicable (no time-based prediction).
5. Dead URLs: Report separately for offline vs live subset evaluation.

Usage:
    python -m app.ml.train --manifest data/eval/eval_manifest.csv --output app/ml/model_b.joblib
"""

import argparse
import hashlib
import json
import logging
import pickle
import warnings
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

# sklearn imports
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupKFold, GridSearchCV
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
)

# Try LightGBM (optional)
try:
    import lightgbm as lgb
    HAVE_LIGHTGBM = True
except ImportError:
    HAVE_LIGHTGBM = False
    warnings.warn("LightGBM not installed; will skip LightGBM model")

from app.core.brands import load_brands
from app.ml.features import (
    extract_features,
    FEATURE_COLUMNS_HOST_ONLY,
    FEATURE_COLUMNS_WITH_PATH,
    save_feature_schema,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def load_manifest(manifest_path: Path) -> pd.DataFrame:
    """Load eval_manifest.csv."""
    df = pd.read_csv(manifest_path)
    logger.info(f"Loaded {len(df)} rows from {manifest_path}")
    logger.info(f"Train: {len(df[df['split']=='train'])}, Val: {len(df[df['split']=='val'])}, Test: {len(df[df['split']=='test'])}")
    return df


def extract_features_batch(df: pd.DataFrame, catalog) -> pd.DataFrame:
    """Extract features for all URLs in manifest (offline mode)."""
    logger.info("Extracting features for all URLs (offline mode)...")
    
    features_list = []
    for idx, row in df.iterrows():
        try:
            feat = extract_features(
                row["url"],
                catalog=catalog,
                infrastructure_data=None,  # No infra data in offline mode
                offline_mode=True,
            )
            feat["url"] = row["url"]
            feat["label"] = row["label"]
            feat["split"] = row["split"]
            feat["registrable_domain"] = row["registrable_domain"]
            features_list.append(feat)
        except Exception as e:
            logger.warning(f"Failed to extract features for {row['url']}: {e}")
            continue
        
        if (idx + 1) % 100 == 0:
            logger.info(f"Processed {idx + 1}/{len(df)} URLs")
    
    features_df = pd.DataFrame(features_list)
    logger.info(f"Extracted features for {len(features_df)} URLs")
    
    # Save feature schema
    if len(features_df) > 0:
        sample_features = {k: v for k, v in features_df.iloc[0].items() if k not in ["url", "label", "split", "registrable_domain", "missing_features"]}
        save_feature_schema(sample_features)
    
    return features_df


def train_model(X_train, y_train, groups_train, model_name="logistic"):
    """Train a single model with GroupKFold cross-validation."""
    logger.info(f"Training {model_name}...")
    
    if model_name == "logistic":
        base_model = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42)
        param_grid = {
            "C": [0.01, 0.1, 1.0, 10.0],
            "penalty": ["l2"],
        }
    elif model_name == "random_forest":
        base_model = RandomForestClassifier(class_weight="balanced", random_state=42, n_jobs=-1)
        param_grid = {
            "n_estimators": [50, 100, 200],
            "max_depth": [10, 20, None],
            "min_samples_split": [2, 5],
        }
    elif model_name == "lightgbm":
        if not HAVE_LIGHTGBM:
            logger.warning("LightGBM not available, skipping")
            return None
        base_model = lgb.LGBMClassifier(
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
            verbosity=-1,
        )
        param_grid = {
            "n_estimators": [50, 100],
            "max_depth": [5, 10, 20],
            "learning_rate": [0.01, 0.1],
        }
    else:
        raise ValueError(f"Unknown model: {model_name}")
    
    # GroupKFold to avoid domain leakage
    group_kfold = GroupKFold(n_splits=3)
    
    grid_search = GridSearchCV(
        base_model,
        param_grid,
        cv=group_kfold,
        scoring="roc_auc",
        n_jobs=1,  # Nested parallelism can cause issues
        verbose=1,
    )
    
    grid_search.fit(X_train, y_train, groups=groups_train)
    
    logger.info(f"Best params for {model_name}: {grid_search.best_params_}")
    logger.info(f"Best CV score: {grid_search.best_score_:.4f}")
    
    return grid_search.best_estimator_


def calibrate_model(model, X_val, y_val):
    """Calibrate probabilities using isotonic regression."""
    logger.info("Calibrating probabilities...")
    calibrated = CalibratedClassifierCV(model, method="isotonic", cv="prefit")
    calibrated.fit(X_val, y_val)
    return calibrated


def evaluate_model(model, X, y, split_name=""):
    """Evaluate model and return metrics."""
    y_pred = model.predict(X)
    y_proba = model.predict_proba(X)[:, 1]
    
    auc = roc_auc_score(y, y_proba)
    cm = confusion_matrix(y, y_pred)
    report = classification_report(y, y_pred, output_dict=True)
    
    logger.info(f"{split_name} AUC: {auc:.4f}")
    logger.info(f"{split_name} Confusion Matrix:\n{cm}")
    
    return {
        "auc": auc,
        "confusion_matrix": cm.tolist(),
        "classification_report": report,
        "y_pred": y_pred,
        "y_proba": y_proba,
    }


def check_feature_importances(model, feature_names):
    """Check for suspicious feature importances (leakage detection)."""
    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
    elif hasattr(model, "coef_"):
        importances = np.abs(model.coef_[0])
    else:
        logger.warning("Model has no feature importances")
        return {}
    
    # Sort by importance
    indices = np.argsort(importances)[::-1]
    
    logger.info("Top 10 feature importances:")
    top_features = {}
    for i in range(min(10, len(indices))):
        idx = indices[i]
        feat_name = feature_names[idx]
        importance = importances[idx]
        logger.info(f"  {i+1}. {feat_name}: {importance:.4f}")
        top_features[feat_name] = float(importance)
    
    # Check for single feature dominance (possible leakage)
    max_importance = importances.max()
    if max_importance > 0.7:
        logger.warning(f"⚠️  Feature {feature_names[indices[0]]} dominates with importance {max_importance:.4f}")
        logger.warning("    This may indicate feed-identity leakage or path artefact.")
    
    return top_features


def main():
    parser = argparse.ArgumentParser(description="Train phishing detection models")
    parser.add_argument("--manifest", required=True, help="Path to eval_manifest.csv")
    parser.add_argument("--output", default="app/ml/model_b.joblib", help="Output model path")
    parser.add_argument("--models", nargs="+", default=["logistic", "random_forest", "lightgbm"], help="Models to train")
    parser.add_argument("--with-path-features", action="store_true", help="Train optimistic model with path features")
    
    args = parser.parse_args()
    
    manifest_path = Path(args.manifest)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Load data
    df = load_manifest(manifest_path)
    catalog = load_brands()
    
    # Extract features
    features_df = extract_features_batch(df, catalog)
    
    # Select feature columns
    if args.with_path_features:
        feature_cols = FEATURE_COLUMNS_WITH_PATH
        logger.info("Using host+path features (optimistic model)")
    else:
        feature_cols = FEATURE_COLUMNS_HOST_ONLY
        logger.info("Using host-level features only (default model)")
    
    # Prepare train/val/test splits
    train_df = features_df[features_df["split"] == "train"]
    val_df = features_df[features_df["split"] == "val"]
    test_df = features_df[features_df["split"] == "test"]
    
    X_train = train_df[feature_cols].values
    y_train = train_df["label"].values
    groups_train = train_df["registrable_domain"].values
    
    X_val = val_df[feature_cols].values
    y_val = val_df["label"].values
    
    X_test = test_df[feature_cols].values
    y_test = test_df["label"].values
    
    logger.info(f"Train: {len(X_train)} samples, Val: {len(X_val)}, Test: {len(X_test)}")
    
    # Train models
    trained_models = {}
    val_scores = {}
    
    for model_name in args.models:
        try:
            model = train_model(X_train, y_train, groups_train, model_name)
            if model is None:
                continue
            
            # Evaluate on validation
            val_metrics = evaluate_model(model, X_val, y_val, split_name=f"{model_name} VAL")
            val_scores[model_name] = val_metrics["auc"]
            
            # Calibrate
            calibrated = calibrate_model(model, X_val, y_val)
            
            # Check feature importances
            importances = check_feature_importances(model, feature_cols)
            
            trained_models[model_name] = {
                "model": calibrated,
                "val_auc": val_metrics["auc"],
                "feature_importances": importances,
            }
        
        except Exception as e:
            logger.error(f"Failed to train {model_name}: {e}")
    
    # Pick best model based on validation AUC
    if not trained_models:
        logger.error("No models trained successfully")
        return
    
    best_model_name = max(val_scores, key=val_scores.get)
    best_model_data = trained_models[best_model_name]
    best_model = best_model_data["model"]
    
    logger.info(f"Best model: {best_model_name} (VAL AUC: {val_scores[best_model_name]:.4f})")
    
    # Evaluate on test (DO NOT use for tuning)
    test_metrics = evaluate_model(best_model, X_test, y_test, split_name=f"{best_model_name} TEST")
    
    # Save model + metadata
    metadata = {
        "model_name": best_model_name,
        "feature_columns": feature_cols,
        "includes_path_features": args.with_path_features,
        "val_auc": val_scores[best_model_name],
        "test_auc": test_metrics["auc"],
        "feature_importances": best_model_data["feature_importances"],
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "manifest_hash": hashlib.sha256(manifest_path.read_bytes()).hexdigest()[:16],
        "sklearn_version": __import__("sklearn").__version__,
        "all_val_scores": val_scores,
    }
    
    model_package = {
        "model": best_model,
        "metadata": metadata,
        "feature_columns": feature_cols,
    }
    
    with open(output_path, "wb") as f:
        pickle.dump(model_package, f)
    
    logger.info(f"Saved model to {output_path}")
    
    # Save metadata JSON
    metadata_path = output_path.with_suffix(".json")
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)
    logger.info(f"Saved metadata to {metadata_path}")
    
    logger.info("Training complete.")
    
    # Warn if path features used
    if args.with_path_features:
        logger.warning("⚠️  Model trained with path features (optimistic).")
        logger.warning("    This has higher leakage risk. Report separately from host-only model.")


if __name__ == "__main__":
    main()
