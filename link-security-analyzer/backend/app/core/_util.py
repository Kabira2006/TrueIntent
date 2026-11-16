"""Shared, dependency-free helpers used by lexical analysis and brand matching."""

from __future__ import annotations

import math
from collections import Counter

#: Confusable character mapping for typosquat detection (raw char -> normal).
CONFUSABLE_MAP: dict[str, str] = {
    "0": "o",
    "1": "l",
    "l": "l",
    "i": "l",
    "rn": "m",
    "vv": "w",
    "5": "s",
    "8": "b",
    "а": "a",  # cyrillic small a
    "е": "e",  # cyrillic small ie
    "і": "i",  # cyrillic short i
    "о": "o",  # cyrillic small o
    "р": "p",  # cyrillic small pe
    "с": "c",  # cyrillic small es
    "у": "y",  # cyrillic small ui
    "х": "x",  # cyrillic small kha
}


def _normalize_for_compare(label: str) -> str:
    """Lowercase and collapse confusables for brand comparison."""
    result = []
    i = 0
    while i < len(label):
        two = label[i : i + 2]
        if two in CONFUSABLE_MAP:
            result.append(CONFUSABLE_MAP[two])
            i += 2
        elif label[i] in CONFUSABLE_MAP:
            result.append(CONFUSABLE_MAP[label[i]])
            i += 1
        else:
            result.append(label[i])
            i += 1
    return "".join(result)


def _levenshtein(a: str, b: str) -> int:
    """Classic Levenshtein distance (dependency-free)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            current[j] = min(
                current[j - 1] + 1,  # insertion
                previous[j] + 1,  # deletion
                previous[j - 1] + cost,  # substitution
            )
        previous = current
    return previous[-1]


def _entropy(text: str) -> float:
    """Shannon entropy of a string in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )
