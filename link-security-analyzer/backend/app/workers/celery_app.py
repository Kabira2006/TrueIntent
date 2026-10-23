"""Celery application for bounded background browser scans."""

from celery import Celery

from app.config import get_settings

_settings = get_settings()
celery_app = Celery(
    "trueintent",
    broker=_settings.redis_url,
    backend=_settings.redis_url,
    include=["app.workers.tasks"],
)
celery_app.conf.update(
    worker_concurrency=2,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_soft_time_limit=_settings.sandbox_task_soft_time_limit_seconds,
    task_time_limit=_settings.sandbox_task_time_limit_seconds,
    task_default_retry_delay=0,
    task_annotations={"app.workers.tasks.sandbox_scan": {"max_retries": 0}},
)
