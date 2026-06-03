import os
from celery import Celery

# Setup Celery with Redis as broker and backend
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "shivam_os",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["agents.orchestrator", "agents.analyzer"]
)

# Optional configuration
celery_app.conf.update(
    task_track_started=True,
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
)
