from core.celery_app import celery_app
import os
import sys

# Add current directory to path so agents can be imported
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    # Start the worker
    # Note: To run this, use: celery -A worker worker --loglevel=info
    celery_app.worker_main(argv=['worker', '--loglevel=info', '-P', 'solo'])
