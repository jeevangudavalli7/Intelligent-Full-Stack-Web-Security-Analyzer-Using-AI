from celery import Celery

app = Celery('tasks', broker='redis://redis:6379/0')

@app.task
def run_scan(scan_id, config):
    # Simulate scan work
    import time
    time.sleep(10)
    # Update database, etc.
    return {"status": "complete", "scan_id": scan_id}