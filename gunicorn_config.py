import os
import multiprocessing

# Server socket
bind = f"0.0.0.0:{os.getenv('PORT', '10000')}"
backlog = 2048

# Worker Configuration - Optimized for 4 CPUs and 8GB RAM
workers = multiprocessing.cpu_count() * 2 + 1  # 9 workers for 4 CPUs
worker_class = 'geventwebsocket.gunicorn.workers.GeventWebSocketWorker'
threads = 4

# Timeouts
timeout = 300
keepalive = 65
graceful_timeout = 60

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'
access_log_format = '%({x-forwarded-for}i)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Resource Management
max_requests = 1000
max_requests_jitter = 50
worker_connections = 1000

# Process Naming
proc_name = 'semgrep-analysis'

# Server Mechanics
preload_app = True
reload = False

# SSL/TLS Settings
forwarded_allow_ips = '*'
secure_scheme_headers = {
    'X-FORWARDED-PROTOCOL': 'ssl',
    'X-FORWARDED-PROTO': 'https',
    'X-FORWARDED-SSL': 'on'
}

# Debugging
capture_output = True
enable_stdio_inheritance = True

def when_ready(server):
    """Log when server is ready"""
    server.log.info("Server is ready. Spawning workers")

def on_starting(server):
    """Log when server is starting"""
    server.log.info("Server is starting")

def post_fork(server, worker):
    """Log worker spawn"""
    server.log.info(f"Worker spawned (pid: {worker.pid})")

# Event Handlers
def worker_abort(worker):
    worker.log.info("worker received SIGABRT signal")

def on_exit(server):
    server.log.info("Server is shutting down")