"""Gunicorn configuration for veil-frame."""

# Allow long-running forensic analysis (up to 30 minutes).
timeout = 1800

# Keep-alive for reverse proxies (Render, etc.)
keep_alive = 5

# Workers
workers = 2
threads = 4
