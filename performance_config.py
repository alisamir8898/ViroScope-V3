"""
Performance optimization configuration for ViroScope
Ensures the host runs at maximum speed with minimal overhead
"""

import os

# Flask Performance Settings
FLASK_CONFIG = {
    # Disable debug mode in production
    "DEBUG": False,
    "TESTING": False,
    
    # Disable auto-reloader and debugger for maximum speed
    "ENV": "production",
    
    # Session configuration
    "SESSION_COOKIE_SECURE": False,
    "SESSION_COOKIE_HTTPONLY": True,
    "SESSION_COOKIE_SAMESITE": "Lax",
    "PERMANENT_SESSION_LIFETIME": 3600,
    
    # Cache configuration
    "SEND_FILE_MAX_AGE_DEFAULT": 31536000,  # 1 year for static files
    "TEMPLATES_AUTO_RELOAD": False,
}

# Database Performance Settings
DATABASE_CONFIG = {
    # Connection pooling
    "POOL_SIZE": 5,
    "MAX_OVERFLOW": 10,
    
    # Timeout settings
    "CONNECT_TIMEOUT": 5,
    "QUERY_TIMEOUT": 30,
    
    # WAL mode for better concurrency
    "JOURNAL_MODE": "WAL",
    "SYNCHRONOUS": "NORMAL",
    "CACHE_SIZE": -64000,  # 64MB cache
    "TEMP_STORE": "MEMORY",
}

# Gunicorn/WSGI Settings (if using production server)
WSGI_CONFIG = {
    "workers": max(2, os.cpu_count() or 2),
    "worker_class": "sync",
    "worker_connections": 1000,
    "timeout": 60,
    "keepalive": 5,
    "max_requests": 1000,
    "max_requests_jitter": 50,
}

# Caching Strategy
CACHE_CONFIG = {
    # Cache TTLs in seconds
    "STATS_CACHE_TTL": 5,
    "EVENTS_CACHE_TTL": 3,
    "SESSION_CACHE_TTL": 10,
    
    # Max cache sizes
    "MAX_STATS_CACHE_ENTRIES": 100,
    "MAX_EVENTS_CACHE_ENTRIES": 500,
}

# Request Optimization
REQUEST_CONFIG = {
    # Max upload size: 64MB
    "MAX_CONTENT_LENGTH": 64 * 1024 * 1024,
    
    # Request timeout
    "TIMEOUT": 30,
    
    # JSON encoding optimization
    "JSON_SORT_KEYS": False,
}

# Logging Configuration (minimal overhead)
LOGGING_CONFIG = {
    "level": "WARNING",  # Only log warnings and errors
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "disable_existing_loggers": False,
}

def apply_performance_config(app):
    """Apply performance optimizations to Flask app"""
    
    # Update Flask config
    app.config.update(FLASK_CONFIG)
    app.config.update(REQUEST_CONFIG)
    
    # Disable JSON encoder overhead
    app.json.sort_keys = False
    
    # Optimize Jinja2 template engine
    app.jinja_env.cache = {}
    app.jinja_env.auto_reload = False
    
    return app

def optimize_database():
    """Optimize SQLite database for performance"""
    import sqlite3
    
    conn = sqlite3.connect("instance/viroscope.db")
    cursor = conn.cursor()
    
    # Enable WAL mode for better concurrency
    cursor.execute("PRAGMA journal_mode=WAL")
    
    # Optimize cache
    cursor.execute("PRAGMA cache_size=-64000")
    
    # Set synchronous to NORMAL for better performance
    cursor.execute("PRAGMA synchronous=NORMAL")
    
    # Use memory for temp storage
    cursor.execute("PRAGMA temp_store=MEMORY")
    
    # Enable query optimization
    cursor.execute("PRAGMA optimize")
    
    conn.commit()
    conn.close()

if __name__ == "__main__":
    print("Performance optimization configuration loaded")
    print(f"Recommended workers: {WSGI_CONFIG['workers']}")
