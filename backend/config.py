"""
Configuration settings for ThreatLoom
"""

# Analysis configuration
ANALYZER_CONFIG = {
    'thresholds': {
        'port_scan': 100,        # Number of different ports per minute to trigger port scan alert
        'ddos': 3000,           # Packets per minute threshold (adjusted from infinity)
        'ddos_bytes': 5242880,  # Bytes per minute threshold (5MB)
        'burst_allowance': 500, # Number of packets allowed in burst window
        'burst_window': 10,     # Burst window in seconds
        'max_packet_age': 60,   # How long to keep packet history (seconds)
        'alert_cooldown': 180,  # Minimum time between similar alerts (reduced from 300s)
        'stats_update_interval': 5,  # Statistics update interval in seconds
    },
    'patterns': {
        'sql_injection': r'(?i)(union\s+select|select.*from|insert\s+into|delete\s+from)',
        'xss': r'(?i)(<script>|javascript:)',
        'command_injection': r'(?i)([;&|`]\s*[$({]|\b(cat|wget|curl)\b)',
        'credential_leak': r'(?i)(password=|apikey=|secret=|token=)'
    }
}

# Logging configuration
LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        },
    },
    'handlers': {
        'default': {
            'level': 'INFO',
            'formatter': 'standard',
            'class': 'logging.StreamHandler',
        },
        'file': {
            'level': 'INFO',
            'formatter': 'standard',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': 'threatloom.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 5,
        }
    },
    'loggers': {
        '': {  # root logger
            'handlers': ['default', 'file'],
            'level': 'INFO',
            'propagate': True
        }
    }
}
