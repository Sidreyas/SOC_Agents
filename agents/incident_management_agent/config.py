"""
Incident Management Agent Configuration
Configuration settings for the incident management workflow
"""

import os
from typing import Dict, Any

# Workflow Configuration
WORKFLOW_CONFIG = {
    "max_concurrent_investigations": 10,
    "investigation_timeout_hours": 24,
    "validation_timeout_hours": 4,
    "documentation_timeout_hours": 2,
    "sentinel_sync_timeout_minutes": 30,
    "closure_timeout_hours": 1,
    
    "state_timeouts": {
        "incident_intake": 300,      # 5 minutes
        "evidence_correlation": 1800, # 30 minutes
        "investigation_planning": 600, # 10 minutes
        "analysis_execution": 3600,   # 1 hour
        "documentation_generation": 1200, # 20 minutes
        "resolution_validation": 900,     # 15 minutes
        "sentinel_integration": 600,      # 10 minutes
        "case_closure": 300              # 5 minutes
    },
    
    "retry_policies": {
        "max_retries": 3,
        "retry_delay_seconds": 60,
        "exponential_backoff": True
    }
}

# Agent Integration Configuration
AGENT_INTEGRATION_CONFIG = {
    "enabled_agents": [
        "phishing_agent",
        "powershell_agent",
        "login_and_identity_agent"
    ],
    
    "agent_endpoints": {
        "phishing_agent": {
            "host": "localhost",
            "port": 8001,
            "timeout": 300
        },
        "powershell_agent": {
            "host": "localhost", 
            "port": 8002,
            "timeout": 600
        },
        "login_and_identity_agent": {
            "host": "localhost",
            "port": 8003,
            "timeout": 300
        }
    },
    
    "capability_mapping": {
        "email_analysis": ["phishing_agent"],
        "malware_analysis": ["powershell_agent"],
        "network_analysis": ["powershell_agent"],
        "host_analysis": ["powershell_agent"],
        "user_analysis": ["login_and_identity_agent"],
        "authentication_analysis": ["login_and_identity_agent"],
        "behavioral_analysis": ["login_and_identity_agent"]
    }
}

# Evidence Correlation Configuration
EVIDENCE_CORRELATION_CONFIG = {
    "correlation_rules": {
        "ip_correlation": {
            "enabled": True,
            "confidence_threshold": 0.7,
            "time_window_hours": 24
        },
        "user_correlation": {
            "enabled": True,
            "confidence_threshold": 0.8,
            "time_window_hours": 72
        },
        "host_correlation": {
            "enabled": True,
            "confidence_threshold": 0.75,
            "time_window_hours": 48
        },
        "file_hash_correlation": {
            "enabled": True,
            "confidence_threshold": 0.9,
            "time_window_hours": 168  # 1 week
        },
        "domain_correlation": {
            "enabled": True,
            "confidence_threshold": 0.6,
            "time_window_hours": 24
        },
        "temporal_correlation": {
            "enabled": True,
            "confidence_threshold": 0.5,
            "time_window_minutes": 60
        },
        "behavioral_correlation": {
            "enabled": True,
            "confidence_threshold": 0.65,
            "time_window_hours": 12
        }
    },
    
    "graph_analysis": {
        "max_nodes": 1000,
        "max_edges": 5000,
        "community_detection": True,
        "centrality_analysis": True
    }
}

# Investigation Planning Configuration
INVESTIGATION_PLANNING_CONFIG = {
    "strategy_templates": {
        "malware": {
            "priority_tasks": [
                "malware_analysis",
                "host_forensics",
                "network_analysis"
            ],
            "estimated_duration_hours": 6,
            "required_agents": ["powershell_agent"]
        },
        "phishing": {
            "priority_tasks": [
                "email_analysis",
                "link_analysis",
                "user_impact_assessment"
            ],
            "estimated_duration_hours": 4,
            "required_agents": ["phishing_agent", "login_and_identity_agent"]
        },
        "data_breach": {
            "priority_tasks": [
                "data_access_analysis",
                "user_activity_analysis",
                "network_forensics",
                "compliance_assessment"
            ],
            "estimated_duration_hours": 12,
            "required_agents": ["login_and_identity_agent", "powershell_agent"]
        },
        "insider_threat": {
            "priority_tasks": [
                "user_behavior_analysis",
                "data_access_patterns",
                "privilege_escalation_check"
            ],
            "estimated_duration_hours": 8,
            "required_agents": ["login_and_identity_agent"]
        }
    },
    
    "resource_allocation": {
        "max_parallel_tasks": 5,
        "task_prioritization": "severity_based",
        "load_balancing": True
    }
}

# Documentation Configuration
DOCUMENTATION_CONFIG = {
    "default_templates": ["incident_report", "executive_summary"],
    "default_formats": ["pdf", "html"],
    
    "template_settings": {
        "incident_report": {
            "max_pages": 25,
            "classification": "confidential",
            "retention_years": 7
        },
        "executive_summary": {
            "max_pages": 4,
            "classification": "internal",
            "retention_years": 5
        },
        "technical_analysis": {
            "max_pages": 15,
            "classification": "confidential",
            "retention_years": 10
        }
    },
    
    "compliance_frameworks": ["gdpr", "hipaa", "pci_dss", "sox"],
    
    "quality_checks": {
        "completeness_check": True,
        "accuracy_review": False,  # Manual review required
        "compliance_verification": True
    }
}

# Validation Configuration
VALIDATION_CONFIG = {
    "success_thresholds": {
        "overall_validation": 0.80,
        "mandatory_criteria": 1.0,
        "confidence_minimum": 0.70
    },
    
    "validation_criteria": {
        "critical_incidents": [
            "threat_eliminated",
            "systems_secured", 
            "data_integrity",
            "business_continuity",
            "compliance_met",
            "stakeholders_notified",
            "lessons_documented",
            "controls_improved"
        ],
        "standard_incidents": [
            "threat_eliminated",
            "systems_secured",
            "compliance_met",
            "stakeholders_notified"
        ]
    },
    
    "approval_requirements": {
        "critical": ["incident_commander", "ciso", "executive_team"],
        "high": ["incident_commander", "ciso"],
        "medium": ["incident_commander"],
        "low": ["incident_commander"]
    }
}

# Sentinel Integration Configuration
SENTINEL_CONFIG = {
    "enabled": os.getenv("SENTINEL_ENABLED", "false").lower() == "true",
    "base_url": os.getenv("SENTINEL_BASE_URL", "https://management.azure.com"),
    "subscription_id": os.getenv("AZURE_SUBSCRIPTION_ID"),
    "resource_group": os.getenv("AZURE_RESOURCE_GROUP"),
    "workspace_name": os.getenv("SENTINEL_WORKSPACE_NAME"),
    "tenant_id": os.getenv("AZURE_TENANT_ID"),
    "client_id": os.getenv("AZURE_CLIENT_ID"),
    "client_secret": os.getenv("AZURE_CLIENT_SECRET"),
    
    "api_settings": {
        "api_version": "2023-02-01",
        "timeout_seconds": 30,
        "max_retries": 3
    },
    
    "sync_settings": {
        "auto_sync": True,
        "sync_on_creation": True,
        "sync_on_update": True,
        "sync_on_closure": True
    }
}

# Case Closure Configuration
CLOSURE_CONFIG = {
    "closure_criteria": {
        "validation_score_threshold": 0.75,
        "required_documentation": ["incident_report"],
        "approval_timeout_hours": 48
    },
    
    "post_incident_actions": {
        "mandatory_for_critical": [
            "lessons_learned_session",
            "compliance_reporting",
            "security_enhancement"
        ],
        "mandatory_for_high": [
            "lessons_learned_session",
            "security_enhancement"
        ],
        "mandatory_for_standard": [
            "lessons_learned_session"
        ]
    },
    
    "metrics_tracking": {
        "resolution_time": True,
        "detection_time": True,
        "response_time": True,
        "investigation_quality": True
    }
}

# Logging Configuration
LOGGING_CONFIG = {
    "level": os.getenv("LOG_LEVEL", "INFO"),
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "handlers": {
        "file": {
            "enabled": True,
            "filename": "incident_management.log",
            "max_bytes": 10485760,  # 10MB
            "backup_count": 5
        },
        "console": {
            "enabled": True
        }
    }
}

# Database Configuration
DATABASE_CONFIG = {
    "incident_storage": {
        "type": "json_file",  # or "database" for production
        "file_path": "incident_data.json",
        "backup_enabled": True,
        "backup_interval_hours": 6
    },
    
    "evidence_storage": {
        "type": "json_file",
        "file_path": "evidence_data.json",
        "max_file_size_mb": 100
    }
}

# Security Configuration
SECURITY_CONFIG = {
    "encryption": {
        "enabled": True,
        "algorithm": "AES-256-GCM",
        "key_rotation_days": 90
    },
    
    "access_control": {
        "rbac_enabled": True,
        "session_timeout_minutes": 60,
        "max_concurrent_sessions": 5
    },
    
    "audit": {
        "enabled": True,
        "log_all_actions": True,
        "retention_days": 2555  # 7 years
    }
}

# Performance Configuration
PERFORMANCE_CONFIG = {
    "memory_limits": {
        "max_memory_mb": 2048,
        "evidence_cache_mb": 512,
        "document_cache_mb": 256
    },
    
    "processing_limits": {
        "max_evidence_items": 10000,
        "max_correlation_nodes": 1000,
        "max_concurrent_tasks": 10
    },
    
    "optimization": {
        "enable_caching": True,
        "cache_ttl_minutes": 30,
        "async_processing": True
    }
}

# Notification Configuration
NOTIFICATION_CONFIG = {
    "email_notifications": {
        "enabled": True,
        "smtp_server": os.getenv("SMTP_SERVER"),
        "smtp_port": int(os.getenv("SMTP_PORT", "587")),
        "username": os.getenv("SMTP_USERNAME"),
        "password": os.getenv("SMTP_PASSWORD"),
        "use_tls": True
    },
    
    "notification_triggers": {
        "incident_created": ["incident_commander"],
        "critical_incident": ["incident_commander", "ciso"],
        "investigation_completed": ["incident_commander"],
        "validation_failed": ["incident_commander", "technical_lead"],
        "case_closed": ["incident_commander"]
    }
}

# Master Configuration Dictionary
CONFIG = {
    "workflow": WORKFLOW_CONFIG,
    "agent_integration": AGENT_INTEGRATION_CONFIG,
    "evidence_correlation": EVIDENCE_CORRELATION_CONFIG,
    "investigation_planning": INVESTIGATION_PLANNING_CONFIG,
    "documentation": DOCUMENTATION_CONFIG,
    "validation": VALIDATION_CONFIG,
    "sentinel": SENTINEL_CONFIG,
    "closure": CLOSURE_CONFIG,
    "logging": LOGGING_CONFIG,
    "database": DATABASE_CONFIG,
    "security": SECURITY_CONFIG,
    "performance": PERFORMANCE_CONFIG,
    "notifications": NOTIFICATION_CONFIG
}

def get_config() -> Dict[str, Any]:
    """Get the complete configuration"""
    return CONFIG

def get_config_section(section: str) -> Dict[str, Any]:
    """Get a specific configuration section"""
    return CONFIG.get(section, {})
