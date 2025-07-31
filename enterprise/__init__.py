"""
Enterprise Module for SOC Agents
Provides enterprise-grade security, scalability, compliance, and operations features
"""

from .security import (
    EnterpriseSecurityManager,
    SecurityRole,
    EncryptionLevel,
    AuditEventType,
    RoleBasedAccessControl,
    EnterpriseAuditLogger,
    CertificateManager
)

from .scaling import (
    EnterpriseScalingManager,
    ScalingMode,
    LoadBalancingStrategy,
    HealthStatus,
    NodeMetrics,
    ScalingDecision,
    ClusterManager,
    EnterpriseLoadBalancer,
    AutoScaler,
    PerformanceMonitor,
    ConnectionPoolManager
)

from .compliance import (
    EnterpriseComplianceManager,
    ComplianceFramework,
    DataClassification,
    RetentionPeriod,
    PrivacyAction,
    ComplianceRecord,
    DataProcessingActivity,
    ComplianceAuditStorage,
    PrivacyManager,
    DataRetentionManager,
    ConsentManager,
    DataClassifier
)

from .operations import (
    EnterpriseOperationsManager,
    AlertSeverity,
    HealthStatus,
    MetricType,
    HealthCheck,
    Alert,
    Metric,
    SLATarget,
    HealthMonitor,
    AlertManager,
    MetricsCollector,
    SLAManager,
    NotificationManager,
    DeploymentManager
)

__all__ = [
    # Security
    'EnterpriseSecurityManager',
    'SecurityRole',
    'EncryptionLevel', 
    'AuditEventType',
    'RoleBasedAccessControl',
    'EnterpriseAuditLogger',
    'CertificateManager',
    
    # Scaling
    'EnterpriseScalingManager',
    'ScalingMode',
    'LoadBalancingStrategy',
    'HealthStatus',
    'NodeMetrics',
    'ScalingDecision',
    'ClusterManager',
    'EnterpriseLoadBalancer',
    'AutoScaler',
    'PerformanceMonitor',
    'ConnectionPoolManager',
    
    # Compliance
    'EnterpriseComplianceManager',
    'ComplianceFramework',
    'DataClassification',
    'RetentionPeriod',
    'PrivacyAction',
    'ComplianceRecord',
    'DataProcessingActivity',
    'ComplianceAuditStorage',
    'PrivacyManager',
    'DataRetentionManager',
    'ConsentManager',
    'DataClassifier',
    
    # Operations
    'EnterpriseOperationsManager',
    'AlertSeverity',
    'MetricType',
    'HealthCheck',
    'Alert',
    'Metric',
    'SLATarget',
    'HealthMonitor',
    'AlertManager',
    'MetricsCollector',
    'SLAManager',
    'NotificationManager',
    'DeploymentManager'
]

# Enterprise feature flags
ENTERPRISE_FEATURES = {
    "security": True,
    "scaling": True,
    "compliance": True,
    "operations": True,
    "monitoring": True,
    "alerting": True,
    "sla_management": True,
    "deployment_automation": True
}

# Version information
__version__ = "2.0.0"
__enterprise_edition__ = True
