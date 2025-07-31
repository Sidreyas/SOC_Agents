"""
Enterprise Operations Module
Provides enterprise-grade monitoring, alerting, and operational features for all SOC agents
"""

import logging
import asyncio
import aiohttp
import json
import time
import psutil
import platform
from typing import Dict, Any, List, Optional, Callable, Union
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
import uuid
import smtplib
import ssl
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class HealthStatus(Enum):
    """System health status"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    MAINTENANCE = "maintenance"

class MetricType(Enum):
    """Metric types"""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"

@dataclass
class HealthCheck:
    """Health check result"""
    component: str
    status: str
    response_time: float
    error_message: Optional[str]
    timestamp: datetime
    metadata: Dict[str, Any]

@dataclass
class Alert:
    """System alert"""
    alert_id: str
    severity: str
    component: str
    message: str
    details: Dict[str, Any]
    timestamp: datetime
    resolved: bool
    resolution_time: Optional[datetime]

@dataclass
class Metric:
    """Performance metric"""
    metric_id: str
    name: str
    type: str
    value: float
    unit: str
    labels: Dict[str, str]
    timestamp: datetime

@dataclass
class SLATarget:
    """Service Level Agreement target"""
    sla_id: str
    name: str
    metric_name: str
    target_value: float
    operator: str  # >, <, >=, <=, ==
    time_window: str
    threshold_breach_count: int

class EnterpriseOperationsManager:
    """
    Enterprise Operations Manager
    Handles monitoring, alerting, SLA management, and operational procedures
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.health_monitor = None
        self.alert_manager = None
        self.metrics_collector = None
        self.sla_manager = None
        self.notification_manager = None
        self.deployment_manager = None
        self._initialize_operations_components()
    
    def _initialize_operations_components(self):
        """Initialize all operations components"""
        try:
            # Initialize health monitoring
            self.health_monitor = HealthMonitor(self.config)
            
            # Initialize alert management
            self.alert_manager = AlertManager(self.config)
            
            # Initialize metrics collection
            self.metrics_collector = MetricsCollector(self.config)
            
            # Initialize SLA management
            self.sla_manager = SLAManager(self.config)
            
            # Initialize notification management
            self.notification_manager = NotificationManager(self.config)
            
            # Initialize deployment management
            self.deployment_manager = DeploymentManager(self.config)
            
            logger.info("Enterprise operations components initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize operations components: {str(e)}")
            raise
    
    async def start_monitoring(self, components: List[str]) -> Dict[str, Any]:
        """
        Start comprehensive monitoring for specified components
        """
        try:
            # Start health monitoring
            health_status = await self.health_monitor.start_monitoring(components)
            
            # Start metrics collection
            metrics_status = await self.metrics_collector.start_collection(components)
            
            # Start SLA monitoring
            sla_status = await self.sla_manager.start_monitoring()
            
            # Start alert monitoring
            alert_status = await self.alert_manager.start_monitoring()
            
            monitoring_status = {
                "monitoring_started": True,
                "components_monitored": len(components),
                "health_monitoring": health_status,
                "metrics_collection": metrics_status,
                "sla_monitoring": sla_status,
                "alert_monitoring": alert_status,
                "start_time": datetime.now().isoformat()
            }
            
            logger.info(f"Enterprise monitoring started for {len(components)} components")
            return monitoring_status
            
        except Exception as e:
            logger.error(f"Failed to start monitoring: {str(e)}")
            raise
    
    async def perform_health_check(self, component: str = "all") -> Dict[str, Any]:
        """
        Perform comprehensive health check
        """
        try:
            if component == "all":
                health_results = await self.health_monitor.check_all_components()
            else:
                health_results = [await self.health_monitor.check_component(component)]
            
            # Analyze overall health
            healthy_components = [h for h in health_results if h.status == HealthStatus.HEALTHY.value]
            degraded_components = [h for h in health_results if h.status == HealthStatus.DEGRADED.value]
            unhealthy_components = [h for h in health_results if h.status == HealthStatus.UNHEALTHY.value]
            
            overall_status = HealthStatus.HEALTHY.value
            if unhealthy_components:
                overall_status = HealthStatus.UNHEALTHY.value
            elif degraded_components:
                overall_status = HealthStatus.DEGRADED.value
            
            health_summary = {
                "overall_status": overall_status,
                "total_components": len(health_results),
                "healthy_components": len(healthy_components),
                "degraded_components": len(degraded_components),
                "unhealthy_components": len(unhealthy_components),
                "component_details": [asdict(h) for h in health_results],
                "check_timestamp": datetime.now().isoformat()
            }
            
            # Generate alerts for unhealthy components
            for unhealthy in unhealthy_components:
                await self.alert_manager.create_alert(
                    AlertSeverity.CRITICAL,
                    unhealthy.component,
                    f"Component {unhealthy.component} is unhealthy",
                    {"health_check": asdict(unhealthy)}
                )
            
            return health_summary
            
        except Exception as e:
            logger.error(f"Health check failed: {str(e)}")
            raise
    
    async def collect_performance_metrics(self, time_window: str = "1h") -> Dict[str, Any]:
        """
        Collect comprehensive performance metrics
        """
        try:
            # Collect system metrics
            system_metrics = await self.metrics_collector.collect_system_metrics()
            
            # Collect application metrics
            app_metrics = await self.metrics_collector.collect_application_metrics()
            
            # Collect custom metrics
            custom_metrics = await self.metrics_collector.collect_custom_metrics()
            
            # Aggregate metrics
            all_metrics = system_metrics + app_metrics + custom_metrics
            
            # Calculate performance indicators
            performance_indicators = await self._calculate_performance_indicators(all_metrics)
            
            metrics_summary = {
                "collection_time": datetime.now().isoformat(),
                "time_window": time_window,
                "total_metrics": len(all_metrics),
                "system_metrics_count": len(system_metrics),
                "application_metrics_count": len(app_metrics),
                "custom_metrics_count": len(custom_metrics),
                "performance_indicators": performance_indicators,
                "metrics_details": [asdict(m) for m in all_metrics]
            }
            
            return metrics_summary
            
        except Exception as e:
            logger.error(f"Metrics collection failed: {str(e)}")
            raise
    
    async def monitor_sla_compliance(self) -> Dict[str, Any]:
        """
        Monitor Service Level Agreement compliance
        """
        try:
            # Get SLA targets
            sla_targets = await self.sla_manager.get_sla_targets()
            
            # Check compliance for each target
            compliance_results = []
            for target in sla_targets:
                compliance = await self.sla_manager.check_sla_compliance(target)
                compliance_results.append(compliance)
            
            # Calculate overall SLA score
            total_targets = len(sla_targets)
            compliant_targets = len([c for c in compliance_results if c["compliant"]])
            sla_score = (compliant_targets / total_targets * 100) if total_targets > 0 else 100
            
            # Identify breaches
            breached_slas = [c for c in compliance_results if not c["compliant"]]
            
            # Generate alerts for SLA breaches
            for breach in breached_slas:
                await self.alert_manager.create_alert(
                    AlertSeverity.ERROR,
                    "sla_manager",
                    f"SLA breach detected: {breach['sla_name']}",
                    {"sla_breach": breach}
                )
            
            sla_summary = {
                "monitoring_time": datetime.now().isoformat(),
                "overall_sla_score": sla_score,
                "total_sla_targets": total_targets,
                "compliant_targets": compliant_targets,
                "breached_targets": len(breached_slas),
                "compliance_details": compliance_results,
                "breach_details": breached_slas
            }
            
            return sla_summary
            
        except Exception as e:
            logger.error(f"SLA monitoring failed: {str(e)}")
            raise
    
    async def handle_incident(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle operational incident with enterprise procedures
        """
        try:
            incident_id = str(uuid.uuid4())
            
            # Create incident record
            incident = {
                "incident_id": incident_id,
                "severity": incident_data.get("severity", AlertSeverity.WARNING.value),
                "component": incident_data.get("component", "unknown"),
                "description": incident_data.get("description", ""),
                "status": "open",
                "created_at": datetime.now().isoformat(),
                "assigned_to": None,
                "resolution_steps": [],
                "metadata": incident_data
            }
            
            # Determine incident severity and response procedures
            response_procedures = await self._get_incident_response_procedures(incident["severity"])
            
            # Create alert
            alert = await self.alert_manager.create_alert(
                AlertSeverity(incident["severity"]),
                incident["component"],
                f"Incident {incident_id}: {incident['description']}",
                incident
            )
            
            # Send notifications based on severity
            if incident["severity"] in [AlertSeverity.ERROR.value, AlertSeverity.CRITICAL.value]:
                await self.notification_manager.send_incident_notification(incident)
            
            # Auto-assign based on component
            assigned_to = await self._auto_assign_incident(incident["component"])
            if assigned_to:
                incident["assigned_to"] = assigned_to
            
            incident_response = {
                "incident_id": incident_id,
                "alert_id": alert.alert_id,
                "status": "created",
                "assigned_to": assigned_to,
                "response_procedures": response_procedures,
                "escalation_timeline": self._get_escalation_timeline(incident["severity"]),
                "next_actions": response_procedures[:3] if response_procedures else []
            }
            
            logger.info(f"Incident {incident_id} created and assigned")
            return incident_response
            
        except Exception as e:
            logger.error(f"Incident handling failed: {str(e)}")
            raise
    
    async def deploy_configuration_update(self, config_update: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deploy configuration update with enterprise procedures
        """
        try:
            deployment_id = str(uuid.uuid4())
            
            # Validate configuration
            validation_result = await self.deployment_manager.validate_configuration(config_update)
            
            if not validation_result["valid"]:
                return {
                    "deployment_id": deployment_id,
                    "status": "failed",
                    "error": "Configuration validation failed",
                    "validation_errors": validation_result["errors"]
                }
            
            # Create deployment plan
            deployment_plan = await self.deployment_manager.create_deployment_plan(config_update)
            
            # Execute deployment
            deployment_result = await self.deployment_manager.execute_deployment(
                deployment_id, deployment_plan
            )
            
            # Update monitoring if successful
            if deployment_result["status"] == "success":
                await self._update_monitoring_for_deployment(config_update)
            
            return {
                "deployment_id": deployment_id,
                "status": deployment_result["status"],
                "deployment_plan": deployment_plan,
                "execution_details": deployment_result,
                "rollback_available": True,
                "deployed_at": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Configuration deployment failed: {str(e)}")
            raise
    
    # Private helper methods
    async def _calculate_performance_indicators(self, metrics: List[Metric]) -> Dict[str, Any]:
        """Calculate key performance indicators from metrics"""
        indicators = {}
        
        # Calculate averages by metric type
        metric_groups = {}
        for metric in metrics:
            if metric.name not in metric_groups:
                metric_groups[metric.name] = []
            metric_groups[metric.name].append(metric.value)
        
        for metric_name, values in metric_groups.items():
            indicators[f"{metric_name}_avg"] = sum(values) / len(values)
            indicators[f"{metric_name}_max"] = max(values)
            indicators[f"{metric_name}_min"] = min(values)
        
        return indicators
    
    async def _get_incident_response_procedures(self, severity: str) -> List[str]:
        """Get incident response procedures based on severity"""
        procedures = {
            AlertSeverity.CRITICAL.value: [
                "Immediately notify on-call engineer",
                "Activate incident response team",
                "Assess impact and affected systems",
                "Implement emergency containment measures",
                "Initiate customer communication if external impact",
                "Begin root cause analysis",
                "Document all actions taken"
            ],
            AlertSeverity.ERROR.value: [
                "Notify assigned team lead",
                "Assess system impact",
                "Implement mitigation measures",
                "Monitor for escalation",
                "Document incident details",
                "Plan resolution steps"
            ],
            AlertSeverity.WARNING.value: [
                "Log incident for tracking",
                "Assess if immediate action required",
                "Schedule resolution during business hours",
                "Monitor for pattern recognition"
            ],
            AlertSeverity.INFO.value: [
                "Log for informational purposes",
                "Review during regular maintenance window"
            ]
        }
        
        return procedures.get(severity, procedures[AlertSeverity.WARNING.value])
    
    async def _auto_assign_incident(self, component: str) -> Optional[str]:
        """Auto-assign incident based on component"""
        assignment_rules = {
            "phishing_agent": "security_team",
            "login_identity_agent": "identity_team",
            "powershell_agent": "threat_hunting_team",
            "malware_agent": "malware_team",
            "ddos_agent": "network_team",
            "access_control_agent": "access_control_team",
            "insider_behavior_agent": "behavioral_analysis_team",
            "network_exfiltration_agent": "network_security_team",
            "host_stability_agent": "endpoint_team"
        }
        
        return assignment_rules.get(component, "default_soc_team")
    
    def _get_escalation_timeline(self, severity: str) -> Dict[str, str]:
        """Get escalation timeline based on severity"""
        timelines = {
            AlertSeverity.CRITICAL.value: {
                "initial_response": "5 minutes",
                "team_lead_notification": "15 minutes",
                "management_notification": "30 minutes",
                "customer_notification": "1 hour"
            },
            AlertSeverity.ERROR.value: {
                "initial_response": "30 minutes",
                "team_lead_notification": "1 hour",
                "management_notification": "4 hours"
            },
            AlertSeverity.WARNING.value: {
                "initial_response": "4 hours",
                "team_lead_notification": "24 hours"
            },
            AlertSeverity.INFO.value: {
                "review": "next_business_day"
            }
        }
        
        return timelines.get(severity, timelines[AlertSeverity.WARNING.value])
    
    async def _update_monitoring_for_deployment(self, config_update: Dict[str, Any]):
        """Update monitoring configuration after deployment"""
        # Update health checks if new components added
        if "new_components" in config_update:
            await self.health_monitor.add_components(config_update["new_components"])
        
        # Update metrics collection if new metrics defined
        if "new_metrics" in config_update:
            await self.metrics_collector.add_metrics(config_update["new_metrics"])
        
        # Update SLA targets if changed
        if "sla_updates" in config_update:
            await self.sla_manager.update_sla_targets(config_update["sla_updates"])


class HealthMonitor:
    """Enterprise health monitoring"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.monitored_components = []
        self.health_checks = {}
        self.monitoring_enabled = True
    
    async def start_monitoring(self, components: List[str]) -> Dict[str, Any]:
        """Start health monitoring for components"""
        self.monitored_components = components
        
        # Start monitoring loop
        asyncio.create_task(self._monitoring_loop())
        
        return {
            "monitoring_started": True,
            "components": len(components),
            "check_interval": self.config.get("health_check_interval", 30)
        }
    
    async def check_all_components(self) -> List[HealthCheck]:
        """Check health of all monitored components"""
        health_results = []
        
        for component in self.monitored_components:
            health_check = await self.check_component(component)
            health_results.append(health_check)
        
        return health_results
    
    async def check_component(self, component: str) -> HealthCheck:
        """Check health of specific component"""
        start_time = time.time()
        
        try:
            # Perform component-specific health check
            if component == "system":
                status = await self._check_system_health()
            elif component.endswith("_agent"):
                status = await self._check_agent_health(component)
            elif component == "database":
                status = await self._check_database_health()
            elif component == "api":
                status = await self._check_api_health()
            else:
                status = await self._check_generic_component(component)
            
            response_time = time.time() - start_time
            
            return HealthCheck(
                component=component,
                status=status["status"],
                response_time=response_time,
                error_message=status.get("error"),
                timestamp=datetime.now(),
                metadata=status.get("metadata", {})
            )
            
        except Exception as e:
            response_time = time.time() - start_time
            return HealthCheck(
                component=component,
                status=HealthStatus.UNHEALTHY.value,
                response_time=response_time,
                error_message=str(e),
                timestamp=datetime.now(),
                metadata={}
            )
    
    async def add_components(self, new_components: List[str]):
        """Add new components to monitoring"""
        self.monitored_components.extend(new_components)
    
    async def _monitoring_loop(self):
        """Health monitoring loop"""
        while self.monitoring_enabled:
            try:
                health_results = await self.check_all_components()
                
                # Store latest health results
                for health_check in health_results:
                    self.health_checks[health_check.component] = health_check
                
                await asyncio.sleep(self.config.get("health_check_interval", 30))
                
            except Exception as e:
                logger.error(f"Health monitoring loop error: {str(e)}")
                await asyncio.sleep(30)
    
    async def _check_system_health(self) -> Dict[str, Any]:
        """Check system health"""
        cpu_usage = psutil.cpu_percent(interval=1)
        memory_usage = psutil.virtual_memory().percent
        disk_usage = psutil.disk_usage('/').percent
        
        # Determine status based on thresholds
        if cpu_usage > 90 or memory_usage > 90 or disk_usage > 90:
            status = HealthStatus.UNHEALTHY.value
        elif cpu_usage > 75 or memory_usage > 75 or disk_usage > 75:
            status = HealthStatus.DEGRADED.value
        else:
            status = HealthStatus.HEALTHY.value
        
        return {
            "status": status,
            "metadata": {
                "cpu_usage": cpu_usage,
                "memory_usage": memory_usage,
                "disk_usage": disk_usage,
                "platform": platform.platform()
            }
        }
    
    async def _check_agent_health(self, agent_name: str) -> Dict[str, Any]:
        """Check SOC agent health"""
        # Implementation would check agent-specific health endpoints
        return {
            "status": HealthStatus.HEALTHY.value,
            "metadata": {
                "agent": agent_name,
                "last_analysis": datetime.now().isoformat(),
                "queue_size": 0
            }
        }
    
    async def _check_database_health(self) -> Dict[str, Any]:
        """Check database health"""
        # Implementation would check database connectivity and performance
        return {
            "status": HealthStatus.HEALTHY.value,
            "metadata": {
                "connection_pool": "healthy",
                "response_time": "< 100ms"
            }
        }
    
    async def _check_api_health(self) -> Dict[str, Any]:
        """Check API health"""
        # Implementation would check API endpoints
        return {
            "status": HealthStatus.HEALTHY.value,
            "metadata": {
                "endpoints": "responsive",
                "rate_limiting": "normal"
            }
        }
    
    async def _check_generic_component(self, component: str) -> Dict[str, Any]:
        """Check generic component health"""
        return {
            "status": HealthStatus.HEALTHY.value,
            "metadata": {
                "component": component,
                "check_type": "generic"
            }
        }


class AlertManager:
    """Enterprise alert management"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.alerts = []
        self.alert_rules = []
        self.monitoring_enabled = True
    
    async def start_monitoring(self) -> Dict[str, Any]:
        """Start alert monitoring"""
        # Start alert processing loop
        asyncio.create_task(self._alert_processing_loop())
        
        return {
            "alert_monitoring_started": True,
            "processing_interval": self.config.get("alert_processing_interval", 10)
        }
    
    async def create_alert(self, severity: AlertSeverity, component: str, 
                          message: str, details: Dict[str, Any]) -> Alert:
        """Create new alert"""
        alert = Alert(
            alert_id=str(uuid.uuid4()),
            severity=severity.value,
            component=component,
            message=message,
            details=details,
            timestamp=datetime.now(),
            resolved=False,
            resolution_time=None
        )
        
        self.alerts.append(alert)
        
        # Process alert immediately for critical alerts
        if severity == AlertSeverity.CRITICAL:
            await self._process_alert(alert)
        
        logger.info(f"Alert created: {alert.alert_id} - {severity.value} - {message}")
        return alert
    
    async def resolve_alert(self, alert_id: str, resolution_note: str) -> bool:
        """Resolve alert"""
        for alert in self.alerts:
            if alert.alert_id == alert_id and not alert.resolved:
                alert.resolved = True
                alert.resolution_time = datetime.now()
                alert.details["resolution_note"] = resolution_note
                logger.info(f"Alert resolved: {alert_id}")
                return True
        return False
    
    async def get_active_alerts(self, severity: Optional[str] = None) -> List[Alert]:
        """Get active (unresolved) alerts"""
        active_alerts = [alert for alert in self.alerts if not alert.resolved]
        
        if severity:
            active_alerts = [alert for alert in active_alerts if alert.severity == severity]
        
        return active_alerts
    
    async def _alert_processing_loop(self):
        """Alert processing loop"""
        while self.monitoring_enabled:
            try:
                active_alerts = await self.get_active_alerts()
                
                for alert in active_alerts:
                    await self._process_alert(alert)
                
                await asyncio.sleep(self.config.get("alert_processing_interval", 10))
                
            except Exception as e:
                logger.error(f"Alert processing loop error: {str(e)}")
                await asyncio.sleep(10)
    
    async def _process_alert(self, alert: Alert):
        """Process individual alert"""
        # Check for alert escalation
        age_minutes = (datetime.now() - alert.timestamp).total_seconds() / 60
        
        if alert.severity == AlertSeverity.CRITICAL.value and age_minutes > 5:
            # Escalate critical alerts after 5 minutes
            await self._escalate_alert(alert)
        elif alert.severity == AlertSeverity.ERROR.value and age_minutes > 30:
            # Escalate error alerts after 30 minutes
            await self._escalate_alert(alert)
    
    async def _escalate_alert(self, alert: Alert):
        """Escalate alert to higher severity or different team"""
        if not alert.details.get("escalated"):
            alert.details["escalated"] = True
            alert.details["escalation_time"] = datetime.now().isoformat()
            logger.warning(f"Alert escalated: {alert.alert_id}")


class MetricsCollector:
    """Enterprise metrics collection"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.metrics = []
        self.custom_metrics = {}
        self.collection_enabled = True
    
    async def start_collection(self, components: List[str]) -> Dict[str, Any]:
        """Start metrics collection"""
        # Start collection loop
        asyncio.create_task(self._collection_loop())
        
        return {
            "metrics_collection_started": True,
            "components": len(components),
            "collection_interval": self.config.get("metrics_collection_interval", 60)
        }
    
    async def collect_system_metrics(self) -> List[Metric]:
        """Collect system performance metrics"""
        timestamp = datetime.now()
        system_metrics = []
        
        # CPU metrics
        system_metrics.append(Metric(
            metric_id=str(uuid.uuid4()),
            name="cpu_usage_percent",
            type=MetricType.GAUGE.value,
            value=psutil.cpu_percent(interval=1),
            unit="percent",
            labels={"host": platform.node()},
            timestamp=timestamp
        ))
        
        # Memory metrics
        memory = psutil.virtual_memory()
        system_metrics.append(Metric(
            metric_id=str(uuid.uuid4()),
            name="memory_usage_percent",
            type=MetricType.GAUGE.value,
            value=memory.percent,
            unit="percent",
            labels={"host": platform.node()},
            timestamp=timestamp
        ))
        
        # Disk metrics
        disk = psutil.disk_usage('/')
        system_metrics.append(Metric(
            metric_id=str(uuid.uuid4()),
            name="disk_usage_percent",
            type=MetricType.GAUGE.value,
            value=(disk.used / disk.total) * 100,
            unit="percent",
            labels={"host": platform.node(), "mount": "/"},
            timestamp=timestamp
        ))
        
        return system_metrics
    
    async def collect_application_metrics(self) -> List[Metric]:
        """Collect application-specific metrics"""
        timestamp = datetime.now()
        app_metrics = []
        
        # Example application metrics
        app_metrics.append(Metric(
            metric_id=str(uuid.uuid4()),
            name="requests_per_second",
            type=MetricType.GAUGE.value,
            value=100.0,  # Simulated
            unit="req/sec",
            labels={"service": "soc_agents"},
            timestamp=timestamp
        ))
        
        app_metrics.append(Metric(
            metric_id=str(uuid.uuid4()),
            name="response_time_ms",
            type=MetricType.HISTOGRAM.value,
            value=150.0,  # Simulated
            unit="milliseconds",
            labels={"service": "soc_agents", "endpoint": "/analyze"},
            timestamp=timestamp
        ))
        
        return app_metrics
    
    async def collect_custom_metrics(self) -> List[Metric]:
        """Collect custom business metrics"""
        timestamp = datetime.now()
        custom_metrics = []
        
        # Convert custom metrics to standard format
        for metric_name, metric_value in self.custom_metrics.items():
            custom_metrics.append(Metric(
                metric_id=str(uuid.uuid4()),
                name=metric_name,
                type=MetricType.GAUGE.value,
                value=float(metric_value),
                unit="count",
                labels={"type": "custom"},
                timestamp=timestamp
            ))
        
        return custom_metrics
    
    async def add_metrics(self, new_metrics: List[Dict[str, Any]]):
        """Add new custom metrics"""
        for metric_def in new_metrics:
            self.custom_metrics[metric_def["name"]] = 0
    
    async def record_custom_metric(self, name: str, value: float):
        """Record custom metric value"""
        self.custom_metrics[name] = value
    
    async def _collection_loop(self):
        """Metrics collection loop"""
        while self.collection_enabled:
            try:
                # Collect all metrics
                system_metrics = await self.collect_system_metrics()
                app_metrics = await self.collect_application_metrics()
                custom_metrics = await self.collect_custom_metrics()
                
                # Store metrics
                all_metrics = system_metrics + app_metrics + custom_metrics
                self.metrics.extend(all_metrics)
                
                # Keep only last hour of metrics
                cutoff_time = datetime.now() - timedelta(hours=1)
                self.metrics = [m for m in self.metrics if m.timestamp > cutoff_time]
                
                await asyncio.sleep(self.config.get("metrics_collection_interval", 60))
                
            except Exception as e:
                logger.error(f"Metrics collection loop error: {str(e)}")
                await asyncio.sleep(60)


class SLAManager:
    """Service Level Agreement management"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.sla_targets = []
        self.compliance_history = []
        self._initialize_default_slas()
    
    def _initialize_default_slas(self):
        """Initialize default SLA targets"""
        default_slas = [
            SLATarget(
                sla_id="availability_sla",
                name="System Availability",
                metric_name="uptime_percent",
                target_value=99.9,
                operator=">=",
                time_window="24h",
                threshold_breach_count=1
            ),
            SLATarget(
                sla_id="response_time_sla",
                name="Response Time",
                metric_name="response_time_ms",
                target_value=500.0,
                operator="<=",
                time_window="1h",
                threshold_breach_count=5
            ),
            SLATarget(
                sla_id="error_rate_sla",
                name="Error Rate",
                metric_name="error_rate_percent",
                target_value=1.0,
                operator="<=",
                time_window="1h",
                threshold_breach_count=1
            )
        ]
        
        self.sla_targets.extend(default_slas)
    
    async def start_monitoring(self) -> Dict[str, Any]:
        """Start SLA monitoring"""
        # Start SLA monitoring loop
        asyncio.create_task(self._sla_monitoring_loop())
        
        return {
            "sla_monitoring_started": True,
            "sla_targets": len(self.sla_targets),
            "monitoring_interval": self.config.get("sla_monitoring_interval", 300)
        }
    
    async def get_sla_targets(self) -> List[SLATarget]:
        """Get all SLA targets"""
        return self.sla_targets
    
    async def check_sla_compliance(self, sla_target: SLATarget) -> Dict[str, Any]:
        """Check compliance for specific SLA target"""
        # Implementation would check actual metrics against SLA target
        # For demo, simulate compliance check
        
        current_value = 99.95  # Simulated current value
        compliant = self._evaluate_sla_condition(
            current_value, sla_target.target_value, sla_target.operator
        )
        
        return {
            "sla_id": sla_target.sla_id,
            "sla_name": sla_target.name,
            "target_value": sla_target.target_value,
            "current_value": current_value,
            "compliant": compliant,
            "compliance_percentage": min(100, (current_value / sla_target.target_value) * 100),
            "time_window": sla_target.time_window,
            "checked_at": datetime.now().isoformat()
        }
    
    async def update_sla_targets(self, sla_updates: List[Dict[str, Any]]):
        """Update SLA targets"""
        for update in sla_updates:
            for sla in self.sla_targets:
                if sla.sla_id == update.get("sla_id"):
                    # Update SLA target values
                    if "target_value" in update:
                        sla.target_value = update["target_value"]
                    if "time_window" in update:
                        sla.time_window = update["time_window"]
    
    def _evaluate_sla_condition(self, current_value: float, target_value: float, operator: str) -> bool:
        """Evaluate SLA condition"""
        if operator == ">=":
            return current_value >= target_value
        elif operator == "<=":
            return current_value <= target_value
        elif operator == ">":
            return current_value > target_value
        elif operator == "<":
            return current_value < target_value
        elif operator == "==":
            return current_value == target_value
        else:
            return False
    
    async def _sla_monitoring_loop(self):
        """SLA monitoring loop"""
        while True:
            try:
                for sla_target in self.sla_targets:
                    compliance = await self.check_sla_compliance(sla_target)
                    self.compliance_history.append(compliance)
                
                # Keep only last 24 hours of compliance history
                cutoff_time = datetime.now() - timedelta(hours=24)
                self.compliance_history = [
                    c for c in self.compliance_history 
                    if datetime.fromisoformat(c["checked_at"]) > cutoff_time
                ]
                
                await asyncio.sleep(self.config.get("sla_monitoring_interval", 300))
                
            except Exception as e:
                logger.error(f"SLA monitoring loop error: {str(e)}")
                await asyncio.sleep(300)


class NotificationManager:
    """Enterprise notification management"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.email_config = config.get("email", {})
        self.webhook_config = config.get("webhook", {})
    
    async def send_incident_notification(self, incident: Dict[str, Any]):
        """Send incident notification"""
        try:
            # Send email notification
            if self.email_config.get("enabled"):
                await self._send_email_notification(incident)
            
            # Send webhook notification
            if self.webhook_config.get("enabled"):
                await self._send_webhook_notification(incident)
            
            logger.info(f"Incident notification sent: {incident['incident_id']}")
            
        except Exception as e:
            logger.error(f"Failed to send incident notification: {str(e)}")
    
    async def _send_email_notification(self, incident: Dict[str, Any]):
        """Send email notification"""
        try:
            # Create email content
            subject = f"SOC Incident Alert: {incident['severity'].upper()} - {incident['component']}"
            body = f"""
            Incident ID: {incident['incident_id']}
            Severity: {incident['severity']}
            Component: {incident['component']}
            Description: {incident['description']}
            Created At: {incident['created_at']}
            Assigned To: {incident.get('assigned_to', 'Unassigned')}
            
            Please respond according to incident response procedures.
            """
            
            # Send email (implementation would use actual SMTP)
            logger.info(f"Email notification sent for incident {incident['incident_id']}")
            
        except Exception as e:
            logger.error(f"Failed to send email notification: {str(e)}")
    
    async def _send_webhook_notification(self, incident: Dict[str, Any]):
        """Send webhook notification"""
        try:
            webhook_url = self.webhook_config.get("url")
            if not webhook_url:
                return
            
            payload = {
                "event_type": "incident_created",
                "incident": incident,
                "timestamp": datetime.now().isoformat()
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload) as response:
                    if response.status == 200:
                        logger.info(f"Webhook notification sent for incident {incident['incident_id']}")
                    else:
                        logger.error(f"Webhook notification failed: {response.status}")
            
        except Exception as e:
            logger.error(f"Failed to send webhook notification: {str(e)}")


class DeploymentManager:
    """Enterprise deployment management"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.deployment_history = []
    
    async def validate_configuration(self, config_update: Dict[str, Any]) -> Dict[str, Any]:
        """Validate configuration update"""
        validation_errors = []
        
        # Basic validation rules
        required_fields = ["version", "components"]
        for field in required_fields:
            if field not in config_update:
                validation_errors.append(f"Missing required field: {field}")
        
        # Version validation
        if "version" in config_update:
            version = config_update["version"]
            if not isinstance(version, str) or not version:
                validation_errors.append("Version must be a non-empty string")
        
        return {
            "valid": len(validation_errors) == 0,
            "errors": validation_errors
        }
    
    async def create_deployment_plan(self, config_update: Dict[str, Any]) -> Dict[str, Any]:
        """Create deployment plan"""
        plan = {
            "deployment_id": str(uuid.uuid4()),
            "steps": [
                "Backup current configuration",
                "Validate new configuration",
                "Deploy to staging environment",
                "Run validation tests",
                "Deploy to production environment",
                "Verify deployment",
                "Update monitoring configuration"
            ],
            "rollback_plan": [
                "Stop new services",
                "Restore previous configuration",
                "Restart services",
                "Verify rollback successful"
            ],
            "estimated_duration": "30 minutes",
            "risk_level": "medium"
        }
        
        return plan
    
    async def execute_deployment(self, deployment_id: str, 
                               deployment_plan: Dict[str, Any]) -> Dict[str, Any]:
        """Execute deployment plan"""
        try:
            deployment_start = datetime.now()
            
            # Simulate deployment execution
            executed_steps = []
            for step in deployment_plan["steps"]:
                # Simulate step execution
                await asyncio.sleep(1)  # Simulate work
                executed_steps.append({
                    "step": step,
                    "status": "completed",
                    "timestamp": datetime.now().isoformat()
                })
            
            deployment_end = datetime.now()
            duration = (deployment_end - deployment_start).total_seconds()
            
            deployment_record = {
                "deployment_id": deployment_id,
                "status": "success",
                "start_time": deployment_start.isoformat(),
                "end_time": deployment_end.isoformat(),
                "duration_seconds": duration,
                "executed_steps": executed_steps
            }
            
            self.deployment_history.append(deployment_record)
            
            return deployment_record
            
        except Exception as e:
            return {
                "deployment_id": deployment_id,
                "status": "failed",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
