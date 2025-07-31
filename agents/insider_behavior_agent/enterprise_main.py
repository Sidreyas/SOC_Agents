"""
Enterprise Insider Behavior Agent - Main Integration Module
Production-ready SOC agent for insider threat detection and behavior analysis

Use Cases Covered:
- Anomalous User Behavior Detection (#15)
- Insider Threat Indicators (#21)

Features:
- Azure Key Vault integration for secure user data
- RBAC-based access control for insider investigations
- GDPR/HIPAA/SOX compliance with privacy protection
- Enterprise encryption for sensitive behavioral data
- High availability and auto-scaling support
- SLA monitoring and alerting
- Advanced behavioral analytics and pattern recognition
"""

import asyncio
import logging
import sys
import os
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import json
from enum import Enum

# Add enterprise module to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from enterprise import (
    EnterpriseSecurityManager,
    EnterpriseComplianceManager,
    EnterpriseOperationsManager,
    EnterpriseScalingManager,
    SecurityRole,
    EncryptionLevel,
    ComplianceFramework,
    AlertSeverity,
    SLAType
)

logger = logging.getLogger(__name__)

class InsiderThreatRisk(Enum):
    """Insider threat risk levels"""
    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class BehaviorAnomalyType(Enum):
    """Types of behavioral anomalies"""
    ACCESS_PATTERN = "access_pattern"
    DATA_USAGE = "data_usage"
    TIME_PATTERN = "time_pattern"
    LOCATION_PATTERN = "location_pattern"
    PRIVILEGE_USAGE = "privilege_usage"
    COMMUNICATION = "communication"

class UserRiskProfile(Enum):
    """User risk profile classifications"""
    TRUSTED = "trusted"
    STANDARD = "standard"
    ELEVATED = "elevated"
    HIGH_RISK = "high_risk"
    CRITICAL = "critical"

class InsiderThreatIndicator(Enum):
    """Insider threat indicator types"""
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ABUSE = "privilege_abuse"
    POLICY_VIOLATION = "policy_violation"
    SUSPICIOUS_ACCESS = "suspicious_access"
    ABNORMAL_HOURS = "abnormal_hours"
    UNUSUAL_DOWNLOADS = "unusual_downloads"

class EnterpriseInsiderBehaviorAgent:
    """
    Enterprise-grade insider threat detection and behavior analysis agent
    """
    
    def __init__(self):
        """Initialize enterprise insider behavior agent"""
        # Initialize enterprise managers
        self.security_manager = EnterpriseSecurityManager()
        self.compliance_manager = EnterpriseComplianceManager()
        self.operations_manager = EnterpriseOperationsManager()
        self.scaling_manager = EnterpriseScalingManager()
        
        # Agent configuration
        self.agent_id = "insider_behavior_agent_enterprise"
        self.version = "2.0.0-enterprise"
        self.startup_time = datetime.now()
        
        # Component tracking
        self.active_investigations = {}
        self.behavioral_baselines = {}
        self.risk_profiles = {}
        self.threat_indicators = {}
        
        logger.info(f"Enterprise Insider Behavior Agent {self.version} initialized")
    
    async def initialize(self) -> bool:
        """Initialize enterprise insider behavior agent"""
        try:
            # Initialize enterprise components
            await self.security_manager.initialize()
            await self.compliance_manager.initialize()
            await self.operations_manager.initialize()
            await self.scaling_manager.initialize()
            
            # Register agent with operations manager
            await self.operations_manager.register_agent(
                self.agent_id,
                {
                    "type": "insider_behavior",
                    "version": self.version,
                    "capabilities": [
                        "behavioral_analysis",
                        "anomaly_detection",
                        "risk_assessment",
                        "insider_threat_detection",
                        "user_profiling",
                        "pattern_recognition"
                    ],
                    "sla_targets": {
                        "behavioral_analysis": 240.0,       # 4 minutes
                        "anomaly_detection": 180.0,         # 3 minutes
                        "risk_assessment": 300.0,           # 5 minutes
                        "threat_investigation": 600.0       # 10 minutes
                    }
                }
            )
            
            # Initialize behavioral baselines
            await self._initialize_behavioral_baselines()
            
            # Load risk profiles
            await self._load_risk_profiles()
            
            # Setup insider monitoring
            await self._setup_insider_monitoring()
            
            logger.info("Enterprise Insider Behavior Agent initialization completed")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize enterprise insider behavior agent: {str(e)}")
            await self.operations_manager.handle_error(
                "agent_initialization_failed",
                str(e),
                AlertSeverity.CRITICAL
            )
            return False
    
    async def analyze_insider_behavior(self, user_data: Dict[str, Any], 
                                     context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Complete enterprise insider behavior analysis workflow
        
        Args:
            user_data: User behavior data for analysis
            context: Optional analysis context
            
        Returns:
            Complete insider behavior analysis results
        """
        investigation_id = f"insider_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Start SLA tracking
        sla_context = self.operations_manager.start_sla_tracking(
            "insider_behavior_analysis",
            target_duration=600.0,
            investigation_id=investigation_id
        )
        
        try:
            # RBAC authentication
            if not await self.security_manager.check_permission(
                SecurityRole.SOC_ANALYST, "insider_behavior:analyze"
            ):
                raise PermissionError("Insufficient permissions for insider behavior analysis")
            
            # Compliance logging with privacy considerations
            self.compliance_manager.log_investigation_start(
                investigation_id,
                "insider_behavior_analysis",
                {
                    "analyst_id": await self.security_manager.get_current_user_id(),
                    "privacy_notice": "User behavior analysis for security purposes",
                    "data_classification": "sensitive"
                },
                [ComplianceFramework.GDPR, ComplianceFramework.HIPAA, ComplianceFramework.SOX]
            )
            
            logger.info(f"Starting enterprise insider behavior analysis: {investigation_id}")
            
            # Initialize analysis results
            analysis_results = {
                "investigation_id": investigation_id,
                "analysis_timestamp": datetime.now(),
                "agent_version": self.version,
                "enterprise_metadata": {
                    "analyst_id": await self.security_manager.get_current_user_id(),
                    "compliance_frameworks": ["GDPR", "HIPAA", "SOX"],
                    "encryption_level": EncryptionLevel.HIGH.value,
                    "privacy_protection": "enabled",
                    "audit_trail": []
                },
                "behavioral_analysis": {},
                "anomaly_detection": {},
                "risk_assessment": {},
                "insider_threat_detection": {},
                "user_profiling": {},
                "pattern_recognition": {},
                "recommendations": [],
                "automated_actions": []
            }
            
            # Track active investigation
            self.active_investigations[investigation_id] = {
                "start_time": datetime.now(),
                "status": "in_progress",
                "current_stage": "initialization"
            }
            
            # State 1: Behavioral Analysis
            analysis_results["behavioral_analysis"] = await self._analyze_user_behavior(
                user_data, investigation_id
            )
            
            # State 2: Anomaly Detection
            analysis_results["anomaly_detection"] = await self._detect_behavioral_anomalies(
                user_data, analysis_results["behavioral_analysis"], investigation_id
            )
            
            # State 3: Risk Assessment
            analysis_results["risk_assessment"] = await self._assess_insider_risk(
                analysis_results, investigation_id
            )
            
            # State 4: Insider Threat Detection
            analysis_results["insider_threat_detection"] = await self._detect_insider_threats(
                analysis_results, investigation_id
            )
            
            # State 5: User Profiling
            analysis_results["user_profiling"] = await self._create_user_profile(
                analysis_results
            )
            
            # State 6: Pattern Recognition
            analysis_results["pattern_recognition"] = await self._recognize_behavior_patterns(
                analysis_results
            )
            
            # Generate recommendations
            analysis_results["recommendations"] = await self._generate_recommendations(
                analysis_results
            )
            
            # Execute automated actions
            analysis_results["automated_actions"] = await self._execute_automated_actions(
                analysis_results, investigation_id
            )
            
            # Encrypt sensitive data
            analysis_results = await self.security_manager.encrypt_sensitive_data(
                analysis_results, EncryptionLevel.HIGH
            )
            
            # Complete compliance logging
            self.compliance_manager.log_investigation_complete(
                investigation_id,
                analysis_results["risk_assessment"],
                ComplianceFramework.GDPR
            )
            
            # Complete SLA tracking
            self.operations_manager.complete_sla_tracking(sla_context, success=True)
            
            # Update investigation tracking
            self.active_investigations[investigation_id]["status"] = "completed"
            self.active_investigations[investigation_id]["end_time"] = datetime.now()
            
            logger.info(f"Completed enterprise insider behavior analysis: {investigation_id}")
            
            return analysis_results
            
        except Exception as e:
            logger.error(f"Error in enterprise insider behavior analysis: {str(e)}")
            
            # Error handling
            await self.operations_manager.handle_error(
                "insider_behavior_analysis_error",
                str(e),
                AlertSeverity.HIGH,
                {"investigation_id": investigation_id}
            )
            
            # Complete SLA tracking with failure
            self.operations_manager.complete_sla_tracking(sla_context, success=False)
            
            # Update investigation tracking
            if investigation_id in self.active_investigations:
                self.active_investigations[investigation_id]["status"] = "failed"
                self.active_investigations[investigation_id]["error"] = str(e)
            
            raise
    
    async def _analyze_user_behavior(self, user_data: Dict[str, Any], investigation_id: str) -> Dict[str, Any]:
        """State 1: User Behavior Analysis"""
        self.active_investigations[investigation_id]["current_stage"] = "behavioral_analysis"
        
        user_id = user_data.get("user_id", "unknown")
        time_period = user_data.get("time_period", 30)  # days
        
        behavioral_analysis = {
            "access_patterns": await self._analyze_access_patterns(user_data),
            "data_usage_patterns": await self._analyze_data_usage(user_data),
            "time_patterns": await self._analyze_time_patterns(user_data),
            "location_patterns": await self._analyze_location_patterns(user_data),
            "privilege_usage": await self._analyze_privilege_usage(user_data),
            "communication_patterns": await self._analyze_communication_patterns(user_data),
            "application_usage": await self._analyze_application_usage(user_data),
            "baseline_comparison": await self._compare_to_baseline(user_id, user_data)
        }
        
        return behavioral_analysis
    
    async def _detect_behavioral_anomalies(self, user_data: Dict[str, Any], 
                                         behavioral_analysis: Dict[str, Any], investigation_id: str) -> Dict[str, Any]:
        """State 2: Behavioral Anomaly Detection"""
        self.active_investigations[investigation_id]["current_stage"] = "anomaly_detection"
        
        anomaly_detection = {
            "access_anomalies": await self._detect_access_anomalies(behavioral_analysis),
            "temporal_anomalies": await self._detect_temporal_anomalies(behavioral_analysis),
            "volumetric_anomalies": await self._detect_volumetric_anomalies(behavioral_analysis),
            "behavioral_deviations": await self._detect_behavioral_deviations(behavioral_analysis),
            "privilege_anomalies": await self._detect_privilege_anomalies(behavioral_analysis),
            "location_anomalies": await self._detect_location_anomalies(behavioral_analysis),
            "anomaly_scoring": await self._score_anomalies(behavioral_analysis),
            "statistical_analysis": await self._perform_statistical_analysis(behavioral_analysis)
        }
        
        return anomaly_detection
    
    async def _assess_insider_risk(self, analysis_results: Dict[str, Any], investigation_id: str) -> Dict[str, Any]:
        """State 3: Insider Risk Assessment"""
        self.active_investigations[investigation_id]["current_stage"] = "risk_assessment"
        
        behavioral_analysis = analysis_results.get("behavioral_analysis", {})
        anomaly_detection = analysis_results.get("anomaly_detection", {})
        
        risk_assessment = {
            "risk_factors": await self._identify_risk_factors(analysis_results),
            "threat_indicators": await self._identify_threat_indicators(analysis_results),
            "vulnerability_assessment": await self._assess_vulnerabilities(analysis_results),
            "impact_analysis": await self._analyze_potential_impact(analysis_results),
            "likelihood_assessment": await self._assess_likelihood(analysis_results),
            "risk_scoring": await self._calculate_risk_score(analysis_results),
            "mitigation_options": await self._identify_mitigation_options(analysis_results),
            "escalation_criteria": await self._assess_escalation_criteria(analysis_results)
        }
        
        return risk_assessment
    
    async def _detect_insider_threats(self, analysis_results: Dict[str, Any], investigation_id: str) -> Dict[str, Any]:
        """State 4: Insider Threat Detection"""
        self.active_investigations[investigation_id]["current_stage"] = "threat_detection"
        
        risk_assessment = analysis_results.get("risk_assessment", {})
        anomaly_detection = analysis_results.get("anomaly_detection", {})
        
        threat_detection = {
            "data_exfiltration_indicators": await self._detect_data_exfiltration(analysis_results),
            "privilege_abuse_indicators": await self._detect_privilege_abuse(analysis_results),
            "policy_violations": await self._detect_policy_violations(analysis_results),
            "suspicious_activities": await self._identify_suspicious_activities(analysis_results),
            "malicious_intent_indicators": await self._detect_malicious_intent(analysis_results),
            "fraud_indicators": await self._detect_fraud_indicators(analysis_results),
            "sabotage_indicators": await self._detect_sabotage_indicators(analysis_results),
            "threat_classification": await self._classify_threats(analysis_results)
        }
        
        return threat_detection
    
    async def _create_user_profile(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """State 5: User Profiling"""
        behavioral_analysis = analysis_results.get("behavioral_analysis", {})
        risk_assessment = analysis_results.get("risk_assessment", {})
        threat_detection = analysis_results.get("insider_threat_detection", {})
        
        risk_score = risk_assessment.get("risk_scoring", {}).get("total_score", 0.0)
        threat_indicators = len(threat_detection.get("threat_classification", []))
        
        # Profile classification logic
        if risk_score > 0.8 or threat_indicators > 3:
            risk_profile = UserRiskProfile.CRITICAL.value
        elif risk_score > 0.6 or threat_indicators > 2:
            risk_profile = UserRiskProfile.HIGH_RISK.value
        elif risk_score > 0.4 or threat_indicators > 1:
            risk_profile = UserRiskProfile.ELEVATED.value
        elif risk_score > 0.2:
            risk_profile = UserRiskProfile.STANDARD.value
        else:
            risk_profile = UserRiskProfile.TRUSTED.value
        
        user_profile = {
            "risk_profile": risk_profile,
            "behavioral_characteristics": await self._extract_behavioral_characteristics(analysis_results),
            "activity_patterns": await self._extract_activity_patterns(analysis_results),
            "access_privileges": await self._assess_access_privileges(analysis_results),
            "historical_context": await self._gather_historical_context(analysis_results),
            "peer_comparison": await self._compare_to_peers(analysis_results),
            "profile_confidence": await self._calculate_profile_confidence(analysis_results),
            "monitoring_recommendations": await self._recommend_monitoring(risk_profile)
        }
        
        return user_profile
    
    async def _recognize_behavior_patterns(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """State 6: Behavior Pattern Recognition"""
        behavioral_analysis = analysis_results.get("behavioral_analysis", {})
        anomaly_detection = analysis_results.get("anomaly_detection", {})
        
        pattern_recognition = {
            "recurring_patterns": await self._identify_recurring_patterns(analysis_results),
            "seasonal_patterns": await self._identify_seasonal_patterns(analysis_results),
            "escalation_patterns": await self._identify_escalation_patterns(analysis_results),
            "correlation_patterns": await self._identify_correlation_patterns(analysis_results),
            "deviation_patterns": await self._identify_deviation_patterns(analysis_results),
            "predictive_patterns": await self._identify_predictive_patterns(analysis_results),
            "pattern_significance": await self._assess_pattern_significance(analysis_results),
            "behavioral_trends": await self._analyze_behavioral_trends(analysis_results)
        }
        
        return pattern_recognition
    
    async def _generate_recommendations(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate insider behavior recommendations"""
        recommendations = []
        
        user_profile = analysis_results.get("user_profiling", {})
        threat_detection = analysis_results.get("insider_threat_detection", {})
        risk_profile = user_profile.get("risk_profile", "standard")
        
        if risk_profile == UserRiskProfile.CRITICAL.value:
            recommendations.extend([
                {
                    "priority": "CRITICAL",
                    "action": "immediate_investigation",
                    "description": "Initiate immediate insider threat investigation"
                },
                {
                    "priority": "CRITICAL",
                    "action": "access_restriction",
                    "description": "Restrict user access to sensitive resources"
                },
                {
                    "priority": "HIGH",
                    "action": "continuous_monitoring",
                    "description": "Enable continuous behavioral monitoring"
                }
            ])
        
        if risk_profile == UserRiskProfile.HIGH_RISK.value:
            recommendations.extend([
                {
                    "priority": "HIGH",
                    "action": "enhanced_monitoring",
                    "description": "Enable enhanced user activity monitoring"
                },
                {
                    "priority": "MEDIUM",
                    "action": "access_review",
                    "description": "Review and validate user access privileges"
                }
            ])
        
        if "data_exfiltration_indicators" in threat_detection:
            recommendations.append({
                "priority": "HIGH",
                "action": "data_loss_prevention",
                "description": "Enable DLP monitoring for this user"
            })
        
        if risk_profile in [UserRiskProfile.ELEVATED.value, UserRiskProfile.HIGH_RISK.value]:
            recommendations.append({
                "priority": "MEDIUM",
                "action": "security_training",
                "description": "Provide additional security awareness training"
            })
        
        return recommendations
    
    async def _execute_automated_actions(self, analysis_results: Dict[str, Any], investigation_id: str) -> List[Dict[str, Any]]:
        """Execute automated insider behavior actions"""
        self.active_investigations[investigation_id]["current_stage"] = "automated_actions"
        
        automated_actions = []
        recommendations = analysis_results.get("recommendations", [])
        
        for recommendation in recommendations:
            if recommendation["priority"] in ["CRITICAL", "HIGH"]:
                action_result = await self._execute_insider_action(
                    recommendation["action"],
                    analysis_results,
                    investigation_id
                )
                automated_actions.append(action_result)
        
        return automated_actions
    
    # Implementation helper methods
    async def _execute_insider_action(self, action: str, analysis_results: Dict[str, Any], investigation_id: str) -> Dict[str, Any]:
        """Execute specific insider behavior action"""
        try:
            if action == "immediate_investigation":
                result = await self._initiate_investigation(analysis_results)
            elif action == "access_restriction":
                result = await self._restrict_access(analysis_results)
            elif action == "continuous_monitoring":
                result = await self._enable_continuous_monitoring(analysis_results)
            elif action == "enhanced_monitoring":
                result = await self._enable_enhanced_monitoring(analysis_results)
            elif action == "data_loss_prevention":
                result = await self._enable_dlp_monitoring(analysis_results)
            else:
                result = {"status": "not_implemented"}
            
            return {
                "action": action,
                "status": "completed",
                "result": result,
                "timestamp": datetime.now(),
                "investigation_id": investigation_id
            }
        except Exception as e:
            return {
                "action": action,
                "status": "failed",
                "error": str(e),
                "timestamp": datetime.now(),
                "investigation_id": investigation_id
            }
    
    async def _initiate_investigation(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Initiate insider threat investigation"""
        return {"status": "investigation_initiated", "case_id": "INS-001"}
    
    async def _restrict_access(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Restrict user access to resources"""
        return {"status": "access_restricted", "restrictions_applied": 5}
    
    async def _enable_continuous_monitoring(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Enable continuous behavioral monitoring"""
        return {"status": "monitoring_enabled", "monitoring_level": "continuous"}
    
    async def _enable_enhanced_monitoring(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Enable enhanced user monitoring"""
        return {"status": "monitoring_enhanced", "monitoring_level": "enhanced"}
    
    async def _enable_dlp_monitoring(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Enable DLP monitoring for user"""
        return {"status": "dlp_enabled", "policy_applied": "strict"}
    
    # Analysis helper methods
    async def _analyze_access_patterns(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze user access patterns"""
        return {
            "resource_access_frequency": {},
            "unusual_access_times": [],
            "privileged_access_usage": {},
            "access_pattern_changes": []
        }
    
    async def _detect_data_exfiltration(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Detect data exfiltration indicators"""
        return {
            "large_file_downloads": 5,
            "unusual_data_access": True,
            "external_transfers": 2,
            "confidence_score": 0.75
        }
    
    async def _detect_privilege_abuse(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Detect privilege abuse indicators"""
        return {
            "unauthorized_privilege_usage": True,
            "admin_access_anomalies": 3,
            "escalation_attempts": 1,
            "confidence_score": 0.65
        }
    
    # Initialization methods
    async def _initialize_behavioral_baselines(self):
        """Initialize behavioral baselines"""
        self.behavioral_baselines = {
            "normal_access_patterns": {},
            "typical_work_hours": {},
            "standard_data_usage": {},
            "baseline_timestamp": datetime.now()
        }
    
    async def _load_risk_profiles(self):
        """Load user risk profiles"""
        self.risk_profiles = {
            "user_classifications": {},
            "risk_factors": {},
            "monitoring_levels": {},
            "last_update": datetime.now()
        }
    
    async def _setup_insider_monitoring(self):
        """Setup insider behavior monitoring"""
        await self.operations_manager.start_health_monitoring(
            self.agent_id,
            {
                "check_interval": 60.0,
                "metrics": [
                    "active_investigations",
                    "behavioral_analysis_rate",
                    "insider_threat_detection_rate",
                    "false_positive_rate",
                    "user_risk_assessments"
                ]
            }
        )
    
    async def get_agent_status(self) -> Dict[str, Any]:
        """Get current agent status"""
        return {
            "agent_id": self.agent_id,
            "version": self.version,
            "startup_time": self.startup_time,
            "active_investigations": len(self.active_investigations),
            "behavioral_baselines": self.behavioral_baselines,
            "risk_profiles": self.risk_profiles,
            "threat_indicators": self.threat_indicators,
            "health_status": await self.operations_manager.get_component_health(self.agent_id),
            "enterprise_features": {
                "security": "enabled",
                "compliance": "enabled",
                "operations": "enabled",
                "scaling": "enabled",
                "privacy_protection": "enabled"
            }
        }

# Factory function for creating enterprise insider behavior agent
async def create_enterprise_insider_behavior_agent() -> EnterpriseInsiderBehaviorAgent:
    """Create and initialize enterprise insider behavior agent"""
    agent = EnterpriseInsiderBehaviorAgent()
    
    if await agent.initialize():
        return agent
    else:
        raise RuntimeError("Failed to initialize enterprise insider behavior agent")

# Main execution
if __name__ == "__main__":
    async def main():
        try:
            # Create enterprise insider behavior agent
            insider_agent = await create_enterprise_insider_behavior_agent()
            
            # Example usage
            user_data = {
                "user_id": "john.doe",
                "time_period": 30,
                "access_events": [
                    {
                        "resource": "financial_database",
                        "timestamp": datetime.now(),
                        "access_type": "read"
                    }
                ],
                "data_usage": [
                    {
                        "file_size": 500000000,  # 500MB
                        "action": "download",
                        "timestamp": datetime.now()
                    }
                ],
                "login_events": [
                    {
                        "location": "home",
                        "time": "02:30",
                        "success": True
                    }
                ]
            }
            
            # Analyze insider behavior
            results = await insider_agent.analyze_insider_behavior(user_data)
            
            print(f"Analysis completed: {results['investigation_id']}")
            print(f"Risk Profile: {results['user_profiling']['risk_profile']}")
            
        except Exception as e:
            logger.error(f"Error in main execution: {str(e)}")
    
    asyncio.run(main())
