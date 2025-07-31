"""
Access Control Agent
Handles privilege escalation detection, suspicious role assignments, and unauthorized resource creation
Use Cases: #8, #23, #26

This agent implements a 5-state workflow:
1. Permission Analysis - Extract and analyze permission changes, role assignments, and administrative activities
2. Baseline Validation - Validate against historical user behavior patterns and organizational policies  
3. Investigation Coordination - Gather additional evidence and perform contextual enrichment
4. Risk Assessment - Calculate comprehensive risk scores and determine threat levels
5. Classification & Response - Provide final classification and escalation decisions
"""

import logging
from typing import Dict, Any, List, Tuple
from datetime import datetime, timedelta
import json

from .permission_analyzer import PermissionAnalyzer
from .baseline_validator import BaselineValidator
from .investigation_coordinator import InvestigationCoordinator
from .risk_assessor import RiskAssessor
from .classification_engine import ClassificationEngine

logger = logging.getLogger(__name__)

class AccessControlAgent:
    """
    Main Access Control Agent class that orchestrates the 5-state workflow
    for detecting and responding to access control anomalies
    """
    
    def __init__(self):
        self.permission_analyzer = PermissionAnalyzer()
        self.baseline_validator = BaselineValidator()
        self.investigation_coordinator = InvestigationCoordinator()
        self.risk_assessor = RiskAssessor()
        self.classification_engine = ClassificationEngine()
        
        self.agent_metadata = {
            "agent_name": "Access Control Agent",
            "version": "1.0",
            "use_cases": ["UC008", "UC023", "UC026"],
            "capabilities": [
                "Privilege escalation detection",
                "Suspicious role assignment analysis", 
                "Unauthorized resource creation monitoring",
                "RBAC policy compliance validation",
                "Cross-agent correlation"
            ]
        }
        
    def analyze_access_control_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point for analyzing access control events
        Implements the complete 5-state workflow
        
        Args:
            event_data: Raw event data containing permission changes, role assignments, etc.
            
        Returns:
            Complete analysis results with classification and response recommendations
        """
        logger.info("Starting Access Control Agent analysis")
        
        analysis_results = {
            "agent_metadata": self.agent_metadata,
            "analysis_start_time": datetime.now(),
            "workflow_states": {},
            "final_classification": {},
            "escalation_plan": {},
            "incident_ticket": {},
            "final_report": {}
        }
        
        try:
            # State 1: Permission Analysis
            logger.info("State 1: Permission Analysis")
            permission_analysis = self.permission_analyzer.extract_permission_entities(
                event_data.get("permission_data", {}),
                event_data.get("time_window", {
                    "start": datetime.now() - timedelta(hours=24),
                    "end": datetime.now()
                })
            )
            
            azure_ad_analysis = self.permission_analyzer.analyze_azure_ad_logs(
                event_data.get("azure_ad_logs", [])
            )
            
            arm_analysis = self.permission_analyzer.analyze_arm_activity(
                event_data.get("arm_logs", [])
            )
            
            suspicious_patterns = self.permission_analyzer.detect_suspicious_patterns(
                permission_analysis,
                azure_ad_analysis, 
                arm_analysis
            )
            
            state1_results = {
                "permission_analysis": permission_analysis,
                "azure_ad_analysis": azure_ad_analysis,
                "arm_analysis": arm_analysis,
                "suspicious_patterns": suspicious_patterns
            }
            analysis_results["workflow_states"]["state1_permission_analysis"] = state1_results
            
            # State 2: Baseline Validation
            logger.info("State 2: Baseline Validation")
            user_baselines = self.baseline_validator.establish_user_baselines(
                permission_analysis.get("user_accounts", []),
                event_data.get("time_window", {})
            )
            
            rbac_validation = self.baseline_validator.validate_rbac_policies(
                permission_analysis.get("role_assignments", []),
                permission_analysis.get("permission_changes", [])
            )
            
            change_management_validation = self.baseline_validator.validate_change_management(
                arm_analysis.get("administrative_actions", [])
            )
            
            azure_policy_validation = self.baseline_validator.validate_azure_policy_compliance(
                arm_analysis
            )
            
            state2_results = {
                "user_baselines": user_baselines,
                "rbac_validation": rbac_validation,
                "change_management_validation": change_management_validation,
                "azure_policy_validation": azure_policy_validation
            }
            analysis_results["workflow_states"]["state2_baseline_validation"] = state2_results
            
            # State 3: Investigation Coordination
            logger.info("State 3: Investigation Coordination")
            additional_evidence = self.investigation_coordinator.gather_additional_evidence(
                list(permission_analysis.get("user_accounts", {}).keys()),
                event_data.get("time_window", {})
            )
            
            contextual_enrichment = self.investigation_coordinator.perform_contextual_enrichment(
                additional_evidence,
                permission_analysis
            )
            
            cmdb_relationships = self.investigation_coordinator.query_cmdb_relationships(
                list(permission_analysis.get("user_accounts", {}).keys())
            )
            
            cross_agent_correlations = self.investigation_coordinator.correlate_cross_agent_findings(
                event_data.get("other_agent_data", {})
            )
            
            security_tool_data = self.investigation_coordinator.query_security_tools(
                list(permission_analysis.get("user_accounts", {}).keys()),
                event_data.get("time_window", {})
            )
            
            state3_results = {
                "additional_evidence": additional_evidence,
                "contextual_enrichment": contextual_enrichment,
                "cmdb_relationships": cmdb_relationships,
                "cross_agent_correlations": cross_agent_correlations,
                "security_tool_data": security_tool_data
            }
            analysis_results["workflow_states"]["state3_investigation_coordination"] = state3_results
            
            # State 4: Risk Assessment
            logger.info("State 4: Risk Assessment")
            permission_risk_score = self.risk_assessor.calculate_permission_risk_score(
                permission_analysis,
                state2_results
            )
            
            threat_assessment = self.risk_assessor.assess_threat_level(
                contextual_enrichment,
                cross_agent_correlations
            )
            
            business_impact = self.risk_assessor.calculate_business_impact(
                permission_analysis,
                contextual_enrichment.get("organizational_context", {})
            )
            
            response_prioritization = self.risk_assessor.prioritize_response_actions(
                permission_risk_score.get("overall_risk_score", 0.0),
                threat_assessment.get("threat_level", "low"),
                business_impact
            )
            
            state4_results = {
                "permission_risk_score": permission_risk_score,
                "threat_assessment": threat_assessment,
                "business_impact": business_impact,
                "response_prioritization": response_prioritization
            }
            analysis_results["workflow_states"]["state4_risk_assessment"] = state4_results
            
            # State 5: Classification & Response
            logger.info("State 5: Classification & Response")
            incident_classification = self.classification_engine.classify_incident_severity(
                permission_risk_score,
                threat_assessment,
                business_impact
            )
            
            escalation_plan = self.classification_engine.determine_escalation_path(
                incident_classification,
                response_prioritization
            )
            
            incident_ticket = self.classification_engine.generate_incident_ticket(
                incident_classification,
                escalation_plan,
                {**state1_results, **state2_results, **state3_results}
            )
            
            final_report = self.classification_engine.create_final_report(
                analysis_results["workflow_states"],
                incident_classification,
                escalation_plan
            )
            
            state5_results = {
                "incident_classification": incident_classification,
                "escalation_plan": escalation_plan,
                "incident_ticket": incident_ticket,
                "final_report": final_report
            }
            analysis_results["workflow_states"]["state5_classification_response"] = state5_results
            
            # Set final results
            analysis_results["final_classification"] = incident_classification
            analysis_results["escalation_plan"] = escalation_plan
            analysis_results["incident_ticket"] = incident_ticket
            analysis_results["final_report"] = final_report
            
            analysis_results["analysis_end_time"] = datetime.now()
            analysis_results["analysis_duration"] = (
                analysis_results["analysis_end_time"] - analysis_results["analysis_start_time"]
            ).total_seconds()
            
            logger.info(f"Access Control Agent analysis complete. Severity: {incident_classification.get('severity_level', 'unknown')}")
            
        except Exception as e:
            logger.error(f"Error in Access Control Agent analysis: {str(e)}")
            analysis_results["error"] = {
                "message": str(e),
                "timestamp": datetime.now(),
                "stage": "workflow_execution"
            }
        
        return analysis_results
    
    def get_agent_status(self) -> Dict[str, Any]:
        """
        Get current agent status and health information
        
        Returns:
            Agent status information
        """
        return {
            "agent_name": self.agent_metadata["agent_name"],
            "version": self.agent_metadata["version"],
            "status": "operational",
            "last_health_check": datetime.now(),
            "module_status": {
                "permission_analyzer": "operational",
                "baseline_validator": "operational", 
                "investigation_coordinator": "operational",
                "risk_assessor": "operational",
                "classification_engine": "operational"
            },
            "supported_use_cases": self.agent_metadata["use_cases"],
            "capabilities": self.agent_metadata["capabilities"]
        }
    
    def validate_event_data(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate incoming event data for required fields and structure
        
        Args:
            event_data: Event data to validate
            
        Returns:
            Validation results with any issues identified
        """
        validation_results = {
            "is_valid": True,
            "issues": [],
            "warnings": [],
            "required_fields_present": True,
            "data_quality_score": 1.0
        }
        
        # Check required fields
        required_fields = ["permission_data", "time_window"]
        for field in required_fields:
            if field not in event_data:
                validation_results["issues"].append(f"Missing required field: {field}")
                validation_results["required_fields_present"] = False
        
        # Check optional but recommended fields
        recommended_fields = ["azure_ad_logs", "arm_logs", "other_agent_data"]
        missing_recommended = []
        for field in recommended_fields:
            if field not in event_data:
                missing_recommended.append(field)
        
        if missing_recommended:
            validation_results["warnings"].append(f"Missing recommended fields: {', '.join(missing_recommended)}")
            validation_results["data_quality_score"] -= 0.1 * len(missing_recommended)
        
        # Validate time_window structure
        if "time_window" in event_data:
            time_window = event_data["time_window"]
            if not isinstance(time_window, dict):
                validation_results["issues"].append("time_window must be a dictionary")
            elif "start" not in time_window or "end" not in time_window:
                validation_results["issues"].append("time_window must contain 'start' and 'end' fields")
        
        # Set overall validity
        validation_results["is_valid"] = len(validation_results["issues"]) == 0
        
        return validation_results
    
    def get_supported_use_cases(self) -> List[Dict[str, Any]]:
        """
        Get detailed information about supported use cases
        
        Returns:
            List of supported use cases with descriptions
        """
        return [
            {
                "use_case_id": "UC008",
                "title": "Privilege Escalation Detection",
                "description": "Detect unauthorized elevation of user privileges and administrative access",
                "detection_methods": [
                    "Role assignment analysis",
                    "Permission change monitoring",
                    "Administrative activity correlation"
                ],
                "data_sources": [
                    "Azure AD Audit Logs",
                    "Role Assignment Events",
                    "Privilege Change Events"
                ]
            },
            {
                "use_case_id": "UC023", 
                "title": "Suspicious Role Assignment",
                "description": "Identify suspicious or unauthorized role assignments to users",
                "detection_methods": [
                    "Baseline deviation analysis",
                    "Role assignment pattern analysis",
                    "RBAC policy validation"
                ],
                "data_sources": [
                    "Azure AD Logs",
                    "RBAC Assignment Events",
                    "Administrative Logs"
                ]
            },
            {
                "use_case_id": "UC026",
                "title": "Unauthorized Resource Creation",
                "description": "Monitor for unauthorized creation of cloud resources and infrastructure",
                "detection_methods": [
                    "ARM activity analysis",
                    "Resource creation monitoring",
                    "Policy compliance validation"
                ],
                "data_sources": [
                    "Azure Resource Manager Logs",
                    "Resource Creation Events",
                    "Policy Violation Events"
                ]
            }
        ]
