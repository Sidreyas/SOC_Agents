"""
Resolution Validator Module
State 6: Resolution Validation and Verification
Validates incident resolution against success criteria
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
import json
import hashlib

logger = logging.getLogger(__name__)

class ValidationStatus(Enum):
    """Validation status types"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress" 
    PASSED = "passed"
    FAILED = "failed"
    PARTIAL = "partial"
    REQUIRES_REVIEW = "requires_review"

class ValidationCriteria(Enum):
    """Types of validation criteria"""
    THREAT_ELIMINATED = "threat_eliminated"
    SYSTEMS_SECURED = "systems_secured"
    DATA_INTEGRITY = "data_integrity"
    BUSINESS_CONTINUITY = "business_continuity"
    COMPLIANCE_MET = "compliance_met"
    LESSONS_DOCUMENTED = "lessons_documented"
    CONTROLS_IMPROVED = "controls_improved"
    STAKEHOLDERS_NOTIFIED = "stakeholders_notified"

class ResolutionConfidence(Enum):
    """Confidence levels for resolution validation"""
    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"

@dataclass
class ValidationResult:
    """Individual validation result"""
    criteria: str
    status: str
    confidence: str
    evidence: List[str]
    validation_date: datetime
    validator: str
    notes: str
    remediation_required: bool
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['validation_date'] = self.validation_date.isoformat()
        return result

@dataclass
class ResolutionValidation:
    """Complete resolution validation"""
    validation_id: str
    incident_id: str
    validation_date: datetime
    overall_status: str
    overall_confidence: str
    validation_results: List[ValidationResult]
    success_score: float
    remediation_actions: List[str]
    approval_required: bool
    approved_by: Optional[str]
    approval_date: Optional[datetime]
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['validation_date'] = self.validation_date.isoformat()
        result['approval_date'] = self.approval_date.isoformat() if self.approval_date else None
        result['validation_results'] = [vr.to_dict() for vr in self.validation_results]
        return result

class ResolutionValidator:
    """
    Validates incident resolution against predefined success criteria
    """
    
    def __init__(self):
        self.validation_criteria = self._initialize_validation_criteria()
        self.validation_rules = self._initialize_validation_rules()
        self.success_thresholds = self._initialize_success_thresholds()
        self.validation_history = []
        self.validation_stats = {
            "total_validations": 0,
            "validations_passed": 0,
            "validations_failed": 0,
            "average_success_score": 0,
            "common_failures": {},
            "validation_trends": []
        }
    
    def _initialize_validation_criteria(self) -> Dict[str, Dict[str, Any]]:
        """Initialize validation criteria for different incident types"""
        return {
            ValidationCriteria.THREAT_ELIMINATED.value: {
                "description": "Verify that the identified threat has been completely eliminated",
                "validation_methods": [
                    "malware_scan_verification",
                    "ioc_monitoring",
                    "behavioral_analysis",
                    "network_traffic_analysis"
                ],
                "evidence_requirements": [
                    "clean_malware_scans",
                    "no_ioc_detections",
                    "normal_system_behavior",
                    "clean_network_traffic"
                ],
                "confidence_factors": {
                    "scan_results": 0.3,
                    "monitoring_duration": 0.2,
                    "behavioral_analysis": 0.3,
                    "expert_review": 0.2
                },
                "minimum_confidence": ResolutionConfidence.HIGH.value,
                "mandatory": True
            },
            
            ValidationCriteria.SYSTEMS_SECURED.value: {
                "description": "Verify that all affected systems are properly secured",
                "validation_methods": [
                    "vulnerability_assessment",
                    "configuration_review",
                    "access_control_verification",
                    "patch_status_check"
                ],
                "evidence_requirements": [
                    "vulnerability_scan_clean",
                    "secure_configurations",
                    "proper_access_controls",
                    "current_patch_levels"
                ],
                "confidence_factors": {
                    "vulnerability_scans": 0.4,
                    "configuration_audit": 0.3,
                    "access_review": 0.2,
                    "patch_verification": 0.1
                },
                "minimum_confidence": ResolutionConfidence.HIGH.value,
                "mandatory": True
            },
            
            ValidationCriteria.DATA_INTEGRITY.value: {
                "description": "Verify data integrity and identify any data compromise",
                "validation_methods": [
                    "data_integrity_checks",
                    "backup_verification",
                    "audit_log_analysis",
                    "forensic_validation"
                ],
                "evidence_requirements": [
                    "integrity_hash_verification",
                    "backup_consistency",
                    "complete_audit_trails",
                    "forensic_evidence"
                ],
                "confidence_factors": {
                    "hash_verification": 0.4,
                    "backup_validation": 0.3,
                    "audit_completeness": 0.2,
                    "forensic_analysis": 0.1
                },
                "minimum_confidence": ResolutionConfidence.MEDIUM.value,
                "mandatory": True
            },
            
            ValidationCriteria.BUSINESS_CONTINUITY.value: {
                "description": "Verify business operations have been restored to normal",
                "validation_methods": [
                    "service_availability_check",
                    "performance_monitoring",
                    "user_acceptance_testing",
                    "business_process_validation"
                ],
                "evidence_requirements": [
                    "service_uptime_metrics",
                    "performance_benchmarks",
                    "user_satisfaction",
                    "process_completion_rates"
                ],
                "confidence_factors": {
                    "service_metrics": 0.3,
                    "performance_data": 0.3,
                    "user_feedback": 0.2,
                    "process_metrics": 0.2
                },
                "minimum_confidence": ResolutionConfidence.MEDIUM.value,
                "mandatory": False
            },
            
            ValidationCriteria.COMPLIANCE_MET.value: {
                "description": "Verify all compliance requirements have been met",
                "validation_methods": [
                    "regulatory_checklist_review",
                    "notification_verification",
                    "documentation_completeness",
                    "audit_trail_validation"
                ],
                "evidence_requirements": [
                    "compliance_checklist_complete",
                    "required_notifications_sent",
                    "complete_documentation",
                    "audit_trail_integrity"
                ],
                "confidence_factors": {
                    "checklist_completion": 0.4,
                    "notification_records": 0.3,
                    "documentation_quality": 0.2,
                    "audit_trail": 0.1
                },
                "minimum_confidence": ResolutionConfidence.HIGH.value,
                "mandatory": True
            },
            
            ValidationCriteria.LESSONS_DOCUMENTED.value: {
                "description": "Verify lessons learned have been properly documented",
                "validation_methods": [
                    "documentation_review",
                    "knowledge_base_update",
                    "procedure_updates",
                    "training_plan_development"
                ],
                "evidence_requirements": [
                    "lessons_learned_document",
                    "updated_procedures",
                    "knowledge_base_entries",
                    "training_materials"
                ],
                "confidence_factors": {
                    "documentation_quality": 0.4,
                    "procedure_updates": 0.3,
                    "knowledge_sharing": 0.2,
                    "training_readiness": 0.1
                },
                "minimum_confidence": ResolutionConfidence.MEDIUM.value,
                "mandatory": False
            },
            
            ValidationCriteria.CONTROLS_IMPROVED.value: {
                "description": "Verify security controls have been improved based on findings",
                "validation_methods": [
                    "control_assessment",
                    "detection_capability_testing",
                    "response_procedure_validation",
                    "monitoring_enhancement_verification"
                ],
                "evidence_requirements": [
                    "enhanced_controls",
                    "improved_detection",
                    "updated_procedures",
                    "enhanced_monitoring"
                ],
                "confidence_factors": {
                    "control_effectiveness": 0.4,
                    "detection_improvement": 0.3,
                    "procedure_enhancement": 0.2,
                    "monitoring_capability": 0.1
                },
                "minimum_confidence": ResolutionConfidence.MEDIUM.value,
                "mandatory": False
            },
            
            ValidationCriteria.STAKEHOLDERS_NOTIFIED.value: {
                "description": "Verify all stakeholders have been properly notified",
                "validation_methods": [
                    "notification_tracking",
                    "communication_verification",
                    "stakeholder_acknowledgment",
                    "feedback_collection"
                ],
                "evidence_requirements": [
                    "notification_records",
                    "delivery_confirmations",
                    "acknowledgment_receipts",
                    "stakeholder_feedback"
                ],
                "confidence_factors": {
                    "notification_delivery": 0.4,
                    "acknowledgment_rate": 0.3,
                    "feedback_quality": 0.2,
                    "communication_completeness": 0.1
                },
                "minimum_confidence": ResolutionConfidence.MEDIUM.value,
                "mandatory": True
            }
        }
    
    def _initialize_validation_rules(self) -> Dict[str, Dict[str, Any]]:
        """Initialize validation rules for different incident types"""
        return {
            "malware": {
                "required_criteria": [
                    ValidationCriteria.THREAT_ELIMINATED.value,
                    ValidationCriteria.SYSTEMS_SECURED.value,
                    ValidationCriteria.DATA_INTEGRITY.value,
                    ValidationCriteria.COMPLIANCE_MET.value,
                    ValidationCriteria.STAKEHOLDERS_NOTIFIED.value
                ],
                "optional_criteria": [
                    ValidationCriteria.BUSINESS_CONTINUITY.value,
                    ValidationCriteria.LESSONS_DOCUMENTED.value,
                    ValidationCriteria.CONTROLS_IMPROVED.value
                ],
                "success_threshold": 0.85,
                "minimum_required_pass": 5
            },
            
            "phishing": {
                "required_criteria": [
                    ValidationCriteria.THREAT_ELIMINATED.value,
                    ValidationCriteria.SYSTEMS_SECURED.value,
                    ValidationCriteria.COMPLIANCE_MET.value,
                    ValidationCriteria.STAKEHOLDERS_NOTIFIED.value,
                    ValidationCriteria.LESSONS_DOCUMENTED.value
                ],
                "optional_criteria": [
                    ValidationCriteria.DATA_INTEGRITY.value,
                    ValidationCriteria.BUSINESS_CONTINUITY.value,
                    ValidationCriteria.CONTROLS_IMPROVED.value
                ],
                "success_threshold": 0.80,
                "minimum_required_pass": 4
            },
            
            "data_breach": {
                "required_criteria": [
                    ValidationCriteria.THREAT_ELIMINATED.value,
                    ValidationCriteria.SYSTEMS_SECURED.value,
                    ValidationCriteria.DATA_INTEGRITY.value,
                    ValidationCriteria.COMPLIANCE_MET.value,
                    ValidationCriteria.STAKEHOLDERS_NOTIFIED.value,
                    ValidationCriteria.LESSONS_DOCUMENTED.value
                ],
                "optional_criteria": [
                    ValidationCriteria.BUSINESS_CONTINUITY.value,
                    ValidationCriteria.CONTROLS_IMPROVED.value
                ],
                "success_threshold": 0.90,
                "minimum_required_pass": 6
            },
            
            "insider_threat": {
                "required_criteria": [
                    ValidationCriteria.THREAT_ELIMINATED.value,
                    ValidationCriteria.SYSTEMS_SECURED.value,
                    ValidationCriteria.DATA_INTEGRITY.value,
                    ValidationCriteria.COMPLIANCE_MET.value,
                    ValidationCriteria.STAKEHOLDERS_NOTIFIED.value,
                    ValidationCriteria.CONTROLS_IMPROVED.value
                ],
                "optional_criteria": [
                    ValidationCriteria.BUSINESS_CONTINUITY.value,
                    ValidationCriteria.LESSONS_DOCUMENTED.value
                ],
                "success_threshold": 0.90,
                "minimum_required_pass": 6
            },
            
            "default": {
                "required_criteria": [
                    ValidationCriteria.THREAT_ELIMINATED.value,
                    ValidationCriteria.SYSTEMS_SECURED.value,
                    ValidationCriteria.COMPLIANCE_MET.value,
                    ValidationCriteria.STAKEHOLDERS_NOTIFIED.value
                ],
                "optional_criteria": [
                    ValidationCriteria.DATA_INTEGRITY.value,
                    ValidationCriteria.BUSINESS_CONTINUITY.value,
                    ValidationCriteria.LESSONS_DOCUMENTED.value,
                    ValidationCriteria.CONTROLS_IMPROVED.value
                ],
                "success_threshold": 0.75,
                "minimum_required_pass": 3
            }
        }
    
    def _initialize_success_thresholds(self) -> Dict[str, float]:
        """Initialize success thresholds for different validation aspects"""
        return {
            "overall_validation": 0.80,
            "mandatory_criteria": 1.0,
            "confidence_minimum": 0.70,
            "evidence_completeness": 0.75,
            "stakeholder_satisfaction": 0.80
        }
    
    async def validate_incident_resolution(self, 
                                         incident_data: Dict[str, Any],
                                         investigation_results: Dict[str, Any],
                                         documentation_package: Dict[str, Any],
                                         response_actions: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform comprehensive incident resolution validation
        
        Args:
            incident_data: Complete incident information
            investigation_results: Investigation findings and analysis
            documentation_package: Generated documentation
            response_actions: Actions taken during response
            
        Returns:
            Comprehensive validation results
        """
        try:
            validation_start_time = datetime.now()
            incident_id = incident_data.get("incident_id", "unknown")
            incident_type = incident_data.get("classification", {}).get("category", "default")
            
            logger.info(f"Starting resolution validation for incident {incident_id}")
            
            # Get validation rules for incident type
            validation_rules = self.validation_rules.get(incident_type, self.validation_rules["default"])
            
            # Perform individual validations
            validation_results = await self._perform_validation_checks(
                incident_data, investigation_results, documentation_package, 
                response_actions, validation_rules
            )
            
            # Calculate overall validation status
            overall_status, overall_confidence, success_score = await self._calculate_overall_status(
                validation_results, validation_rules
            )
            
            # Identify remediation actions
            remediation_actions = await self._identify_remediation_actions(validation_results)
            
            # Determine approval requirements
            approval_required = self._requires_approval(overall_status, success_score, validation_results)
            
            # Create validation summary
            validation_summary = ResolutionValidation(
                validation_id=f"val_{incident_id}_{int(validation_start_time.timestamp())}",
                incident_id=incident_id,
                validation_date=validation_start_time,
                overall_status=overall_status.value,
                overall_confidence=overall_confidence.value,
                validation_results=validation_results,
                success_score=success_score,
                remediation_actions=remediation_actions,
                approval_required=approval_required,
                approved_by=None,
                approval_date=None
            )
            
            # Store validation history
            self.validation_history.append(validation_summary)
            
            # Update statistics
            self._update_validation_stats(validation_summary)
            
            logger.info(f"Resolution validation completed for incident {incident_id}")
            
            return {
                "status": "completed",
                "incident_id": incident_id,
                "validation_summary": validation_summary.to_dict(),
                "validation_details": {
                    "total_criteria_checked": len(validation_results),
                    "criteria_passed": len([r for r in validation_results if r.status == ValidationStatus.PASSED.value]),
                    "criteria_failed": len([r for r in validation_results if r.status == ValidationStatus.FAILED.value]),
                    "overall_success_score": success_score,
                    "validation_time": (datetime.now() - validation_start_time).total_seconds() / 60
                },
                "next_steps": self._determine_next_steps(overall_status, remediation_actions, approval_required)
            }
            
        except Exception as e:
            logger.error(f"Error validating incident resolution: {str(e)}")
            return {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    async def _perform_validation_checks(self, 
                                       incident_data: Dict[str, Any],
                                       investigation_results: Dict[str, Any],
                                       documentation_package: Dict[str, Any],
                                       response_actions: Dict[str, Any],
                                       validation_rules: Dict[str, Any]) -> List[ValidationResult]:
        """Perform individual validation checks"""
        
        validation_results = []
        required_criteria = validation_rules["required_criteria"]
        optional_criteria = validation_rules["optional_criteria"]
        
        all_criteria = required_criteria + optional_criteria
        
        for criteria in all_criteria:
            result = await self._validate_single_criteria(
                criteria, incident_data, investigation_results, 
                documentation_package, response_actions
            )
            validation_results.append(result)
        
        return validation_results
    
    async def _validate_single_criteria(self, 
                                      criteria: str,
                                      incident_data: Dict[str, Any],
                                      investigation_results: Dict[str, Any],
                                      documentation_package: Dict[str, Any],
                                      response_actions: Dict[str, Any]) -> ValidationResult:
        """Validate a single resolution criteria"""
        
        criteria_config = self.validation_criteria[criteria]
        
        # Collect evidence based on criteria type
        evidence = await self._collect_validation_evidence(
            criteria, incident_data, investigation_results, 
            documentation_package, response_actions, criteria_config
        )
        
        # Assess validation status
        status, confidence = await self._assess_validation_status(
            criteria, evidence, criteria_config
        )
        
        # Determine if remediation is required
        remediation_required = status in [ValidationStatus.FAILED.value, ValidationStatus.PARTIAL.value]
        
        return ValidationResult(
            criteria=criteria,
            status=status.value,
            confidence=confidence.value,
            evidence=evidence,
            validation_date=datetime.now(),
            validator="Resolution Validator Agent",
            notes=self._generate_validation_notes(criteria, status, evidence),
            remediation_required=remediation_required
        )
    
    async def _collect_validation_evidence(self, 
                                         criteria: str,
                                         incident_data: Dict[str, Any],
                                         investigation_results: Dict[str, Any],
                                         documentation_package: Dict[str, Any],
                                         response_actions: Dict[str, Any],
                                         criteria_config: Dict[str, Any]) -> List[str]:
        """Collect evidence for validation criteria"""
        
        evidence = []
        
        if criteria == ValidationCriteria.THREAT_ELIMINATED.value:
            evidence.extend(await self._collect_threat_elimination_evidence(
                incident_data, investigation_results, response_actions
            ))
        
        elif criteria == ValidationCriteria.SYSTEMS_SECURED.value:
            evidence.extend(await self._collect_systems_security_evidence(
                incident_data, investigation_results, response_actions
            ))
        
        elif criteria == ValidationCriteria.DATA_INTEGRITY.value:
            evidence.extend(await self._collect_data_integrity_evidence(
                incident_data, investigation_results, response_actions
            ))
        
        elif criteria == ValidationCriteria.BUSINESS_CONTINUITY.value:
            evidence.extend(await self._collect_business_continuity_evidence(
                incident_data, investigation_results, response_actions
            ))
        
        elif criteria == ValidationCriteria.COMPLIANCE_MET.value:
            evidence.extend(await self._collect_compliance_evidence(
                incident_data, investigation_results, documentation_package
            ))
        
        elif criteria == ValidationCriteria.LESSONS_DOCUMENTED.value:
            evidence.extend(await self._collect_lessons_learned_evidence(
                documentation_package, response_actions
            ))
        
        elif criteria == ValidationCriteria.CONTROLS_IMPROVED.value:
            evidence.extend(await self._collect_controls_improvement_evidence(
                investigation_results, response_actions
            ))
        
        elif criteria == ValidationCriteria.STAKEHOLDERS_NOTIFIED.value:
            evidence.extend(await self._collect_stakeholder_notification_evidence(
                incident_data, response_actions, documentation_package
            ))
        
        return evidence
    
    async def _collect_threat_elimination_evidence(self, 
                                                 incident_data: Dict[str, Any],
                                                 investigation_results: Dict[str, Any],
                                                 response_actions: Dict[str, Any]) -> List[str]:
        """Collect evidence for threat elimination"""
        
        evidence = []
        
        # Check for malware scan results
        analysis_results = investigation_results.get("analysis_results", {})
        executed_tasks = analysis_results.get("executed_tasks", [])
        
        for task in executed_tasks:
            if "malware" in task.get("task_name", "").lower():
                if "clean" in str(task.get("findings", [])).lower():
                    evidence.append("Clean malware scan results obtained")
                else:
                    evidence.append("Malware scan completed - review findings")
        
        # Check for IOC monitoring
        summary = analysis_results.get("summary", {})
        if summary.get("threat_level", "").lower() in ["low", "minimal"]:
            evidence.append("Threat level reduced to acceptable levels")
        
        # Check containment actions
        if response_actions.get("containment_completed", False):
            evidence.append("Containment actions successfully completed")
        
        # Default evidence if specific evidence not found
        if not evidence:
            evidence.append("Standard threat elimination procedures executed")
        
        return evidence
    
    async def _collect_systems_security_evidence(self, 
                                               incident_data: Dict[str, Any],
                                               investigation_results: Dict[str, Any],
                                               response_actions: Dict[str, Any]) -> List[str]:
        """Collect evidence for systems security"""
        
        evidence = []
        
        # Check for vulnerability assessments
        analysis_results = investigation_results.get("analysis_results", {})
        executed_tasks = analysis_results.get("executed_tasks", [])
        
        for task in executed_tasks:
            task_name = task.get("task_name", "").lower()
            if "vulnerability" in task_name or "security" in task_name:
                evidence.append(f"Security assessment completed: {task.get('task_name', 'Unknown')}")
        
        # Check for patching actions
        if response_actions.get("patches_applied", False):
            evidence.append("Critical security patches applied")
        
        # Check for configuration changes
        if response_actions.get("configurations_updated", False):
            evidence.append("Security configurations updated")
        
        # Check affected systems
        affected_hosts = incident_data.get("alert_data", {}).get("affected_hosts", [])
        if affected_hosts:
            evidence.append(f"Security validation completed for {len(affected_hosts)} affected systems")
        
        # Default evidence
        if not evidence:
            evidence.append("Systems security validation in progress")
        
        return evidence
    
    async def _collect_data_integrity_evidence(self, 
                                             incident_data: Dict[str, Any],
                                             investigation_results: Dict[str, Any],
                                             response_actions: Dict[str, Any]) -> List[str]:
        """Collect evidence for data integrity"""
        
        evidence = []
        
        # Check for data integrity verification
        analysis_results = investigation_results.get("analysis_results", {})
        executed_tasks = analysis_results.get("executed_tasks", [])
        
        for task in executed_tasks:
            task_name = task.get("task_name", "").lower()
            if "data" in task_name or "integrity" in task_name:
                evidence.append(f"Data integrity check completed: {task.get('task_name', 'Unknown')}")
        
        # Check for backup verification
        if response_actions.get("backups_verified", False):
            evidence.append("Backup integrity verified")
        
        # Check for forensic analysis
        if any("forensic" in task.get("task_name", "").lower() for task in executed_tasks):
            evidence.append("Forensic analysis completed - data integrity assessed")
        
        # Default evidence
        if not evidence:
            evidence.append("Data integrity assessment completed")
        
        return evidence
    
    async def _collect_business_continuity_evidence(self, 
                                                  incident_data: Dict[str, Any],
                                                  investigation_results: Dict[str, Any],
                                                  response_actions: Dict[str, Any]) -> List[str]:
        """Collect evidence for business continuity"""
        
        evidence = []
        
        # Check for service restoration
        if response_actions.get("services_restored", False):
            evidence.append("Critical business services restored")
        
        # Check for performance monitoring
        if response_actions.get("performance_monitored", False):
            evidence.append("System performance monitoring confirmed normal operations")
        
        # Check user impact
        affected_users = incident_data.get("alert_data", {}).get("affected_users", [])
        if affected_users:
            evidence.append(f"Business continuity validated for {len(affected_users)} affected users")
        else:
            evidence.append("Minimal business impact confirmed")
        
        return evidence
    
    async def _collect_compliance_evidence(self, 
                                         incident_data: Dict[str, Any],
                                         investigation_results: Dict[str, Any],
                                         documentation_package: Dict[str, Any]) -> List[str]:
        """Collect evidence for compliance requirements"""
        
        evidence = []
        
        # Check documentation completeness
        package_summary = documentation_package.get("package_summary", {})
        total_documents = package_summary.get("total_documents", 0)
        
        if total_documents > 0:
            evidence.append(f"Comprehensive documentation package created ({total_documents} documents)")
        
        # Check for compliance reports
        document_types = package_summary.get("document_types", [])
        if "compliance_report" in document_types:
            evidence.append("Regulatory compliance report generated")
        
        # Check quality assurance
        qa_status = documentation_package.get("quality_assurance", {})
        if qa_status.get("compliance_verification") == "passed":
            evidence.append("Compliance verification completed successfully")
        
        # Check retention and archival
        archive_info = documentation_package.get("archive_information", {})
        if archive_info.get("storage_location"):
            evidence.append("Compliance documentation properly archived")
        
        return evidence
    
    async def _collect_lessons_learned_evidence(self, 
                                              documentation_package: Dict[str, Any],
                                              response_actions: Dict[str, Any]) -> List[str]:
        """Collect evidence for lessons learned documentation"""
        
        evidence = []
        
        # Check for lessons learned documents
        document_types = documentation_package.get("package_summary", {}).get("document_types", [])
        
        if "lessons_learned" in document_types:
            evidence.append("Formal lessons learned document created")
        
        # Check for procedure updates
        if response_actions.get("procedures_updated", False):
            evidence.append("Incident response procedures updated based on lessons learned")
        
        # Check for training materials
        if response_actions.get("training_developed", False):
            evidence.append("Training materials developed from incident experience")
        
        # Check documentation quality
        qa_status = documentation_package.get("quality_assurance", {})
        if qa_status.get("completeness_check") == "passed":
            evidence.append("Documentation completeness verified")
        
        return evidence
    
    async def _collect_controls_improvement_evidence(self, 
                                                   investigation_results: Dict[str, Any],
                                                   response_actions: Dict[str, Any]) -> List[str]:
        """Collect evidence for security controls improvement"""
        
        evidence = []
        
        # Check for control enhancements
        if response_actions.get("controls_enhanced", False):
            evidence.append("Security controls enhanced based on incident findings")
        
        # Check for detection improvements
        if response_actions.get("detection_improved", False):
            evidence.append("Detection capabilities improved")
        
        # Check for monitoring enhancements
        if response_actions.get("monitoring_enhanced", False):
            evidence.append("Monitoring capabilities enhanced")
        
        # Check for recommendations implementation
        analysis_summary = investigation_results.get("analysis_results", {}).get("summary", {})
        recommendations = analysis_summary.get("recommendations", [])
        
        if recommendations:
            evidence.append(f"Security improvement recommendations documented ({len(recommendations)} items)")
        
        return evidence
    
    async def _collect_stakeholder_notification_evidence(self, 
                                                        incident_data: Dict[str, Any],
                                                        response_actions: Dict[str, Any],
                                                        documentation_package: Dict[str, Any]) -> List[str]:
        """Collect evidence for stakeholder notifications"""
        
        evidence = []
        
        # Check notification records
        if response_actions.get("stakeholders_notified", False):
            evidence.append("Required stakeholders notified according to policy")
        
        # Check documentation distribution
        package_metadata = documentation_package.get("package_metadata", {})
        if package_metadata.get("distribution_restrictions"):
            evidence.append("Documentation distributed to appropriate stakeholders")
        
        # Check severity-based notifications
        severity = incident_data.get("classification", {}).get("severity", "medium")
        if severity in ["critical", "high"]:
            evidence.append("Executive notifications completed for high-severity incident")
        
        # Check compliance notifications
        if response_actions.get("regulatory_notifications_sent", False):
            evidence.append("Regulatory notifications completed as required")
        
        return evidence
    
    async def _assess_validation_status(self, 
                                      criteria: str,
                                      evidence: List[str],
                                      criteria_config: Dict[str, Any]) -> Tuple[ValidationStatus, ResolutionConfidence]:
        """Assess validation status based on evidence and configuration"""
        
        # Calculate evidence score
        evidence_count = len(evidence)
        required_evidence = len(criteria_config.get("evidence_requirements", []))
        
        if evidence_count == 0:
            return ValidationStatus.FAILED, ResolutionConfidence.VERY_LOW
        
        evidence_score = min(evidence_count / max(required_evidence, 1), 1.0)
        
        # Assess confidence based on evidence quality
        confidence = await self._calculate_confidence(evidence, criteria_config)
        
        # Determine status
        if evidence_score >= 0.9 and confidence.value in ["high", "very_high"]:
            status = ValidationStatus.PASSED
        elif evidence_score >= 0.7 and confidence.value in ["medium", "high", "very_high"]:
            status = ValidationStatus.PARTIAL
        elif evidence_score >= 0.5:
            status = ValidationStatus.REQUIRES_REVIEW
        else:
            status = ValidationStatus.FAILED
        
        return status, confidence
    
    async def _calculate_confidence(self, evidence: List[str], criteria_config: Dict[str, Any]) -> ResolutionConfidence:
        """Calculate confidence level based on evidence quality"""
        
        confidence_factors = criteria_config.get("confidence_factors", {})
        evidence_text = " ".join(evidence).lower()
        
        confidence_score = 0.0
        
        # Check for specific confidence indicators
        for factor, weight in confidence_factors.items():
            if factor.replace("_", " ") in evidence_text:
                confidence_score += weight
        
        # Adjust based on evidence completeness
        evidence_completeness = len(evidence) / max(len(criteria_config.get("evidence_requirements", [])), 1)
        confidence_score *= evidence_completeness
        
        # Map score to confidence level
        if confidence_score >= 0.9:
            return ResolutionConfidence.VERY_HIGH
        elif confidence_score >= 0.7:
            return ResolutionConfidence.HIGH
        elif confidence_score >= 0.5:
            return ResolutionConfidence.MEDIUM
        elif confidence_score >= 0.3:
            return ResolutionConfidence.LOW
        else:
            return ResolutionConfidence.VERY_LOW
    
    def _generate_validation_notes(self, criteria: str, status: ValidationStatus, evidence: List[str]) -> str:
        """Generate validation notes"""
        
        notes = []
        
        # Status-based notes
        if status == ValidationStatus.PASSED:
            notes.append(f"Validation criteria '{criteria}' successfully met")
        elif status == ValidationStatus.FAILED:
            notes.append(f"Validation criteria '{criteria}' not met - remediation required")
        elif status == ValidationStatus.PARTIAL:
            notes.append(f"Validation criteria '{criteria}' partially met - additional verification recommended")
        elif status == ValidationStatus.REQUIRES_REVIEW:
            notes.append(f"Validation criteria '{criteria}' requires manual review")
        
        # Evidence summary
        if evidence:
            notes.append(f"Evidence collected: {len(evidence)} items")
        else:
            notes.append("Limited evidence available for validation")
        
        return "; ".join(notes)
    
    async def _calculate_overall_status(self, 
                                      validation_results: List[ValidationResult],
                                      validation_rules: Dict[str, Any]) -> Tuple[ValidationStatus, ResolutionConfidence, float]:
        """Calculate overall validation status and confidence"""
        
        required_criteria = validation_rules["required_criteria"]
        success_threshold = validation_rules["success_threshold"]
        minimum_required_pass = validation_rules["minimum_required_pass"]
        
        # Count passed validations
        total_validations = len(validation_results)
        passed_validations = len([r for r in validation_results if r.status == ValidationStatus.PASSED.value])
        failed_validations = len([r for r in validation_results if r.status == ValidationStatus.FAILED.value])
        
        # Check required criteria
        required_passed = 0
        for result in validation_results:
            if result.criteria in required_criteria and result.status == ValidationStatus.PASSED.value:
                required_passed += 1
        
        # Calculate success score
        success_score = passed_validations / max(total_validations, 1)
        
        # Determine overall status
        if (success_score >= success_threshold and 
            passed_validations >= minimum_required_pass and
            required_passed >= len(required_criteria) * 0.8):  # 80% of required criteria must pass
            overall_status = ValidationStatus.PASSED
        elif failed_validations > total_validations * 0.3:  # More than 30% failed
            overall_status = ValidationStatus.FAILED
        else:
            overall_status = ValidationStatus.PARTIAL
        
        # Calculate overall confidence
        confidence_scores = []
        for result in validation_results:
            if result.confidence == ResolutionConfidence.VERY_HIGH.value:
                confidence_scores.append(1.0)
            elif result.confidence == ResolutionConfidence.HIGH.value:
                confidence_scores.append(0.8)
            elif result.confidence == ResolutionConfidence.MEDIUM.value:
                confidence_scores.append(0.6)
            elif result.confidence == ResolutionConfidence.LOW.value:
                confidence_scores.append(0.4)
            else:
                confidence_scores.append(0.2)
        
        avg_confidence_score = sum(confidence_scores) / max(len(confidence_scores), 1)
        
        if avg_confidence_score >= 0.9:
            overall_confidence = ResolutionConfidence.VERY_HIGH
        elif avg_confidence_score >= 0.7:
            overall_confidence = ResolutionConfidence.HIGH
        elif avg_confidence_score >= 0.5:
            overall_confidence = ResolutionConfidence.MEDIUM
        elif avg_confidence_score >= 0.3:
            overall_confidence = ResolutionConfidence.LOW
        else:
            overall_confidence = ResolutionConfidence.VERY_LOW
        
        return overall_status, overall_confidence, success_score
    
    async def _identify_remediation_actions(self, validation_results: List[ValidationResult]) -> List[str]:
        """Identify required remediation actions"""
        
        remediation_actions = []
        
        for result in validation_results:
            if result.remediation_required:
                action = self._get_remediation_action_for_criteria(result.criteria, result.status)
                remediation_actions.append(action)
        
        return remediation_actions
    
    def _get_remediation_action_for_criteria(self, criteria: str, status: str) -> str:
        """Get specific remediation action for failed criteria"""
        
        remediation_map = {
            ValidationCriteria.THREAT_ELIMINATED.value: "Perform additional threat elimination procedures and verification",
            ValidationCriteria.SYSTEMS_SECURED.value: "Complete systems security hardening and verification",
            ValidationCriteria.DATA_INTEGRITY.value: "Conduct comprehensive data integrity assessment",
            ValidationCriteria.BUSINESS_CONTINUITY.value: "Verify business operations restoration and performance",
            ValidationCriteria.COMPLIANCE_MET.value: "Complete remaining compliance requirements and documentation",
            ValidationCriteria.LESSONS_DOCUMENTED.value: "Create comprehensive lessons learned documentation",
            ValidationCriteria.CONTROLS_IMPROVED.value: "Implement security control improvements based on findings",
            ValidationCriteria.STAKEHOLDERS_NOTIFIED.value: "Complete stakeholder notifications and communications"
        }
        
        base_action = remediation_map.get(criteria, f"Address {criteria} validation requirements")
        
        if status == ValidationStatus.FAILED.value:
            return f"CRITICAL: {base_action}"
        else:
            return f"REVIEW: {base_action}"
    
    def _requires_approval(self, overall_status: ValidationStatus, success_score: float, validation_results: List[ValidationResult]) -> bool:
        """Determine if approval is required for resolution"""
        
        # Always require approval if validation failed
        if overall_status == ValidationStatus.FAILED:
            return True
        
        # Require approval if success score is below threshold
        if success_score < self.success_thresholds["overall_validation"]:
            return True
        
        # Require approval if any critical validations failed
        critical_failures = [r for r in validation_results 
                           if r.status == ValidationStatus.FAILED.value and 
                           r.criteria in [ValidationCriteria.THREAT_ELIMINATED.value, 
                                        ValidationCriteria.SYSTEMS_SECURED.value,
                                        ValidationCriteria.COMPLIANCE_MET.value]]
        
        if critical_failures:
            return True
        
        return False
    
    def _determine_next_steps(self, overall_status: ValidationStatus, remediation_actions: List[str], approval_required: bool) -> List[str]:
        """Determine next steps based on validation results"""
        
        next_steps = []
        
        if overall_status == ValidationStatus.PASSED:
            next_steps.append("Proceed to incident closure")
            if approval_required:
                next_steps.append("Obtain final approval for incident closure")
        
        elif overall_status == ValidationStatus.PARTIAL:
            next_steps.append("Complete remediation actions")
            next_steps.extend(remediation_actions[:3])  # Show top 3 actions
            next_steps.append("Re-validate after remediation")
        
        else:  # FAILED
            next_steps.append("IMMEDIATE ACTION REQUIRED")
            next_steps.extend(remediation_actions)
            next_steps.append("Escalate to incident commander")
            next_steps.append("Re-validate after all remediation completed")
        
        return next_steps
    
    def _update_validation_stats(self, validation_summary: ResolutionValidation):
        """Update validation statistics"""
        
        self.validation_stats["total_validations"] += 1
        
        if validation_summary.overall_status == ValidationStatus.PASSED.value:
            self.validation_stats["validations_passed"] += 1
        else:
            self.validation_stats["validations_failed"] += 1
        
        # Update average success score
        current_avg = self.validation_stats["average_success_score"]
        total_validations = self.validation_stats["total_validations"]
        
        new_avg = ((current_avg * (total_validations - 1)) + validation_summary.success_score) / total_validations
        self.validation_stats["average_success_score"] = new_avg
        
        # Track common failures
        for result in validation_summary.validation_results:
            if result.status == ValidationStatus.FAILED.value:
                criteria = result.criteria
                self.validation_stats["common_failures"][criteria] = self.validation_stats["common_failures"].get(criteria, 0) + 1
    
    async def get_validation_statistics(self) -> Dict[str, Any]:
        """Get validation statistics and metrics"""
        
        return {
            "validation_stats": self.validation_stats,
            "supported_criteria": [criteria.value for criteria in ValidationCriteria],
            "confidence_levels": [conf.value for conf in ResolutionConfidence],
            "validation_history_count": len(self.validation_history),
            "success_thresholds": self.success_thresholds
        }

def create_resolution_validator() -> ResolutionValidator:
    """Factory function to create resolution validator"""
    return ResolutionValidator()

# Example usage
async def main():
    validator = create_resolution_validator()
    
    # Example validation
    sample_incident = {
        "incident_id": "inc_001",
        "classification": {"category": "malware", "severity": "high"},
        "alert_data": {"affected_hosts": ["DESKTOP-001"]}
    }
    
    sample_investigation = {
        "analysis_results": {
            "executed_tasks": [{"task_name": "malware scan", "findings": ["System clean"]}],
            "summary": {"threat_level": "low"}
        }
    }
    
    sample_documentation = {
        "package_summary": {"total_documents": 3, "document_types": ["incident_report"]},
        "quality_assurance": {"compliance_verification": "passed"}
    }
    
    sample_actions = {
        "containment_completed": True,
        "stakeholders_notified": True
    }
    
    result = await validator.validate_incident_resolution(
        sample_incident, sample_investigation, sample_documentation, sample_actions
    )
    
    print(f"Validation result: {json.dumps(result, indent=2)}")

if __name__ == "__main__":
    asyncio.run(main())
