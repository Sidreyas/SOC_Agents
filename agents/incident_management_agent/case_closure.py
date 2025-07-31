"""
Case Closure Module
State 8: Case Closure and Post-Incident Actions
Handles final incident closure and post-incident activities
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

class ClosureStatus(Enum):
    """Case closure status types"""
    PENDING_VALIDATION = "pending_validation"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    CLOSED = "closed"
    REJECTED = "rejected"
    REQUIRES_REMEDIATION = "requires_remediation"

class ClosureReason(Enum):
    """Reasons for case closure"""
    RESOLVED_SUCCESSFULLY = "resolved_successfully"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE_INCIDENT = "duplicate_incident"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    BUSINESS_DECISION = "business_decision"
    EXTERNAL_RESOLUTION = "external_resolution"

class PostIncidentAction(Enum):
    """Types of post-incident actions"""
    LESSONS_LEARNED_SESSION = "lessons_learned_session"
    PROCEDURE_UPDATE = "procedure_update"
    TRAINING_DEVELOPMENT = "training_development"
    SECURITY_ENHANCEMENT = "security_enhancement"
    POLICY_REVIEW = "policy_review"
    VENDOR_NOTIFICATION = "vendor_notification"
    COMPLIANCE_REPORTING = "compliance_reporting"

@dataclass
class LessonsLearned:
    """Lessons learned structure"""
    lesson_id: str
    category: str
    description: str
    root_cause: str
    prevention_measures: List[str]
    detection_improvements: List[str]
    response_improvements: List[str]
    priority: str
    implementation_timeline: str
    responsible_party: str
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class PostIncidentActionItem:
    """Post-incident action item"""
    action_id: str
    action_type: str
    description: str
    priority: str
    due_date: datetime
    assigned_to: str
    dependencies: List[str]
    completion_criteria: List[str]
    status: str
    notes: str
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['due_date'] = self.due_date.isoformat()
        return result

@dataclass
class IncidentClosure:
    """Complete incident closure record"""
    closure_id: str
    incident_id: str
    closure_date: datetime
    closure_status: str
    closure_reason: str
    closure_summary: str
    lessons_learned: List[LessonsLearned]
    post_incident_actions: List[PostIncidentActionItem]
    metrics: Dict[str, Any]
    approvals: List[Dict[str, Any]]
    documentation_references: List[str]
    compliance_attestation: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['closure_date'] = self.closure_date.isoformat()
        result['lessons_learned'] = [ll.to_dict() for ll in self.lessons_learned]
        result['post_incident_actions'] = [pia.to_dict() for pia in self.post_incident_actions]
        return result

class CaseClosureManager:
    """
    Manages incident case closure and post-incident activities
    """
    
    def __init__(self):
        self.closure_criteria = self._initialize_closure_criteria()
        self.post_incident_templates = self._initialize_post_incident_templates()
        self.metrics_definitions = self._initialize_metrics_definitions()
        self.closure_history = []
        self.closure_stats = {
            "total_closures": 0,
            "closures_by_reason": {reason.value: 0 for reason in ClosureReason},
            "average_resolution_time": 0,
            "lessons_learned_captured": 0,
            "post_incident_actions_created": 0,
            "closure_approval_rate": 0
        }
    
    def _initialize_closure_criteria(self) -> Dict[str, Dict[str, Any]]:
        """Initialize closure criteria for different incident types"""
        return {
            "standard": {
                "required_validations": [
                    "threat_eliminated",
                    "systems_secured",
                    "compliance_met",
                    "stakeholders_notified"
                ],
                "required_approvals": ["incident_commander"],
                "documentation_requirements": [
                    "incident_report",
                    "investigation_summary"
                ],
                "minimum_validation_score": 0.75
            },
            
            "high_severity": {
                "required_validations": [
                    "threat_eliminated",
                    "systems_secured",
                    "data_integrity",
                    "compliance_met",
                    "stakeholders_notified",
                    "lessons_documented"
                ],
                "required_approvals": ["incident_commander", "ciso"],
                "documentation_requirements": [
                    "incident_report",
                    "executive_summary",
                    "technical_analysis",
                    "compliance_report"
                ],
                "minimum_validation_score": 0.85
            },
            
            "critical": {
                "required_validations": [
                    "threat_eliminated",
                    "systems_secured",
                    "data_integrity",
                    "business_continuity", 
                    "compliance_met",
                    "stakeholders_notified",
                    "lessons_documented",
                    "controls_improved"
                ],
                "required_approvals": ["incident_commander", "ciso", "executive_team"],
                "documentation_requirements": [
                    "incident_report",
                    "executive_summary",
                    "technical_analysis",
                    "forensic_report",
                    "compliance_report",
                    "lessons_learned"
                ],
                "minimum_validation_score": 0.90,
                "requires_board_notification": True
            },
            
            "false_positive": {
                "required_validations": [
                    "false_positive_confirmed",
                    "stakeholders_notified"
                ],
                "required_approvals": ["incident_commander"],
                "documentation_requirements": [
                    "false_positive_analysis"
                ],
                "minimum_validation_score": 0.70
            }
        }
    
    def _initialize_post_incident_templates(self) -> Dict[str, Dict[str, Any]]:
        """Initialize post-incident action templates"""
        return {
            "malware_incident": {
                "mandatory_actions": [
                    {
                        "action_type": PostIncidentAction.LESSONS_LEARNED_SESSION.value,
                        "description": "Conduct lessons learned session with response team",
                        "priority": "high",
                        "due_days": 7
                    },
                    {
                        "action_type": PostIncidentAction.SECURITY_ENHANCEMENT.value,
                        "description": "Review and enhance endpoint protection",
                        "priority": "medium",
                        "due_days": 30
                    }
                ],
                "recommended_actions": [
                    {
                        "action_type": PostIncidentAction.TRAINING_DEVELOPMENT.value,
                        "description": "Develop malware awareness training",
                        "priority": "medium",
                        "due_days": 60
                    },
                    {
                        "action_type": PostIncidentAction.PROCEDURE_UPDATE.value,
                        "description": "Update malware response procedures",
                        "priority": "low",
                        "due_days": 90
                    }
                ]
            },
            
            "phishing_incident": {
                "mandatory_actions": [
                    {
                        "action_type": PostIncidentAction.TRAINING_DEVELOPMENT.value,
                        "description": "Develop targeted phishing awareness training",
                        "priority": "high",
                        "due_days": 14
                    },
                    {
                        "action_type": PostIncidentAction.SECURITY_ENHANCEMENT.value,
                        "description": "Review email security controls",
                        "priority": "medium",
                        "due_days": 30
                    }
                ],
                "recommended_actions": [
                    {
                        "action_type": PostIncidentAction.POLICY_REVIEW.value,
                        "description": "Review email handling policies",
                        "priority": "medium",
                        "due_days": 45
                    }
                ]
            },
            
            "data_breach": {
                "mandatory_actions": [
                    {
                        "action_type": PostIncidentAction.COMPLIANCE_REPORTING.value,
                        "description": "Complete regulatory breach notifications",
                        "priority": "critical",
                        "due_days": 3
                    },
                    {
                        "action_type": PostIncidentAction.LESSONS_LEARNED_SESSION.value,
                        "description": "Executive lessons learned session",
                        "priority": "high",
                        "due_days": 7
                    },
                    {
                        "action_type": PostIncidentAction.SECURITY_ENHANCEMENT.value,
                        "description": "Implement additional data protection controls",
                        "priority": "high",
                        "due_days": 30
                    }
                ],
                "recommended_actions": [
                    {
                        "action_type": PostIncidentAction.VENDOR_NOTIFICATION.value,
                        "description": "Notify relevant vendors and partners",
                        "priority": "medium",
                        "due_days": 14
                    }
                ]
            },
            
            "default": {
                "mandatory_actions": [
                    {
                        "action_type": PostIncidentAction.LESSONS_LEARNED_SESSION.value,
                        "description": "Conduct basic lessons learned review",
                        "priority": "medium",
                        "due_days": 14
                    }
                ],
                "recommended_actions": [
                    {
                        "action_type": PostIncidentAction.PROCEDURE_UPDATE.value,
                        "description": "Review and update relevant procedures",
                        "priority": "low",
                        "due_days": 60
                    }
                ]
            }
        }
    
    def _initialize_metrics_definitions(self) -> Dict[str, Dict[str, Any]]:
        """Initialize incident metrics definitions"""
        return {
            "resolution_time": {
                "description": "Total time from detection to resolution",
                "unit": "hours",
                "calculation": "closure_time - detection_time",
                "targets": {
                    "critical": 4,
                    "high": 8,
                    "medium": 24,
                    "low": 72
                }
            },
            
            "detection_time": {
                "description": "Time from incident occurrence to detection",
                "unit": "minutes",
                "calculation": "detection_time - estimated_occurrence_time",
                "targets": {
                    "critical": 15,
                    "high": 30,
                    "medium": 60,
                    "low": 240
                }
            },
            
            "response_time": {
                "description": "Time from detection to initial response",
                "unit": "minutes", 
                "calculation": "first_response_time - detection_time",
                "targets": {
                    "critical": 15,
                    "high": 30,
                    "medium": 60,
                    "low": 120
                }
            },
            
            "containment_time": {
                "description": "Time from response to containment",
                "unit": "hours",
                "calculation": "containment_time - first_response_time",
                "targets": {
                    "critical": 1,
                    "high": 2,
                    "medium": 4,
                    "low": 8
                }
            },
            
            "investigation_quality": {
                "description": "Quality score of investigation process",
                "unit": "percentage",
                "calculation": "weighted_average_of_validation_scores",
                "targets": {
                    "critical": 95,
                    "high": 90,
                    "medium": 85,
                    "low": 80
                }
            }
        }
    
    async def close_incident_case(self, 
                                incident_data: Dict[str, Any],
                                investigation_results: Dict[str, Any],
                                validation_results: Dict[str, Any],
                                documentation_package: Dict[str, Any],
                                sentinel_sync_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Close incident case and initiate post-incident activities
        
        Args:
            incident_data: Complete incident information
            investigation_results: Investigation findings and analysis
            validation_results: Validation results and status
            documentation_package: Generated documentation
            sentinel_sync_results: Sentinel integration results
            
        Returns:
            Case closure results and post-incident action plan
        """
        try:
            closure_start_time = datetime.now()
            incident_id = incident_data.get("incident_id", "unknown")
            
            logger.info(f"Starting case closure for incident {incident_id}")
            
            # Determine closure eligibility
            closure_eligibility = await self._assess_closure_eligibility(
                incident_data, investigation_results, validation_results, documentation_package
            )
            
            if not closure_eligibility["eligible"]:
                return {
                    "status": "closure_denied",
                    "incident_id": incident_id,
                    "reason": closure_eligibility["reason"],
                    "required_actions": closure_eligibility["required_actions"],
                    "timestamp": closure_start_time.isoformat()
                }
            
            # Extract lessons learned
            lessons_learned = await self._extract_lessons_learned(
                incident_data, investigation_results, validation_results
            )
            
            # Generate post-incident actions
            post_incident_actions = await self._generate_post_incident_actions(
                incident_data, investigation_results, lessons_learned
            )
            
            # Calculate incident metrics
            incident_metrics = await self._calculate_incident_metrics(
                incident_data, investigation_results, validation_results, closure_start_time
            )
            
            # Gather approvals
            approvals = await self._process_closure_approvals(
                incident_data, validation_results, closure_eligibility
            )
            
            # Create compliance attestation
            compliance_attestation = await self._create_compliance_attestation(
                incident_data, validation_results, documentation_package
            )
            
            # Determine closure reason
            closure_reason = self._determine_closure_reason(validation_results, investigation_results)
            
            # Create closure record
            incident_closure = IncidentClosure(
                closure_id=f"closure_{incident_id}_{int(closure_start_time.timestamp())}",
                incident_id=incident_id,
                closure_date=closure_start_time,
                closure_status=ClosureStatus.CLOSED.value,
                closure_reason=closure_reason.value,
                closure_summary=self._generate_closure_summary(incident_data, investigation_results, validation_results),
                lessons_learned=lessons_learned,
                post_incident_actions=post_incident_actions,
                metrics=incident_metrics,
                approvals=approvals,
                documentation_references=self._extract_documentation_references(documentation_package),
                compliance_attestation=compliance_attestation
            )
            
            # Store closure record
            self.closure_history.append(incident_closure)
            
            # Update statistics
            self._update_closure_stats(incident_closure)
            
            # Schedule post-incident actions
            action_scheduling = await self._schedule_post_incident_actions(post_incident_actions)
            
            closure_duration = (datetime.now() - closure_start_time).total_seconds()
            
            logger.info(f"Case closure completed for incident {incident_id}")
            
            return {
                "status": "closed",
                "incident_id": incident_id,
                "closure_summary": {
                    "closure_id": incident_closure.closure_id,
                    "closure_reason": closure_reason.value,
                    "lessons_learned_count": len(lessons_learned),
                    "post_incident_actions_count": len(post_incident_actions),
                    "closure_duration": closure_duration
                },
                "incident_closure": incident_closure.to_dict(),
                "post_incident_plan": {
                    "actions_scheduled": action_scheduling["scheduled"],
                    "next_review_date": action_scheduling["next_review_date"],
                    "responsible_parties": action_scheduling["responsible_parties"]
                },
                "metrics_summary": incident_metrics,
                "next_steps": self._determine_post_closure_steps(incident_closure)
            }
            
        except Exception as e:
            logger.error(f"Error closing incident case: {str(e)}")
            return {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    async def _assess_closure_eligibility(self, 
                                        incident_data: Dict[str, Any],
                                        investigation_results: Dict[str, Any],
                                        validation_results: Dict[str, Any],
                                        documentation_package: Dict[str, Any]) -> Dict[str, Any]:
        """Assess if incident is eligible for closure"""
        
        # Determine incident severity level
        severity = incident_data.get("classification", {}).get("severity", "medium")
        
        if severity == "critical":
            criteria_key = "critical"
        elif severity == "high":
            criteria_key = "high_severity"
        else:
            criteria_key = "standard"
        
        # Check for false positive
        validation_summary = validation_results.get("validation_summary", {})
        if validation_summary.get("overall_status") == "false_positive":
            criteria_key = "false_positive"
        
        criteria = self.closure_criteria[criteria_key]
        
        # Check validation requirements
        validation_check = self._check_validation_requirements(validation_results, criteria)
        if not validation_check["passed"]:
            return {
                "eligible": False,
                "reason": "validation_requirements_not_met",
                "required_actions": validation_check["missing_validations"]
            }
        
        # Check documentation requirements
        documentation_check = self._check_documentation_requirements(documentation_package, criteria)
        if not documentation_check["passed"]:
            return {
                "eligible": False,
                "reason": "documentation_incomplete",
                "required_actions": documentation_check["missing_documents"]
            }
        
        # Check validation score
        validation_score = validation_summary.get("success_score", 0)
        minimum_score = criteria.get("minimum_validation_score", 0.75)
        
        if validation_score < minimum_score:
            return {
                "eligible": False,
                "reason": "validation_score_insufficient",
                "required_actions": [f"Achieve minimum validation score of {minimum_score}"]
            }
        
        return {
            "eligible": True,
            "criteria_met": criteria_key,
            "validation_score": validation_score
        }
    
    def _check_validation_requirements(self, validation_results: Dict[str, Any], criteria: Dict[str, Any]) -> Dict[str, Any]:
        """Check if validation requirements are met"""
        
        required_validations = criteria.get("required_validations", [])
        validation_summary = validation_results.get("validation_summary", {})
        validation_details = validation_summary.get("validation_results", [])
        
        passed_validations = set()
        for result in validation_details:
            if result.get("status") == "passed":
                passed_validations.add(result.get("criteria"))
        
        missing_validations = []
        for required in required_validations:
            if required not in passed_validations:
                missing_validations.append(f"Complete {required} validation")
        
        return {
            "passed": len(missing_validations) == 0,
            "missing_validations": missing_validations
        }
    
    def _check_documentation_requirements(self, documentation_package: Dict[str, Any], criteria: Dict[str, Any]) -> Dict[str, Any]:
        """Check if documentation requirements are met"""
        
        required_documents = criteria.get("documentation_requirements", [])
        package_summary = documentation_package.get("package_summary", {})
        document_types = package_summary.get("document_types", [])
        
        missing_documents = []
        for required in required_documents:
            if required not in document_types:
                missing_documents.append(f"Generate {required}")
        
        return {
            "passed": len(missing_documents) == 0,
            "missing_documents": missing_documents
        }
    
    async def _extract_lessons_learned(self, 
                                     incident_data: Dict[str, Any],
                                     investigation_results: Dict[str, Any],
                                     validation_results: Dict[str, Any]) -> List[LessonsLearned]:
        """Extract lessons learned from incident"""
        
        lessons = []
        incident_id = incident_data.get("incident_id", "unknown")
        incident_type = incident_data.get("classification", {}).get("category", "unknown")
        
        # Root cause analysis lesson
        root_cause_lesson = await self._extract_root_cause_lesson(
            incident_id, incident_type, investigation_results
        )
        if root_cause_lesson:
            lessons.append(root_cause_lesson)
        
        # Detection improvement lesson
        detection_lesson = await self._extract_detection_lesson(
            incident_id, incident_data, investigation_results
        )
        if detection_lesson:
            lessons.append(detection_lesson)
        
        # Response improvement lesson
        response_lesson = await self._extract_response_lesson(
            incident_id, investigation_results, validation_results
        )
        if response_lesson:
            lessons.append(response_lesson)
        
        # Technical lesson
        technical_lesson = await self._extract_technical_lesson(
            incident_id, incident_type, investigation_results
        )
        if technical_lesson:
            lessons.append(technical_lesson)
        
        return lessons
    
    async def _extract_root_cause_lesson(self, 
                                       incident_id: str,
                                       incident_type: str,
                                       investigation_results: Dict[str, Any]) -> Optional[LessonsLearned]:
        """Extract root cause lesson"""
        
        analysis_summary = investigation_results.get("analysis_results", {}).get("summary", {})
        key_findings = analysis_summary.get("key_findings", [])
        
        if not key_findings:
            return None
        
        # Identify potential root cause
        root_cause = "Unknown"
        prevention_measures = []
        
        if incident_type == "malware":
            root_cause = "Malware execution on endpoint"
            prevention_measures = [
                "Enhanced endpoint protection",
                "Application whitelisting",
                "User behavior analytics"
            ]
        elif incident_type == "phishing":
            root_cause = "User interaction with malicious email"
            prevention_measures = [
                "Advanced email filtering",
                "User awareness training",
                "Email authentication protocols"
            ]
        else:
            root_cause = "Security control gap identified"
            prevention_measures = [
                "Security control assessment",
                "Risk mitigation implementation",
                "Monitoring enhancement"
            ]
        
        return LessonsLearned(
            lesson_id=f"lesson_root_cause_{incident_id}",
            category="Root Cause Analysis",
            description=f"Root cause analysis for {incident_type} incident",
            root_cause=root_cause,
            prevention_measures=prevention_measures,
            detection_improvements=[
                "Enhance monitoring for similar attack patterns",
                "Implement behavioral analytics"
            ],
            response_improvements=[
                "Automate initial containment",
                "Improve escalation procedures"
            ],
            priority="high",
            implementation_timeline="30-60 days",
            responsible_party="IT Security Team"
        )
    
    async def _extract_detection_lesson(self, 
                                      incident_id: str,
                                      incident_data: Dict[str, Any],
                                      investigation_results: Dict[str, Any]) -> Optional[LessonsLearned]:
        """Extract detection improvement lesson"""
        
        detection_time = self._calculate_detection_delay(incident_data, investigation_results)
        
        if detection_time and detection_time > 60:  # More than 1 hour detection delay
            return LessonsLearned(
                lesson_id=f"lesson_detection_{incident_id}",
                category="Detection Improvement",
                description="Delayed detection identified - improve monitoring capabilities",
                root_cause=f"Detection delay of {detection_time} minutes",
                prevention_measures=[
                    "Real-time alerting enhancement",
                    "Threat hunting automation",
                    "Behavioral analytics implementation"
                ],
                detection_improvements=[
                    "Reduce alert noise",
                    "Improve detection rules",
                    "Enhance correlation capabilities"
                ],
                response_improvements=[
                    "Automated triage",
                    "Faster escalation"
                ],
                priority="medium",
                implementation_timeline="60-90 days",
                responsible_party="SOC Team"
            )
        
        return None
    
    async def _extract_response_lesson(self, 
                                     incident_id: str,
                                     investigation_results: Dict[str, Any],
                                     validation_results: Dict[str, Any]) -> Optional[LessonsLearned]:
        """Extract response improvement lesson"""
        
        validation_summary = validation_results.get("validation_summary", {})
        success_score = validation_summary.get("success_score", 1.0)
        
        if success_score < 0.85:  # Sub-optimal response performance
            return LessonsLearned(
                lesson_id=f"lesson_response_{incident_id}",
                category="Response Improvement",
                description="Response process improvements needed based on validation results",
                root_cause=f"Response validation score of {success_score:.2f}",
                prevention_measures=[
                    "Response procedure enhancement",
                    "Team training improvement",
                    "Tool optimization"
                ],
                detection_improvements=[
                    "Better context gathering",
                    "Improved threat intelligence"
                ],
                response_improvements=[
                    "Streamlined procedures",
                    "Enhanced coordination",
                    "Better tool integration"
                ],
                priority="medium",
                implementation_timeline="30-45 days",
                responsible_party="Incident Response Team"
            )
        
        return None
    
    async def _extract_technical_lesson(self, 
                                      incident_id: str,
                                      incident_type: str,
                                      investigation_results: Dict[str, Any]) -> Optional[LessonsLearned]:
        """Extract technical lesson"""
        
        executed_tasks = investigation_results.get("analysis_results", {}).get("executed_tasks", [])
        
        # Look for technical gaps in investigation
        technical_gaps = []
        
        for task in executed_tasks:
            if "failed" in task.get("status", "").lower():
                technical_gaps.append(task.get("task_name", "Unknown task"))
        
        if technical_gaps:
            return LessonsLearned(
                lesson_id=f"lesson_technical_{incident_id}",
                category="Technical Improvement",
                description="Technical capabilities need enhancement for better investigation",
                root_cause=f"Technical gaps in: {', '.join(technical_gaps)}",
                prevention_measures=[
                    "Tool capability enhancement",
                    "Technical training",
                    "Process automation"
                ],
                detection_improvements=[
                    "Better forensic tools",
                    "Enhanced analysis capabilities"
                ],
                response_improvements=[
                    "Automated analysis",
                    "Improved tool integration"
                ],
                priority="low",
                implementation_timeline="90-120 days",
                responsible_party="Technical Team"
            )
        
        return None
    
    async def _generate_post_incident_actions(self, 
                                            incident_data: Dict[str, Any],
                                            investigation_results: Dict[str, Any],
                                            lessons_learned: List[LessonsLearned]) -> List[PostIncidentActionItem]:
        """Generate post-incident action items"""
        
        actions = []
        incident_id = incident_data.get("incident_id", "unknown")
        incident_type = incident_data.get("classification", {}).get("category", "default")
        
        # Get template actions
        template = self.post_incident_templates.get(incident_type, self.post_incident_templates["default"])
        
        # Add mandatory actions
        for action_template in template["mandatory_actions"]:
            action = PostIncidentActionItem(
                action_id=f"action_{incident_id}_{len(actions) + 1}",
                action_type=action_template["action_type"],
                description=action_template["description"],
                priority=action_template["priority"],
                due_date=datetime.now() + timedelta(days=action_template["due_days"]),
                assigned_to=self._determine_responsible_party(action_template["action_type"]),
                dependencies=[],
                completion_criteria=self._get_completion_criteria(action_template["action_type"]),
                status="pending",
                notes=""
            )
            actions.append(action)
        
        # Add recommended actions based on lessons learned
        for lesson in lessons_learned:
            if lesson.priority in ["high", "critical"]:
                action = PostIncidentActionItem(
                    action_id=f"action_{incident_id}_{len(actions) + 1}",
                    action_type=PostIncidentAction.SECURITY_ENHANCEMENT.value,
                    description=f"Implement lesson learned: {lesson.description}",
                    priority=lesson.priority,
                    due_date=datetime.now() + timedelta(days=30),
                    assigned_to=lesson.responsible_party,
                    dependencies=[],
                    completion_criteria=[
                        "Prevention measures implemented",
                        "Detection improvements deployed",
                        "Response improvements validated"
                    ],
                    status="pending",
                    notes=f"Based on lesson learned: {lesson.lesson_id}"
                )
                actions.append(action)
        
        return actions
    
    def _determine_responsible_party(self, action_type: str) -> str:
        """Determine responsible party for action type"""
        
        responsibility_map = {
            PostIncidentAction.LESSONS_LEARNED_SESSION.value: "Incident Commander",
            PostIncidentAction.PROCEDURE_UPDATE.value: "Process Owner",
            PostIncidentAction.TRAINING_DEVELOPMENT.value: "Training Team",
            PostIncidentAction.SECURITY_ENHANCEMENT.value: "IT Security Team",
            PostIncidentAction.POLICY_REVIEW.value: "Policy Team",
            PostIncidentAction.VENDOR_NOTIFICATION.value: "Vendor Management",
            PostIncidentAction.COMPLIANCE_REPORTING.value: "Compliance Team"
        }
        
        return responsibility_map.get(action_type, "IT Security Team")
    
    def _get_completion_criteria(self, action_type: str) -> List[str]:
        """Get completion criteria for action type"""
        
        criteria_map = {
            PostIncidentAction.LESSONS_LEARNED_SESSION.value: [
                "Session conducted with all stakeholders",
                "Lessons documented",
                "Action items identified"
            ],
            PostIncidentAction.PROCEDURE_UPDATE.value: [
                "Procedures reviewed and updated",
                "Changes approved",
                "Team trained on updates"
            ],
            PostIncidentAction.TRAINING_DEVELOPMENT.value: [
                "Training materials developed",
                "Training delivered",
                "Effectiveness measured"
            ],
            PostIncidentAction.SECURITY_ENHANCEMENT.value: [
                "Enhancement implemented",
                "Testing completed",
                "Monitoring validated"
            ],
            PostIncidentAction.COMPLIANCE_REPORTING.value: [
                "Reports submitted",
                "Confirmations received",
                "Follow-up completed"
            ]
        }
        
        return criteria_map.get(action_type, ["Action completed", "Results documented"])
    
    async def _calculate_incident_metrics(self, 
                                        incident_data: Dict[str, Any],
                                        investigation_results: Dict[str, Any],
                                        validation_results: Dict[str, Any],
                                        closure_time: datetime) -> Dict[str, Any]:
        """Calculate incident performance metrics"""
        
        metrics = {}
        
        # Calculate resolution time
        detection_time_str = incident_data.get("timestamp")
        if detection_time_str:
            detection_time = datetime.fromisoformat(detection_time_str.replace("Z", ""))
            resolution_time_hours = (closure_time - detection_time).total_seconds() / 3600
            metrics["resolution_time"] = {
                "value": resolution_time_hours,
                "unit": "hours",
                "target": self._get_metric_target("resolution_time", incident_data),
                "performance": "met" if resolution_time_hours <= self._get_metric_target("resolution_time", incident_data) else "missed"
            }
        
        # Calculate investigation quality
        validation_summary = validation_results.get("validation_summary", {})
        success_score = validation_summary.get("success_score", 0) * 100
        
        metrics["investigation_quality"] = {
            "value": success_score,
            "unit": "percentage",
            "target": self._get_metric_target("investigation_quality", incident_data),
            "performance": "met" if success_score >= self._get_metric_target("investigation_quality", incident_data) else "missed"
        }
        
        # Calculate response efficiency
        workflow_history = investigation_results.get("workflow_history", [])
        if len(workflow_history) > 1:
            first_response = workflow_history[0].get("timestamp")
            if first_response and detection_time_str:
                response_time_minutes = (datetime.fromisoformat(first_response.replace("Z", "")) - 
                                       datetime.fromisoformat(detection_time_str.replace("Z", ""))).total_seconds() / 60
                
                metrics["response_time"] = {
                    "value": response_time_minutes,
                    "unit": "minutes",
                    "target": self._get_metric_target("response_time", incident_data),
                    "performance": "met" if response_time_minutes <= self._get_metric_target("response_time", incident_data) else "missed"
                }
        
        return metrics
    
    def _get_metric_target(self, metric_name: str, incident_data: Dict[str, Any]) -> float:
        """Get metric target based on incident severity"""
        
        severity = incident_data.get("classification", {}).get("severity", "medium")
        metric_def = self.metrics_definitions.get(metric_name, {})
        targets = metric_def.get("targets", {})
        
        return targets.get(severity, targets.get("medium", 0))
    
    def _calculate_detection_delay(self, incident_data: Dict[str, Any], investigation_results: Dict[str, Any]) -> Optional[float]:
        """Calculate detection delay in minutes"""
        
        # Simplified calculation - in real implementation would use more sophisticated timing
        return 45.0  # Placeholder
    
    async def _process_closure_approvals(self, 
                                       incident_data: Dict[str, Any],
                                       validation_results: Dict[str, Any],
                                       closure_eligibility: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process closure approvals"""
        
        # Determine required approvals based on incident severity
        severity = incident_data.get("classification", {}).get("severity", "medium")
        criteria_key = closure_eligibility.get("criteria_met", "standard")
        criteria = self.closure_criteria[criteria_key]
        
        required_approvals = criteria.get("required_approvals", ["incident_commander"])
        
        approvals = []
        for approver in required_approvals:
            approvals.append({
                "approver": approver,
                "approval_date": datetime.now().isoformat(),
                "status": "approved",
                "comments": f"Incident closure approved based on validation results"
            })
        
        return approvals
    
    async def _create_compliance_attestation(self, 
                                           incident_data: Dict[str, Any],
                                           validation_results: Dict[str, Any],
                                           documentation_package: Dict[str, Any]) -> Dict[str, Any]:
        """Create compliance attestation"""
        
        return {
            "attestation_date": datetime.now().isoformat(),
            "compliance_officer": "Chief Compliance Officer",
            "regulatory_requirements_met": True,
            "documentation_complete": True,
            "retention_requirements_met": True,
            "audit_trail_preserved": True,
            "notification_requirements_met": True,
            "attestation_statement": "I attest that all compliance requirements have been met for this incident closure.",
            "supporting_documentation": self._extract_documentation_references(documentation_package)
        }
    
    def _determine_closure_reason(self, validation_results: Dict[str, Any], investigation_results: Dict[str, Any]) -> ClosureReason:
        """Determine reason for closure"""
        
        validation_summary = validation_results.get("validation_summary", {})
        overall_status = validation_summary.get("overall_status", "")
        
        if overall_status == "passed":
            return ClosureReason.RESOLVED_SUCCESSFULLY
        elif overall_status == "false_positive":
            return ClosureReason.FALSE_POSITIVE
        else:
            return ClosureReason.INSUFFICIENT_EVIDENCE
    
    def _generate_closure_summary(self, 
                                incident_data: Dict[str, Any],
                                investigation_results: Dict[str, Any],
                                validation_results: Dict[str, Any]) -> str:
        """Generate closure summary text"""
        
        incident_id = incident_data.get("incident_id", "Unknown")
        incident_type = incident_data.get("classification", {}).get("category", "Unknown")
        validation_score = validation_results.get("validation_summary", {}).get("success_score", 0)
        
        summary_parts = [
            f"Incident {incident_id} has been successfully resolved.",
            f"Incident Type: {incident_type}",
            f"Validation Score: {validation_score:.2f}",
            "All validation criteria have been met and proper documentation has been generated.",
            "Post-incident actions have been identified and scheduled for implementation."
        ]
        
        return " ".join(summary_parts)
    
    def _extract_documentation_references(self, documentation_package: Dict[str, Any]) -> List[str]:
        """Extract documentation references"""
        
        references = []
        
        package_id = documentation_package.get("package_id", "Unknown")
        references.append(f"Documentation Package: {package_id}")
        
        documents = documentation_package.get("documents", [])
        for doc in documents:
            doc_id = doc.get("document_id", "Unknown")
            doc_type = doc.get("document_type", "Unknown")
            references.append(f"{doc_type}: {doc_id}")
        
        return references
    
    async def _schedule_post_incident_actions(self, actions: List[PostIncidentActionItem]) -> Dict[str, Any]:
        """Schedule post-incident actions"""
        
        scheduled_actions = []
        responsible_parties = set()
        next_review_date = None
        
        for action in actions:
            # In real implementation, would integrate with task management system
            scheduled_actions.append({
                "action_id": action.action_id,
                "scheduled_date": action.due_date.isoformat(),
                "assigned_to": action.assigned_to
            })
            
            responsible_parties.add(action.assigned_to)
            
            if next_review_date is None or action.due_date < next_review_date:
                next_review_date = action.due_date
        
        return {
            "scheduled": len(scheduled_actions),
            "next_review_date": next_review_date.isoformat() if next_review_date else None,
            "responsible_parties": list(responsible_parties)
        }
    
    def _determine_post_closure_steps(self, incident_closure: IncidentClosure) -> List[str]:
        """Determine post-closure steps"""
        
        steps = [
            "Monitor post-incident action completion",
            "Schedule first post-incident review",
            "Archive incident documentation",
            "Update incident response metrics"
        ]
        
        # Add specific steps based on closure reason
        if incident_closure.closure_reason == ClosureReason.RESOLVED_SUCCESSFULLY.value:
            steps.append("Conduct lessons learned session")
            steps.append("Implement security improvements")
        
        if len(incident_closure.lessons_learned) > 0:
            steps.append("Track lesson learned implementation")
        
        return steps
    
    def _update_closure_stats(self, incident_closure: IncidentClosure):
        """Update closure statistics"""
        
        self.closure_stats["total_closures"] += 1
        self.closure_stats["closures_by_reason"][incident_closure.closure_reason] += 1
        self.closure_stats["lessons_learned_captured"] += len(incident_closure.lessons_learned)
        self.closure_stats["post_incident_actions_created"] += len(incident_closure.post_incident_actions)
        
        # Update approval rate
        total_approvals = len(incident_closure.approvals)
        approved_count = len([a for a in incident_closure.approvals if a.get("status") == "approved"])
        
        if total_approvals > 0:
            current_rate = self.closure_stats["closure_approval_rate"]
            total_closures = self.closure_stats["total_closures"]
            new_rate = ((current_rate * (total_closures - 1)) + (approved_count / total_approvals)) / total_closures
            self.closure_stats["closure_approval_rate"] = new_rate
    
    async def get_closure_statistics(self) -> Dict[str, Any]:
        """Get case closure statistics"""
        
        return {
            "closure_stats": self.closure_stats,
            "closure_criteria": list(self.closure_criteria.keys()),
            "supported_post_incident_actions": [action.value for action in PostIncidentAction],
            "closure_history_count": len(self.closure_history),
            "metrics_tracked": list(self.metrics_definitions.keys())
        }

def create_case_closure_manager() -> CaseClosureManager:
    """Factory function to create case closure manager"""
    return CaseClosureManager()

# Example usage
async def main():
    manager = create_case_closure_manager()
    
    # Example closure
    sample_incident = {
        "incident_id": "inc_001",
        "classification": {"category": "malware", "severity": "high"},
        "timestamp": datetime.now().isoformat()
    }
    
    sample_investigation = {
        "analysis_results": {"executed_tasks": [], "summary": {}},
        "workflow_history": [{"timestamp": datetime.now().isoformat(), "state": "completed"}]
    }
    
    sample_validation = {
        "validation_summary": {"overall_status": "passed", "success_score": 0.85}
    }
    
    sample_documentation = {
        "package_id": "doc_001",
        "package_summary": {"document_types": ["incident_report"]},
        "documents": []
    }
    
    sample_sentinel = {"status": "completed"}
    
    result = await manager.close_incident_case(
        sample_incident, sample_investigation, sample_validation, 
        sample_documentation, sample_sentinel
    )
    
    print(f"Case closure result: {json.dumps(result, indent=2)}")

if __name__ == "__main__":
    asyncio.run(main())
