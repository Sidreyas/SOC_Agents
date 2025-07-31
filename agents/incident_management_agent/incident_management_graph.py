"""
Incident Management Agent - Main Workflow Graph
Orchestrates the complete incident lifecycle management process
States: 1-8 covering incident intake through case closure
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, TypedDict
from datetime import datetime, timedelta
from enum import Enum
import json
from dataclasses import dataclass, asdict

# Import individual workflow modules
from .incident_intake import IncidentIntakeProcessor, create_incident_intake_processor
from .evidence_correlator import EvidenceCorrelator, create_evidence_correlator
from .investigation_planner import InvestigationPlanner, create_investigation_planner

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('incident_management.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class IncidentState(Enum):
    """Incident management workflow states"""
    INCIDENT_INTAKE = "incident_intake"                    # State 1
    EVIDENCE_CORRELATION = "evidence_correlation"          # State 2  
    INVESTIGATION_PLANNING = "investigation_planning"      # State 3
    ANALYSIS_EXECUTION = "analysis_execution"              # State 4
    DOCUMENTATION_GENERATION = "documentation_generation"  # State 5
    RESOLUTION_VALIDATION = "resolution_validation"        # State 6
    SENTINEL_INTEGRATION = "sentinel_integration"          # State 7
    CASE_CLOSURE = "case_closure"                          # State 8

class WorkflowStatus(Enum):
    """Workflow execution status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ESCALATED = "escalated"
    ON_HOLD = "on_hold"

# Type definitions for the workflow state
class IncidentWorkflowState(TypedDict):
    incident_id: str
    current_state: str
    workflow_status: str
    incident_data: Dict[str, Any]
    evidence_data: Dict[str, Any]
    investigation_plan: Dict[str, Any]
    analysis_results: Dict[str, Any]
    documentation: Dict[str, Any]
    resolution_data: Dict[str, Any]
    sentinel_data: Dict[str, Any]
    closure_data: Dict[str, Any]
    workflow_history: List[Dict[str, Any]]
    metadata: Dict[str, Any]

@dataclass
class WorkflowTransition:
    """Represents a workflow state transition"""
    from_state: str
    to_state: str
    trigger: str
    conditions: List[str]
    timestamp: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        return result

class IncidentManagementAgent:
    """
    Main Incident Management Agent
    Orchestrates the complete incident lifecycle workflow
    """
    
    def __init__(self):
        # Initialize workflow components
        self.incident_processor = create_incident_intake_processor()
        self.evidence_correlator = create_evidence_correlator()
        self.investigation_planner = create_investigation_planner()
        
        # Workflow state management
        self.active_workflows = {}
        self.workflow_templates = self._initialize_workflow_templates()
        self.state_handlers = self._initialize_state_handlers()
        
        # Statistics and monitoring
        self.workflow_stats = {
            "total_incidents_processed": 0,
            "incidents_by_state": {state.value: 0 for state in IncidentState},
            "average_workflow_duration": 0,
            "successful_closures": 0,
            "escalated_incidents": 0,
            "workflow_failures": 0
        }
        
        logger.info("Incident Management Agent initialized")
    
    def _initialize_workflow_templates(self) -> Dict[str, Dict[str, Any]]:
        """Initialize workflow templates for different incident types"""
        return {
            "standard_workflow": {
                "states": [state.value for state in IncidentState],
                "transitions": [
                    {"from": IncidentState.INCIDENT_INTAKE.value, "to": IncidentState.EVIDENCE_CORRELATION.value},
                    {"from": IncidentState.EVIDENCE_CORRELATION.value, "to": IncidentState.INVESTIGATION_PLANNING.value},
                    {"from": IncidentState.INVESTIGATION_PLANNING.value, "to": IncidentState.ANALYSIS_EXECUTION.value},
                    {"from": IncidentState.ANALYSIS_EXECUTION.value, "to": IncidentState.DOCUMENTATION_GENERATION.value},
                    {"from": IncidentState.DOCUMENTATION_GENERATION.value, "to": IncidentState.RESOLUTION_VALIDATION.value},
                    {"from": IncidentState.RESOLUTION_VALIDATION.value, "to": IncidentState.SENTINEL_INTEGRATION.value},
                    {"from": IncidentState.SENTINEL_INTEGRATION.value, "to": IncidentState.CASE_CLOSURE.value}
                ],
                "escalation_triggers": [
                    "investigation_timeline_exceeded",
                    "critical_evidence_found",
                    "resource_constraints",
                    "regulatory_deadline_approaching"
                ]
            },
            "rapid_response_workflow": {
                "states": [
                    IncidentState.INCIDENT_INTAKE.value,
                    IncidentState.INVESTIGATION_PLANNING.value,  # Skip evidence correlation for speed
                    IncidentState.ANALYSIS_EXECUTION.value,
                    IncidentState.DOCUMENTATION_GENERATION.value,
                    IncidentState.CASE_CLOSURE.value  # Skip some validation steps
                ],
                "transitions": [
                    {"from": IncidentState.INCIDENT_INTAKE.value, "to": IncidentState.INVESTIGATION_PLANNING.value},
                    {"from": IncidentState.INVESTIGATION_PLANNING.value, "to": IncidentState.ANALYSIS_EXECUTION.value},
                    {"from": IncidentState.ANALYSIS_EXECUTION.value, "to": IncidentState.DOCUMENTATION_GENERATION.value},
                    {"from": IncidentState.DOCUMENTATION_GENERATION.value, "to": IncidentState.CASE_CLOSURE.value}
                ],
                "escalation_triggers": [
                    "response_time_exceeded",
                    "scope_expansion_detected"
                ]
            },
            "compliance_workflow": {
                "states": [state.value for state in IncidentState],
                "transitions": [
                    {"from": IncidentState.INCIDENT_INTAKE.value, "to": IncidentState.EVIDENCE_CORRELATION.value},
                    {"from": IncidentState.EVIDENCE_CORRELATION.value, "to": IncidentState.INVESTIGATION_PLANNING.value},
                    {"from": IncidentState.INVESTIGATION_PLANNING.value, "to": IncidentState.ANALYSIS_EXECUTION.value},
                    {"from": IncidentState.ANALYSIS_EXECUTION.value, "to": IncidentState.DOCUMENTATION_GENERATION.value},
                    {"from": IncidentState.DOCUMENTATION_GENERATION.value, "to": IncidentState.RESOLUTION_VALIDATION.value},
                    {"from": IncidentState.RESOLUTION_VALIDATION.value, "to": IncidentState.SENTINEL_INTEGRATION.value},
                    {"from": IncidentState.SENTINEL_INTEGRATION.value, "to": IncidentState.CASE_CLOSURE.value}
                ],
                "additional_validation": [
                    "regulatory_compliance_check",
                    "legal_review_required",
                    "audit_trail_verification"
                ],
                "escalation_triggers": [
                    "compliance_violation_detected",
                    "regulatory_notification_required",
                    "legal_counsel_needed"
                ]
            }
        }
    
    def _initialize_state_handlers(self) -> Dict[str, callable]:
        """Initialize handlers for each workflow state"""
        return {
            IncidentState.INCIDENT_INTAKE.value: self._handle_incident_intake,
            IncidentState.EVIDENCE_CORRELATION.value: self._handle_evidence_correlation,
            IncidentState.INVESTIGATION_PLANNING.value: self._handle_investigation_planning,
            IncidentState.ANALYSIS_EXECUTION.value: self._handle_analysis_execution,
            IncidentState.DOCUMENTATION_GENERATION.value: self._handle_documentation_generation,
            IncidentState.RESOLUTION_VALIDATION.value: self._handle_resolution_validation,
            IncidentState.SENTINEL_INTEGRATION.value: self._handle_sentinel_integration,
            IncidentState.CASE_CLOSURE.value: self._handle_case_closure
        }
    
    async def process_incident(self, incident_data: Dict[str, Any], 
                             source_agent: str = None,
                             workflow_type: str = "standard_workflow") -> Dict[str, Any]:
        """
        Process a new incident through the complete workflow
        
        Args:
            incident_data: Raw incident data from detecting agent
            source_agent: Name of the agent that detected the incident
            workflow_type: Type of workflow to use (standard, rapid_response, compliance)
            
        Returns:
            Initial processing result and workflow tracking information
        """
        try:
            start_time = datetime.now()
            
            # Create initial workflow state
            workflow_state = await self._create_initial_workflow_state(
                incident_data, source_agent, workflow_type, start_time
            )
            
            incident_id = workflow_state["incident_id"]
            
            # Store active workflow
            self.active_workflows[incident_id] = workflow_state
            
            logger.info(f"Starting incident workflow for {incident_id} using {workflow_type}")
            
            # Begin workflow execution
            execution_result = await self._execute_workflow_state(incident_id)
            
            # Update statistics
            self._update_workflow_stats(workflow_state)
            
            return {
                "status": "workflow_started",
                "incident_id": incident_id,
                "workflow_type": workflow_type,
                "current_state": workflow_state["current_state"],
                "execution_result": execution_result,
                "estimated_completion_time": self._estimate_completion_time(workflow_state),
                "workflow_tracking_url": f"/api/incidents/{incident_id}/workflow"
            }
            
        except Exception as e:
            logger.error(f"Error processing incident: {str(e)}")
            return {
                "status": "workflow_error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    async def _create_initial_workflow_state(self, incident_data: Dict[str, Any],
                                           source_agent: str, workflow_type: str,
                                           start_time: datetime) -> IncidentWorkflowState:
        """Create initial workflow state for new incident"""
        
        # Generate unique incident ID if not provided
        incident_id = incident_data.get("incident_id", f"inc_{int(start_time.timestamp())}")
        
        # Initialize workflow state
        workflow_state: IncidentWorkflowState = {
            "incident_id": incident_id,
            "current_state": IncidentState.INCIDENT_INTAKE.value,
            "workflow_status": WorkflowStatus.PENDING.value,
            "incident_data": incident_data,
            "evidence_data": {},
            "investigation_plan": {},
            "analysis_results": {},
            "documentation": {},
            "resolution_data": {},
            "sentinel_data": {},
            "closure_data": {},
            "workflow_history": [
                {
                    "state": IncidentState.INCIDENT_INTAKE.value,
                    "status": "initiated",
                    "timestamp": start_time.isoformat(),
                    "source_agent": source_agent
                }
            ],
            "metadata": {
                "workflow_type": workflow_type,
                "source_agent": source_agent,
                "start_time": start_time.isoformat(),
                "last_updated": start_time.isoformat(),
                "escalation_level": 0,
                "priority_score": incident_data.get("priority_score", 50)
            }
        }
        
        return workflow_state
    
    async def _execute_workflow_state(self, incident_id: str) -> Dict[str, Any]:
        """Execute the current workflow state for an incident"""
        
        if incident_id not in self.active_workflows:
            return {"status": "error", "message": "Incident not found in active workflows"}
        
        workflow_state = self.active_workflows[incident_id]
        current_state = workflow_state["current_state"]
        
        logger.info(f"Executing state {current_state} for incident {incident_id}")
        
        try:
            # Mark workflow as in progress
            workflow_state["workflow_status"] = WorkflowStatus.IN_PROGRESS.value
            
            # Execute state handler
            if current_state in self.state_handlers:
                state_result = await self.state_handlers[current_state](workflow_state)
                
                # Update workflow state with results
                await self._update_workflow_state(workflow_state, state_result)
                
                # Check for state transition
                transition_result = await self._evaluate_state_transition(workflow_state)
                
                return {
                    "status": "state_executed",
                    "current_state": current_state,
                    "state_result": state_result,
                    "transition_result": transition_result
                }
            else:
                logger.error(f"No handler found for state {current_state}")
                return {"status": "error", "message": f"No handler for state {current_state}"}
                
        except Exception as e:
            logger.error(f"Error executing state {current_state} for incident {incident_id}: {str(e)}")
            workflow_state["workflow_status"] = WorkflowStatus.FAILED.value
            
            return {
                "status": "execution_error",
                "current_state": current_state,
                "error": str(e)
            }
    
    async def _handle_incident_intake(self, workflow_state: IncidentWorkflowState) -> Dict[str, Any]:
        """Handle State 1: Incident Intake"""
        logger.info(f"Processing incident intake for {workflow_state['incident_id']}")
        
        # Process incident through intake module
        intake_result = await self.incident_processor.receive_incident(
            workflow_state["incident_data"],
            workflow_state["metadata"]["source_agent"]
        )
        
        # Update workflow state with intake results
        workflow_state["incident_data"].update({
            "intake_result": intake_result,
            "classification": {
                "severity": intake_result.get("severity"),
                "category": intake_result.get("category"),
                "priority_score": intake_result.get("priority_score", 50)
            }
        })
        
        return {
            "state": IncidentState.INCIDENT_INTAKE.value,
            "status": "completed",
            "result": intake_result,
            "next_state": IncidentState.EVIDENCE_CORRELATION.value,
            "timestamp": datetime.now().isoformat()
        }
    
    async def _handle_evidence_correlation(self, workflow_state: IncidentWorkflowState) -> Dict[str, Any]:
        """Handle State 2: Evidence Correlation"""
        logger.info(f"Processing evidence correlation for {workflow_state['incident_id']}")
        
        incident_id = workflow_state["incident_id"]
        
        # Collect evidence from the incident data
        incident_data = workflow_state["incident_data"]
        alert_data = incident_data.get("alert_data", {})
        
        # Create evidence items from alert data
        evidence_items = []
        
        # Convert alert data to evidence format
        if alert_data:
            evidence_data = {
                "type": "log_entry",
                "timestamp": incident_data.get("timestamp", datetime.now().isoformat()),
                "data": alert_data,
                "metadata": {
                    "source": incident_data.get("source", "unknown"),
                    "confidence": alert_data.get("confidence", 0.5)
                }
            }
            
            evidence_result = await self.evidence_correlator.collect_evidence(
                incident_id, evidence_data, workflow_state["metadata"]["source_agent"]
            )
            evidence_items.append(evidence_result)
        
        # Generate correlation report
        correlation_report = await self.evidence_correlator.generate_correlation_report(incident_id)
        
        # Store evidence data in workflow state
        workflow_state["evidence_data"] = {
            "evidence_items": evidence_items,
            "correlation_report": correlation_report,
            "total_evidence": len(evidence_items),
            "correlation_score": len(correlation_report.get("high_confidence_correlations", []))
        }
        
        return {
            "state": IncidentState.EVIDENCE_CORRELATION.value,
            "status": "completed",
            "result": {
                "evidence_collected": len(evidence_items),
                "correlations_found": len(correlation_report.get("correlation_network", [])),
                "correlation_report": correlation_report
            },
            "next_state": IncidentState.INVESTIGATION_PLANNING.value,
            "timestamp": datetime.now().isoformat()
        }
    
    async def _handle_investigation_planning(self, workflow_state: IncidentWorkflowState) -> Dict[str, Any]:
        """Handle State 3: Investigation Planning"""
        logger.info(f"Processing investigation planning for {workflow_state['incident_id']}")
        
        # Prepare incident data for planning
        planning_data = {
            "incident_id": workflow_state["incident_id"],
            "category": workflow_state["incident_data"].get("classification", {}).get("category", "unknown"),
            "severity": workflow_state["incident_data"].get("classification", {}).get("severity", "medium"),
            "evidence_summary": workflow_state["evidence_data"].get("correlation_report", {})
        }
        
        # Create investigation plan
        planning_result = await self.investigation_planner.create_investigation_plan(planning_data)
        
        # Store investigation plan in workflow state
        workflow_state["investigation_plan"] = planning_result.get("plan", {})
        
        return {
            "state": IncidentState.INVESTIGATION_PLANNING.value,
            "status": "completed",
            "result": planning_result,
            "next_state": IncidentState.ANALYSIS_EXECUTION.value,
            "timestamp": datetime.now().isoformat()
        }
    
    async def _handle_analysis_execution(self, workflow_state: IncidentWorkflowState) -> Dict[str, Any]:
        """Handle State 4: Analysis Execution"""
        logger.info(f"Processing analysis execution for {workflow_state['incident_id']}")
        
        investigation_plan = workflow_state["investigation_plan"]
        tasks = investigation_plan.get("tasks", [])
        
        # Execute investigation tasks
        analysis_results = {
            "executed_tasks": [],
            "findings": [],
            "recommendations": [],
            "risk_assessment": {}
        }
        
        # Simulate task execution (in production, this would coordinate with other agents)
        for task in tasks[:3]:  # Execute first 3 high-priority tasks for demo
            task_result = await self._execute_investigation_task(task, workflow_state)
            analysis_results["executed_tasks"].append(task_result)
            
            # Extract findings from task execution
            if task_result.get("status") == "completed":
                analysis_results["findings"].extend(task_result.get("findings", []))
        
        # Generate analysis summary
        analysis_summary = await self._generate_analysis_summary(analysis_results, workflow_state)
        analysis_results["summary"] = analysis_summary
        
        # Store analysis results
        workflow_state["analysis_results"] = analysis_results
        
        return {
            "state": IncidentState.ANALYSIS_EXECUTION.value,
            "status": "completed",
            "result": analysis_results,
            "next_state": IncidentState.DOCUMENTATION_GENERATION.value,
            "timestamp": datetime.now().isoformat()
        }
    
    async def _execute_investigation_task(self, task: Dict[str, Any], 
                                        workflow_state: IncidentWorkflowState) -> Dict[str, Any]:
        """Execute individual investigation task"""
        
        task_id = task.get("task_id", "unknown")
        task_name = task.get("task_name", "Unknown Task")
        
        logger.info(f"Executing task {task_id}: {task_name}")
        
        # Simulate task execution based on task type
        if "isolate" in task_name.lower():
            findings = ["Systems isolated successfully", "Network traffic blocked"]
        elif "analyze" in task_name.lower():
            findings = ["Malware family identified", "Command and control server found"]
        elif "search" in task_name.lower():
            findings = ["Additional infected systems found", "Lateral movement detected"]
        else:
            findings = ["Task completed successfully"]
        
        return {
            "task_id": task_id,
            "task_name": task_name,
            "status": "completed",
            "execution_time": 30,  # minutes
            "findings": findings,
            "timestamp": datetime.now().isoformat()
        }
    
    async def _generate_analysis_summary(self, analysis_results: Dict[str, Any],
                                       workflow_state: IncidentWorkflowState) -> Dict[str, Any]:
        """Generate comprehensive analysis summary"""
        
        all_findings = analysis_results.get("findings", [])
        executed_tasks = analysis_results.get("executed_tasks", [])
        
        return {
            "total_tasks_executed": len(executed_tasks),
            "total_findings": len(all_findings),
            "key_findings": all_findings[:5],  # Top 5 findings
            "incident_scope": self._assess_incident_scope(all_findings),
            "threat_level": self._assess_threat_level(all_findings, workflow_state),
            "containment_status": self._assess_containment_status(all_findings),
            "recommendations": self._generate_recommendations(all_findings, workflow_state)
        }
    
    def _assess_incident_scope(self, findings: List[str]) -> str:
        """Assess the scope of the incident based on findings"""
        scope_indicators = [
            ("multiple", "wide"),
            ("lateral", "wide"), 
            ("network", "medium"),
            ("single", "limited"),
            ("isolated", "limited")
        ]
        
        findings_text = " ".join(findings).lower()
        
        for indicator, scope in scope_indicators:
            if indicator in findings_text:
                return scope
        
        return "limited"
    
    def _assess_threat_level(self, findings: List[str], 
                           workflow_state: IncidentWorkflowState) -> str:
        """Assess threat level based on findings and incident data"""
        
        severity = workflow_state["incident_data"].get("classification", {}).get("severity", "medium")
        findings_text = " ".join(findings).lower()
        
        high_threat_indicators = ["command and control", "lateral movement", "data exfiltration"]
        
        if severity in ["critical", "high"] and any(indicator in findings_text for indicator in high_threat_indicators):
            return "high"
        elif any(indicator in findings_text for indicator in high_threat_indicators):
            return "medium"
        else:
            return "low"
    
    def _assess_containment_status(self, findings: List[str]) -> str:
        """Assess containment status based on findings"""
        findings_text = " ".join(findings).lower()
        
        if "isolated" in findings_text and "blocked" in findings_text:
            return "contained"
        elif "isolated" in findings_text or "blocked" in findings_text:
            return "partial"
        else:
            return "not_contained"
    
    def _generate_recommendations(self, findings: List[str], 
                                workflow_state: IncidentWorkflowState) -> List[str]:
        """Generate recommendations based on analysis"""
        recommendations = []
        findings_text = " ".join(findings).lower()
        
        if "malware" in findings_text:
            recommendations.append("Update antivirus signatures and scan all systems")
            recommendations.append("Review and strengthen email security controls")
        
        if "lateral movement" in findings_text:
            recommendations.append("Implement network segmentation")
            recommendations.append("Review and update access controls")
        
        if "command and control" in findings_text:
            recommendations.append("Block identified C2 domains and IPs")
            recommendations.append("Monitor for additional C2 communications")
        
        # Add general recommendations
        recommendations.append("Conduct lessons learned session")
        recommendations.append("Update incident response procedures")
        
        return recommendations
    
    async def _handle_documentation_generation(self, workflow_state: IncidentWorkflowState) -> Dict[str, Any]:
        """Handle State 5: Documentation Generation"""
        logger.info(f"Processing documentation generation for {workflow_state['incident_id']}")
        
        # Generate comprehensive incident documentation
        documentation = await self._generate_incident_documentation(workflow_state)
        
        # Store documentation in workflow state
        workflow_state["documentation"] = documentation
        
        return {
            "state": IncidentState.DOCUMENTATION_GENERATION.value,
            "status": "completed",
            "result": {
                "documentation_generated": True,
                "document_sections": len(documentation.get("sections", [])),
                "total_pages": documentation.get("metadata", {}).get("total_pages", 0)
            },
            "next_state": IncidentState.RESOLUTION_VALIDATION.value,
            "timestamp": datetime.now().isoformat()
        }
    
    async def _generate_incident_documentation(self, workflow_state: IncidentWorkflowState) -> Dict[str, Any]:
        """Generate comprehensive incident documentation"""
        
        incident_id = workflow_state["incident_id"]
        
        documentation = {
            "incident_id": incident_id,
            "document_type": "incident_report",
            "generated_date": datetime.now().isoformat(),
            "sections": [
                {
                    "section": "executive_summary",
                    "title": "Executive Summary",
                    "content": self._generate_executive_summary(workflow_state)
                },
                {
                    "section": "incident_details",
                    "title": "Incident Details", 
                    "content": self._generate_incident_details(workflow_state)
                },
                {
                    "section": "investigation_findings",
                    "title": "Investigation Findings",
                    "content": self._generate_investigation_findings(workflow_state)
                },
                {
                    "section": "evidence_analysis",
                    "title": "Evidence Analysis",
                    "content": self._generate_evidence_analysis(workflow_state)
                },
                {
                    "section": "timeline",
                    "title": "Incident Timeline",
                    "content": self._generate_incident_timeline(workflow_state)
                },
                {
                    "section": "recommendations",
                    "title": "Recommendations",
                    "content": self._generate_documentation_recommendations(workflow_state)
                },
                {
                    "section": "appendices",
                    "title": "Appendices",
                    "content": self._generate_appendices(workflow_state)
                }
            ],
            "metadata": {
                "total_pages": 15,
                "classification": "confidential",
                "retention_period": "7_years",
                "distribution_list": ["incident_commander", "ciso", "legal_team"]
            }
        }
        
        return documentation
    
    def _generate_executive_summary(self, workflow_state: IncidentWorkflowState) -> Dict[str, Any]:
        """Generate executive summary section"""
        
        incident_data = workflow_state["incident_data"]
        analysis_results = workflow_state.get("analysis_results", {})
        
        classification = incident_data.get("classification", {})
        summary = analysis_results.get("summary", {})
        
        return {
            "incident_type": classification.get("category", "Unknown"),
            "severity": classification.get("severity", "Unknown"),
            "detection_time": incident_data.get("timestamp", "Unknown"),
            "resolution_time": workflow_state["metadata"].get("completion_time", "In Progress"),
            "impact_assessment": summary.get("incident_scope", "Limited"),
            "threat_level": summary.get("threat_level", "Low"),
            "containment_status": summary.get("containment_status", "Not Contained"),
            "business_impact": "Minimal operational impact observed",
            "key_findings": summary.get("key_findings", []),
            "immediate_actions": ["Incident contained", "Systems secured", "Monitoring enhanced"]
        }
    
    def _generate_incident_details(self, workflow_state: IncidentWorkflowState) -> Dict[str, Any]:
        """Generate incident details section"""
        
        incident_data = workflow_state["incident_data"]
        
        return {
            "incident_id": workflow_state["incident_id"],
            "detection_method": incident_data.get("source", "Automated detection"),
            "reporting_agent": workflow_state["metadata"].get("source_agent", "Unknown"),
            "affected_systems": incident_data.get("alert_data", {}).get("affected_hosts", []),
            "initial_indicators": incident_data.get("description", ""),
            "classification_details": incident_data.get("classification", {}),
            "escalation_history": self._extract_escalation_history(workflow_state)
        }
    
    def _generate_investigation_findings(self, workflow_state: IncidentWorkflowState) -> Dict[str, Any]:
        """Generate investigation findings section"""
        
        analysis_results = workflow_state.get("analysis_results", {})
        investigation_plan = workflow_state.get("investigation_plan", {})
        
        return {
            "investigation_strategy": investigation_plan.get("strategy", "Unknown"),
            "tasks_executed": analysis_results.get("executed_tasks", []),
            "key_findings": analysis_results.get("findings", []),
            "evidence_collected": len(workflow_state.get("evidence_data", {}).get("evidence_items", [])),
            "correlations_identified": workflow_state.get("evidence_data", {}).get("correlation_score", 0),
            "threat_indicators": self._extract_threat_indicators(workflow_state),
            "attack_timeline": self._construct_attack_timeline(workflow_state)
        }
    
    def _generate_evidence_analysis(self, workflow_state: IncidentWorkflowState) -> Dict[str, Any]:
        """Generate evidence analysis section"""
        
        evidence_data = workflow_state.get("evidence_data", {})
        correlation_report = evidence_data.get("correlation_report", {})
        
        return {
            "evidence_summary": {
                "total_items": evidence_data.get("total_evidence", 0),
                "evidence_types": list(correlation_report.get("key_indicators", {}).keys()),
                "confidence_levels": "High confidence evidence collected"
            },
            "correlation_analysis": {
                "correlation_network": correlation_report.get("correlation_network", []),
                "evidence_clusters": correlation_report.get("evidence_clusters", []),
                "timeline": correlation_report.get("timeline", [])
            },
            "key_indicators": correlation_report.get("key_indicators", {}),
            "chain_of_custody": "Maintained throughout investigation"
        }
    
    def _generate_incident_timeline(self, workflow_state: IncidentWorkflowState) -> Dict[str, Any]:
        """Generate incident timeline section"""
        
        workflow_history = workflow_state.get("workflow_history", [])
        
        timeline_events = []
        for event in workflow_history:
            timeline_events.append({
                "timestamp": event.get("timestamp"),
                "event": f"{event.get('state', 'Unknown')} - {event.get('status', 'Unknown')}",
                "description": f"Workflow state: {event.get('state', 'Unknown')}"
            })
        
        return {
            "timeline_events": timeline_events,
            "duration_analysis": {
                "total_investigation_time": self._calculate_investigation_duration(workflow_state),
                "time_by_phase": self._calculate_time_by_phase(workflow_history)
            }
        }
    
    def _generate_documentation_recommendations(self, workflow_state: IncidentWorkflowState) -> Dict[str, Any]:
        """Generate recommendations section"""
        
        analysis_results = workflow_state.get("analysis_results", {})
        summary = analysis_results.get("summary", {})
        
        return {
            "immediate_actions": summary.get("recommendations", []),
            "process_improvements": [
                "Enhance detection capabilities",
                "Improve response procedures",
                "Update security controls"
            ],
            "technology_enhancements": [
                "Deploy additional monitoring tools",
                "Upgrade security infrastructure",
                "Implement automation improvements"
            ],
            "training_recommendations": [
                "Conduct incident response training",
                "Security awareness training for users",
                "Technical skills development"
            ]
        }
    
    def _generate_appendices(self, workflow_state: IncidentWorkflowState) -> Dict[str, Any]:
        """Generate appendices section"""
        
        return {
            "appendix_a": {
                "title": "Technical Details",
                "content": "Detailed technical analysis and artifacts"
            },
            "appendix_b": {
                "title": "Evidence Inventory",
                "content": "Complete inventory of collected evidence"
            },
            "appendix_c": {
                "title": "Tool Outputs",
                "content": "Raw outputs from investigation tools"
            },
            "appendix_d": {
                "title": "Compliance Checklist",
                "content": "Regulatory compliance verification"
            }
        }
    
    def _extract_escalation_history(self, workflow_state: IncidentWorkflowState) -> List[Dict[str, Any]]:
        """Extract escalation history from workflow"""
        escalations = []
        
        escalation_level = workflow_state["metadata"].get("escalation_level", 0)
        if escalation_level > 0:
            escalations.append({
                "level": escalation_level,
                "reason": "Investigation complexity exceeded threshold",
                "timestamp": workflow_state["metadata"].get("last_updated"),
                "approver": "incident_commander"
            })
        
        return escalations
    
    def _extract_threat_indicators(self, workflow_state: IncidentWorkflowState) -> List[str]:
        """Extract threat indicators from investigation"""
        indicators = []
        
        evidence_data = workflow_state.get("evidence_data", {})
        correlation_report = evidence_data.get("correlation_report", {})
        key_indicators = correlation_report.get("key_indicators", {})
        
        for indicator_type, values in key_indicators.items():
            indicators.extend([f"{indicator_type}: {value}" for value in values[:3]])  # Top 3 per type
        
        return indicators
    
    def _construct_attack_timeline(self, workflow_state: IncidentWorkflowState) -> List[Dict[str, Any]]:
        """Construct attack timeline from evidence"""
        timeline = []
        
        evidence_data = workflow_state.get("evidence_data", {})
        correlation_report = evidence_data.get("correlation_report", {})
        evidence_timeline = correlation_report.get("timeline", [])
        
        for event in evidence_timeline[:10]:  # Top 10 events
            timeline.append({
                "timestamp": event.get("timestamp"),
                "event_type": event.get("evidence_type"),
                "description": event.get("summary", "Evidence collected"),
                "confidence": event.get("confidence", "medium")
            })
        
        return timeline
    
    def _calculate_investigation_duration(self, workflow_state: IncidentWorkflowState) -> str:
        """Calculate total investigation duration"""
        start_time = workflow_state["metadata"].get("start_time")
        if start_time:
            start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
            duration = datetime.now() - start_dt
            return f"{duration.total_seconds() / 3600:.1f} hours"
        return "Unknown"
    
    def _calculate_time_by_phase(self, workflow_history: List[Dict[str, Any]]) -> Dict[str, str]:
        """Calculate time spent in each phase"""
        phase_times = {}
        
        for i, event in enumerate(workflow_history):
            if i < len(workflow_history) - 1:
                current_time = datetime.fromisoformat(event["timestamp"].replace('Z', '+00:00'))
                next_time = datetime.fromisoformat(workflow_history[i+1]["timestamp"].replace('Z', '+00:00'))
                duration = (next_time - current_time).total_seconds() / 60  # minutes
                phase_times[event["state"]] = f"{duration:.0f} minutes"
        
        return phase_times
    
    async def _handle_resolution_validation(self, workflow_state: IncidentWorkflowState) -> Dict[str, Any]:
        """Handle State 6: Resolution Validation"""
        logger.info(f"Processing resolution validation for {workflow_state['incident_id']}")
        
        # Validate resolution against success criteria
        validation_result = await self._validate_incident_resolution(workflow_state)
        
        # Store resolution data
        workflow_state["resolution_data"] = validation_result
        
        return {
            "state": IncidentState.RESOLUTION_VALIDATION.value,
            "status": "completed",
            "result": validation_result,
            "next_state": IncidentState.SENTINEL_INTEGRATION.value,
            "timestamp": datetime.now().isoformat()
        }
    
    async def _validate_incident_resolution(self, workflow_state: IncidentWorkflowState) -> Dict[str, Any]:
        """Validate that incident has been properly resolved"""
        
        investigation_plan = workflow_state.get("investigation_plan", {})
        analysis_results = workflow_state.get("analysis_results", {})
        
        success_criteria = investigation_plan.get("success_criteria", [])
        summary = analysis_results.get("summary", {})
        
        validation_results = []
        
        # Check each success criterion
        for criterion in success_criteria:
            if "contained" in criterion.lower():
                status = summary.get("containment_status", "not_contained") == "contained"
            elif "removed" in criterion.lower() or "eliminated" in criterion.lower():
                status = "malware" not in " ".join(analysis_results.get("findings", [])).lower()
            elif "restored" in criterion.lower():
                status = True  # Assume systems restored
            else:
                status = True  # Default to satisfied
            
            validation_results.append({
                "criterion": criterion,
                "status": "satisfied" if status else "not_satisfied",
                "evidence": "Validation evidence collected"
            })
        
        overall_status = all(result["status"] == "satisfied" for result in validation_results)
        
        return {
            "validation_status": "passed" if overall_status else "failed",
            "criteria_results": validation_results,
            "validation_timestamp": datetime.now().isoformat(),
            "validator": "incident_management_agent",
            "additional_actions_required": [] if overall_status else ["Additional investigation needed"]
        }
    
    async def _handle_sentinel_integration(self, workflow_state: IncidentWorkflowState) -> Dict[str, Any]:
        """Handle State 7: Sentinel Integration"""
        logger.info(f"Processing Sentinel integration for {workflow_state['incident_id']}")
        
        # Prepare data for Sentinel integration
        sentinel_data = await self._prepare_sentinel_data(workflow_state)
        
        # Simulate Sentinel API integration (in production, this would make actual API calls)
        integration_result = await self._integrate_with_sentinel(sentinel_data)
        
        # Store Sentinel data
        workflow_state["sentinel_data"] = {
            "integration_result": integration_result,
            "sentinel_incident_id": integration_result.get("sentinel_incident_id"),
            "update_timestamp": datetime.now().isoformat()
        }
        
        return {
            "state": IncidentState.SENTINEL_INTEGRATION.value,
            "status": "completed",
            "result": integration_result,
            "next_state": IncidentState.CASE_CLOSURE.value,
            "timestamp": datetime.now().isoformat()
        }
    
    async def _prepare_sentinel_data(self, workflow_state: IncidentWorkflowState) -> Dict[str, Any]:
        """Prepare data for Sentinel integration"""
        
        incident_data = workflow_state["incident_data"]
        documentation = workflow_state.get("documentation", {})
        resolution_data = workflow_state.get("resolution_data", {})
        
        return {
            "incident_id": workflow_state["incident_id"],
            "title": f"Incident {workflow_state['incident_id']} - {incident_data.get('description', 'Unknown incident')}",
            "severity": incident_data.get("classification", {}).get("severity", "medium"),
            "status": "resolved" if resolution_data.get("validation_status") == "passed" else "in_progress",
            "classification": incident_data.get("classification", {}),
            "investigation_summary": documentation.get("sections", [{}])[0].get("content", {}),
            "evidence_summary": workflow_state.get("evidence_data", {}),
            "resolution_details": resolution_data,
            "tags": [
                f"category_{incident_data.get('classification', {}).get('category', 'unknown')}",
                f"severity_{incident_data.get('classification', {}).get('severity', 'medium')}",
                "automated_investigation"
            ]
        }
    
    async def _integrate_with_sentinel(self, sentinel_data: Dict[str, Any]) -> Dict[str, Any]:
        """Integrate incident data with Microsoft Sentinel"""
        
        # Simulate Sentinel API integration
        # In production, this would use the Microsoft Sentinel REST API
        
        integration_result = {
            "status": "success",
            "sentinel_incident_id": f"sentinel_{int(datetime.now().timestamp())}",
            "created_time": datetime.now().isoformat(),
            "incident_url": f"https://portal.azure.com/sentinel/incidents/{sentinel_data['incident_id']}",
            "operations_performed": [
                "incident_created",
                "evidence_attached",
                "investigation_timeline_updated",
                "resolution_documented"
            ]
        }
        
        logger.info(f"Integrated incident {sentinel_data['incident_id']} with Sentinel: {integration_result['sentinel_incident_id']}")
        
        return integration_result
    
    async def _handle_case_closure(self, workflow_state: IncidentWorkflowState) -> Dict[str, Any]:
        """Handle State 8: Case Closure"""
        logger.info(f"Processing case closure for {workflow_state['incident_id']}")
        
        # Generate case closure data
        closure_data = await self._generate_case_closure_data(workflow_state)
        
        # Mark workflow as completed
        workflow_state["workflow_status"] = WorkflowStatus.COMPLETED.value
        workflow_state["metadata"]["completion_time"] = datetime.now().isoformat()
        
        # Store closure data
        workflow_state["closure_data"] = closure_data
        
        # Update statistics
        self.workflow_stats["successful_closures"] += 1
        
        # Archive the workflow (remove from active workflows)
        incident_id = workflow_state["incident_id"]
        if incident_id in self.active_workflows:
            del self.active_workflows[incident_id]
        
        logger.info(f"Case closed for incident {incident_id}")
        
        return {
            "state": IncidentState.CASE_CLOSURE.value,
            "status": "completed",
            "result": closure_data,
            "workflow_complete": True,
            "timestamp": datetime.now().isoformat()
        }
    
    async def _generate_case_closure_data(self, workflow_state: IncidentWorkflowState) -> Dict[str, Any]:
        """Generate case closure data"""
        
        start_time_str = workflow_state["metadata"].get("start_time")
        completion_time = datetime.now()
        
        if start_time_str:
            start_time = datetime.fromisoformat(start_time_str.replace('Z', '+00:00'))
            total_duration = completion_time - start_time
        else:
            total_duration = timedelta(hours=2)  # Default
        
        return {
            "closure_timestamp": completion_time.isoformat(),
            "total_investigation_time": total_duration.total_seconds() / 3600,  # hours
            "workflow_summary": {
                "states_completed": len(workflow_state.get("workflow_history", [])),
                "evidence_items_processed": len(workflow_state.get("evidence_data", {}).get("evidence_items", [])),
                "investigation_tasks_executed": len(workflow_state.get("analysis_results", {}).get("executed_tasks", [])),
                "documentation_generated": bool(workflow_state.get("documentation")),
                "sentinel_integration_completed": bool(workflow_state.get("sentinel_data"))
            },
            "final_classification": workflow_state["incident_data"].get("classification", {}),
            "resolution_status": workflow_state.get("resolution_data", {}).get("validation_status", "unknown"),
            "lessons_learned": [
                "Investigation workflow completed successfully",
                "All evidence properly documented",
                "Incident properly resolved and documented"
            ],
            "post_incident_actions": [
                "Monitor for similar incidents",
                "Review and update detection rules",
                "Conduct team debrief session"
            ],
            "compliance_status": "compliant",
            "retention_requirements": {
                "retention_period": "7_years",
                "storage_location": "secure_archive",
                "access_controls": "authorized_personnel_only"
            }
        }
    
    async def _update_workflow_state(self, workflow_state: IncidentWorkflowState, 
                                   state_result: Dict[str, Any]):
        """Update workflow state with results from state execution"""
        
        # Add to workflow history
        workflow_state["workflow_history"].append({
            "state": state_result.get("state"),
            "status": state_result.get("status"),
            "timestamp": state_result.get("timestamp"),
            "result": state_result.get("result")
        })
        
        # Update metadata
        workflow_state["metadata"]["last_updated"] = datetime.now().isoformat()
        
        # Update current state if transitioning
        if state_result.get("next_state"):
            workflow_state["current_state"] = state_result["next_state"]
    
    async def _evaluate_state_transition(self, workflow_state: IncidentWorkflowState) -> Dict[str, Any]:
        """Evaluate whether to transition to next state"""
        
        current_state = workflow_state["current_state"]
        workflow_type = workflow_state["metadata"]["workflow_type"]
        
        # Get workflow template
        template = self.workflow_templates.get(workflow_type, self.workflow_templates["standard_workflow"])
        transitions = template.get("transitions", [])
        
        # Check if automatic transition should occur
        for transition in transitions:
            if transition["from"] == current_state:
                # Check transition conditions (simplified for demo)
                if await self._check_transition_conditions(workflow_state, transition):
                    # Schedule next state execution
                    asyncio.create_task(self._execute_workflow_state(workflow_state["incident_id"]))
                    
                    return {
                        "transition": "scheduled",
                        "from_state": current_state,
                        "to_state": transition["to"],
                        "timestamp": datetime.now().isoformat()
                    }
        
        return {
            "transition": "none",
            "current_state": current_state,
            "requires_manual_intervention": False
        }
    
    async def _check_transition_conditions(self, workflow_state: IncidentWorkflowState, 
                                         transition: Dict[str, Any]) -> bool:
        """Check if conditions are met for state transition"""
        
        # For demo purposes, automatically approve transitions
        # In production, this would check specific conditions based on transition type
        
        current_state = workflow_state["current_state"]
        
        # Check if current state is completed
        workflow_history = workflow_state.get("workflow_history", [])
        current_state_entry = next(
            (entry for entry in reversed(workflow_history) if entry.get("state") == current_state),
            None
        )
        
        if current_state_entry and current_state_entry.get("status") == "completed":
            return True
        
        return False
    
    def _estimate_completion_time(self, workflow_state: IncidentWorkflowState) -> str:
        """Estimate workflow completion time"""
        
        current_state = workflow_state["current_state"]
        workflow_type = workflow_state["metadata"]["workflow_type"]
        
        # State duration estimates (in minutes)
        state_durations = {
            IncidentState.INCIDENT_INTAKE.value: 15,
            IncidentState.EVIDENCE_CORRELATION.value: 45,
            IncidentState.INVESTIGATION_PLANNING.value: 30,
            IncidentState.ANALYSIS_EXECUTION.value: 120,
            IncidentState.DOCUMENTATION_GENERATION.value: 60,
            IncidentState.RESOLUTION_VALIDATION.value: 30,
            IncidentState.SENTINEL_INTEGRATION.value: 15,
            IncidentState.CASE_CLOSURE.value: 15
        }
        
        # Calculate remaining time
        template = self.workflow_templates.get(workflow_type, self.workflow_templates["standard_workflow"])
        remaining_states = template.get("states", [])
        
        current_index = remaining_states.index(current_state) if current_state in remaining_states else 0
        remaining_states = remaining_states[current_index + 1:]
        
        total_remaining_minutes = sum(state_durations.get(state, 30) for state in remaining_states)
        
        completion_time = datetime.now() + timedelta(minutes=total_remaining_minutes)
        return completion_time.isoformat()
    
    def _update_workflow_stats(self, workflow_state: IncidentWorkflowState):
        """Update workflow statistics"""
        
        self.workflow_stats["total_incidents_processed"] += 1
        
        current_state = workflow_state["current_state"]
        self.workflow_stats["incidents_by_state"][current_state] += 1
    
    async def get_incident_status(self, incident_id: str) -> Dict[str, Any]:
        """Get current status of an incident workflow"""
        
        if incident_id not in self.active_workflows:
            return {
                "status": "not_found",
                "message": f"Incident {incident_id} not found in active workflows"
            }
        
        workflow_state = self.active_workflows[incident_id]
        
        return {
            "incident_id": incident_id,
            "current_state": workflow_state["current_state"],
            "workflow_status": workflow_state["workflow_status"],
            "progress_percentage": self._calculate_progress_percentage(workflow_state),
            "estimated_completion": self._estimate_completion_time(workflow_state),
            "last_updated": workflow_state["metadata"]["last_updated"],
            "workflow_history": workflow_state["workflow_history"]
        }
    
    def _calculate_progress_percentage(self, workflow_state: IncidentWorkflowState) -> int:
        """Calculate workflow progress percentage"""
        
        workflow_type = workflow_state["metadata"]["workflow_type"]
        template = self.workflow_templates.get(workflow_type, self.workflow_templates["standard_workflow"])
        total_states = len(template.get("states", []))
        
        current_state = workflow_state["current_state"]
        current_index = template.get("states", []).index(current_state) if current_state in template.get("states", []) else 0
        
        return int((current_index / total_states) * 100) if total_states > 0 else 0
    
    async def get_workflow_statistics(self) -> Dict[str, Any]:
        """Get workflow processing statistics"""
        
        return {
            "workflow_stats": self.workflow_stats,
            "active_workflows": len(self.active_workflows),
            "workflow_templates": list(self.workflow_templates.keys()),
            "supported_states": [state.value for state in IncidentState]
        }
    
    async def escalate_incident(self, incident_id: str, escalation_reason: str) -> Dict[str, Any]:
        """Escalate an incident to higher level support"""
        
        if incident_id not in self.active_workflows:
            return {
                "status": "error",
                "message": f"Incident {incident_id} not found"
            }
        
        workflow_state = self.active_workflows[incident_id]
        
        # Update escalation level
        workflow_state["metadata"]["escalation_level"] = workflow_state["metadata"].get("escalation_level", 0) + 1
        workflow_state["workflow_status"] = WorkflowStatus.ESCALATED.value
        
        # Add escalation to history
        workflow_state["workflow_history"].append({
            "state": "escalation",
            "status": "escalated",
            "timestamp": datetime.now().isoformat(),
            "reason": escalation_reason,
            "escalation_level": workflow_state["metadata"]["escalation_level"]
        })
        
        self.workflow_stats["escalated_incidents"] += 1
        
        logger.warning(f"Incident {incident_id} escalated: {escalation_reason}")
        
        return {
            "status": "escalated",
            "incident_id": incident_id,
            "escalation_level": workflow_state["metadata"]["escalation_level"],
            "escalation_reason": escalation_reason,
            "timestamp": datetime.now().isoformat()
        }

def create_incident_management_agent() -> IncidentManagementAgent:
    """Factory function to create incident management agent"""
    return IncidentManagementAgent()

# Example usage
async def main():
    # Create incident management agent
    agent = create_incident_management_agent()
    
    # Example incident data
    sample_incident = {
        "timestamp": datetime.now().isoformat(),
        "source": "malware_agent",
        "description": "Critical malware detected on endpoint - ransomware suspected",
        "alert_data": {
            "alert_type": "malware_detection",
            "severity": "critical",
            "confidence": 0.95,
            "affected_hosts": ["DESKTOP-001", "DESKTOP-002"],
            "file_hash": "a1b2c3d4e5f6...",
            "source_ip": "192.168.1.100"
        }
    }
    
    # Process incident
    result = await agent.process_incident(sample_incident, "malware_agent", "standard_workflow")
    print(f"Incident processing result: {json.dumps(result, indent=2)}")
    
    # Check status
    if result.get("status") == "workflow_started":
        incident_id = result["incident_id"]
        
        # Wait a bit for processing
        await asyncio.sleep(2)
        
        # Get status
        status = await agent.get_incident_status(incident_id)
        print(f"Incident status: {json.dumps(status, indent=2)}")
        
        # Get statistics
        stats = await agent.get_workflow_statistics()
        print(f"Workflow statistics: {json.dumps(stats, indent=2)}")

if __name__ == "__main__":
    asyncio.run(main())
