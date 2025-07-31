"""
Investigation Planner Module
State 3: Investigation Strategy and Resource Planning
Plans investigation approach based on incident classification and evidence
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
import json

logger = logging.getLogger(__name__)

class InvestigationStrategy(Enum):
    """Investigation strategy types"""
    RAPID_RESPONSE = "rapid_response"
    DEEP_ANALYSIS = "deep_analysis"
    CONTAINMENT_FIRST = "containment_first"
    EVIDENCE_PRESERVATION = "evidence_preservation"
    THREAT_HUNTING = "threat_hunting"
    FORENSIC_ANALYSIS = "forensic_analysis"
    COMPLIANCE_FOCUSED = "compliance_focused"

class InvestigationPriority(Enum):
    """Investigation priority levels"""
    EMERGENCY = "emergency"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    ROUTINE = "routine"

class InvestigationPhase(Enum):
    """Investigation phases"""
    PREPARATION = "preparation"
    IDENTIFICATION = "identification"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    LESSONS_LEARNED = "lessons_learned"

class ResourceType(Enum):
    """Types of investigation resources"""
    ANALYST = "analyst"
    SPECIALIST = "specialist"
    TOOL = "tool"
    SYSTEM_ACCESS = "system_access"
    EXTERNAL_SUPPORT = "external_support"

@dataclass
class InvestigationTask:
    """Individual investigation task"""
    task_id: str
    task_name: str
    description: str
    phase: str
    priority: int
    estimated_duration: int  # minutes
    required_skills: List[str]
    required_tools: List[str]
    dependencies: List[str]
    assigned_agent: Optional[str]
    status: str
    created_time: datetime
    due_time: Optional[datetime]
    completion_time: Optional[datetime]
    notes: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert task to dictionary"""
        result = asdict(self)
        result['created_time'] = self.created_time.isoformat()
        if self.due_time:
            result['due_time'] = self.due_time.isoformat()
        if self.completion_time:
            result['completion_time'] = self.completion_time.isoformat()
        return result

@dataclass
class InvestigationPlan:
    """Complete investigation plan"""
    plan_id: str
    incident_id: str
    strategy: str
    priority: str
    estimated_duration: int  # minutes
    required_resources: List[Dict[str, Any]]
    tasks: List[InvestigationTask]
    timeline: Dict[str, Any]
    success_criteria: List[str]
    escalation_triggers: List[str]
    created_time: datetime
    updated_time: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert plan to dictionary"""
        result = asdict(self)
        result['created_time'] = self.created_time.isoformat()
        result['updated_time'] = self.updated_time.isoformat()
        result['tasks'] = [task.to_dict() for task in self.tasks]
        return result

class InvestigationPlanner:
    """
    Plans investigation strategies and creates detailed investigation plans
    """
    
    def __init__(self):
        self.investigation_templates = self._initialize_investigation_templates()
        self.resource_catalog = self._initialize_resource_catalog()
        self.skill_requirements = self._initialize_skill_requirements()
        self.planning_stats = {
            "total_plans_created": 0,
            "plans_by_strategy": {},
            "average_planning_time": 0,
            "resource_utilization": {}
        }
    
    def _initialize_investigation_templates(self) -> Dict[str, Dict[str, Any]]:
        """Initialize investigation templates for different incident types"""
        return {
            "malware_incident": {
                "strategy": InvestigationStrategy.CONTAINMENT_FIRST.value,
                "phases": [
                    InvestigationPhase.PREPARATION.value,
                    InvestigationPhase.IDENTIFICATION.value,
                    InvestigationPhase.CONTAINMENT.value,
                    InvestigationPhase.ERADICATION.value,
                    InvestigationPhase.RECOVERY.value,
                    InvestigationPhase.LESSONS_LEARNED.value
                ],
                "standard_tasks": [
                    {
                        "name": "Isolate affected systems",
                        "phase": "containment",
                        "priority": 1,
                        "duration": 30,
                        "skills": ["incident_response", "network_isolation"],
                        "tools": ["network_tools", "endpoint_isolation"]
                    },
                    {
                        "name": "Analyze malware sample",
                        "phase": "identification",
                        "priority": 2,
                        "duration": 120,
                        "skills": ["malware_analysis", "reverse_engineering"],
                        "tools": ["sandbox_analysis", "disassemblers"]
                    },
                    {
                        "name": "Search for additional infections",
                        "phase": "identification",
                        "priority": 2,
                        "duration": 90,
                        "skills": ["threat_hunting", "log_analysis"],
                        "tools": ["siem_tools", "endpoint_detection"]
                    },
                    {
                        "name": "Remove malware",
                        "phase": "eradication",
                        "priority": 3,
                        "duration": 60,
                        "skills": ["malware_removal", "system_administration"],
                        "tools": ["antivirus_tools", "system_cleanup"]
                    },
                    {
                        "name": "Restore systems",
                        "phase": "recovery",
                        "priority": 4,
                        "duration": 120,
                        "skills": ["system_restoration", "backup_recovery"],
                        "tools": ["backup_systems", "restoration_tools"]
                    }
                ],
                "success_criteria": [
                    "All malware removed from environment",
                    "No additional infections detected",
                    "All systems restored to normal operation",
                    "Vulnerability patched to prevent reinfection"
                ]
            },
            
            "phishing_incident": {
                "strategy": InvestigationStrategy.RAPID_RESPONSE.value,
                "phases": [
                    InvestigationPhase.PREPARATION.value,
                    InvestigationPhase.IDENTIFICATION.value,
                    InvestigationPhase.CONTAINMENT.value,
                    InvestigationPhase.RECOVERY.value,
                    InvestigationPhase.LESSONS_LEARNED.value
                ],
                "standard_tasks": [
                    {
                        "name": "Block malicious email domain",
                        "phase": "containment",
                        "priority": 1,
                        "duration": 15,
                        "skills": ["email_security", "dns_management"],
                        "tools": ["email_gateway", "dns_filters"]
                    },
                    {
                        "name": "Identify affected users",
                        "phase": "identification",
                        "priority": 1,
                        "duration": 45,
                        "skills": ["log_analysis", "email_forensics"],
                        "tools": ["email_logs", "user_activity_monitoring"]
                    },
                    {
                        "name": "Reset compromised credentials",
                        "phase": "containment",
                        "priority": 2,
                        "duration": 30,
                        "skills": ["identity_management", "access_control"],
                        "tools": ["active_directory", "password_reset_tools"]
                    },
                    {
                        "name": "Conduct user awareness training",
                        "phase": "recovery",
                        "priority": 3,
                        "duration": 60,
                        "skills": ["security_training", "user_education"],
                        "tools": ["training_platforms", "awareness_materials"]
                    }
                ],
                "success_criteria": [
                    "Malicious emails blocked",
                    "All affected users identified and notified",
                    "Compromised accounts secured",
                    "Users educated on phishing prevention"
                ]
            },
            
            "network_intrusion": {
                "strategy": InvestigationStrategy.FORENSIC_ANALYSIS.value,
                "phases": [
                    InvestigationPhase.PREPARATION.value,
                    InvestigationPhase.IDENTIFICATION.value,
                    InvestigationPhase.CONTAINMENT.value,
                    InvestigationPhase.ERADICATION.value,
                    InvestigationPhase.RECOVERY.value,
                    InvestigationPhase.LESSONS_LEARNED.value
                ],
                "standard_tasks": [
                    {
                        "name": "Preserve network forensic evidence",
                        "phase": "preparation",
                        "priority": 1,
                        "duration": 30,
                        "skills": ["digital_forensics", "evidence_preservation"],
                        "tools": ["packet_capture", "network_forensics"]
                    },
                    {
                        "name": "Analyze network traffic patterns",
                        "phase": "identification",
                        "priority": 1,
                        "duration": 180,
                        "skills": ["network_analysis", "traffic_analysis"],
                        "tools": ["wireshark", "network_monitoring"]
                    },
                    {
                        "name": "Identify attack vectors",
                        "phase": "identification",
                        "priority": 2,
                        "duration": 120,
                        "skills": ["vulnerability_analysis", "penetration_testing"],
                        "tools": ["vulnerability_scanners", "exploitation_tools"]
                    },
                    {
                        "name": "Block malicious IP ranges",
                        "phase": "containment",
                        "priority": 2,
                        "duration": 20,
                        "skills": ["firewall_management", "network_security"],
                        "tools": ["firewalls", "ips_systems"]
                    },
                    {
                        "name": "Patch vulnerabilities",
                        "phase": "eradication",
                        "priority": 3,
                        "duration": 180,
                        "skills": ["patch_management", "system_administration"],
                        "tools": ["patch_management_systems", "vulnerability_scanners"]
                    }
                ],
                "success_criteria": [
                    "Attack vector identified and documented",
                    "All unauthorized access blocked",
                    "Vulnerabilities patched",
                    "Network security posture improved"
                ]
            },
            
            "data_breach": {
                "strategy": InvestigationStrategy.COMPLIANCE_FOCUSED.value,
                "phases": [
                    InvestigationPhase.PREPARATION.value,
                    InvestigationPhase.IDENTIFICATION.value,
                    InvestigationPhase.CONTAINMENT.value,
                    InvestigationPhase.ERADICATION.value,
                    InvestigationPhase.RECOVERY.value,
                    InvestigationPhase.LESSONS_LEARNED.value
                ],
                "standard_tasks": [
                    {
                        "name": "Preserve forensic evidence",
                        "phase": "preparation",
                        "priority": 1,
                        "duration": 45,
                        "skills": ["digital_forensics", "legal_compliance"],
                        "tools": ["forensic_imaging", "chain_of_custody"]
                    },
                    {
                        "name": "Assess data exposure scope",
                        "phase": "identification",
                        "priority": 1,
                        "duration": 240,
                        "skills": ["data_classification", "privacy_analysis"],
                        "tools": ["data_discovery", "classification_tools"]
                    },
                    {
                        "name": "Notify regulatory authorities",
                        "phase": "containment",
                        "priority": 1,
                        "duration": 120,
                        "skills": ["regulatory_compliance", "legal_reporting"],
                        "tools": ["notification_systems", "compliance_templates"]
                    },
                    {
                        "name": "Communicate with affected individuals",
                        "phase": "recovery",
                        "priority": 2,
                        "duration": 180,
                        "skills": ["crisis_communication", "customer_relations"],
                        "tools": ["communication_platforms", "notification_systems"]
                    }
                ],
                "success_criteria": [
                    "Full scope of data exposure determined",
                    "Regulatory notifications completed on time",
                    "Affected individuals notified",
                    "Data protection measures enhanced"
                ]
            }
        }
    
    def _initialize_resource_catalog(self) -> Dict[str, Dict[str, Any]]:
        """Initialize available investigation resources"""
        return {
            "analysts": {
                "incident_responder": {
                    "skills": ["incident_response", "forensics", "containment"],
                    "availability": "24/7",
                    "capacity_hours_per_day": 8
                },
                "malware_analyst": {
                    "skills": ["malware_analysis", "reverse_engineering", "sandbox_analysis"],
                    "availability": "business_hours",
                    "capacity_hours_per_day": 8
                },
                "network_analyst": {
                    "skills": ["network_analysis", "traffic_analysis", "firewall_management"],
                    "availability": "24/7",
                    "capacity_hours_per_day": 8
                },
                "forensic_investigator": {
                    "skills": ["digital_forensics", "evidence_preservation", "legal_compliance"],
                    "availability": "on_call",
                    "capacity_hours_per_day": 6
                }
            },
            "tools": {
                "siem_platform": {
                    "capabilities": ["log_analysis", "correlation", "alerting"],
                    "availability": "24/7",
                    "concurrent_users": 50
                },
                "sandbox_analysis": {
                    "capabilities": ["malware_analysis", "behavior_analysis", "safe_execution"],
                    "availability": "24/7", 
                    "concurrent_analyses": 10
                },
                "network_forensics": {
                    "capabilities": ["packet_analysis", "traffic_reconstruction", "protocol_analysis"],
                    "availability": "24/7",
                    "storage_capacity": "10TB"
                },
                "endpoint_tools": {
                    "capabilities": ["endpoint_isolation", "remote_analysis", "artifact_collection"],
                    "availability": "24/7",
                    "managed_endpoints": 10000
                }
            },
            "external_resources": {
                "threat_intelligence": {
                    "capabilities": ["ioc_lookup", "attribution", "campaign_analysis"],
                    "response_time": "< 1 hour",
                    "cost_per_query": 5
                },
                "legal_counsel": {
                    "capabilities": ["regulatory_guidance", "litigation_support", "compliance_review"],
                    "response_time": "< 4 hours",
                    "hourly_rate": 500
                },
                "forensic_specialists": {
                    "capabilities": ["advanced_forensics", "expert_testimony", "specialized_analysis"],
                    "response_time": "< 24 hours",
                    "daily_rate": 2000
                }
            }
        }
    
    def _initialize_skill_requirements(self) -> Dict[str, List[str]]:
        """Initialize skill requirements for different investigation types"""
        return {
            "malware_incident": [
                "incident_response", "malware_analysis", "reverse_engineering",
                "network_isolation", "threat_hunting", "system_administration"
            ],
            "phishing_incident": [
                "email_security", "log_analysis", "identity_management",
                "user_education", "dns_management"
            ],
            "network_intrusion": [
                "network_analysis", "digital_forensics", "vulnerability_analysis",
                "firewall_management", "penetration_testing"
            ],
            "data_breach": [
                "digital_forensics", "legal_compliance", "data_classification",
                "privacy_analysis", "crisis_communication"
            ],
            "insider_threat": [
                "behavioral_analysis", "access_control", "digital_forensics",
                "hr_coordination", "surveillance_analysis"
            ]
        }
    
    async def create_investigation_plan(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create comprehensive investigation plan for an incident
        
        Args:
            incident_data: Incident information including classification and evidence
            
        Returns:
            Investigation plan with tasks, timeline, and resource requirements
        """
        try:
            plan_start_time = datetime.now()
            
            # Extract incident details
            incident_id = incident_data.get("incident_id")
            incident_category = incident_data.get("category", "unknown")
            incident_severity = incident_data.get("severity", "medium")
            evidence_summary = incident_data.get("evidence_summary", {})
            
            logger.info(f"Creating investigation plan for incident {incident_id}")
            
            # Determine investigation strategy
            strategy = await self._determine_investigation_strategy(
                incident_category, incident_severity, evidence_summary
            )
            
            # Calculate priority
            priority = self._calculate_investigation_priority(incident_severity, incident_category)
            
            # Generate investigation tasks
            tasks = await self._generate_investigation_tasks(
                incident_category, strategy, evidence_summary
            )
            
            # Plan resource allocation
            resource_requirements = await self._plan_resource_allocation(tasks, priority)
            
            # Create timeline
            timeline = await self._create_investigation_timeline(tasks, priority)
            
            # Define success criteria
            success_criteria = self._define_success_criteria(incident_category, strategy)
            
            # Set escalation triggers
            escalation_triggers = self._define_escalation_triggers(incident_severity, strategy)
            
            # Create investigation plan
            plan = InvestigationPlan(
                plan_id=f"plan_{incident_id}_{int(datetime.now().timestamp())}",
                incident_id=incident_id,
                strategy=strategy,
                priority=priority,
                estimated_duration=sum(task.estimated_duration for task in tasks),
                required_resources=resource_requirements,
                tasks=tasks,
                timeline=timeline,
                success_criteria=success_criteria,
                escalation_triggers=escalation_triggers,
                created_time=plan_start_time,
                updated_time=plan_start_time
            )
            
            # Update statistics
            self._update_planning_stats(strategy, datetime.now() - plan_start_time)
            
            logger.info(f"Investigation plan created for incident {incident_id}")
            
            return {
                "status": "plan_created",
                "plan": plan.to_dict(),
                "execution_guidance": await self._generate_execution_guidance(plan),
                "risk_assessment": await self._assess_investigation_risks(plan),
                "resource_conflicts": await self._check_resource_conflicts(resource_requirements)
            }
            
        except Exception as e:
            logger.error(f"Error creating investigation plan: {str(e)}")
            return {
                "status": "planning_error",
                "error": str(e)
            }
    
    async def _determine_investigation_strategy(self, category: str, severity: str, 
                                              evidence_summary: Dict[str, Any]) -> str:
        """Determine optimal investigation strategy"""
        
        # Strategy based on severity
        if severity in ["critical", "high"]:
            if category in ["malware", "network_intrusion"]:
                return InvestigationStrategy.CONTAINMENT_FIRST.value
            elif category == "data_breach":
                return InvestigationStrategy.COMPLIANCE_FOCUSED.value
            else:
                return InvestigationStrategy.RAPID_RESPONSE.value
        
        # Strategy based on category
        strategy_mapping = {
            "malware": InvestigationStrategy.CONTAINMENT_FIRST.value,
            "phishing": InvestigationStrategy.RAPID_RESPONSE.value,
            "network_intrusion": InvestigationStrategy.FORENSIC_ANALYSIS.value,
            "data_breach": InvestigationStrategy.COMPLIANCE_FOCUSED.value,
            "insider_threat": InvestigationStrategy.EVIDENCE_PRESERVATION.value,
            "ddos_attack": InvestigationStrategy.RAPID_RESPONSE.value,
            "access_violation": InvestigationStrategy.DEEP_ANALYSIS.value
        }
        
        return strategy_mapping.get(category, InvestigationStrategy.DEEP_ANALYSIS.value)
    
    def _calculate_investigation_priority(self, severity: str, category: str) -> str:
        """Calculate investigation priority"""
        
        # High-priority categories
        high_priority_categories = ["data_breach", "malware", "network_intrusion"]
        
        if severity == "critical":
            return InvestigationPriority.EMERGENCY.value
        elif severity == "high" or category in high_priority_categories:
            return InvestigationPriority.HIGH.value
        elif severity == "medium":
            return InvestigationPriority.MEDIUM.value
        elif severity == "low":
            return InvestigationPriority.LOW.value
        else:
            return InvestigationPriority.ROUTINE.value
    
    async def _generate_investigation_tasks(self, category: str, strategy: str, 
                                          evidence_summary: Dict[str, Any]) -> List[InvestigationTask]:
        """Generate investigation tasks based on category and strategy"""
        
        tasks = []
        current_time = datetime.now()
        
        # Get template tasks
        template_key = f"{category}_incident"
        if template_key not in self.investigation_templates:
            template_key = "malware_incident"  # Default template
        
        template = self.investigation_templates[template_key]
        standard_tasks = template.get("standard_tasks", [])
        
        # Create tasks from template
        for i, task_template in enumerate(standard_tasks):
            task = InvestigationTask(
                task_id=f"task_{category}_{i+1}",
                task_name=task_template["name"],
                description=f"Execute {task_template['name']} as part of {strategy} strategy",
                phase=task_template["phase"],
                priority=task_template["priority"],
                estimated_duration=task_template["duration"],
                required_skills=task_template["skills"],
                required_tools=task_template["tools"],
                dependencies=self._determine_task_dependencies(i, standard_tasks),
                assigned_agent=None,
                status="planned",
                created_time=current_time,
                due_time=None,
                completion_time=None,
                notes=[]
            )
            tasks.append(task)
        
        # Add evidence-specific tasks
        evidence_tasks = await self._generate_evidence_specific_tasks(evidence_summary, category)
        tasks.extend(evidence_tasks)
        
        # Sort tasks by priority and dependencies
        return self._optimize_task_order(tasks)
    
    def _determine_task_dependencies(self, task_index: int, 
                                   standard_tasks: List[Dict[str, Any]]) -> List[str]:
        """Determine task dependencies based on phases and priorities"""
        dependencies = []
        
        if task_index == 0:
            return dependencies
        
        current_task = standard_tasks[task_index]
        current_phase = current_task["phase"]
        current_priority = current_task["priority"]
        
        # Tasks depend on higher priority tasks in same or earlier phases
        for i in range(task_index):
            prev_task = standard_tasks[i]
            prev_phase = prev_task["phase"]
            prev_priority = prev_task["priority"]
            
            # Dependency rules
            if (prev_priority < current_priority or 
                (prev_phase != current_phase and 
                 self._is_earlier_phase(prev_phase, current_phase))):
                dependencies.append(f"task_{current_task.get('category', 'unknown')}_{i+1}")
        
        return dependencies
    
    def _is_earlier_phase(self, phase1: str, phase2: str) -> bool:
        """Check if phase1 comes before phase2"""
        phase_order = [
            InvestigationPhase.PREPARATION.value,
            InvestigationPhase.IDENTIFICATION.value,
            InvestigationPhase.CONTAINMENT.value,
            InvestigationPhase.ERADICATION.value,
            InvestigationPhase.RECOVERY.value,
            InvestigationPhase.LESSONS_LEARNED.value
        ]
        
        try:
            return phase_order.index(phase1) < phase_order.index(phase2)
        except ValueError:
            return False
    
    async def _generate_evidence_specific_tasks(self, evidence_summary: Dict[str, Any], 
                                              category: str) -> List[InvestigationTask]:
        """Generate tasks specific to available evidence"""
        evidence_tasks = []
        current_time = datetime.now()
        
        # Evidence-based task generation
        evidence_count = evidence_summary.get("total_evidence_items", 0)
        evidence_types = evidence_summary.get("evidence_by_type", {})
        
        if "network_traffic" in evidence_types:
            task = InvestigationTask(
                task_id=f"evidence_network_analysis",
                task_name="Analyze network traffic evidence",
                description="Deep analysis of network traffic evidence",
                phase="identification",
                priority=2,
                estimated_duration=120,
                required_skills=["network_analysis", "traffic_analysis"],
                required_tools=["wireshark", "network_monitoring"],
                dependencies=[],
                assigned_agent=None,
                status="planned",
                created_time=current_time,
                due_time=None,
                completion_time=None,
                notes=[]
            )
            evidence_tasks.append(task)
        
        if "file_hash" in evidence_types:
            task = InvestigationTask(
                task_id=f"evidence_file_analysis",
                task_name="Analyze file hash evidence",
                description="Analyze file hashes and associated artifacts",
                phase="identification",
                priority=2,
                estimated_duration=90,
                required_skills=["malware_analysis", "file_analysis"],
                required_tools=["sandbox_analysis", "hash_databases"],
                dependencies=[],
                assigned_agent=None,
                status="planned",
                created_time=current_time,
                due_time=None,
                completion_time=None,
                notes=[]
            )
            evidence_tasks.append(task)
        
        if evidence_count > 10:  # Large evidence set
            task = InvestigationTask(
                task_id=f"evidence_correlation_analysis",
                task_name="Comprehensive evidence correlation",
                description="Perform advanced correlation analysis on large evidence set",
                phase="identification",
                priority=3,
                estimated_duration=180,
                required_skills=["data_analysis", "correlation_analysis"],
                required_tools=["analytics_platforms", "correlation_tools"],
                dependencies=[],
                assigned_agent=None,
                status="planned",
                created_time=current_time,
                due_time=None,
                completion_time=None,
                notes=[]
            )
            evidence_tasks.append(task)
        
        return evidence_tasks
    
    def _optimize_task_order(self, tasks: List[InvestigationTask]) -> List[InvestigationTask]:
        """Optimize task execution order based on dependencies and priorities"""
        
        # Sort by priority first, then by phase
        phase_weights = {
            InvestigationPhase.PREPARATION.value: 1,
            InvestigationPhase.IDENTIFICATION.value: 2,
            InvestigationPhase.CONTAINMENT.value: 3,
            InvestigationPhase.ERADICATION.value: 4,
            InvestigationPhase.RECOVERY.value: 5,
            InvestigationPhase.LESSONS_LEARNED.value: 6
        }
        
        return sorted(tasks, key=lambda t: (t.priority, phase_weights.get(t.phase, 999)))
    
    async def _plan_resource_allocation(self, tasks: List[InvestigationTask], 
                                      priority: str) -> List[Dict[str, Any]]:
        """Plan resource allocation for investigation tasks"""
        resource_requirements = []
        
        # Collect required skills and tools
        all_skills = set()
        all_tools = set()
        
        for task in tasks:
            all_skills.update(task.required_skills)
            all_tools.update(task.required_tools)
        
        # Map skills to analysts
        required_analysts = []
        for skill in all_skills:
            for analyst_type, analyst_info in self.resource_catalog["analysts"].items():
                if skill in analyst_info["skills"]:
                    if analyst_type not in [a["resource_id"] for a in required_analysts]:
                        required_analysts.append({
                            "resource_type": "analyst",
                            "resource_id": analyst_type,
                            "skills": analyst_info["skills"],
                            "availability": analyst_info["availability"],
                            "estimated_hours": self._estimate_analyst_hours(analyst_type, tasks)
                        })
        
        # Map tools to requirements
        required_tools = []
        for tool in all_tools:
            for tool_type, tool_info in self.resource_catalog["tools"].items():
                if tool in tool_info["capabilities"]:
                    if tool_type not in [t["resource_id"] for t in required_tools]:
                        required_tools.append({
                            "resource_type": "tool",
                            "resource_id": tool_type,
                            "capabilities": tool_info["capabilities"],
                            "availability": tool_info["availability"],
                            "estimated_usage_hours": self._estimate_tool_hours(tool_type, tasks)
                        })
        
        # Determine external resources
        external_resources = self._determine_external_resources(priority, tasks)
        
        resource_requirements.extend(required_analysts)
        resource_requirements.extend(required_tools)
        resource_requirements.extend(external_resources)
        
        return resource_requirements
    
    def _estimate_analyst_hours(self, analyst_type: str, tasks: List[InvestigationTask]) -> int:
        """Estimate hours required for analyst type"""
        total_hours = 0
        
        analyst_skills = self.resource_catalog["analysts"][analyst_type]["skills"]
        
        for task in tasks:
            # Check if analyst can perform task
            if any(skill in analyst_skills for skill in task.required_skills):
                total_hours += task.estimated_duration / 60  # Convert minutes to hours
        
        return int(total_hours)
    
    def _estimate_tool_hours(self, tool_type: str, tasks: List[InvestigationTask]) -> int:
        """Estimate hours required for tool type"""
        total_hours = 0
        
        tool_capabilities = self.resource_catalog["tools"][tool_type]["capabilities"]
        
        for task in tasks:
            # Check if tool is needed for task
            if any(tool in tool_capabilities for tool in task.required_tools):
                total_hours += task.estimated_duration / 60  # Convert minutes to hours
        
        return int(total_hours)
    
    def _determine_external_resources(self, priority: str, 
                                    tasks: List[InvestigationTask]) -> List[Dict[str, Any]]:
        """Determine if external resources are needed"""
        external_resources = []
        
        # High priority investigations may need external support
        if priority in ["emergency", "high"]:
            # Check for specialized skills
            specialized_skills = ["legal_compliance", "advanced_forensics", "expert_testimony"]
            
            for task in tasks:
                if any(skill in specialized_skills for skill in task.required_skills):
                    if skill == "legal_compliance":
                        external_resources.append({
                            "resource_type": "external",
                            "resource_id": "legal_counsel",
                            "justification": "Legal compliance requirements",
                            "estimated_cost": 2000,  # USD
                            "response_time": "< 4 hours"
                        })
                    elif skill in ["advanced_forensics", "expert_testimony"]:
                        external_resources.append({
                            "resource_type": "external", 
                            "resource_id": "forensic_specialists",
                            "justification": "Advanced forensic analysis required",
                            "estimated_cost": 4000,  # USD
                            "response_time": "< 24 hours"
                        })
        
        return external_resources
    
    async def _create_investigation_timeline(self, tasks: List[InvestigationTask], 
                                           priority: str) -> Dict[str, Any]:
        """Create investigation timeline"""
        
        # Calculate timeline based on priority
        urgency_multipliers = {
            "emergency": 0.5,   # Compress timeline by 50%
            "high": 0.75,       # Compress timeline by 25%
            "medium": 1.0,      # Normal timeline
            "low": 1.5,         # Extend timeline by 50%
            "routine": 2.0      # Extend timeline by 100%
        }
        
        multiplier = urgency_multipliers.get(priority, 1.0)
        
        # Build timeline
        current_time = datetime.now()
        timeline = {
            "start_time": current_time.isoformat(),
            "phases": {},
            "milestones": [],
            "critical_path": []
        }
        
        # Group tasks by phase
        phases = {}
        for task in tasks:
            if task.phase not in phases:
                phases[task.phase] = []
            phases[task.phase].append(task)
        
        # Calculate phase timelines
        phase_start_time = current_time
        
        for phase_name in [p.value for p in InvestigationPhase]:
            if phase_name in phases:
                phase_tasks = phases[phase_name]
                phase_duration = sum(task.estimated_duration for task in phase_tasks) * multiplier
                phase_end_time = phase_start_time + timedelta(minutes=phase_duration)
                
                timeline["phases"][phase_name] = {
                    "start_time": phase_start_time.isoformat(),
                    "end_time": phase_end_time.isoformat(),
                    "duration_minutes": int(phase_duration),
                    "tasks": [task.task_id for task in phase_tasks]
                }
                
                # Add milestone
                timeline["milestones"].append({
                    "name": f"{phase_name.title()} Complete",
                    "time": phase_end_time.isoformat(),
                    "description": f"All {phase_name} tasks completed"
                })
                
                phase_start_time = phase_end_time
        
        # Calculate total duration
        total_duration = sum(task.estimated_duration for task in tasks) * multiplier
        timeline["estimated_completion"] = (current_time + timedelta(minutes=total_duration)).isoformat()
        timeline["total_duration_hours"] = total_duration / 60
        
        return timeline
    
    def _define_success_criteria(self, category: str, strategy: str) -> List[str]:
        """Define success criteria for investigation"""
        
        # Get template success criteria
        template_key = f"{category}_incident"
        if template_key in self.investigation_templates:
            base_criteria = self.investigation_templates[template_key].get("success_criteria", [])
        else:
            base_criteria = ["Incident fully investigated", "All evidence collected and analyzed"]
        
        # Add strategy-specific criteria
        strategy_criteria = {
            InvestigationStrategy.RAPID_RESPONSE.value: [
                "Response time under 4 hours",
                "Immediate threats contained"
            ],
            InvestigationStrategy.CONTAINMENT_FIRST.value: [
                "All affected systems isolated",
                "Threat spread prevented"
            ],
            InvestigationStrategy.FORENSIC_ANALYSIS.value: [
                "Complete forensic timeline established",
                "All digital evidence preserved"
            ],
            InvestigationStrategy.COMPLIANCE_FOCUSED.value: [
                "All regulatory requirements met",
                "Compliance documentation complete"
            ]
        }
        
        additional_criteria = strategy_criteria.get(strategy, [])
        
        return base_criteria + additional_criteria
    
    def _define_escalation_triggers(self, severity: str, strategy: str) -> List[str]:
        """Define escalation triggers for investigation"""
        base_triggers = [
            "Investigation timeline exceeded by 50%",
            "Additional high-severity evidence discovered",
            "Resource constraints preventing progress",
            "Legal or regulatory deadlines approaching"
        ]
        
        # Severity-specific triggers
        if severity in ["critical", "high"]:
            base_triggers.extend([
                "No progress in first 2 hours",
                "Scope expansion beyond initial assessment",
                "External threat actor indicators found"
            ])
        
        # Strategy-specific triggers
        strategy_triggers = {
            InvestigationStrategy.COMPLIANCE_FOCUSED.value: [
                "Data breach notification deadline approaching",
                "Regulatory inquiry received"
            ],
            InvestigationStrategy.FORENSIC_ANALYSIS.value: [
                "Evidence tampering suspected",
                "Chain of custody compromised"
            ]
        }
        
        additional_triggers = strategy_triggers.get(strategy, [])
        
        return base_triggers + additional_triggers
    
    async def _generate_execution_guidance(self, plan: InvestigationPlan) -> Dict[str, Any]:
        """Generate execution guidance for investigation plan"""
        return {
            "execution_strategy": f"Execute tasks following {plan.strategy} approach",
            "parallel_execution": self._identify_parallel_tasks(plan.tasks),
            "critical_decisions": self._identify_critical_decisions(plan),
            "quality_checkpoints": self._define_quality_checkpoints(plan),
            "communication_plan": self._create_communication_plan(plan),
            "risk_mitigation": self._define_risk_mitigation(plan)
        }
    
    def _identify_parallel_tasks(self, tasks: List[InvestigationTask]) -> List[List[str]]:
        """Identify tasks that can be executed in parallel"""
        parallel_groups = []
        
        # Group tasks by phase that have no dependencies on each other
        phases = {}
        for task in tasks:
            if task.phase not in phases:
                phases[task.phase] = []
            phases[task.phase].append(task)
        
        for phase_tasks in phases.values():
            if len(phase_tasks) > 1:
                # Find tasks with no interdependencies
                independent_tasks = []
                for task in phase_tasks:
                    task_deps = set(task.dependencies)
                    phase_task_ids = {t.task_id for t in phase_tasks}
                    
                    # If task has no dependencies within this phase, it can run in parallel
                    if not task_deps.intersection(phase_task_ids):
                        independent_tasks.append(task.task_id)
                
                if len(independent_tasks) > 1:
                    parallel_groups.append(independent_tasks)
        
        return parallel_groups
    
    def _identify_critical_decisions(self, plan: InvestigationPlan) -> List[Dict[str, Any]]:
        """Identify critical decision points in investigation"""
        decisions = [
            {
                "decision_point": "Continue investigation vs escalate",
                "trigger": "After initial assessment phase",
                "criteria": "Evidence complexity and resource requirements",
                "stakeholders": ["incident_commander", "technical_lead"]
            },
            {
                "decision_point": "Involve law enforcement",
                "trigger": "Evidence of criminal activity",
                "criteria": "Legal requirements and business impact",
                "stakeholders": ["legal_counsel", "executive_team"]
            }
        ]
        
        # Strategy-specific decisions
        if plan.strategy == InvestigationStrategy.COMPLIANCE_FOCUSED.value:
            decisions.append({
                "decision_point": "Public disclosure timing",
                "trigger": "Scope assessment complete",
                "criteria": "Regulatory requirements and business impact",
                "stakeholders": ["legal_counsel", "communications_team", "executive_team"]
            })
        
        return decisions
    
    def _define_quality_checkpoints(self, plan: InvestigationPlan) -> List[Dict[str, Any]]:
        """Define quality checkpoints for investigation"""
        return [
            {
                "checkpoint": "Evidence validation",
                "phase": "identification",
                "criteria": "All evidence authenticated and documented",
                "reviewer": "senior_analyst"
            },
            {
                "checkpoint": "Analysis quality review",
                "phase": "identification",
                "criteria": "Analysis methodology and conclusions reviewed",
                "reviewer": "technical_lead"
            },
            {
                "checkpoint": "Documentation completeness",
                "phase": "recovery",
                "criteria": "All investigation activities documented",
                "reviewer": "incident_commander"
            }
        ]
    
    def _create_communication_plan(self, plan: InvestigationPlan) -> Dict[str, Any]:
        """Create communication plan for investigation"""
        update_frequency = {
            "emergency": "Every 30 minutes",
            "high": "Every 2 hours", 
            "medium": "Every 8 hours",
            "low": "Daily",
            "routine": "Weekly"
        }
        
        return {
            "update_frequency": update_frequency.get(plan.priority, "Daily"),
            "stakeholders": {
                "executive_team": ["major_milestones", "escalations"],
                "incident_commander": ["all_updates"],
                "technical_team": ["technical_findings", "resource_needs"],
                "legal_team": ["compliance_matters", "evidence_findings"],
                "communications_team": ["external_disclosure_needs"]
            },
            "escalation_chain": [
                "technical_lead",
                "incident_commander", 
                "security_manager",
                "ciso",
                "executive_team"
            ]
        }
    
    def _define_risk_mitigation(self, plan: InvestigationPlan) -> List[Dict[str, Any]]:
        """Define risk mitigation strategies"""
        return [
            {
                "risk": "Evidence degradation",
                "mitigation": "Immediate evidence preservation and chain of custody",
                "owner": "forensic_investigator"
            },
            {
                "risk": "Resource unavailability",
                "mitigation": "Backup resource identification and cross-training",
                "owner": "incident_commander"
            },
            {
                "risk": "Timeline overrun",
                "mitigation": "Regular progress reviews and scope adjustment",
                "owner": "technical_lead"
            },
            {
                "risk": "Scope creep",
                "mitigation": "Strict change control and impact assessment",
                "owner": "incident_commander"
            }
        ]
    
    async def _assess_investigation_risks(self, plan: InvestigationPlan) -> Dict[str, Any]:
        """Assess risks associated with investigation plan"""
        risks = {
            "timeline_risk": "medium",
            "resource_risk": "low",
            "complexity_risk": "medium",
            "external_dependency_risk": "low"
        }
        
        # Assess timeline risk
        if plan.estimated_duration > 2880:  # > 48 hours
            risks["timeline_risk"] = "high"
        elif plan.estimated_duration > 1440:  # > 24 hours
            risks["timeline_risk"] = "medium"
        
        # Assess resource risk
        external_resources = [r for r in plan.required_resources if r.get("resource_type") == "external"]
        if len(external_resources) > 2:
            risks["external_dependency_risk"] = "high"
        elif len(external_resources) > 0:
            risks["external_dependency_risk"] = "medium"
        
        # Assess complexity risk
        if len(plan.tasks) > 15:
            risks["complexity_risk"] = "high"
        elif len(plan.tasks) > 8:
            risks["complexity_risk"] = "medium"
        
        return risks
    
    async def _check_resource_conflicts(self, resource_requirements: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check for potential resource conflicts"""
        conflicts = []
        
        # Simple conflict detection (in production, this would check actual schedules)
        for resource in resource_requirements:
            if resource.get("resource_type") == "analyst":
                estimated_hours = resource.get("estimated_hours", 0)
                availability = resource.get("availability", "unknown")
                
                if estimated_hours > 16 and availability != "24/7":
                    conflicts.append({
                        "resource": resource["resource_id"],
                        "conflict_type": "availability",
                        "description": f"Resource needs {estimated_hours} hours but limited availability",
                        "recommendation": "Consider additional resources or timeline adjustment"
                    })
        
        return conflicts
    
    def _update_planning_stats(self, strategy: str, planning_time: timedelta):
        """Update planning statistics"""
        self.planning_stats["total_plans_created"] += 1
        
        if strategy not in self.planning_stats["plans_by_strategy"]:
            self.planning_stats["plans_by_strategy"][strategy] = 0
        self.planning_stats["plans_by_strategy"][strategy] += 1
        
        # Update average planning time
        current_avg = self.planning_stats["average_planning_time"]
        total_plans = self.planning_stats["total_plans_created"]
        new_avg = ((current_avg * (total_plans - 1)) + planning_time.total_seconds()) / total_plans
        self.planning_stats["average_planning_time"] = new_avg
    
    async def get_planning_statistics(self) -> Dict[str, Any]:
        """Get investigation planning statistics"""
        return self.planning_stats
    
    async def update_investigation_plan(self, plan_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update existing investigation plan"""
        # In production, this would retrieve and update the stored plan
        return {
            "status": "plan_updated",
            "plan_id": plan_id,
            "updates_applied": list(updates.keys()),
            "updated_time": datetime.now().isoformat()
        }

def create_investigation_planner() -> InvestigationPlanner:
    """Factory function to create investigation planner"""
    return InvestigationPlanner()

# Example usage
async def main():
    planner = create_investigation_planner()
    
    # Example incident data
    sample_incident = {
        "incident_id": "inc_001",
        "category": "malware",
        "severity": "high",
        "evidence_summary": {
            "total_evidence_items": 8,
            "evidence_by_type": {
                "network_traffic": 3,
                "file_hash": 2,
                "process_execution": 3
            }
        }
    }
    
    result = await planner.create_investigation_plan(sample_incident)
    print(f"Investigation plan: {json.dumps(result, indent=2)}")

if __name__ == "__main__":
    asyncio.run(main())
