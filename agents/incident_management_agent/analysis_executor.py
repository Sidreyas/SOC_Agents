"""
Analysis Execution Module
State 4: Analysis Execution and Coordination
Coordinates investigation tasks and analysis activities
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
import json

logger = logging.getLogger(__name__)

class AnalysisType(Enum):
    """Types of analysis that can be performed"""
    MALWARE_ANALYSIS = "malware_analysis"
    NETWORK_ANALYSIS = "network_analysis"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    FORENSIC_ANALYSIS = "forensic_analysis"
    THREAT_HUNTING = "threat_hunting"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    COMPLIANCE_ANALYSIS = "compliance_analysis"
    IMPACT_ANALYSIS = "impact_analysis"

class AnalysisStatus(Enum):
    """Status of analysis tasks"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"

class AnalysisPriority(Enum):
    """Priority levels for analysis tasks"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

@dataclass
class AnalysisTask:
    """Individual analysis task"""
    task_id: str
    analysis_type: str
    priority: str
    description: str
    target_data: Dict[str, Any]
    required_tools: List[str]
    estimated_duration: int  # minutes
    assigned_agent: Optional[str]
    status: str
    created_time: datetime
    started_time: Optional[datetime]
    completed_time: Optional[datetime]
    progress_percentage: int
    results: Dict[str, Any]
    error_message: Optional[str]
    dependencies: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['created_time'] = self.created_time.isoformat()
        if self.started_time:
            result['started_time'] = self.started_time.isoformat()
        if self.completed_time:
            result['completed_time'] = self.completed_time.isoformat()
        return result

class AnalysisExecutor:
    """
    Coordinates and executes analysis tasks for incident investigation
    """
    
    def __init__(self):
        self.active_tasks = {}
        self.completed_tasks = {}
        self.agent_capabilities = self._initialize_agent_capabilities()
        self.tool_integrations = self._initialize_tool_integrations()
        self.analysis_templates = self._initialize_analysis_templates()
        self.execution_stats = {
            "total_tasks_executed": 0,
            "tasks_by_type": {atype.value: 0 for atype in AnalysisType},
            "average_execution_time": 0,
            "success_rate": 0,
            "agent_utilization": {}
        }
    
    def _initialize_agent_capabilities(self) -> Dict[str, Dict[str, Any]]:
        """Initialize capabilities of different SOC agents"""
        return {
            "malware_agent": {
                "analysis_types": [
                    AnalysisType.MALWARE_ANALYSIS.value,
                    AnalysisType.BEHAVIORAL_ANALYSIS.value,
                    AnalysisType.FORENSIC_ANALYSIS.value
                ],
                "tools": [
                    "sandbox_analysis", "static_analysis", "dynamic_analysis",
                    "yara_rules", "hash_databases", "disassemblers"
                ],
                "max_concurrent_tasks": 3,
                "average_response_time": 15  # minutes
            },
            "network_agent": {
                "analysis_types": [
                    AnalysisType.NETWORK_ANALYSIS.value,
                    AnalysisType.THREAT_HUNTING.value,
                    AnalysisType.FORENSIC_ANALYSIS.value
                ],
                "tools": [
                    "wireshark", "network_monitoring", "flow_analysis",
                    "packet_capture", "intrusion_detection"
                ],
                "max_concurrent_tasks": 5,
                "average_response_time": 10
            },
            "phishing_agent": {
                "analysis_types": [
                    AnalysisType.MALWARE_ANALYSIS.value,
                    AnalysisType.BEHAVIORAL_ANALYSIS.value,
                    AnalysisType.FORENSIC_ANALYSIS.value
                ],
                "tools": [
                    "email_analysis", "url_analysis", "attachment_analysis",
                    "reputation_checking", "header_analysis"
                ],
                "max_concurrent_tasks": 4,
                "average_response_time": 8
            },
            "host_stability_agent": {
                "analysis_types": [
                    AnalysisType.FORENSIC_ANALYSIS.value,
                    AnalysisType.VULNERABILITY_ANALYSIS.value,
                    AnalysisType.IMPACT_ANALYSIS.value
                ],
                "tools": [
                    "system_monitoring", "performance_analysis", "log_analysis",
                    "process_monitoring", "resource_tracking"
                ],
                "max_concurrent_tasks": 3,
                "average_response_time": 12
            },
            "powershell_agent": {
                "analysis_types": [
                    AnalysisType.BEHAVIORAL_ANALYSIS.value,
                    AnalysisType.FORENSIC_ANALYSIS.value,
                    AnalysisType.THREAT_HUNTING.value
                ],
                "tools": [
                    "script_analysis", "command_analysis", "behavioral_detection",
                    "powershell_logging", "execution_analysis"
                ],
                "max_concurrent_tasks": 2,
                "average_response_time": 20
            },
            "access_control_agent": {
                "analysis_types": [
                    AnalysisType.COMPLIANCE_ANALYSIS.value,
                    AnalysisType.BEHAVIORAL_ANALYSIS.value,
                    AnalysisType.IMPACT_ANALYSIS.value
                ],
                "tools": [
                    "access_monitoring", "privilege_analysis", "compliance_checking",
                    "audit_trail_analysis", "permission_verification"
                ],
                "max_concurrent_tasks": 3,
                "average_response_time": 15
            },
            "insider_behavior_agent": {
                "analysis_types": [
                    AnalysisType.BEHAVIORAL_ANALYSIS.value,
                    AnalysisType.THREAT_HUNTING.value,
                    AnalysisType.IMPACT_ANALYSIS.value
                ],
                "tools": [
                    "user_behavior_analysis", "anomaly_detection", "pattern_analysis",
                    "data_access_monitoring", "risk_scoring"
                ],
                "max_concurrent_tasks": 2,
                "average_response_time": 25
            },
            "ddos_defense_agent": {
                "analysis_types": [
                    AnalysisType.NETWORK_ANALYSIS.value,
                    AnalysisType.IMPACT_ANALYSIS.value,
                    AnalysisType.THREAT_HUNTING.value
                ],
                "tools": [
                    "traffic_analysis", "attack_pattern_detection", "mitigation_analysis",
                    "capacity_monitoring", "performance_impact"
                ],
                "max_concurrent_tasks": 4,
                "average_response_time": 10
            },
            "login_identity_agent": {
                "analysis_types": [
                    AnalysisType.BEHAVIORAL_ANALYSIS.value,
                    AnalysisType.COMPLIANCE_ANALYSIS.value,
                    AnalysisType.FORENSIC_ANALYSIS.value
                ],
                "tools": [
                    "authentication_analysis", "identity_verification", "session_analysis",
                    "credential_monitoring", "access_pattern_analysis"
                ],
                "max_concurrent_tasks": 3,
                "average_response_time": 12
            }
        }
    
    def _initialize_tool_integrations(self) -> Dict[str, Dict[str, Any]]:
        """Initialize tool integration configurations"""
        return {
            "sandbox_analysis": {
                "type": "malware_analysis",
                "api_endpoint": "https://sandbox.internal/api/v1/analyze",
                "authentication": "api_key",
                "timeout": 1800,  # 30 minutes
                "supported_formats": ["pe", "elf", "pdf", "office", "script"],
                "max_file_size": "100MB"
            },
            "wireshark": {
                "type": "network_analysis",
                "tool_path": "/usr/bin/tshark",
                "timeout": 3600,  # 1 hour
                "supported_formats": ["pcap", "pcapng"],
                "max_capture_size": "1GB"
            },
            "yara_rules": {
                "type": "static_analysis",
                "rules_path": "/opt/yara/rules/",
                "timeout": 300,  # 5 minutes
                "rule_categories": ["malware", "apt", "suspicious", "packer"]
            },
            "vulnerability_scanner": {
                "type": "vulnerability_analysis",
                "api_endpoint": "https://vuln-scanner.internal/api/scan",
                "authentication": "oauth2",
                "timeout": 7200,  # 2 hours
                "scan_types": ["network", "web_app", "database", "config"]
            },
            "siem_platform": {
                "type": "log_analysis",
                "api_endpoint": "https://siem.internal/api/v2/search",
                "authentication": "bearer_token",
                "timeout": 1800,
                "query_languages": ["spl", "kql", "lucene"]
            }
        }
    
    def _initialize_analysis_templates(self) -> Dict[str, Dict[str, Any]]:
        """Initialize analysis templates for different scenarios"""
        return {
            "malware_incident_analysis": {
                "required_analyses": [
                    {
                        "type": AnalysisType.MALWARE_ANALYSIS.value,
                        "priority": AnalysisPriority.CRITICAL.value,
                        "description": "Analyze malware sample characteristics",
                        "estimated_duration": 120,
                        "tools": ["sandbox_analysis", "static_analysis", "yara_rules"]
                    },
                    {
                        "type": AnalysisType.NETWORK_ANALYSIS.value,
                        "priority": AnalysisPriority.HIGH.value,
                        "description": "Analyze network communications",
                        "estimated_duration": 90,
                        "tools": ["wireshark", "network_monitoring"]
                    },
                    {
                        "type": AnalysisType.BEHAVIORAL_ANALYSIS.value,
                        "priority": AnalysisPriority.HIGH.value,
                        "description": "Analyze malware behavior patterns",
                        "estimated_duration": 60,
                        "tools": ["dynamic_analysis", "behavioral_detection"]
                    },
                    {
                        "type": AnalysisType.IMPACT_ANALYSIS.value,
                        "priority": AnalysisPriority.MEDIUM.value,
                        "description": "Assess system and data impact",
                        "estimated_duration": 45,
                        "tools": ["system_monitoring", "data_analysis"]
                    }
                ]
            },
            "network_intrusion_analysis": {
                "required_analyses": [
                    {
                        "type": AnalysisType.NETWORK_ANALYSIS.value,
                        "priority": AnalysisPriority.CRITICAL.value,
                        "description": "Analyze network traffic patterns",
                        "estimated_duration": 180,
                        "tools": ["wireshark", "flow_analysis", "intrusion_detection"]
                    },
                    {
                        "type": AnalysisType.FORENSIC_ANALYSIS.value,
                        "priority": AnalysisPriority.HIGH.value,
                        "description": "Forensic analysis of affected systems",
                        "estimated_duration": 240,
                        "tools": ["forensic_imaging", "artifact_analysis"]
                    },
                    {
                        "type": AnalysisType.VULNERABILITY_ANALYSIS.value,
                        "priority": AnalysisPriority.HIGH.value,
                        "description": "Identify exploited vulnerabilities",
                        "estimated_duration": 120,
                        "tools": ["vulnerability_scanner", "exploit_analysis"]
                    },
                    {
                        "type": AnalysisType.THREAT_HUNTING.value,
                        "priority": AnalysisPriority.MEDIUM.value,
                        "description": "Hunt for additional compromise indicators",
                        "estimated_duration": 180,
                        "tools": ["threat_hunting_platform", "ioc_analysis"]
                    }
                ]
            },
            "phishing_incident_analysis": {
                "required_analyses": [
                    {
                        "type": AnalysisType.MALWARE_ANALYSIS.value,
                        "priority": AnalysisPriority.HIGH.value,
                        "description": "Analyze email attachments and links",
                        "estimated_duration": 60,
                        "tools": ["email_analysis", "url_analysis", "attachment_analysis"]
                    },
                    {
                        "type": AnalysisType.BEHAVIORAL_ANALYSIS.value,
                        "priority": AnalysisPriority.MEDIUM.value,
                        "description": "Analyze user interaction patterns",
                        "estimated_duration": 45,
                        "tools": ["user_behavior_analysis", "click_tracking"]
                    },
                    {
                        "type": AnalysisType.IMPACT_ANALYSIS.value,
                        "priority": AnalysisPriority.MEDIUM.value,
                        "description": "Assess credential compromise impact",
                        "estimated_duration": 30,
                        "tools": ["credential_analysis", "access_monitoring"]
                    }
                ]
            }
        }
    
    async def execute_analysis_plan(self, investigation_plan: Dict[str, Any], 
                                  incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute analysis tasks based on investigation plan
        
        Args:
            investigation_plan: Investigation plan with tasks and requirements
            incident_data: Incident data and evidence for analysis
            
        Returns:
            Analysis execution results
        """
        try:
            execution_start_time = datetime.now()
            
            # Extract analysis requirements from investigation plan
            analysis_tasks = await self._create_analysis_tasks(investigation_plan, incident_data)
            
            # Schedule and execute tasks
            execution_results = await self._execute_tasks_parallel(analysis_tasks)
            
            # Aggregate results
            aggregated_results = await self._aggregate_analysis_results(execution_results)
            
            # Update statistics
            self._update_execution_stats(analysis_tasks, execution_start_time)
            
            logger.info(f"Analysis execution completed with {len(execution_results)} tasks")
            
            return {
                "status": "completed",
                "execution_summary": {
                    "total_tasks": len(analysis_tasks),
                    "completed_tasks": len([r for r in execution_results if r["status"] == "completed"]),
                    "failed_tasks": len([r for r in execution_results if r["status"] == "failed"]),
                    "execution_time": (datetime.now() - execution_start_time).total_seconds() / 60  # minutes
                },
                "task_results": execution_results,
                "aggregated_analysis": aggregated_results,
                "recommendations": await self._generate_analysis_recommendations(aggregated_results)
            }
            
        except Exception as e:
            logger.error(f"Error executing analysis plan: {str(e)}")
            return {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    async def _create_analysis_tasks(self, investigation_plan: Dict[str, Any], 
                                   incident_data: Dict[str, Any]) -> List[AnalysisTask]:
        """Create analysis tasks from investigation plan"""
        
        tasks = []
        plan_tasks = investigation_plan.get("tasks", [])
        incident_category = incident_data.get("classification", {}).get("category", "unknown")
        
        # Get analysis template based on incident category
        template_key = f"{incident_category}_incident_analysis"
        if template_key not in self.analysis_templates:
            template_key = "malware_incident_analysis"  # Default
        
        template = self.analysis_templates[template_key]
        required_analyses = template.get("required_analyses", [])
        
        # Create tasks from template and investigation plan
        task_counter = 1
        
        for analysis_req in required_analyses:
            # Check if investigation plan includes this analysis type
            plan_task = self._find_matching_plan_task(analysis_req, plan_tasks)
            
            if plan_task or analysis_req["priority"] in ["critical", "high"]:
                task = AnalysisTask(
                    task_id=f"analysis_{task_counter:03d}",
                    analysis_type=analysis_req["type"],
                    priority=analysis_req["priority"],
                    description=analysis_req["description"],
                    target_data=await self._extract_target_data(analysis_req, incident_data),
                    required_tools=analysis_req["tools"],
                    estimated_duration=analysis_req["estimated_duration"],
                    assigned_agent=await self._assign_optimal_agent(analysis_req),
                    status=AnalysisStatus.PENDING.value,
                    created_time=datetime.now(),
                    started_time=None,
                    completed_time=None,
                    progress_percentage=0,
                    results={},
                    error_message=None,
                    dependencies=self._determine_task_dependencies(analysis_req, required_analyses)
                )
                
                tasks.append(task)
                task_counter += 1
        
        # Add custom tasks from investigation plan
        for plan_task in plan_tasks:
            if self._is_analysis_task(plan_task):
                custom_task = await self._create_custom_analysis_task(plan_task, incident_data, task_counter)
                if custom_task:
                    tasks.append(custom_task)
                    task_counter += 1
        
        return tasks
    
    def _find_matching_plan_task(self, analysis_req: Dict[str, Any], 
                               plan_tasks: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Find matching task in investigation plan"""
        
        analysis_type = analysis_req["type"]
        
        for task in plan_tasks:
            task_skills = task.get("required_skills", [])
            task_name = task.get("task_name", "").lower()
            
            # Match by analysis type keywords
            if analysis_type in task_name or any(skill in analysis_type for skill in task_skills):
                return task
        
        return None
    
    async def _extract_target_data(self, analysis_req: Dict[str, Any], 
                                 incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract relevant data for analysis task"""
        
        analysis_type = analysis_req["type"]
        alert_data = incident_data.get("alert_data", {})
        
        target_data = {
            "incident_id": incident_data.get("incident_id"),
            "timestamp": incident_data.get("timestamp"),
            "source": incident_data.get("source")
        }
        
        # Type-specific data extraction
        if analysis_type == AnalysisType.MALWARE_ANALYSIS.value:
            target_data.update({
                "file_hashes": alert_data.get("file_hash", []),
                "file_paths": alert_data.get("file_path", []),
                "process_names": alert_data.get("process_name", []),
                "affected_hosts": alert_data.get("affected_hosts", [])
            })
        
        elif analysis_type == AnalysisType.NETWORK_ANALYSIS.value:
            target_data.update({
                "source_ips": alert_data.get("source_ip", []),
                "destination_ips": alert_data.get("destination_ip", []),
                "ports": alert_data.get("port", []),
                "protocols": alert_data.get("protocol", []),
                "network_segments": alert_data.get("network_segment", [])
            })
        
        elif analysis_type == AnalysisType.BEHAVIORAL_ANALYSIS.value:
            target_data.update({
                "user_accounts": alert_data.get("user_account", []),
                "process_commands": alert_data.get("command_line", []),
                "registry_keys": alert_data.get("registry_key", []),
                "file_operations": alert_data.get("file_operation", [])
            })
        
        elif analysis_type == AnalysisType.FORENSIC_ANALYSIS.value:
            target_data.update({
                "affected_systems": alert_data.get("affected_hosts", []),
                "time_range": {
                    "start": incident_data.get("timestamp"),
                    "end": datetime.now().isoformat()
                },
                "evidence_types": alert_data.get("evidence_types", [])
            })
        
        return target_data
    
    async def _assign_optimal_agent(self, analysis_req: Dict[str, Any]) -> Optional[str]:
        """Assign optimal agent for analysis task"""
        
        analysis_type = analysis_req["type"]
        required_tools = set(analysis_req.get("tools", []))
        
        # Find agents capable of performing this analysis
        capable_agents = []
        
        for agent_name, capabilities in self.agent_capabilities.items():
            if analysis_type in capabilities["analysis_types"]:
                # Check tool compatibility
                agent_tools = set(capabilities["tools"])
                tool_overlap = len(required_tools.intersection(agent_tools))
                
                capable_agents.append({
                    "agent": agent_name,
                    "tool_overlap": tool_overlap,
                    "response_time": capabilities["average_response_time"],
                    "max_concurrent": capabilities["max_concurrent_tasks"],
                    "current_load": self._get_agent_current_load(agent_name)
                })
        
        if not capable_agents:
            logger.warning(f"No agents found capable of {analysis_type}")
            return None
        
        # Sort by tool compatibility and availability
        capable_agents.sort(
            key=lambda x: (x["tool_overlap"], -x["current_load"], x["response_time"]),
            reverse=True
        )
        
        best_agent = capable_agents[0]
        
        # Check if agent has capacity
        if best_agent["current_load"] < best_agent["max_concurrent"]:
            return best_agent["agent"]
        
        logger.warning(f"Best agent {best_agent['agent']} at capacity for {analysis_type}")
        return best_agent["agent"]  # Assign anyway, will queue
    
    def _get_agent_current_load(self, agent_name: str) -> int:
        """Get current task load for agent"""
        return len([task for task in self.active_tasks.values() 
                   if task.assigned_agent == agent_name and 
                   task.status == AnalysisStatus.IN_PROGRESS.value])
    
    def _determine_task_dependencies(self, analysis_req: Dict[str, Any], 
                                   all_analyses: List[Dict[str, Any]]) -> List[str]:
        """Determine task dependencies"""
        dependencies = []
        
        analysis_type = analysis_req["type"]
        
        # Define dependency rules
        dependency_rules = {
            AnalysisType.BEHAVIORAL_ANALYSIS.value: [AnalysisType.MALWARE_ANALYSIS.value],
            AnalysisType.IMPACT_ANALYSIS.value: [
                AnalysisType.MALWARE_ANALYSIS.value,
                AnalysisType.NETWORK_ANALYSIS.value
            ],
            AnalysisType.THREAT_HUNTING.value: [
                AnalysisType.NETWORK_ANALYSIS.value,
                AnalysisType.FORENSIC_ANALYSIS.value
            ]
        }
        
        required_deps = dependency_rules.get(analysis_type, [])
        
        # Find dependency tasks in analysis list
        for dep_type in required_deps:
            for analysis in all_analyses:
                if analysis["type"] == dep_type:
                    # Use analysis index as dependency (will be converted to task_id)
                    dep_index = all_analyses.index(analysis) + 1
                    dependencies.append(f"analysis_{dep_index:03d}")
                    break
        
        return dependencies
    
    def _is_analysis_task(self, plan_task: Dict[str, Any]) -> bool:
        """Check if plan task is an analysis task"""
        task_name = plan_task.get("task_name", "").lower()
        task_skills = plan_task.get("required_skills", [])
        
        analysis_keywords = ["analyze", "investigation", "examination", "assessment", "review"]
        
        return (any(keyword in task_name for keyword in analysis_keywords) or
                any(skill in ["malware_analysis", "network_analysis", "forensic_analysis"] 
                    for skill in task_skills))
    
    async def _create_custom_analysis_task(self, plan_task: Dict[str, Any], 
                                         incident_data: Dict[str, Any], 
                                         task_counter: int) -> Optional[AnalysisTask]:
        """Create custom analysis task from investigation plan task"""
        
        # Determine analysis type from task characteristics
        analysis_type = self._determine_analysis_type_from_task(plan_task)
        
        if not analysis_type:
            return None
        
        return AnalysisTask(
            task_id=f"analysis_{task_counter:03d}",
            analysis_type=analysis_type,
            priority=self._map_task_priority(plan_task.get("priority", 3)),
            description=plan_task.get("description", plan_task.get("task_name", "")),
            target_data=await self._extract_target_data({"type": analysis_type}, incident_data),
            required_tools=plan_task.get("required_tools", []),
            estimated_duration=plan_task.get("estimated_duration", 60),
            assigned_agent=await self._assign_optimal_agent({"type": analysis_type, "tools": plan_task.get("required_tools", [])}),
            status=AnalysisStatus.PENDING.value,
            created_time=datetime.now(),
            started_time=None,
            completed_time=None,
            progress_percentage=0,
            results={},
            error_message=None,
            dependencies=[]
        )
    
    def _determine_analysis_type_from_task(self, plan_task: Dict[str, Any]) -> Optional[str]:
        """Determine analysis type from plan task"""
        
        task_name = plan_task.get("task_name", "").lower()
        task_skills = plan_task.get("required_skills", [])
        
        # Keyword mapping to analysis types
        type_keywords = {
            AnalysisType.MALWARE_ANALYSIS.value: ["malware", "virus", "trojan", "ransomware"],
            AnalysisType.NETWORK_ANALYSIS.value: ["network", "traffic", "packet", "connection"],
            AnalysisType.BEHAVIORAL_ANALYSIS.value: ["behavior", "pattern", "anomaly", "activity"],
            AnalysisType.FORENSIC_ANALYSIS.value: ["forensic", "evidence", "artifact", "investigation"],
            AnalysisType.VULNERABILITY_ANALYSIS.value: ["vulnerability", "exploit", "patch", "weakness"],
            AnalysisType.COMPLIANCE_ANALYSIS.value: ["compliance", "regulation", "policy", "audit"]
        }
        
        # Check task name and skills for type indicators
        for analysis_type, keywords in type_keywords.items():
            if (any(keyword in task_name for keyword in keywords) or
                any(keyword in skill.lower() for skill in task_skills for keyword in keywords)):
                return analysis_type
        
        # Default to forensic analysis for unknown types
        return AnalysisType.FORENSIC_ANALYSIS.value
    
    def _map_task_priority(self, plan_priority: int) -> str:
        """Map plan task priority to analysis priority"""
        if plan_priority == 1:
            return AnalysisPriority.CRITICAL.value
        elif plan_priority == 2:
            return AnalysisPriority.HIGH.value
        elif plan_priority == 3:
            return AnalysisPriority.MEDIUM.value
        else:
            return AnalysisPriority.LOW.value
    
    async def _execute_tasks_parallel(self, analysis_tasks: List[AnalysisTask]) -> List[Dict[str, Any]]:
        """Execute analysis tasks with parallel processing and dependency management"""
        
        results = []
        completed_tasks = set()
        
        # Create task lookup
        task_lookup = {task.task_id: task for task in analysis_tasks}
        
        # Execute tasks in dependency order
        while len(completed_tasks) < len(analysis_tasks):
            # Find tasks ready to execute (dependencies satisfied)
            ready_tasks = []
            
            for task in analysis_tasks:
                if (task.task_id not in completed_tasks and 
                    task.status == AnalysisStatus.PENDING.value and
                    all(dep in completed_tasks for dep in task.dependencies)):
                    ready_tasks.append(task)
            
            if not ready_tasks:
                # Handle circular dependencies or blocking issues
                logger.warning("No ready tasks found, executing remaining tasks anyway")
                ready_tasks = [task for task in analysis_tasks 
                             if task.task_id not in completed_tasks]
            
            # Execute ready tasks in parallel (limited by agent capacity)
            batch_results = await self._execute_task_batch(ready_tasks[:5])  # Max 5 parallel
            
            # Process results
            for result in batch_results:
                results.append(result)
                completed_tasks.add(result["task_id"])
                
                # Update task status
                if result["task_id"] in task_lookup:
                    task = task_lookup[result["task_id"]]
                    task.status = result["status"]
                    task.results = result.get("analysis_results", {})
                    if result["status"] == AnalysisStatus.COMPLETED.value:
                        task.completed_time = datetime.now()
                        task.progress_percentage = 100
            
            # Small delay between batches
            if len(completed_tasks) < len(analysis_tasks):
                await asyncio.sleep(1)
        
        return results
    
    async def _execute_task_batch(self, tasks: List[AnalysisTask]) -> List[Dict[str, Any]]:
        """Execute a batch of analysis tasks in parallel"""
        
        # Create coroutines for each task
        task_coroutines = []
        for task in tasks:
            task.status = AnalysisStatus.IN_PROGRESS.value
            task.started_time = datetime.now()
            self.active_tasks[task.task_id] = task
            
            coroutine = self._execute_single_task(task)
            task_coroutines.append(coroutine)
        
        # Execute tasks in parallel
        batch_results = await asyncio.gather(*task_coroutines, return_exceptions=True)
        
        # Process results and handle exceptions
        processed_results = []
        for i, result in enumerate(batch_results):
            task = tasks[i]
            
            if isinstance(result, Exception):
                logger.error(f"Task {task.task_id} failed with exception: {str(result)}")
                processed_result = {
                    "task_id": task.task_id,
                    "status": AnalysisStatus.FAILED.value,
                    "error": str(result),
                    "execution_time": 0
                }
            else:
                processed_result = result
            
            processed_results.append(processed_result)
            
            # Move from active to completed
            if task.task_id in self.active_tasks:
                del self.active_tasks[task.task_id]
            self.completed_tasks[task.task_id] = task
        
        return processed_results
    
    async def _execute_single_task(self, task: AnalysisTask) -> Dict[str, Any]:
        """Execute a single analysis task"""
        
        execution_start = datetime.now()
        
        try:
            logger.info(f"Executing analysis task {task.task_id}: {task.description}")
            
            # Route to appropriate analysis handler
            if task.assigned_agent:
                analysis_results = await self._delegate_to_agent(task)
            else:
                analysis_results = await self._execute_internal_analysis(task)
            
            execution_time = (datetime.now() - execution_start).total_seconds() / 60
            
            return {
                "task_id": task.task_id,
                "status": AnalysisStatus.COMPLETED.value,
                "analysis_type": task.analysis_type,
                "execution_time": execution_time,
                "analysis_results": analysis_results,
                "assigned_agent": task.assigned_agent,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error executing task {task.task_id}: {str(e)}")
            
            execution_time = (datetime.now() - execution_start).total_seconds() / 60
            
            return {
                "task_id": task.task_id,
                "status": AnalysisStatus.FAILED.value,
                "error": str(e),
                "execution_time": execution_time,
                "timestamp": datetime.now().isoformat()
            }
    
    async def _delegate_to_agent(self, task: AnalysisTask) -> Dict[str, Any]:
        """Delegate analysis task to appropriate SOC agent"""
        
        agent_name = task.assigned_agent
        
        # Simulate agent delegation (in production, this would make actual API calls)
        logger.info(f"Delegating {task.analysis_type} to {agent_name}")
        
        # Simulate processing time
        await asyncio.sleep(min(task.estimated_duration / 60, 5))  # Max 5 seconds for demo
        
        # Generate realistic analysis results based on task type
        return await self._generate_analysis_results(task)
    
    async def _execute_internal_analysis(self, task: AnalysisTask) -> Dict[str, Any]:
        """Execute analysis internally when no agent is available"""
        
        logger.info(f"Executing {task.analysis_type} internally")
        
        # Simulate internal analysis
        await asyncio.sleep(2)  # Simulate processing time
        
        return await self._generate_analysis_results(task)
    
    async def _generate_analysis_results(self, task: AnalysisTask) -> Dict[str, Any]:
        """Generate realistic analysis results based on task type"""
        
        analysis_type = task.analysis_type
        target_data = task.target_data
        
        if analysis_type == AnalysisType.MALWARE_ANALYSIS.value:
            return {
                "malware_family": "TrojanGeneric",
                "threat_level": "high",
                "file_analysis": {
                    "file_type": "PE32 executable",
                    "packed": True,
                    "digital_signature": "unsigned",
                    "compilation_timestamp": "2024-01-15 10:30:00"
                },
                "behavioral_indicators": [
                    "Network communication to suspicious domains",
                    "Registry modifications detected",
                    "File system changes observed"
                ],
                "iocs": [
                    {"type": "hash", "value": "a1b2c3d4e5f6..."},
                    {"type": "domain", "value": "malicious.example.com"},
                    {"type": "ip", "value": "192.168.100.50"}
                ],
                "confidence": 0.85,
                "analysis_tools_used": task.required_tools
            }
        
        elif analysis_type == AnalysisType.NETWORK_ANALYSIS.value:
            return {
                "traffic_analysis": {
                    "total_connections": 1247,
                    "suspicious_connections": 12,
                    "protocols_detected": ["HTTPS", "DNS", "SMTP"],
                    "peak_traffic_time": "2024-01-15 14:30:00"
                },
                "anomalies_detected": [
                    "Unusual outbound traffic volume",
                    "Communication to known bad IPs",
                    "Non-standard port usage"
                ],
                "threat_indicators": [
                    {"type": "ip", "value": "10.0.0.50", "reputation": "malicious"},
                    {"type": "domain", "value": "c2-server.example.com", "category": "c2"}
                ],
                "bandwidth_impact": "medium",
                "affected_hosts": target_data.get("affected_hosts", ["unknown"]),
                "confidence": 0.78
            }
        
        elif analysis_type == AnalysisType.BEHAVIORAL_ANALYSIS.value:
            return {
                "behavior_patterns": [
                    "Unusual login times detected",
                    "Access to sensitive files outside normal pattern",
                    "Elevated privilege usage"
                ],
                "anomaly_score": 7.2,
                "user_risk_factors": [
                    "Recent password reset",
                    "VPN access from new location",
                    "Multiple failed authentication attempts"
                ],
                "timeline": [
                    {"time": "2024-01-15 09:00:00", "action": "Login from new IP"},
                    {"time": "2024-01-15 09:15:00", "action": "Accessed sensitive database"},
                    {"time": "2024-01-15 09:30:00", "action": "Downloaded large file"}
                ],
                "confidence": 0.72
            }
        
        elif analysis_type == AnalysisType.FORENSIC_ANALYSIS.value:
            return {
                "artifacts_collected": [
                    "System logs", "Registry hives", "Browser history",
                    "Network connections", "Process memory dumps"
                ],
                "timeline_reconstruction": [
                    {"timestamp": "2024-01-15 08:45:00", "event": "Initial compromise"},
                    {"timestamp": "2024-01-15 09:00:00", "event": "Lateral movement"},
                    {"timestamp": "2024-01-15 09:30:00", "event": "Data access"}
                ],
                "evidence_integrity": "maintained",
                "chain_of_custody": "documented",
                "key_findings": [
                    "Evidence of unauthorized access",
                    "Data exfiltration attempt detected",
                    "System configuration changes"
                ],
                "confidence": 0.90
            }
        
        elif analysis_type == AnalysisType.VULNERABILITY_ANALYSIS.value:
            return {
                "vulnerabilities_found": [
                    {"cve": "CVE-2024-0001", "severity": "critical", "exploited": True},
                    {"cve": "CVE-2024-0002", "severity": "high", "exploited": False}
                ],
                "attack_vectors": [
                    "Remote code execution via web application",
                    "Privilege escalation through service misconfiguration"
                ],
                "patch_status": {
                    "missing_patches": 5,
                    "outdated_software": ["Apache 2.4.41", "OpenSSL 1.1.1k"]
                },
                "remediation_priority": "immediate",
                "confidence": 0.88
            }
        
        elif analysis_type == AnalysisType.IMPACT_ANALYSIS.value:
            return {
                "business_impact": {
                    "affected_systems": len(target_data.get("affected_hosts", [])),
                    "data_sensitivity": "high",
                    "operational_impact": "medium",
                    "financial_impact": "low"
                },
                "scope_assessment": {
                    "containment_status": "partial",
                    "spread_potential": "medium",
                    "recovery_time_estimate": "4-8 hours"
                },
                "stakeholder_impact": [
                    "IT operations team",
                    "Business users",
                    "Compliance team"
                ],
                "confidence": 0.75
            }
        
        else:
            # Generic analysis results
            return {
                "analysis_completed": True,
                "findings": ["Analysis completed successfully"],
                "confidence": 0.60,
                "tools_used": task.required_tools
            }
    
    async def _aggregate_analysis_results(self, execution_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate results from all analysis tasks"""
        
        completed_analyses = [r for r in execution_results if r["status"] == "completed"]
        failed_analyses = [r for r in execution_results if r["status"] == "failed"]
        
        # Aggregate findings by type
        aggregated_findings = {
            "threat_indicators": [],
            "vulnerabilities": [],
            "behavioral_anomalies": [],
            "network_anomalies": [],
            "forensic_evidence": [],
            "impact_assessment": {}
        }
        
        # Extract and categorize findings
        for result in completed_analyses:
            analysis_results = result.get("analysis_results", {})
            analysis_type = result.get("analysis_type")
            
            if analysis_type == AnalysisType.MALWARE_ANALYSIS.value:
                iocs = analysis_results.get("iocs", [])
                aggregated_findings["threat_indicators"].extend(iocs)
                
            elif analysis_type == AnalysisType.NETWORK_ANALYSIS.value:
                threat_indicators = analysis_results.get("threat_indicators", [])
                aggregated_findings["threat_indicators"].extend(threat_indicators)
                
                anomalies = analysis_results.get("anomalies_detected", [])
                aggregated_findings["network_anomalies"].extend(anomalies)
                
            elif analysis_type == AnalysisType.BEHAVIORAL_ANALYSIS.value:
                patterns = analysis_results.get("behavior_patterns", [])
                aggregated_findings["behavioral_anomalies"].extend(patterns)
                
            elif analysis_type == AnalysisType.VULNERABILITY_ANALYSIS.value:
                vulns = analysis_results.get("vulnerabilities_found", [])
                aggregated_findings["vulnerabilities"].extend(vulns)
                
            elif analysis_type == AnalysisType.FORENSIC_ANALYSIS.value:
                findings = analysis_results.get("key_findings", [])
                aggregated_findings["forensic_evidence"].extend(findings)
                
            elif analysis_type == AnalysisType.IMPACT_ANALYSIS.value:
                impact = analysis_results.get("business_impact", {})
                aggregated_findings["impact_assessment"] = impact
        
        # Calculate overall confidence and risk scores
        confidence_scores = [r.get("analysis_results", {}).get("confidence", 0.5) 
                           for r in completed_analyses]
        overall_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.5
        
        # Generate comprehensive summary
        return {
            "analysis_summary": {
                "total_analyses": len(execution_results),
                "successful_analyses": len(completed_analyses),
                "failed_analyses": len(failed_analyses),
                "overall_confidence": overall_confidence,
                "analysis_duration": sum(r.get("execution_time", 0) for r in execution_results)
            },
            "aggregated_findings": aggregated_findings,
            "threat_assessment": await self._generate_threat_assessment(aggregated_findings),
            "risk_score": await self._calculate_risk_score(aggregated_findings),
            "key_recommendations": await self._generate_key_recommendations(aggregated_findings),
            "analysis_timestamp": datetime.now().isoformat()
        }
    
    async def _generate_threat_assessment(self, findings: Dict[str, Any]) -> Dict[str, Any]:
        """Generate threat assessment from aggregated findings"""
        
        threat_indicators = findings.get("threat_indicators", [])
        vulnerabilities = findings.get("vulnerabilities", [])
        behavioral_anomalies = findings.get("behavioral_anomalies", [])
        
        # Calculate threat level
        threat_score = 0
        
        # Weight different types of findings
        threat_score += len(threat_indicators) * 2
        threat_score += len([v for v in vulnerabilities if v.get("exploited", False)]) * 3
        threat_score += len(behavioral_anomalies) * 1
        
        if threat_score >= 10:
            threat_level = "critical"
        elif threat_score >= 6:
            threat_level = "high"
        elif threat_score >= 3:
            threat_level = "medium"
        else:
            threat_level = "low"
        
        return {
            "threat_level": threat_level,
            "threat_score": threat_score,
            "primary_threats": [
                "Malware infection confirmed",
                "Network compromise detected",
                "Data access anomalies identified"
            ][:len(threat_indicators)],
            "attack_sophistication": "medium",
            "threat_persistence": "likely",
            "lateral_movement_risk": "medium"
        }
    
    async def _calculate_risk_score(self, findings: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate comprehensive risk score"""
        
        # Base risk calculation
        base_risk = 30  # Baseline risk
        
        # Add risk for each finding type
        threat_indicators = len(findings.get("threat_indicators", []))
        vulnerabilities = len(findings.get("vulnerabilities", []))
        behavioral_anomalies = len(findings.get("behavioral_anomalies", []))
        network_anomalies = len(findings.get("network_anomalies", []))
        
        risk_additions = {
            "threat_indicators": threat_indicators * 15,
            "vulnerabilities": vulnerabilities * 10,
            "behavioral_anomalies": behavioral_anomalies * 8,
            "network_anomalies": network_anomalies * 5
        }
        
        total_risk = base_risk + sum(risk_additions.values())
        
        # Cap at 100
        total_risk = min(total_risk, 100)
        
        # Determine risk category
        if total_risk >= 80:
            risk_category = "critical"
        elif total_risk >= 60:
            risk_category = "high"
        elif total_risk >= 40:
            risk_category = "medium"
        else:
            risk_category = "low"
        
        return {
            "total_risk_score": total_risk,
            "risk_category": risk_category,
            "risk_factors": risk_additions,
            "risk_trend": "increasing",
            "mitigation_urgency": "immediate" if total_risk >= 70 else "standard"
        }
    
    async def _generate_key_recommendations(self, findings: Dict[str, Any]) -> List[str]:
        """Generate key recommendations based on findings"""
        
        recommendations = []
        
        # Threat-based recommendations
        if findings.get("threat_indicators"):
            recommendations.append("Implement threat indicator blocking")
            recommendations.append("Conduct threat hunting for similar indicators")
        
        # Vulnerability-based recommendations
        if findings.get("vulnerabilities"):
            recommendations.append("Prioritize patching of identified vulnerabilities")
            recommendations.append("Review and update vulnerability management process")
        
        # Behavioral anomaly recommendations
        if findings.get("behavioral_anomalies"):
            recommendations.append("Enhance user behavior monitoring")
            recommendations.append("Conduct additional user training")
        
        # Network anomaly recommendations
        if findings.get("network_anomalies"):
            recommendations.append("Strengthen network segmentation")
            recommendations.append("Implement additional network monitoring")
        
        # General recommendations
        recommendations.extend([
            "Update security policies and procedures",
            "Conduct post-incident review and lessons learned",
            "Enhance detection and response capabilities"
        ])
        
        return recommendations[:10]  # Limit to top 10
    
    async def _generate_analysis_recommendations(self, aggregated_results: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on analysis execution"""
        
        recommendations = []
        
        analysis_summary = aggregated_results.get("analysis_summary", {})
        threat_assessment = aggregated_results.get("threat_assessment", {})
        risk_score = aggregated_results.get("risk_score", {})
        
        # Recommendations based on threat level
        threat_level = threat_assessment.get("threat_level", "low")
        
        if threat_level in ["critical", "high"]:
            recommendations.extend([
                "Immediate containment actions required",
                "Escalate to senior incident response team",
                "Consider involving external security experts"
            ])
        
        # Recommendations based on risk score
        risk_category = risk_score.get("risk_category", "low")
        
        if risk_category in ["critical", "high"]:
            recommendations.extend([
                "Implement emergency response procedures",
                "Notify executive leadership",
                "Prepare for potential business disruption"
            ])
        
        # Analysis-specific recommendations
        failed_analyses = analysis_summary.get("failed_analyses", 0)
        if failed_analyses > 0:
            recommendations.append(f"Retry {failed_analyses} failed analysis tasks")
        
        confidence = analysis_summary.get("overall_confidence", 0.5)
        if confidence < 0.7:
            recommendations.append("Conduct additional analysis to increase confidence")
        
        return recommendations
    
    def _update_execution_stats(self, analysis_tasks: List[AnalysisTask], start_time: datetime):
        """Update execution statistics"""
        
        self.execution_stats["total_tasks_executed"] += len(analysis_tasks)
        
        # Update by type
        for task in analysis_tasks:
            self.execution_stats["tasks_by_type"][task.analysis_type] += 1
        
        # Update execution time
        execution_time = (datetime.now() - start_time).total_seconds() / 60
        current_avg = self.execution_stats["average_execution_time"]
        total_tasks = self.execution_stats["total_tasks_executed"]
        
        new_avg = ((current_avg * (total_tasks - len(analysis_tasks))) + execution_time) / total_tasks
        self.execution_stats["average_execution_time"] = new_avg
        
        # Update success rate
        completed_tasks = len([t for t in analysis_tasks if t.status == AnalysisStatus.COMPLETED.value])
        success_rate = completed_tasks / len(analysis_tasks) if analysis_tasks else 0
        self.execution_stats["success_rate"] = success_rate
    
    async def get_execution_statistics(self) -> Dict[str, Any]:
        """Get analysis execution statistics"""
        
        return {
            "execution_stats": self.execution_stats,
            "active_tasks": len(self.active_tasks),
            "completed_tasks": len(self.completed_tasks),
            "agent_capabilities": {agent: caps["analysis_types"] 
                                 for agent, caps in self.agent_capabilities.items()},
            "supported_analysis_types": [atype.value for atype in AnalysisType]
        }

def create_analysis_executor() -> AnalysisExecutor:
    """Factory function to create analysis executor"""
    return AnalysisExecutor()

# Example usage
async def main():
    executor = create_analysis_executor()
    
    # Example investigation plan
    sample_plan = {
        "plan_id": "plan_001",
        "incident_id": "inc_001",
        "strategy": "containment_first",
        "tasks": [
            {
                "task_id": "task_001",
                "task_name": "Analyze malware sample",
                "required_skills": ["malware_analysis"],
                "required_tools": ["sandbox_analysis"],
                "estimated_duration": 120,
                "priority": 1
            }
        ]
    }
    
    # Example incident data
    sample_incident = {
        "incident_id": "inc_001",
        "classification": {"category": "malware", "severity": "high"},
        "alert_data": {
            "file_hash": "a1b2c3d4e5f6...",
            "affected_hosts": ["DESKTOP-001"],
            "source_ip": "192.168.1.100"
        }
    }
    
    # Execute analysis
    result = await executor.execute_analysis_plan(sample_plan, sample_incident)
    print(f"Analysis execution result: {json.dumps(result, indent=2)}")

if __name__ == "__main__":
    asyncio.run(main())
