"""
Coordination Manager Module
Handles agent coordination, workflow orchestration, and result aggregation
Implements the Master Orchestrator pattern with multi-agent coordination
"""

import logging
import asyncio
import json
from typing import Dict, Any, Optional, List, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import uuid

from .incident_classifier import ClassificationResult, AgentType, SentinelIncident, MITRETactic
from .routing_engine import RoutingEngine, RoutingResult

logger = logging.getLogger(__name__)

class WorkflowStatus(Enum):
    INITIALIZING = "initializing"
    CLASSIFYING = "classifying"
    ROUTING = "routing"
    PROCESSING = "processing"
    COORDINATING = "coordinating"
    AGGREGATING = "aggregating"
    COMPLETED = "completed"
    ESCALATED = "escalated"
    FAILED = "failed"

class CoordinationMode(Enum):
    SINGLE_AGENT = "single_agent"
    PARALLEL_AGENTS = "parallel_agents"
    SEQUENTIAL_AGENTS = "sequential_agents"
    HIERARCHICAL_REVIEW = "hierarchical_review"

@dataclass
class AgentResult:
    """Result from individual agent processing"""
    agent_type: AgentType
    agent_instance_id: str
    incident_id: str
    success: bool
    confidence_score: float
    findings: Dict[str, Any]
    recommendations: List[str]
    mitre_tactics: List[MITRETactic]
    processing_time: float
    errors: List[str] = field(default_factory=list)
    requires_followup: bool = False
    followup_agents: List[AgentType] = field(default_factory=list)

@dataclass
class WorkflowContext:
    """Context for workflow execution"""
    incident_id: str
    incident: SentinelIncident
    coordination_mode: CoordinationMode
    required_agents: List[AgentType]
    completed_agents: Set[AgentType] = field(default_factory=set)
    agent_results: Dict[AgentType, AgentResult] = field(default_factory=dict)
    escalation_reasons: List[str] = field(default_factory=list)
    human_review_required: bool = False

@dataclass
class AggregatedResult:
    """Final aggregated result from multiple agents"""
    incident_id: str
    overall_confidence: float
    primary_threat_assessment: str
    mitre_tactics: List[MITRETactic]
    consolidated_findings: Dict[str, Any]
    recommended_actions: List[str]
    agent_contributions: Dict[AgentType, float]  # Confidence weights
    requires_human_review: bool
    escalation_level: str
    processing_summary: Dict[str, Any]

class CoordinationManager:
    """
    Manages multi-agent coordination and workflow orchestration
    Implements accuracy-first coordination with conservative decision making
    """
    
    def __init__(self, routing_engine: RoutingEngine):
        self.routing_engine = routing_engine
        self.active_workflows: Dict[str, WorkflowContext] = {}
        self.coordination_rules: Dict[str, Dict] = {}
        self.accuracy_threshold = 0.85
        self.consensus_threshold = 0.70
        
        # Initialize coordination rules
        self._initialize_coordination_rules()
    
    async def orchestrate_incident(self, incident: SentinelIncident, 
                                 classification: ClassificationResult) -> AggregatedResult:
        """
        Main orchestration method - coordinates entire incident processing
        Returns aggregated result from all involved agents
        """
        logger.info(f"Starting orchestration for incident {incident.incident_id}")
        
        # Determine coordination mode
        coordination_mode = self._determine_coordination_mode(incident, classification)
        
        # Create workflow context
        context = WorkflowContext(
            incident_id=incident.incident_id,
            incident=incident,
            coordination_mode=coordination_mode,
            required_agents=self._get_required_agents(classification, coordination_mode)
        )
        
        self.active_workflows[incident.incident_id] = context
        
        try:
            # Execute coordination based on mode
            if coordination_mode == CoordinationMode.SINGLE_AGENT:
                result = await self._single_agent_processing(context, classification)
            elif coordination_mode == CoordinationMode.PARALLEL_AGENTS:
                result = await self._parallel_agent_processing(context, classification)
            elif coordination_mode == CoordinationMode.SEQUENTIAL_AGENTS:
                result = await self._sequential_agent_processing(context, classification)
            elif coordination_mode == CoordinationMode.HIERARCHICAL_REVIEW:
                result = await self._hierarchical_review_processing(context, classification)
            else:
                raise ValueError(f"Unknown coordination mode: {coordination_mode}")
            
            logger.info(f"Completed orchestration for incident {incident.incident_id}")
            return result
            
        except Exception as e:
            logger.error(f"Orchestration failed for incident {incident.incident_id}: {e}")
            
            # Create fallback result
            return AggregatedResult(
                incident_id=incident.incident_id,
                overall_confidence=0.0,
                primary_threat_assessment="Processing failed - requires manual review",
                mitre_tactics=classification.mitre_tactics,
                consolidated_findings={"error": str(e)},
                recommended_actions=["Manual investigation required"],
                agent_contributions={},
                requires_human_review=True,
                escalation_level="Critical",
                processing_summary={"status": "failed", "error": str(e)}
            )
        
        finally:
            # Clean up workflow context
            if incident.incident_id in self.active_workflows:
                del self.active_workflows[incident.incident_id]
    
    async def _single_agent_processing(self, context: WorkflowContext, 
                                     classification: ClassificationResult) -> AggregatedResult:
        """Process incident with single agent"""
        logger.info(f"Single agent processing for {context.incident_id}")
        
        primary_agent = classification.assigned_agent
        
        # Route to primary agent
        routing_result = await self.routing_engine.route_incident(
            context.incident, classification
        )
        
        # Simulate agent processing (replace with actual agent call)
        agent_result = await self._simulate_agent_processing(
            primary_agent, context.incident, routing_result
        )
        
        context.agent_results[primary_agent] = agent_result
        context.completed_agents.add(primary_agent)
        
        # Check if additional agents needed based on result
        if agent_result.requires_followup and agent_result.confidence_score < self.accuracy_threshold:
            logger.info(f"Primary agent confidence low ({agent_result.confidence_score:.2f}), adding followup agents")
            
            # Add followup agents for parallel processing
            for followup_agent in agent_result.followup_agents:
                if followup_agent not in context.completed_agents:
                    followup_routing = await self.routing_engine.route_incident(
                        context.incident, classification
                    )
                    followup_result = await self._simulate_agent_processing(
                        followup_agent, context.incident, followup_routing
                    )
                    context.agent_results[followup_agent] = followup_result
                    context.completed_agents.add(followup_agent)
        
        # Aggregate results
        return await self._aggregate_results(context)
    
    async def _parallel_agent_processing(self, context: WorkflowContext, 
                                       classification: ClassificationResult) -> AggregatedResult:
        """Process incident with multiple agents in parallel"""
        logger.info(f"Parallel agent processing for {context.incident_id} with {len(context.required_agents)} agents")
        
        # Create routing tasks for all required agents
        routing_tasks = []
        for agent_type in context.required_agents:
            agent_classification = self._create_agent_classification(agent_type, classification)
            task = self.routing_engine.route_incident(context.incident, agent_classification)
            routing_tasks.append((agent_type, task))
        
        # Execute all agents in parallel
        agent_tasks = []
        for agent_type, routing_task in routing_tasks:
            routing_result = await routing_task
            agent_task = self._simulate_agent_processing(
                agent_type, context.incident, routing_result
            )
            agent_tasks.append((agent_type, agent_task))
        
        # Wait for all agents to complete
        for agent_type, agent_task in agent_tasks:
            try:
                agent_result = await agent_task
                context.agent_results[agent_type] = agent_result
                context.completed_agents.add(agent_type)
            except Exception as e:
                logger.error(f"Agent {agent_type} failed: {e}")
                context.escalation_reasons.append(f"Agent {agent_type} processing failed: {e}")
        
        # Check if we have enough successful results
        if len(context.completed_agents) < len(context.required_agents) / 2:
            context.human_review_required = True
            context.escalation_reasons.append("Insufficient agent results for reliable analysis")
        
        return await self._aggregate_results(context)
    
    async def _sequential_agent_processing(self, context: WorkflowContext, 
                                         classification: ClassificationResult) -> AggregatedResult:
        """Process incident with agents in sequence"""
        logger.info(f"Sequential agent processing for {context.incident_id}")
        
        previous_result = None
        
        for agent_type in context.required_agents:
            logger.info(f"Processing with agent {agent_type}")
            
            # Create classification for this agent (potentially enhanced by previous results)
            agent_classification = self._create_enhanced_classification(
                agent_type, classification, previous_result
            )
            
            # Route and process
            routing_result = await self.routing_engine.route_incident(
                context.incident, agent_classification
            )
            
            agent_result = await self._simulate_agent_processing(
                agent_type, context.incident, routing_result
            )
            
            context.agent_results[agent_type] = agent_result
            context.completed_agents.add(agent_type)
            previous_result = agent_result
            
            # Check if we can stop early with high confidence
            if (agent_result.confidence_score >= 0.95 and 
                not agent_result.requires_followup and
                len(agent_result.errors) == 0):
                logger.info(f"High confidence result from {agent_type}, stopping sequence early")
                break
            
            # Check if we need to escalate
            if agent_result.confidence_score < 0.50:
                logger.warning(f"Low confidence from {agent_type}, may need escalation")
                context.escalation_reasons.append(f"Low confidence from {agent_type}: {agent_result.confidence_score:.2f}")
        
        return await self._aggregate_results(context)
    
    async def _hierarchical_review_processing(self, context: WorkflowContext, 
                                            classification: ClassificationResult) -> AggregatedResult:
        """Process with hierarchical review pattern"""
        logger.info(f"Hierarchical review processing for {context.incident_id}")
        
        # Level 1: Primary specialized agent
        primary_agent = classification.assigned_agent
        routing_result = await self.routing_engine.route_incident(
            context.incident, classification
        )
        
        primary_result = await self._simulate_agent_processing(
            primary_agent, context.incident, routing_result
        )
        
        context.agent_results[primary_agent] = primary_result
        context.completed_agents.add(primary_agent)
        
        # Level 2: Secondary review if confidence is borderline
        if 0.60 <= primary_result.confidence_score < 0.85:
            logger.info("Primary result requires secondary review")
            
            secondary_agents = self._get_secondary_review_agents(primary_agent, classification)
            
            for secondary_agent in secondary_agents:
                secondary_routing = await self.routing_engine.route_incident(
                    context.incident, classification
                )
                secondary_result = await self._simulate_agent_processing(
                    secondary_agent, context.incident, secondary_routing
                )
                context.agent_results[secondary_agent] = secondary_result
                context.completed_agents.add(secondary_agent)
        
        # Level 3: Tertiary expert review if still uncertain
        overall_confidence = self._calculate_overall_confidence(context)
        if overall_confidence < 0.75:
            logger.info("Results require tertiary expert review")
            context.human_review_required = True
            context.escalation_reasons.append(f"Low overall confidence: {overall_confidence:.2f}")
        
        return await self._aggregate_results(context)
    
    async def _aggregate_results(self, context: WorkflowContext) -> AggregatedResult:
        """Aggregate results from all completed agents"""
        logger.info(f"Aggregating results from {len(context.completed_agents)} agents")
        
        if not context.agent_results:
            raise Exception("No agent results to aggregate")
        
        # Calculate overall confidence using weighted average
        total_weight = 0
        weighted_confidence = 0
        agent_contributions = {}
        
        for agent_type, result in context.agent_results.items():
            # Weight based on agent type importance and result confidence
            weight = self._get_agent_weight(agent_type) * (1 + result.confidence_score)
            agent_contributions[agent_type] = weight
            weighted_confidence += result.confidence_score * weight
            total_weight += weight
        
        overall_confidence = weighted_confidence / total_weight if total_weight > 0 else 0.0
        
        # Consolidate MITRE tactics
        all_tactics = set()
        for result in context.agent_results.values():
            all_tactics.update(result.mitre_tactics)
        
        # Consolidate findings
        consolidated_findings = {}
        for agent_type, result in context.agent_results.items():
            consolidated_findings[agent_type.value] = result.findings
        
        # Aggregate recommendations
        all_recommendations = []
        for result in context.agent_results.values():
            all_recommendations.extend(result.recommendations)
        
        # Remove duplicates while preserving order
        unique_recommendations = list(dict.fromkeys(all_recommendations))
        
        # Determine primary threat assessment
        primary_threat = self._determine_primary_threat(context)
        
        # Determine escalation level
        escalation_level = self._determine_escalation_level(context, overall_confidence)
        
        # Check if human review is required
        requires_review = (
            context.human_review_required or
            overall_confidence < self.consensus_threshold or
            len(context.escalation_reasons) > 0 or
            any(result.requires_followup for result in context.agent_results.values())
        )
        
        # Create processing summary
        processing_summary = {
            "coordination_mode": context.coordination_mode.value,
            "agents_involved": [agent.value for agent in context.completed_agents],
            "total_processing_time": sum(r.processing_time for r in context.agent_results.values()),
            "escalation_reasons": context.escalation_reasons,
            "agent_success_rates": {
                agent.value: result.success for agent, result in context.agent_results.items()
            }
        }
        
        logger.info(f"Aggregation complete - Overall confidence: {overall_confidence:.2f}")
        
        return AggregatedResult(
            incident_id=context.incident_id,
            overall_confidence=overall_confidence,
            primary_threat_assessment=primary_threat,
            mitre_tactics=list(all_tactics),
            consolidated_findings=consolidated_findings,
            recommended_actions=unique_recommendations,
            agent_contributions=agent_contributions,
            requires_human_review=requires_review,
            escalation_level=escalation_level,
            processing_summary=processing_summary
        )
    
    def _determine_coordination_mode(self, incident: SentinelIncident, 
                                   classification: ClassificationResult) -> CoordinationMode:
        """Determine appropriate coordination mode based on incident characteristics"""
        
        # High confidence single agent cases
        if (classification.confidence_score >= 0.95 and 
            classification.tier_used == "rule_based" and
            incident.severity.value in ["Low", "Medium"]):
            return CoordinationMode.SINGLE_AGENT
        
        # Complex incidents requiring multiple perspectives
        if (len(classification.mitre_tactics) > 2 or
            incident.severity.value == "Critical" or
            "multi_vector" in incident.title.lower()):
            return CoordinationMode.PARALLEL_AGENTS
        
        # Sequential processing for building context
        if (classification.confidence_score < 0.80 or
            "investigation" in incident.title.lower()):
            return CoordinationMode.SEQUENTIAL_AGENTS
        
        # Hierarchical review for borderline cases
        if 0.70 <= classification.confidence_score < 0.85:
            return CoordinationMode.HIERARCHICAL_REVIEW
        
        # Default to single agent
        return CoordinationMode.SINGLE_AGENT
    
    def _get_required_agents(self, classification: ClassificationResult, 
                           coordination_mode: CoordinationMode) -> List[AgentType]:
        """Get list of required agents based on classification and coordination mode"""
        
        if coordination_mode == CoordinationMode.SINGLE_AGENT:
            return [classification.assigned_agent]
        
        required = [classification.assigned_agent]
        
        # Add fallback agents for parallel/sequential processing
        if coordination_mode in [CoordinationMode.PARALLEL_AGENTS, CoordinationMode.SEQUENTIAL_AGENTS]:
            required.extend(classification.fallback_agents[:2])  # Limit to 2 additional agents
        
        # Add specialized agents based on MITRE tactics
        tactic_agents = {
            MITRETactic.INITIAL_ACCESS: [AgentType.PHISHING, AgentType.LOGIN_IDENTITY],
            MITRETactic.EXECUTION: [AgentType.POWERSHELL_EXPLOITATION, AgentType.MALWARE_THREAT_INTEL],
            MITRETactic.PERSISTENCE: [AgentType.ACCESS_CONTROL, AgentType.HOST_STABILITY],
            MITRETactic.DEFENSE_EVASION: [AgentType.MALWARE_THREAT_INTEL, AgentType.POWERSHELL_EXPLOITATION],
            MITRETactic.CREDENTIAL_ACCESS: [AgentType.LOGIN_IDENTITY, AgentType.ACCESS_CONTROL],
            MITRETactic.DISCOVERY: [AgentType.NETWORK_EXFILTRATION, AgentType.HOST_STABILITY],
            MITRETactic.COLLECTION: [AgentType.INSIDER_BEHAVIOR, AgentType.NETWORK_EXFILTRATION],
            MITRETactic.EXFILTRATION: [AgentType.NETWORK_EXFILTRATION, AgentType.INSIDER_BEHAVIOR],
            MITRETactic.IMPACT: [AgentType.DDOS_DEFENSE, AgentType.HOST_STABILITY]
        }
        
        for tactic in classification.mitre_tactics:
            if tactic in tactic_agents:
                for agent in tactic_agents[tactic]:
                    if agent not in required:
                        required.append(agent)
        
        # Limit total agents to prevent overwhelming
        return required[:4]
    
    async def _simulate_agent_processing(self, agent_type: AgentType, 
                                       incident: SentinelIncident,
                                       routing_result: RoutingResult) -> AgentResult:
        """Simulate agent processing (replace with actual agent calls)"""
        
        # Simulate processing time
        processing_time = 10 + (hash(incident.incident_id) % 20)  # 10-30 seconds
        await asyncio.sleep(0.1)  # Small delay for simulation
        
        # Simulate confidence based on agent type and incident characteristics
        base_confidence = 0.75
        if agent_type.value.lower() in incident.title.lower():
            base_confidence = 0.90
        
        confidence = min(0.98, base_confidence + (hash(incident.incident_id) % 20) / 100)
        
        # Simulate findings
        findings = {
            "primary_indicators": [f"Indicator_{i}" for i in range(3)],
            "risk_score": confidence * 100,
            "evidence_quality": "high" if confidence > 0.85 else "medium",
            "false_positive_likelihood": max(0, (1 - confidence) * 100)
        }
        
        # Simulate recommendations
        recommendations = [
            f"Block suspicious {agent_type.value.lower()} activity",
            f"Monitor for additional {agent_type.value.lower()} indicators",
            "Update security policies if confirmed malicious"
        ]
        
        # Simulate MITRE tactics
        agent_tactics = {
            AgentType.PHISHING: [MITRETactic.INITIAL_ACCESS],
            AgentType.LOGIN_IDENTITY: [MITRETactic.CREDENTIAL_ACCESS, MITRETactic.INITIAL_ACCESS],
            AgentType.POWERSHELL_EXPLOITATION: [MITRETactic.EXECUTION, MITRETactic.DEFENSE_EVASION],
            AgentType.MALWARE_THREAT_INTEL: [MITRETactic.EXECUTION, MITRETactic.PERSISTENCE],
            AgentType.ACCESS_CONTROL: [MITRETactic.PRIVILEGE_ESCALATION, MITRETactic.PERSISTENCE],
            AgentType.INSIDER_BEHAVIOR: [MITRETactic.COLLECTION, MITRETactic.EXFILTRATION],
            AgentType.NETWORK_EXFILTRATION: [MITRETactic.EXFILTRATION, MITRETactic.DISCOVERY],
            AgentType.HOST_STABILITY: [MITRETactic.IMPACT, MITRETactic.PERSISTENCE],
            AgentType.DDOS_DEFENSE: [MITRETactic.IMPACT]
        }.get(agent_type, [])
        
        return AgentResult(
            agent_type=agent_type,
            agent_instance_id=routing_result.agent_instance_id,
            incident_id=incident.incident_id,
            success=confidence > 0.60,
            confidence_score=confidence,
            findings=findings,
            recommendations=recommendations,
            mitre_tactics=agent_tactics,
            processing_time=processing_time,
            requires_followup=confidence < 0.80,
            followup_agents=[AgentType.MALWARE_THREAT_INTEL] if confidence < 0.70 else []
        )
    
    def _calculate_overall_confidence(self, context: WorkflowContext) -> float:
        """Calculate overall confidence from all agent results"""
        if not context.agent_results:
            return 0.0
        
        confidences = [result.confidence_score for result in context.agent_results.values()]
        return sum(confidences) / len(confidences)
    
    def _get_agent_weight(self, agent_type: AgentType) -> float:
        """Get weight for agent type in aggregation"""
        weights = {
            AgentType.PHISHING: 1.0,
            AgentType.LOGIN_IDENTITY: 1.0,
            AgentType.POWERSHELL_EXPLOITATION: 0.9,
            AgentType.MALWARE_THREAT_INTEL: 0.9,
            AgentType.ACCESS_CONTROL: 0.8,
            AgentType.INSIDER_BEHAVIOR: 0.8,
            AgentType.NETWORK_EXFILTRATION: 0.8,
            AgentType.HOST_STABILITY: 0.7,
            AgentType.DDOS_DEFENSE: 0.7
        }
        return weights.get(agent_type, 0.5)
    
    def _determine_primary_threat(self, context: WorkflowContext) -> str:
        """Determine primary threat assessment from agent results"""
        if not context.agent_results:
            return "Unable to determine threat"
        
        # Get highest confidence result
        best_result = max(context.agent_results.values(), key=lambda x: x.confidence_score)
        
        if best_result.confidence_score >= 0.90:
            return f"High confidence {best_result.agent_type.value} threat detected"
        elif best_result.confidence_score >= 0.70:
            return f"Probable {best_result.agent_type.value} threat detected"
        else:
            return "Suspicious activity detected - requires investigation"
    
    def _determine_escalation_level(self, context: WorkflowContext, overall_confidence: float) -> str:
        """Determine escalation level based on results"""
        if len(context.escalation_reasons) > 2:
            return "Critical"
        elif overall_confidence < 0.60:
            return "High"
        elif context.human_review_required:
            return "Medium"
        else:
            return "Low"
    
    def _create_agent_classification(self, agent_type: AgentType, 
                                   base_classification: ClassificationResult) -> ClassificationResult:
        """Create agent-specific classification"""
        return ClassificationResult(
            assigned_agent=agent_type,
            confidence_score=base_classification.confidence_score * 0.9,  # Slightly reduce for delegation
            tier_used=base_classification.tier_used,
            reasoning=f"Delegated to {agent_type.value}: {base_classification.reasoning}",
            mitre_tactics=base_classification.mitre_tactics,
            requires_human_review=base_classification.requires_human_review,
            fallback_agents=[]
        )
    
    def _create_enhanced_classification(self, agent_type: AgentType,
                                      base_classification: ClassificationResult,
                                      previous_result: Optional[AgentResult]) -> ClassificationResult:
        """Create enhanced classification based on previous agent results"""
        enhanced_reasoning = base_classification.reasoning
        
        if previous_result:
            enhanced_reasoning += f" | Previous {previous_result.agent_type.value} analysis: {previous_result.confidence_score:.2f} confidence"
        
        return ClassificationResult(
            assigned_agent=agent_type,
            confidence_score=base_classification.confidence_score,
            tier_used=base_classification.tier_used,
            reasoning=enhanced_reasoning,
            mitre_tactics=base_classification.mitre_tactics,
            requires_human_review=base_classification.requires_human_review,
            fallback_agents=[]
        )
    
    def _get_secondary_review_agents(self, primary_agent: AgentType, 
                                   classification: ClassificationResult) -> List[AgentType]:
        """Get appropriate secondary review agents"""
        review_agents = {
            AgentType.PHISHING: [AgentType.MALWARE_THREAT_INTEL, AgentType.LOGIN_IDENTITY],
            AgentType.LOGIN_IDENTITY: [AgentType.ACCESS_CONTROL, AgentType.INSIDER_BEHAVIOR],
            AgentType.POWERSHELL_EXPLOITATION: [AgentType.MALWARE_THREAT_INTEL, AgentType.HOST_STABILITY],
            AgentType.MALWARE_THREAT_INTEL: [AgentType.POWERSHELL_EXPLOITATION, AgentType.NETWORK_EXFILTRATION],
            AgentType.DDOS_DEFENSE: [AgentType.NETWORK_EXFILTRATION, AgentType.HOST_STABILITY]
        }
        
        return review_agents.get(primary_agent, [classification.fallback_agents[0]] if classification.fallback_agents else [])
    
    def _initialize_coordination_rules(self):
        """Initialize coordination rules for different scenarios"""
        self.coordination_rules = {
            "high_confidence_single": {
                "confidence_threshold": 0.95,
                "mode": CoordinationMode.SINGLE_AGENT,
                "max_agents": 1
            },
            "parallel_investigation": {
                "confidence_threshold": 0.70,
                "mode": CoordinationMode.PARALLEL_AGENTS,
                "max_agents": 3
            },
            "sequential_analysis": {
                "confidence_threshold": 0.60,
                "mode": CoordinationMode.SEQUENTIAL_AGENTS,
                "max_agents": 4
            },
            "hierarchical_review": {
                "confidence_threshold": 0.50,
                "mode": CoordinationMode.HIERARCHICAL_REVIEW,
                "max_agents": 3
            }
        }
