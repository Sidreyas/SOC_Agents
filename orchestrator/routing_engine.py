"""
Routing Engine Module
Handles agent assignment, load balancing, and workflow coordination
Implements accuracy-first routing with fallback mechanisms
"""

import logging
import asyncio
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import uuid

from .incident_classifier import ClassificationResult, AgentType, SentinelIncident

logger = logging.getLogger(__name__)

class RoutingStatus(Enum):
    PENDING = "pending"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    ESCALATED = "escalated"
    FAILED = "failed"

class AgentStatus(Enum):
    AVAILABLE = "available"
    BUSY = "busy"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"

@dataclass
class AgentCapacity:
    """Track agent capacity and performance"""
    agent_type: AgentType
    max_concurrent: int = 3
    current_load: int = 0
    avg_processing_time: float = 15.0  # minutes
    success_rate: float = 0.95
    last_heartbeat: datetime = field(default_factory=datetime.now)
    status: AgentStatus = AgentStatus.AVAILABLE

@dataclass
class RoutingRequest:
    """Request to route an incident to an agent"""
    incident_id: str
    incident: SentinelIncident
    classification: ClassificationResult
    priority: int  # 1 (highest) to 5 (lowest)
    created_at: datetime = field(default_factory=datetime.now)
    routing_id: str = field(default_factory=lambda: str(uuid.uuid4()))

@dataclass
class RoutingResult:
    """Result of routing decision"""
    routing_id: str
    assigned_agent: AgentType
    agent_instance_id: str
    estimated_completion: datetime
    confidence_score: float
    requires_human_review: bool
    fallback_plan: List[AgentType]
    routing_reason: str

class RoutingEngine:
    """
    Intelligent routing engine with load balancing and accuracy optimization
    Prioritizes accuracy over speed with conservative decision making
    """
    
    def __init__(self):
        self.agent_capacities: Dict[AgentType, AgentCapacity] = {}
        self.active_routes: Dict[str, RoutingResult] = {}
        self.routing_queue: List[RoutingRequest] = []
        self.accuracy_threshold = 0.85
        self.human_review_threshold = 0.70
        
        # Initialize agent capacities
        self._initialize_agent_capacities()
    
    async def route_incident(self, incident: SentinelIncident, classification: ClassificationResult) -> RoutingResult:
        """
        Route incident to appropriate agent based on classification and capacity
        Returns routing result with agent assignment
        """
        logger.info(f"Routing incident {incident.incident_id} to {classification.assigned_agent}")
        
        # Create routing request
        priority = self._calculate_priority(incident, classification)
        request = RoutingRequest(
            incident_id=incident.incident_id,
            incident=incident,
            classification=classification,
            priority=priority
        )
        
        # Check if immediate routing is possible
        if self._can_route_immediately(classification.assigned_agent):
            result = await self._assign_to_agent(request)
            self.active_routes[request.routing_id] = result
            return result
        
        # Add to queue for later processing
        self._add_to_queue(request)
        
        # Try fallback agents if primary is unavailable
        for fallback_agent in classification.fallback_agents:
            if self._can_route_immediately(fallback_agent):
                # Update classification for fallback
                fallback_classification = ClassificationResult(
                    assigned_agent=fallback_agent,
                    confidence_score=classification.confidence_score * 0.8,  # Reduce confidence
                    tier_used=classification.tier_used,
                    reasoning=f"Fallback routing: {classification.reasoning}",
                    mitre_tactics=classification.mitre_tactics,
                    requires_human_review=True,  # Always review fallback routes
                    fallback_agents=[]
                )
                
                request.classification = fallback_classification
                result = await self._assign_to_agent(request)
                self.active_routes[request.routing_id] = result
                return result
        
        # No agents available - queue with high priority for human review
        return RoutingResult(
            routing_id=request.routing_id,
            assigned_agent=classification.assigned_agent,
            agent_instance_id="QUEUED",
            estimated_completion=datetime.now() + timedelta(minutes=30),
            confidence_score=0.0,
            requires_human_review=True,
            fallback_plan=classification.fallback_agents,
            routing_reason="No agents available - queued for processing"
        )
    
    async def process_routing_queue(self):
        """
        Process queued routing requests
        Called periodically to handle backlog
        """
        if not self.routing_queue:
            return
        
        logger.info(f"Processing {len(self.routing_queue)} queued routing requests")
        
        # Sort by priority (1 = highest priority)
        self.routing_queue.sort(key=lambda x: (x.priority, x.created_at))
        
        processed_requests = []
        for request in self.routing_queue[:]:
            if self._can_route_immediately(request.classification.assigned_agent):
                result = await self._assign_to_agent(request)
                self.active_routes[request.routing_id] = result
                processed_requests.append(request)
                logger.info(f"Processed queued request {request.routing_id}")
        
        # Remove processed requests from queue
        for request in processed_requests:
            self.routing_queue.remove(request)
    
    def update_agent_status(self, agent_type: AgentType, status: AgentStatus, 
                           processing_time: Optional[float] = None):
        """Update agent status and performance metrics"""
        if agent_type in self.agent_capacities:
            capacity = self.agent_capacities[agent_type]
            capacity.status = status
            capacity.last_heartbeat = datetime.now()
            
            if processing_time:
                # Update average processing time (exponential moving average)
                capacity.avg_processing_time = (
                    0.7 * capacity.avg_processing_time + 0.3 * processing_time
                )
            
            logger.info(f"Updated {agent_type} status to {status}")
    
    def complete_routing(self, routing_id: str, success: bool, processing_time: float):
        """Mark routing as completed and update metrics"""
        if routing_id in self.active_routes:
            result = self.active_routes[routing_id]
            agent_type = result.assigned_agent
            
            # Update agent capacity
            if agent_type in self.agent_capacities:
                capacity = self.agent_capacities[agent_type]
                capacity.current_load = max(0, capacity.current_load - 1)
                
                # Update success rate (exponential moving average)
                if success:
                    capacity.success_rate = 0.9 * capacity.success_rate + 0.1 * 1.0
                else:
                    capacity.success_rate = 0.9 * capacity.success_rate + 0.1 * 0.0
                
                # Update processing time
                capacity.avg_processing_time = (
                    0.7 * capacity.avg_processing_time + 0.3 * processing_time
                )
            
            # Remove from active routes
            del self.active_routes[routing_id]
            logger.info(f"Completed routing {routing_id} - Success: {success}")
    
    def get_agent_status(self) -> Dict[AgentType, Dict[str, Any]]:
        """Get current status of all agents"""
        status = {}
        for agent_type, capacity in self.agent_capacities.items():
            status[agent_type] = {
                "status": capacity.status.value,
                "current_load": capacity.current_load,
                "max_concurrent": capacity.max_concurrent,
                "utilization": capacity.current_load / capacity.max_concurrent,
                "avg_processing_time": capacity.avg_processing_time,
                "success_rate": capacity.success_rate,
                "last_heartbeat": capacity.last_heartbeat
            }
        return status
    
    def get_queue_status(self) -> Dict[str, Any]:
        """Get current queue status"""
        return {
            "queue_length": len(self.routing_queue),
            "active_routes": len(self.active_routes),
            "pending_by_priority": {
                i: len([r for r in self.routing_queue if r.priority == i])
                for i in range(1, 6)
            }
        }
    
    def _can_route_immediately(self, agent_type: AgentType) -> bool:
        """Check if agent can accept new work immediately"""
        if agent_type not in self.agent_capacities:
            return False
        
        capacity = self.agent_capacities[agent_type]
        
        # Check if agent is available and under capacity
        return (
            capacity.status == AgentStatus.AVAILABLE and
            capacity.current_load < capacity.max_concurrent and
            (datetime.now() - capacity.last_heartbeat).seconds < 300  # 5 minutes
        )
    
    async def _assign_to_agent(self, request: RoutingRequest) -> RoutingResult:
        """Assign request to specific agent"""
        agent_type = request.classification.assigned_agent
        capacity = self.agent_capacities[agent_type]
        
        # Increase agent load
        capacity.current_load += 1
        
        # Generate agent instance ID
        agent_instance_id = f"{agent_type.value}_{uuid.uuid4().hex[:8]}"
        
        # Calculate estimated completion
        estimated_completion = datetime.now() + timedelta(
            minutes=capacity.avg_processing_time
        )
        
        # Determine if human review is required
        requires_review = (
            request.classification.requires_human_review or
            request.classification.confidence_score < self.human_review_threshold or
            capacity.success_rate < 0.90
        )
        
        logger.info(
            f"Assigned incident {request.incident_id} to {agent_instance_id} "
            f"(ETA: {estimated_completion}, Review: {requires_review})"
        )
        
        return RoutingResult(
            routing_id=request.routing_id,
            assigned_agent=agent_type,
            agent_instance_id=agent_instance_id,
            estimated_completion=estimated_completion,
            confidence_score=request.classification.confidence_score,
            requires_human_review=requires_review,
            fallback_plan=request.classification.fallback_agents,
            routing_reason=f"Assigned to {agent_type.value} with {request.classification.confidence_score:.2f} confidence"
        )
    
    def _calculate_priority(self, incident: SentinelIncident, classification: ClassificationResult) -> int:
        """Calculate routing priority (1 = highest, 5 = lowest)"""
        base_priority = {
            "Critical": 1,
            "High": 2,
            "Medium": 3,
            "Low": 4
        }.get(incident.severity.value, 5)
        
        # Adjust based on confidence
        if classification.confidence_score >= 0.95:
            priority_adjustment = 0
        elif classification.confidence_score >= 0.85:
            priority_adjustment = 0
        elif classification.confidence_score >= 0.70:
            priority_adjustment = 1
        else:
            priority_adjustment = 2
        
        return min(5, max(1, base_priority + priority_adjustment))
    
    def _add_to_queue(self, request: RoutingRequest):
        """Add request to routing queue"""
        self.routing_queue.append(request)
        logger.info(f"Added incident {request.incident_id} to routing queue (Priority: {request.priority})")
    
    def _initialize_agent_capacities(self):
        """Initialize agent capacity tracking"""
        agent_configs = {
            AgentType.PHISHING: {"max_concurrent": 5, "avg_time": 12.0},
            AgentType.LOGIN_IDENTITY: {"max_concurrent": 4, "avg_time": 15.0},
            AgentType.POWERSHELL_EXPLOITATION: {"max_concurrent": 3, "avg_time": 20.0},
            AgentType.MALWARE_THREAT_INTEL: {"max_concurrent": 3, "avg_time": 25.0},
            AgentType.ACCESS_CONTROL: {"max_concurrent": 4, "avg_time": 10.0},
            AgentType.INSIDER_BEHAVIOR: {"max_concurrent": 2, "avg_time": 30.0},
            AgentType.NETWORK_EXFILTRATION: {"max_concurrent": 3, "avg_time": 18.0},
            AgentType.HOST_STABILITY: {"max_concurrent": 4, "avg_time": 15.0},
            AgentType.DDOS_DEFENSE: {"max_concurrent": 5, "avg_time": 8.0},
        }
        
        for agent_type, config in agent_configs.items():
            self.agent_capacities[agent_type] = AgentCapacity(
                agent_type=agent_type,
                max_concurrent=config["max_concurrent"],
                avg_processing_time=config["avg_time"]
            )
