"""
Master Orchestrator Package
Handles incident classification, routing, and multi-agent coordination
"""

__version__ = "1.0.0"

from .master_orchestrator import MasterOrchestrator
from .incident_classifier import IncidentClassifier, ClassificationResult, SentinelIncident, AgentType, IncidentSeverity, MITRETactic
from .routing_engine import RoutingEngine, RoutingResult, AgentCapacity, RoutingRequest
from .coordination_manager import CoordinationManager, AggregatedResult, WorkflowContext, AgentResult
from .tool_integration import ToolIntegrationLayer, ToolRequest, ToolResponse, ToolCapability

__all__ = [
    "MasterOrchestrator",
    "IncidentClassifier",
    "ClassificationResult", 
    "SentinelIncident",
    "AgentType",
    "IncidentSeverity",
    "MITRETactic",
    "RoutingEngine",
    "RoutingResult",
    "AgentCapacity",
    "RoutingRequest",
    "CoordinationManager",
    "AggregatedResult",
    "WorkflowContext",
    "AgentResult",
    "ToolIntegrationLayer",
    "ToolRequest",
    "ToolResponse",
    "ToolCapability"
]
