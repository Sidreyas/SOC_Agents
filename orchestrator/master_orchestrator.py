"""
Master Orchestrator Module
Main entry point for the SOC AI Agent System
Coordinates incident processing through classification, routing, and multi-agent coordination
"""

import logging
import asyncio
import json
from typing import Dict, Any, Optional, List
from datetime import datetime
import uuid

from .incident_classifier import IncidentClassifier, ClassificationResult, SentinelIncident, AgentType, IncidentSeverity
from .routing_engine import RoutingEngine, RoutingResult
from .coordination_manager import CoordinationManager, AggregatedResult

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class MasterOrchestrator:
    """
    Master Orchestrator for SOC AI Agent System
    
    Implements 3-tier classification and accuracy-first coordination:
    - Tier 1: Rule-based classification (70% of cases)
    - Tier 2: GPT-4 enhanced analysis (25% of cases) 
    - Tier 3: Multi-agent coordination (5% of cases)
    
    Prioritizes accuracy over speed with conservative decision making
    """
    
    def __init__(self):
        # Initialize core components
        self.incident_classifier = IncidentClassifier()
        self.routing_engine = RoutingEngine()
        self.coordination_manager = CoordinationManager(self.routing_engine)
        
        # Configuration
        self.accuracy_threshold = 0.85
        self.processing_timeout = 300  # 5 minutes
        self.max_concurrent_incidents = 10
        
        # State tracking
        self.active_incidents: Dict[str, Dict[str, Any]] = {}
        self.processing_stats = {
            "total_processed": 0,
            "tier_usage": {"rule_based": 0, "gpt4_enhanced": 0, "multi_agent": 0},
            "agent_usage": {agent.value: 0 for agent in AgentType},
            "avg_processing_time": 0.0,
            "accuracy_rate": 0.0
        }
        
        logger.info("Master Orchestrator initialized")
    
    async def process_incident(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main processing method for incoming incidents
        
        Args:
            incident_data: Raw incident data from Sentinel or other sources
            
        Returns:
            Complete processing result with recommendations and actions
        """
        start_time = datetime.now()
        
        try:
            # Parse incident data
            incident = self._parse_incident_data(incident_data)
            logger.info(f"Processing incident {incident.incident_id}: {incident.title}")
            
            # Track active incident
            self.active_incidents[incident.incident_id] = {
                "start_time": start_time,
                "status": "classifying",
                "incident": incident
            }
            
            # Step 1: Classify incident using 3-tier system
            self.active_incidents[incident.incident_id]["status"] = "classifying"
            classification = self.incident_classifier.classify_incident(incident)
            
            logger.info(
                f"Incident {incident.incident_id} classified as {classification.assigned_agent.value} "
                f"with {classification.confidence_score:.2f} confidence using {classification.tier_used}"
            )
            
            # Update statistics
            self.processing_stats["tier_usage"][classification.tier_used] += 1
            self.processing_stats["agent_usage"][classification.assigned_agent.value] += 1
            
            # Step 2: Orchestrate multi-agent processing
            self.active_incidents[incident.incident_id]["status"] = "coordinating"
            aggregated_result = await self.coordination_manager.orchestrate_incident(
                incident, classification
            )
            
            # Step 3: Generate final response
            self.active_incidents[incident.incident_id]["status"] = "finalizing"
            response = await self._generate_response(
                incident, classification, aggregated_result, start_time
            )
            
            # Update statistics
            processing_time = (datetime.now() - start_time).total_seconds()
            self._update_processing_stats(processing_time, aggregated_result.overall_confidence)
            
            # Clean up
            self.active_incidents[incident.incident_id]["status"] = "completed"
            del self.active_incidents[incident.incident_id]
            
            logger.info(
                f"Completed processing incident {incident.incident_id} in {processing_time:.1f}s "
                f"(Confidence: {aggregated_result.overall_confidence:.2f})"
            )
            
            return response
            
        except Exception as e:
            logger.error(f"Error processing incident: {e}")
            
            # Clean up on error
            if incident_data.get("incident_id") in self.active_incidents:
                del self.active_incidents[incident_data["incident_id"]]
            
            # Return error response
            return {
                "incident_id": incident_data.get("incident_id", "unknown"),
                "status": "error",
                "error": str(e),
                "requires_human_review": True,
                "escalation_level": "Critical",
                "processing_time": (datetime.now() - start_time).total_seconds(),
                "timestamp": datetime.now().isoformat()
            }
    
    async def process_batch_incidents(self, incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process multiple incidents concurrently with rate limiting
        
        Args:
            incidents: List of incident data dictionaries
            
        Returns:
            List of processing results
        """
        logger.info(f"Processing batch of {len(incidents)} incidents")
        
        # Limit concurrent processing
        semaphore = asyncio.Semaphore(self.max_concurrent_incidents)
        
        async def process_with_semaphore(incident_data):
            async with semaphore:
                return await self.process_incident(incident_data)
        
        # Process all incidents concurrently
        tasks = [process_with_semaphore(incident) for incident in incidents]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle any exceptions
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Batch processing error for incident {i}: {result}")
                processed_results.append({
                    "incident_id": incidents[i].get("incident_id", f"batch_{i}"),
                    "status": "error",
                    "error": str(result),
                    "requires_human_review": True
                })
            else:
                processed_results.append(result)
        
        logger.info(f"Completed batch processing: {len(processed_results)} results")
        return processed_results
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get current system status and statistics"""
        agent_status = self.routing_engine.get_agent_status()
        queue_status = self.routing_engine.get_queue_status()
        
        return {
            "system_health": "operational",
            "active_incidents": len(self.active_incidents),
            "processing_stats": self.processing_stats,
            "agent_status": agent_status,
            "queue_status": queue_status,
            "timestamp": datetime.now().isoformat()
        }
    
    async def get_incident_status(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Get status of specific incident"""
        if incident_id in self.active_incidents:
            incident_info = self.active_incidents[incident_id]
            processing_time = (datetime.now() - incident_info["start_time"]).total_seconds()
            
            return {
                "incident_id": incident_id,
                "status": incident_info["status"],
                "processing_time": processing_time,
                "alert_title": incident_info["incident"].title,
                "severity": incident_info["incident"].severity.value
            }
        
        return None
    
    def _parse_incident_data(self, incident_data: Dict[str, Any]) -> SentinelIncident:
        """Parse raw incident data into SentinelIncident object"""
        
        # Handle different input formats
        if "incident_id" not in incident_data:
            incident_data["incident_id"] = str(uuid.uuid4())
        
        if "title" not in incident_data:
            incident_data["title"] = incident_data.get("alert_title", "Unknown Alert")
        
        if "severity" not in incident_data:
            incident_data["severity"] = "Medium"
        
        # Parse severity
        severity_map = {
            "critical": IncidentSeverity.CRITICAL,
            "high": IncidentSeverity.HIGH,
            "medium": IncidentSeverity.MEDIUM,
            "low": IncidentSeverity.LOW
        }
        severity = severity_map.get(
            incident_data["severity"].lower(), 
            IncidentSeverity.MEDIUM
        )
        
        return SentinelIncident(
            incident_id=incident_data["incident_id"],
            title=incident_data["title"],
            description=incident_data.get("description", ""),
            severity=severity,
            status=incident_data.get("status", "New"),
            created_time=datetime.fromisoformat(incident_data.get("timestamp", datetime.now().isoformat())),
            alert_rule_name=incident_data.get("source_system", "Unknown"),
            entities=incident_data.get("entities", []),
            tactics=incident_data.get("alert_rules", []),
            techniques=[],
            raw_data=incident_data
        )
    
    async def _generate_response(self, incident: SentinelIncident, 
                               classification: ClassificationResult,
                               aggregated_result: AggregatedResult,
                               start_time: datetime) -> Dict[str, Any]:
        """Generate comprehensive response for incident processing"""
        
        processing_time = (datetime.now() - start_time).total_seconds()
        
        # Determine response status
        if aggregated_result.overall_confidence >= self.accuracy_threshold:
            status = "completed"
        elif aggregated_result.requires_human_review:
            status = "requires_review"
        else:
            status = "low_confidence"
        
        # Generate action plan
        action_plan = self._generate_action_plan(aggregated_result)
        
        # Create comprehensive response
        response = {
            # Basic incident information
            "incident_id": incident.incident_id,
            "alert_title": incident.title,
            "severity": incident.severity.value,
            "status": status,
            
            # Classification results
            "classification": {
                "primary_agent": classification.assigned_agent.value,
                "confidence_score": classification.confidence_score,
                "tier_used": classification.tier_used,
                "reasoning": classification.reasoning
            },
            
            # Aggregated analysis results
            "analysis": {
                "overall_confidence": aggregated_result.overall_confidence,
                "primary_threat_assessment": aggregated_result.primary_threat_assessment,
                "mitre_tactics": [tactic.value for tactic in aggregated_result.mitre_tactics],
                "escalation_level": aggregated_result.escalation_level,
                "agents_involved": list(aggregated_result.agent_contributions.keys())
            },
            
            # Findings and evidence
            "findings": aggregated_result.consolidated_findings,
            
            # Recommended actions
            "recommendations": aggregated_result.recommended_actions,
            "action_plan": action_plan,
            
            # Review and escalation
            "requires_human_review": aggregated_result.requires_human_review,
            "review_reasons": self._get_review_reasons(aggregated_result),
            
            # Processing metadata
            "processing": {
                "processing_time": processing_time,
                "coordination_mode": aggregated_result.processing_summary.get("coordination_mode"),
                "agents_success_rate": aggregated_result.processing_summary.get("agent_success_rates", {}),
                "timestamp": datetime.now().isoformat()
            },
            
            # Quality metrics
            "quality": {
                "confidence_score": aggregated_result.overall_confidence,
                "evidence_quality": self._assess_evidence_quality(aggregated_result),
                "false_positive_likelihood": max(0, (1 - aggregated_result.overall_confidence) * 100)
            }
        }
        
        return response
    
    def _generate_action_plan(self, aggregated_result: AggregatedResult) -> Dict[str, Any]:
        """Generate specific action plan based on analysis results"""
        
        actions = {
            "immediate": [],
            "short_term": [],
            "long_term": []
        }
        
        # Immediate actions based on confidence and escalation level
        if aggregated_result.escalation_level == "Critical":
            actions["immediate"].extend([
                "Initiate incident response protocol",
                "Notify security team lead",
                "Isolate affected systems if confirmed malicious"
            ])
        elif aggregated_result.overall_confidence >= 0.90:
            actions["immediate"].extend([
                "Implement recommended security controls",
                "Monitor for additional indicators"
            ])
        
        # Short-term actions
        if aggregated_result.requires_human_review:
            actions["short_term"].append("Schedule expert review within 24 hours")
        
        actions["short_term"].extend([
            "Update threat intelligence database",
            "Review related alerts for patterns"
        ])
        
        # Long-term actions
        actions["long_term"].extend([
            "Update security policies based on findings",
            "Conduct lessons learned review",
            "Enhance detection rules if necessary"
        ])
        
        return actions
    
    def _get_review_reasons(self, aggregated_result: AggregatedResult) -> List[str]:
        """Get reasons why human review is required"""
        reasons = []
        
        if aggregated_result.overall_confidence < 0.70:
            reasons.append(f"Low confidence score: {aggregated_result.overall_confidence:.2f}")
        
        if aggregated_result.escalation_level in ["Critical", "High"]:
            reasons.append(f"High escalation level: {aggregated_result.escalation_level}")
        
        if len(aggregated_result.mitre_tactics) > 3:
            reasons.append("Multiple MITRE tactics detected")
        
        escalation_reasons = aggregated_result.processing_summary.get("escalation_reasons", [])
        reasons.extend(escalation_reasons)
        
        return reasons
    
    def _assess_evidence_quality(self, aggregated_result: AggregatedResult) -> str:
        """Assess overall evidence quality"""
        confidence = aggregated_result.overall_confidence
        
        if confidence >= 0.90:
            return "high"
        elif confidence >= 0.75:
            return "medium"
        elif confidence >= 0.60:
            return "low"
        else:
            return "insufficient"
    
    def _update_processing_stats(self, processing_time: float, confidence: float):
        """Update system processing statistics"""
        self.processing_stats["total_processed"] += 1
        
        # Update average processing time (exponential moving average)
        if self.processing_stats["avg_processing_time"] == 0:
            self.processing_stats["avg_processing_time"] = processing_time
        else:
            self.processing_stats["avg_processing_time"] = (
                0.9 * self.processing_stats["avg_processing_time"] + 
                0.1 * processing_time
            )
        
        # Update accuracy rate (exponential moving average)
        accuracy_point = 1.0 if confidence >= self.accuracy_threshold else 0.0
        if self.processing_stats["accuracy_rate"] == 0:
            self.processing_stats["accuracy_rate"] = accuracy_point
        else:
            self.processing_stats["accuracy_rate"] = (
                0.95 * self.processing_stats["accuracy_rate"] + 
                0.05 * accuracy_point
            )

# Example usage and testing
async def main():
    """Example usage of Master Orchestrator"""
    orchestrator = MasterOrchestrator()
    
    # Example incident data
    sample_incident = {
        "incident_id": "INC-2024-001",
        "alert_title": "Suspicious PowerShell Activity Detected",
        "severity": "High",
        "description": "Encoded PowerShell commands executed with suspicious parameters",
        "source_system": "Microsoft Defender",
        "entities": [
            {"type": "user", "value": "john.doe@company.com"},
            {"type": "host", "value": "WORKSTATION-01"},
            {"type": "process", "value": "powershell.exe"}
        ],
        "alert_rules": ["PowerShell Obfuscation", "Suspicious Process Execution"]
    }
    
    # Process the incident
    result = await orchestrator.process_incident(sample_incident)
    
    # Print results
    print("Processing Result:")
    print(json.dumps(result, indent=2, default=str))
    
    # Get system status
    status = await orchestrator.get_system_status()
    print("\nSystem Status:")
    print(json.dumps(status, indent=2, default=str))

if __name__ == "__main__":
    asyncio.run(main())
