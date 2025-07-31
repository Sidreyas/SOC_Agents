"""
Host Stability Agent
Main orchestrator for host stability and security analysis
Coordinates lateral movement detection, endpoint pattern analysis, threat classification, 
stability correlation, and risk assessment
"""

import logging
from typing import Dict, Any, List
from datetime import datetime
import asyncio
from langgraph.graph import StateGraph, END
from langgraph.graph.message import AnyMessage, add_messages
from typing_extensions import Annotated, TypedDict

from .lateral_movement_detector import LateralMovementDetector
from .endpoint_pattern_analyzer import EndpointPatternAnalyzer
from .host_threat_classifier import HostThreatClassifier
from .stability_correlator import StabilityCorrelator
from .host_risk_assessor import HostRiskAssessor

logger = logging.getLogger(__name__)

class HostStabilityState(TypedDict):
    """State for Host Stability Agent workflow"""
    messages: Annotated[list[AnyMessage], add_messages]
    alert_data: Dict[str, Any]
    lateral_movement_analysis: Dict[str, Any]
    endpoint_pattern_analysis: Dict[str, Any]
    threat_classification: Dict[str, Any]
    stability_correlation: Dict[str, Any]
    risk_assessment: Dict[str, Any]
    final_verdict: Dict[str, Any]
    error_state: Dict[str, Any]
    next_action: str

class HostStabilityAgent:
    """
    Main orchestrator for host stability and security analysis
    Implements 5-state workflow for comprehensive host threat detection
    """
    
    def __init__(self):
        self.lateral_movement_detector = LateralMovementDetector()
        self.endpoint_pattern_analyzer = EndpointPatternAnalyzer()
        self.host_threat_classifier = HostThreatClassifier()
        self.stability_correlator = StabilityCorrelator()
        self.host_risk_assessor = HostRiskAssessor()
        
        # Initialize workflow graph
        self.workflow = self._create_workflow()
        
    def _create_workflow(self) -> StateGraph:
        """Create the LangGraph workflow for host stability analysis"""
        workflow = StateGraph(HostStabilityState)
        
        # Add nodes for each state
        workflow.add_node("lateral_movement_detection", self._lateral_movement_detection_node)
        workflow.add_node("endpoint_pattern_analysis", self._endpoint_pattern_analysis_node)
        workflow.add_node("threat_classification", self._threat_classification_node)
        workflow.add_node("stability_correlation", self._stability_correlation_node)
        workflow.add_node("risk_assessment", self._risk_assessment_node)
        workflow.add_node("error_handling", self._error_handling_node)
        
        # Define workflow edges
        workflow.set_entry_point("lateral_movement_detection")
        
        workflow.add_edge("lateral_movement_detection", "endpoint_pattern_analysis")
        workflow.add_edge("endpoint_pattern_analysis", "threat_classification")
        workflow.add_edge("threat_classification", "stability_correlation")
        workflow.add_edge("stability_correlation", "risk_assessment")
        workflow.add_edge("risk_assessment", END)
        workflow.add_edge("error_handling", END)
        
        # Add conditional edges for error handling
        workflow.add_conditional_edges(
            "lateral_movement_detection",
            self._check_for_errors,
            {
                "continue": "endpoint_pattern_analysis",
                "error": "error_handling"
            }
        )
        
        workflow.add_conditional_edges(
            "endpoint_pattern_analysis", 
            self._check_for_errors,
            {
                "continue": "threat_classification",
                "error": "error_handling"
            }
        )
        
        workflow.add_conditional_edges(
            "threat_classification",
            self._check_for_errors,
            {
                "continue": "stability_correlation", 
                "error": "error_handling"
            }
        )
        
        workflow.add_conditional_edges(
            "stability_correlation",
            self._check_for_errors,
            {
                "continue": "risk_assessment",
                "error": "error_handling"
            }
        )
        
        return workflow.compile()
    
    async def analyze_host_stability(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point for host stability analysis
        
        Args:
            alert_data: Host stability alert data
            
        Returns:
            Complete host stability analysis results
        """
        logger.info("Starting host stability analysis")
        
        try:
            # Initialize state
            initial_state = HostStabilityState(
                messages=[],
                alert_data=alert_data,
                lateral_movement_analysis={},
                endpoint_pattern_analysis={},
                threat_classification={},
                stability_correlation={},
                risk_assessment={},
                final_verdict={},
                error_state={},
                next_action=""
            )
            
            # Execute workflow
            final_state = await self.workflow.ainvoke(initial_state)
            
            # Compile final results
            results = self._compile_final_results(final_state)
            
            logger.info("Host stability analysis completed successfully")
            return results
            
        except Exception as e:
            logger.error(f"Error in host stability analysis: {str(e)}")
            return {
                "analysis_status": "error",
                "error_message": str(e),
                "timestamp": datetime.now(),
                "alert_id": alert_data.get("alert_id", "unknown")
            }
    
    def _lateral_movement_detection_node(self, state: HostStabilityState) -> HostStabilityState:
        """
        State 1: Lateral Movement Detection
        Detect and analyze lateral movement patterns
        """
        logger.info("Executing lateral movement detection")
        
        try:
            alert_data = state["alert_data"]
            
            # Extract movement patterns
            movement_patterns = self.lateral_movement_detector.extract_movement_patterns(alert_data)
            
            # Detect suspicious hosts
            suspicious_hosts = self.lateral_movement_detector.detect_suspicious_hosts(
                movement_patterns, alert_data
            )
            
            # Analyze attack vectors
            attack_vectors = self.lateral_movement_detector.analyze_attack_vectors(
                movement_patterns, suspicious_hosts
            )
            
            # Track attack progression
            attack_progression = self.lateral_movement_detector.track_attack_progression(
                movement_patterns, attack_vectors
            )
            
            # Generate host compromise indicators
            compromise_indicators = self.lateral_movement_detector.generate_host_compromise_indicators(
                suspicious_hosts, attack_vectors, attack_progression
            )
            
            # Compile lateral movement analysis
            lateral_movement_analysis = {
                "movement_patterns": movement_patterns,
                "suspicious_hosts": suspicious_hosts,
                "attack_vectors": attack_vectors,
                "attack_progression": attack_progression,
                "compromise_indicators": compromise_indicators,
                "analysis_timestamp": datetime.now(),
                "analysis_status": "completed"
            }
            
            state["lateral_movement_analysis"] = lateral_movement_analysis
            state["next_action"] = "endpoint_pattern_analysis"
            
            logger.info("Lateral movement detection completed")
            
        except Exception as e:
            logger.error(f"Error in lateral movement detection: {str(e)}")
            state["error_state"] = {
                "stage": "lateral_movement_detection",
                "error": str(e),
                "timestamp": datetime.now()
            }
            state["next_action"] = "error"
        
        return state
    
    def _endpoint_pattern_analysis_node(self, state: HostStabilityState) -> HostStabilityState:
        """
        State 2: Endpoint Pattern Analysis
        Analyze endpoint alert patterns and behaviors
        """
        logger.info("Executing endpoint pattern analysis")
        
        try:
            alert_data = state["alert_data"]
            lateral_movement_analysis = state["lateral_movement_analysis"]
            
            # Extract alert patterns
            alert_patterns = self.endpoint_pattern_analyzer.extract_alert_patterns(alert_data)
            
            # Analyze endpoint behaviors
            behavior_analysis = self.endpoint_pattern_analyzer.analyze_endpoint_behaviors(
                alert_patterns, lateral_movement_analysis
            )
            
            # Detect persistent threats
            persistent_threats = self.endpoint_pattern_analyzer.detect_persistent_threats(
                alert_patterns, behavior_analysis
            )
            
            # Calculate endpoint risk scores
            endpoint_risk_scores = self.endpoint_pattern_analyzer.calculate_endpoint_risk_scores(
                alert_patterns, behavior_analysis, persistent_threats
            )
            
            # Generate pattern intelligence
            pattern_intelligence = self.endpoint_pattern_analyzer.generate_pattern_intelligence(
                alert_patterns, behavior_analysis, persistent_threats, endpoint_risk_scores
            )
            
            # Compile endpoint pattern analysis
            endpoint_pattern_analysis = {
                "alert_patterns": alert_patterns,
                "behavior_analysis": behavior_analysis,
                "persistent_threats": persistent_threats,
                "endpoint_risk_scores": endpoint_risk_scores,
                "pattern_intelligence": pattern_intelligence,
                "analysis_timestamp": datetime.now(),
                "analysis_status": "completed"
            }
            
            state["endpoint_pattern_analysis"] = endpoint_pattern_analysis
            state["next_action"] = "threat_classification"
            
            logger.info("Endpoint pattern analysis completed")
            
        except Exception as e:
            logger.error(f"Error in endpoint pattern analysis: {str(e)}")
            state["error_state"] = {
                "stage": "endpoint_pattern_analysis",
                "error": str(e),
                "timestamp": datetime.now()
            }
            state["next_action"] = "error"
        
        return state
    
    def _threat_classification_node(self, state: HostStabilityState) -> HostStabilityState:
        """
        State 3: Threat Classification
        Classify threats and assess severity
        """
        logger.info("Executing threat classification")
        
        try:
            alert_data = state["alert_data"]
            lateral_movement_analysis = state["lateral_movement_analysis"]
            endpoint_pattern_analysis = state["endpoint_pattern_analysis"]
            
            # Categorize threats
            threat_categories = self.host_threat_classifier.categorize_threats(
                lateral_movement_analysis, endpoint_pattern_analysis
            )
            
            # Assess threat severity
            severity_assessment = self.host_threat_classifier.assess_threat_severity(
                threat_categories, alert_data
            )
            
            # Map to MITRE ATT&CK
            mitre_mapping = self.host_threat_classifier.map_to_mitre_attack(
                threat_categories, severity_assessment
            )
            
            # Generate threat intelligence
            threat_intelligence = self.host_threat_classifier.generate_threat_intelligence(
                threat_categories, severity_assessment, mitre_mapping
            )
            
            # Assess business impact
            business_impact = self.host_threat_classifier.assess_business_impact(
                threat_categories, severity_assessment, alert_data
            )
            
            # Compile threat classification
            threat_classification = {
                "threat_categories": threat_categories,
                "severity_assessment": severity_assessment,
                "mitre_mapping": mitre_mapping,
                "threat_intelligence": threat_intelligence,
                "business_impact": business_impact,
                "analysis_timestamp": datetime.now(),
                "analysis_status": "completed"
            }
            
            state["threat_classification"] = threat_classification
            state["next_action"] = "stability_correlation"
            
            logger.info("Threat classification completed")
            
        except Exception as e:
            logger.error(f"Error in threat classification: {str(e)}")
            state["error_state"] = {
                "stage": "threat_classification",
                "error": str(e),
                "timestamp": datetime.now()
            }
            state["next_action"] = "error"
        
        return state
    
    def _stability_correlation_node(self, state: HostStabilityState) -> HostStabilityState:
        """
        State 4: Stability Correlation
        Correlate stability metrics with security events
        """
        logger.info("Executing stability correlation")
        
        try:
            alert_data = state["alert_data"]
            lateral_movement_analysis = state["lateral_movement_analysis"]
            endpoint_pattern_analysis = state["endpoint_pattern_analysis"]
            threat_classification = state["threat_classification"]
            
            # Correlate stability and security
            stability_security_correlations = self.stability_correlator.correlate_stability_security(
                alert_data, threat_classification
            )
            
            # Correlate performance and threats
            performance_threat_correlations = self.stability_correlator.correlate_performance_threats(
                endpoint_pattern_analysis, threat_classification
            )
            
            # Analyze resource impact
            resource_impact_analysis = self.stability_correlator.analyze_resource_impact(
                lateral_movement_analysis, endpoint_pattern_analysis, threat_classification
            )
            
            # Analyze trends
            trend_analysis = self.stability_correlator.analyze_trends(
                stability_security_correlations, performance_threat_correlations
            )
            
            # Assess impact
            impact_assessment = self.stability_correlator.assess_impact(
                stability_security_correlations, performance_threat_correlations, 
                resource_impact_analysis, trend_analysis
            )
            
            # Compile stability correlation
            stability_correlation = {
                "stability_security_correlations": stability_security_correlations,
                "performance_threat_correlations": performance_threat_correlations,
                "resource_impact_analysis": resource_impact_analysis,
                "trend_analysis": trend_analysis,
                "impact_assessment": impact_assessment,
                "analysis_timestamp": datetime.now(),
                "analysis_status": "completed"
            }
            
            state["stability_correlation"] = stability_correlation
            state["next_action"] = "risk_assessment"
            
            logger.info("Stability correlation completed")
            
        except Exception as e:
            logger.error(f"Error in stability correlation: {str(e)}")
            state["error_state"] = {
                "stage": "stability_correlation",
                "error": str(e),
                "timestamp": datetime.now()
            }
            state["next_action"] = "error"
        
        return state
    
    def _risk_assessment_node(self, state: HostStabilityState) -> HostStabilityState:
        """
        State 5: Risk Assessment
        Perform comprehensive risk assessment and generate recommendations
        """
        logger.info("Executing risk assessment")
        
        try:
            lateral_movement_analysis = state["lateral_movement_analysis"]
            endpoint_pattern_analysis = state["endpoint_pattern_analysis"]
            threat_classification = state["threat_classification"]
            stability_correlation = state["stability_correlation"]
            
            # Assess comprehensive host risk
            risk_assessment = self.host_risk_assessor.assess_comprehensive_host_risk(
                lateral_movement_analysis, endpoint_pattern_analysis,
                threat_classification, stability_correlation
            )
            
            # Generate mitigation plan
            business_context = state["alert_data"].get("business_context", {})
            mitigation_plan = self.host_risk_assessor.generate_risk_mitigation_plan(
                risk_assessment, business_context
            )
            
            # Generate final recommendations
            all_assessment_results = {
                "risk_assessment": risk_assessment,
                "mitigation_plan": mitigation_plan
            }
            final_recommendations = self.host_risk_assessor.generate_final_recommendations(
                all_assessment_results
            )
            
            # Compile final verdict
            final_verdict = {
                "overall_risk_level": self._determine_overall_risk_level(risk_assessment),
                "critical_findings": self._extract_critical_findings(risk_assessment),
                "immediate_actions": self._extract_immediate_actions(mitigation_plan),
                "confidence_score": self._calculate_confidence_score(risk_assessment),
                "business_impact": final_recommendations.get("executive_summary", {}).get("business_impact", {}),
                "recommendations_summary": self._summarize_recommendations(final_recommendations)
            }
            
            # Store complete risk assessment
            complete_risk_assessment = {
                "risk_assessment": risk_assessment,
                "mitigation_plan": mitigation_plan,
                "final_recommendations": final_recommendations,
                "analysis_timestamp": datetime.now(),
                "analysis_status": "completed"
            }
            
            state["risk_assessment"] = complete_risk_assessment
            state["final_verdict"] = final_verdict
            state["next_action"] = "completed"
            
            logger.info("Risk assessment completed")
            
        except Exception as e:
            logger.error(f"Error in risk assessment: {str(e)}")
            state["error_state"] = {
                "stage": "risk_assessment",
                "error": str(e),
                "timestamp": datetime.now()
            }
            state["next_action"] = "error"
        
        return state
    
    def _error_handling_node(self, state: HostStabilityState) -> HostStabilityState:
        """Handle errors in the workflow"""
        logger.info("Handling workflow error")
        
        error_state = state.get("error_state", {})
        
        # Generate error response
        error_response = {
            "analysis_status": "error",
            "error_stage": error_state.get("stage", "unknown"),
            "error_message": error_state.get("error", "Unknown error occurred"),
            "error_timestamp": error_state.get("timestamp", datetime.now()),
            "partial_results": self._extract_partial_results(state),
            "recovery_recommendations": self._generate_recovery_recommendations(error_state)
        }
        
        state["final_verdict"] = error_response
        state["next_action"] = "completed"
        
        return state
    
    def _check_for_errors(self, state: HostStabilityState) -> str:
        """Check if errors occurred in the workflow"""
        if state.get("error_state"):
            return "error"
        return "continue"
    
    def _compile_final_results(self, final_state: HostStabilityState) -> Dict[str, Any]:
        """Compile final analysis results"""
        return {
            "analysis_id": f"host_stability_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "analysis_timestamp": datetime.now(),
            "alert_data": final_state.get("alert_data", {}),
            "lateral_movement_analysis": final_state.get("lateral_movement_analysis", {}),
            "endpoint_pattern_analysis": final_state.get("endpoint_pattern_analysis", {}),
            "threat_classification": final_state.get("threat_classification", {}),
            "stability_correlation": final_state.get("stability_correlation", {}),
            "risk_assessment": final_state.get("risk_assessment", {}),
            "final_verdict": final_state.get("final_verdict", {}),
            "workflow_status": "completed" if not final_state.get("error_state") else "error"
        }
    
    def _determine_overall_risk_level(self, risk_assessment: Dict[str, Any]) -> str:
        """Determine overall risk level from assessment"""
        metadata = risk_assessment.get("assessment_metadata", {})
        critical_count = metadata.get("critical_risk_hosts", 0)
        high_count = metadata.get("high_risk_hosts", 0)
        
        if critical_count > 0:
            return "Critical"
        elif high_count > 0:
            return "High"
        else:
            return "Medium"
    
    def _extract_critical_findings(self, risk_assessment: Dict[str, Any]) -> List[str]:
        """Extract critical findings from risk assessment"""
        findings = []
        
        critical_risks = risk_assessment.get("critical_risks", {})
        immediate_threats = critical_risks.get("immediate_threats", [])
        
        for threat in immediate_threats:
            findings.append(f"Critical threat detected on {threat.get('host', 'unknown host')}")
        
        return findings
    
    def _extract_immediate_actions(self, mitigation_plan: Dict[str, Any]) -> List[str]:
        """Extract immediate actions from mitigation plan"""
        actions = []
        
        immediate_actions = mitigation_plan.get("immediate_actions", {})
        for action_data in immediate_actions.values():
            actions.append(action_data.get("description", "Unknown action"))
        
        return actions
    
    def _calculate_confidence_score(self, risk_assessment: Dict[str, Any]) -> float:
        """Calculate overall confidence score"""
        metadata = risk_assessment.get("assessment_metadata", {})
        return metadata.get("assessment_confidence", 0.7)
    
    def _summarize_recommendations(self, final_recommendations: Dict[str, Any]) -> Dict[str, Any]:
        """Summarize key recommendations"""
        return {
            "priority_actions_count": len(final_recommendations.get("priority_actions", [])),
            "technical_recommendations_count": len(final_recommendations.get("technical_recommendations", {})),
            "estimated_cost": final_recommendations.get("budget_recommendations", {}).get("total_budget", 0),
            "timeline": final_recommendations.get("timeline_roadmap", {}).get("total_duration", "unknown")
        }
    
    def _extract_partial_results(self, state: HostStabilityState) -> Dict[str, Any]:
        """Extract partial results in case of error"""
        partial_results = {}
        
        if state.get("lateral_movement_analysis"):
            partial_results["lateral_movement_analysis"] = state["lateral_movement_analysis"]
        if state.get("endpoint_pattern_analysis"):
            partial_results["endpoint_pattern_analysis"] = state["endpoint_pattern_analysis"]
        if state.get("threat_classification"):
            partial_results["threat_classification"] = state["threat_classification"]
        if state.get("stability_correlation"):
            partial_results["stability_correlation"] = state["stability_correlation"]
        
        return partial_results
    
    def _generate_recovery_recommendations(self, error_state: Dict[str, Any]) -> List[str]:
        """Generate recommendations for error recovery"""
        stage = error_state.get("stage", "unknown")
        
        recommendations = [
            "Review alert data quality and completeness",
            "Verify data source connectivity",
            "Check system resource availability"
        ]
        
        if stage == "lateral_movement_detection":
            recommendations.append("Verify network monitoring data availability")
        elif stage == "endpoint_pattern_analysis":
            recommendations.append("Check endpoint monitoring system status")
        elif stage == "threat_classification":
            recommendations.append("Verify threat intelligence feed connectivity")
        elif stage == "stability_correlation":
            recommendations.append("Check performance monitoring data sources")
        elif stage == "risk_assessment":
            recommendations.append("Review risk assessment configuration")
        
        return recommendations

# Create workflow instance
def create_host_stability_agent() -> HostStabilityAgent:
    """Create and return Host Stability Agent instance"""
    return HostStabilityAgent()
