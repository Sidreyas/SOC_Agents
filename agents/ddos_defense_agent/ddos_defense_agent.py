"""
DDoS Defense Agent - Main Module
Integrates all DDoS defense analysis states and provides unified interface
"""

import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum

# Import all state modules
from traffic_pattern_analyzer import TrafficPatternAnalyzer, TrafficAnalysisResult
from source_ip_intelligence import SourceIPIntelligenceAnalyzer, SourceIntelligenceResult
from attack_vector_classifier import AttackVectorClassifier, AttackClassificationResult
from impact_assessment import ImpactAssessmentAnalyzer, ImpactAssessmentResult
from mitigation_effectiveness import MitigationEffectivenessAnalyzer, MitigationEffectivenessResult
from threat_attribution import ThreatAttributionAnalyzer, ThreatAttributionResult

# Configure logger
logger = logging.getLogger(__name__)

class DDoSDefenseAgentStatus(Enum):
    """DDoS Defense Agent status levels"""
    IDLE = "idle"
    ANALYZING = "analyzing"
    MITIGATING = "mitigating"
    REPORTING = "reporting"
    ERROR = "error"

@dataclass
class DDoSAnalysisRequest:
    """Request for DDoS analysis"""
    request_id: str
    request_timestamp: datetime
    traffic_data: Dict[str, Any]
    azure_monitor_data: Dict[str, Any]
    network_security_logs: Dict[str, Any]
    application_logs: Dict[str, Any]
    priority: str = "normal"
    analysis_scope: List[str] = None

@dataclass
class DDoSAnalysisResult:
    """Comprehensive DDoS analysis result"""
    analysis_id: str
    request_id: str
    analysis_timestamp: datetime
    completion_timestamp: datetime
    overall_status: str
    threat_level: str
    confidence_score: float
    
    # State results
    traffic_analysis: TrafficAnalysisResult
    source_intelligence: SourceIntelligenceResult
    attack_classification: AttackClassificationResult
    impact_assessment: ImpactAssessmentResult
    mitigation_effectiveness: MitigationEffectivenessResult
    threat_attribution: ThreatAttributionResult
    
    # Summary information
    executive_summary: Dict[str, Any]
    recommendations: List[Dict[str, Any]]
    next_actions: List[str]

class DDoSDefenseAgent:
    """
    DDoS Defense Agent - Complete Analysis Pipeline
    Orchestrates all 6 states of DDoS attack analysis and defense
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the DDoS Defense Agent
        
        Args:
            config: Configuration dictionary for the agent
        """
        self.config = config or self._get_default_config()
        self.status = DDoSDefenseAgentStatus.IDLE
        self.analysis_history = []
        
        # Initialize all state analyzers
        self.traffic_analyzer = TrafficPatternAnalyzer()
        self.source_intelligence_analyzer = SourceIPIntelligenceAnalyzer()
        self.attack_classifier = AttackVectorClassifier()
        self.impact_assessor = ImpactAssessmentAnalyzer()
        self.mitigation_analyzer = MitigationEffectivenessAnalyzer()
        self.attribution_analyzer = ThreatAttributionAnalyzer()
        
        logger.info("DDoS Defense Agent initialized successfully")
    
    async def analyze_ddos_threat(self, request: DDoSAnalysisRequest) -> DDoSAnalysisResult:
        """
        Perform comprehensive DDoS threat analysis
        
        Args:
            request: DDoS analysis request
            
        Returns:
            Complete DDoS analysis results
        """
        logger.info(f"Starting DDoS threat analysis for request: {request.request_id}")
        
        analysis_id = f"ddos-analysis-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        start_time = datetime.now()
        
        try:
            self.status = DDoSDefenseAgentStatus.ANALYZING
            
            # State 1: Traffic Pattern Analysis
            logger.info("State 1: Analyzing traffic patterns")
            traffic_analysis = await self._analyze_traffic_patterns(
                request.traffic_data, request.azure_monitor_data
            )
            
            # State 2: Source IP Intelligence
            logger.info("State 2: Analyzing source IP intelligence")
            source_intelligence = await self._analyze_source_intelligence(
                traffic_analysis, request.network_security_logs
            )
            
            # State 3: Attack Vector Classification
            logger.info("State 3: Classifying attack vectors")
            attack_classification = await self._classify_attack_vectors(
                traffic_analysis, source_intelligence, request.azure_monitor_data
            )
            
            # State 4: Impact Assessment
            logger.info("State 4: Assessing impact")
            impact_assessment = await self._assess_impact(
                attack_classification, request.application_logs, source_intelligence
            )
            
            # State 5: Mitigation Effectiveness
            logger.info("State 5: Analyzing mitigation effectiveness")
            mitigation_effectiveness = await self._analyze_mitigation_effectiveness(
                attack_classification, impact_assessment, request.azure_monitor_data
            )
            
            # State 6: Threat Attribution
            logger.info("State 6: Performing threat attribution")
            threat_attribution = await self._perform_threat_attribution(
                attack_classification, source_intelligence, mitigation_effectiveness
            )
            
            # Generate comprehensive analysis result
            result = await self._compile_analysis_result(
                analysis_id, request, start_time,
                traffic_analysis, source_intelligence, attack_classification,
                impact_assessment, mitigation_effectiveness, threat_attribution
            )
            
            self.status = DDoSDefenseAgentStatus.IDLE
            self.analysis_history.append(result)
            
            logger.info(f"DDoS threat analysis completed: {analysis_id}")
            return result
            
        except Exception as e:
            self.status = DDoSDefenseAgentStatus.ERROR
            logger.error(f"Error in DDoS threat analysis: {str(e)}")
            raise
    
    async def generate_comprehensive_report(self, analysis_result: DDoSAnalysisResult) -> Dict[str, Any]:
        """
        Generate comprehensive DDoS analysis report
        
        Args:
            analysis_result: Complete DDoS analysis results
            
        Returns:
            Comprehensive analysis report
        """
        logger.info(f"Generating comprehensive DDoS report for: {analysis_result.analysis_id}")
        
        try:
            self.status = DDoSDefenseAgentStatus.REPORTING
            
            # Generate individual state reports
            traffic_report = self.traffic_analyzer.generate_traffic_analysis_report(
                analysis_result.traffic_analysis,
                {},  # baseline_comparison
                {},  # anomaly_analysis
                {}   # threat_indicators
            )
            
            source_intel_report = self.source_intelligence_analyzer.generate_source_intelligence_report(
                analysis_result.source_intelligence,
                {},  # geographic_analysis
                {},  # reputation_analysis
                {}   # threat_correlation
            )
            
            attack_classification_report = self.attack_classifier.generate_attack_classification_report(
                analysis_result.attack_classification,
                {},  # volumetric_analysis
                {},  # protocol_analysis
                {}   # application_analysis
            )
            
            impact_report = self.impact_assessor.generate_impact_assessment_report(
                analysis_result.impact_assessment,
                {},  # availability_analysis
                {},  # degradation_analysis
                {},  # financial_analysis
                {}   # customer_analysis
            )
            
            mitigation_report = self.mitigation_analyzer.generate_mitigation_effectiveness_report(
                analysis_result.mitigation_effectiveness,
                {},  # ddos_analysis
                {},  # waf_analysis
                {},  # cdn_analysis
                {}   # optimization
            )
            
            attribution_report = self.attribution_analyzer.generate_threat_attribution_report(
                analysis_result.threat_attribution,
                {},  # pattern_analysis
                {},  # historical_correlation
                []   # actor_profiles
            )
            
            # Compile comprehensive report
            comprehensive_report = {
                "report_metadata": {
                    "report_id": f"DDOS-COMPREHENSIVE-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                    "analysis_id": analysis_result.analysis_id,
                    "generation_timestamp": datetime.now(),
                    "report_type": "comprehensive_ddos_analysis",
                    "threat_level": analysis_result.threat_level,
                    "confidence_score": analysis_result.confidence_score
                },
                "executive_summary": self._create_executive_summary(analysis_result),
                "attack_overview": self._create_attack_overview(analysis_result),
                "detailed_analysis": {
                    "traffic_analysis": traffic_report,
                    "source_intelligence": source_intel_report,
                    "attack_classification": attack_classification_report,
                    "impact_assessment": impact_report,
                    "mitigation_effectiveness": mitigation_report,
                    "threat_attribution": attribution_report
                },
                "risk_assessment": self._create_risk_assessment(analysis_result),
                "mitigation_recommendations": self._create_mitigation_recommendations(analysis_result),
                "lessons_learned": self._extract_lessons_learned(analysis_result),
                "next_actions": analysis_result.next_actions,
                "appendices": {
                    "technical_details": self._compile_technical_details(analysis_result),
                    "data_sources": self._document_data_sources(analysis_result),
                    "analysis_timeline": self._create_analysis_timeline(analysis_result)
                }
            }
            
            self.status = DDoSDefenseAgentStatus.IDLE
            
            logger.info(f"Comprehensive DDoS report generated: {comprehensive_report['report_metadata']['report_id']}")
            return comprehensive_report
            
        except Exception as e:
            self.status = DDoSDefenseAgentStatus.ERROR
            logger.error(f"Error generating comprehensive report: {str(e)}")
            raise
    
    async def get_real_time_status(self) -> Dict[str, Any]:
        """
        Get real-time status of DDoS defense systems
        
        Returns:
            Real-time status information
        """
        logger.info("Retrieving real-time DDoS defense status")
        
        try:
            status_info = {
                "agent_status": self.status.value,
                "timestamp": datetime.now(),
                "protection_status": {
                    "azure_ddos_protection": await self._check_azure_ddos_status(),
                    "waf_status": await self._check_waf_status(),
                    "cdn_status": await self._check_cdn_status(),
                    "firewall_status": await self._check_firewall_status()
                },
                "current_metrics": {
                    "traffic_volume": await self._get_current_traffic_volume(),
                    "attack_indicators": await self._get_current_attack_indicators(),
                    "mitigation_status": await self._get_current_mitigation_status()
                },
                "recent_activity": {
                    "recent_analyses": len([a for a in self.analysis_history 
                                          if a.analysis_timestamp > datetime.now() - timedelta(hours=24)]),
                    "last_analysis": self.analysis_history[-1].analysis_timestamp if self.analysis_history else None,
                    "current_threat_level": self._assess_current_threat_level()
                }
            }
            
            return status_info
            
        except Exception as e:
            logger.error(f"Error retrieving real-time status: {str(e)}")
            raise
    
    async def optimize_defense_configuration(self, historical_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Optimize DDoS defense configuration based on historical data
        
        Args:
            historical_data: Historical attack and defense data
            
        Returns:
            Optimization recommendations
        """
        logger.info("Optimizing DDoS defense configuration")
        
        try:
            optimization_result = {
                "optimization_id": f"ddos-opt-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                "analysis_timestamp": datetime.now(),
                "current_configuration": await self._get_current_configuration(),
                "optimization_recommendations": [],
                "expected_improvements": {},
                "implementation_plan": [],
                "risk_assessment": {}
            }
            
            # Analyze historical patterns
            historical_patterns = await self._analyze_historical_patterns(historical_data)
            
            # Generate optimization recommendations
            optimization_result["optimization_recommendations"] = await self._generate_optimization_recommendations(
                historical_patterns, optimization_result["current_configuration"]
            )
            
            # Assess expected improvements
            optimization_result["expected_improvements"] = await self._assess_expected_improvements(
                optimization_result["optimization_recommendations"]
            )
            
            # Create implementation plan
            optimization_result["implementation_plan"] = await self._create_implementation_plan(
                optimization_result["optimization_recommendations"]
            )
            
            # Assess risks
            optimization_result["risk_assessment"] = await self._assess_optimization_risks(
                optimization_result["optimization_recommendations"]
            )
            
            logger.info(f"Defense configuration optimization completed: {optimization_result['optimization_id']}")
            return optimization_result
            
        except Exception as e:
            logger.error(f"Error optimizing defense configuration: {str(e)}")
            raise
    
    def get_analysis_history(self, limit: int = 10) -> List[DDoSAnalysisResult]:
        """
        Get recent analysis history
        
        Args:
            limit: Maximum number of results to return
            
        Returns:
            List of recent analysis results
        """
        return sorted(self.analysis_history, 
                     key=lambda x: x.analysis_timestamp, 
                     reverse=True)[:limit]
    
    def get_agent_metrics(self) -> Dict[str, Any]:
        """
        Get agent performance metrics
        
        Returns:
            Agent performance metrics
        """
        total_analyses = len(self.analysis_history)
        if total_analyses == 0:
            return {"total_analyses": 0, "average_analysis_time": 0, "success_rate": 0}
        
        # Calculate metrics
        successful_analyses = len([a for a in self.analysis_history if a.overall_status == "completed"])
        success_rate = (successful_analyses / total_analyses) * 100
        
        # Calculate average analysis time (if available)
        analysis_times = []
        for analysis in self.analysis_history:
            if hasattr(analysis, 'completion_timestamp') and analysis.completion_timestamp:
                duration = analysis.completion_timestamp - analysis.analysis_timestamp
                analysis_times.append(duration.total_seconds())
        
        avg_analysis_time = sum(analysis_times) / len(analysis_times) if analysis_times else 0
        
        return {
            "total_analyses": total_analyses,
            "successful_analyses": successful_analyses,
            "success_rate": success_rate,
            "average_analysis_time_seconds": avg_analysis_time,
            "current_status": self.status.value,
            "agent_uptime": datetime.now(),  # Simplified - would track actual uptime
            "threat_levels_detected": self._get_threat_level_distribution()
        }
    
    # Internal methods for state execution
    async def _analyze_traffic_patterns(self, traffic_data: Dict[str, Any], 
                                       azure_data: Dict[str, Any]) -> TrafficAnalysisResult:
        """Execute State 1: Traffic Pattern Analysis"""
        return self.traffic_analyzer.analyze_traffic_patterns(
            azure_data.get("ddos_protection_metrics", {}),
            traffic_data.get("baseline_data", {}),
            azure_data.get("network_analytics", {})
        )
    
    async def _analyze_source_intelligence(self, traffic_analysis: TrafficAnalysisResult,
                                         network_logs: Dict[str, Any]) -> SourceIntelligenceResult:
        """Execute State 2: Source IP Intelligence"""
        return self.source_intelligence_analyzer.analyze_source_intelligence(
            {"traffic_data": asdict(traffic_analysis)},
            network_logs.get("firewall_logs", []),
            network_logs.get("flow_logs", [])
        )
    
    async def _classify_attack_vectors(self, traffic_analysis: TrafficAnalysisResult,
                                     source_intelligence: SourceIntelligenceResult,
                                     azure_data: Dict[str, Any]) -> AttackClassificationResult:
        """Execute State 3: Attack Vector Classification"""
        return self.attack_classifier.classify_attack_vectors(
            asdict(traffic_analysis),
            asdict(source_intelligence),
            azure_data
        )
    
    async def _assess_impact(self, attack_classification: AttackClassificationResult,
                           app_logs: Dict[str, Any],
                           source_intelligence: SourceIntelligenceResult) -> ImpactAssessmentResult:
        """Execute State 4: Impact Assessment"""
        return self.impact_assessor.assess_ddos_impact(
            asdict(attack_classification),
            app_logs.get("service_metrics", {}),
            app_logs.get("business_metrics", {})
        )
    
    async def _analyze_mitigation_effectiveness(self, attack_classification: AttackClassificationResult,
                                              impact_assessment: ImpactAssessmentResult,
                                              azure_data: Dict[str, Any]) -> MitigationEffectivenessResult:
        """Execute State 5: Mitigation Effectiveness"""
        return self.mitigation_analyzer.analyze_mitigation_effectiveness(
            asdict(attack_classification),
            asdict(impact_assessment),
            azure_data.get("protection_logs", {})
        )
    
    async def _perform_threat_attribution(self, attack_classification: AttackClassificationResult,
                                        source_intelligence: SourceIntelligenceResult,
                                        mitigation_analysis: MitigationEffectivenessResult) -> ThreatAttributionResult:
        """Execute State 6: Threat Attribution"""
        return self.attribution_analyzer.perform_threat_attribution(
            asdict(attack_classification),
            asdict(source_intelligence),
            asdict(attack_classification),
            asdict(mitigation_analysis)
        )
    
    async def _compile_analysis_result(self, analysis_id: str, request: DDoSAnalysisRequest,
                                     start_time: datetime, *state_results) -> DDoSAnalysisResult:
        """Compile all state results into comprehensive analysis result"""
        (traffic_analysis, source_intelligence, attack_classification,
         impact_assessment, mitigation_effectiveness, threat_attribution) = state_results
        
        # Determine overall threat level and confidence
        threat_level = self._determine_threat_level(attack_classification, impact_assessment)
        confidence_score = self._calculate_overall_confidence(*state_results)
        
        # Generate executive summary
        executive_summary = self._create_executive_summary_from_states(*state_results)
        
        # Generate recommendations
        recommendations = self._generate_recommendations_from_states(*state_results)
        
        # Determine next actions
        next_actions = self._determine_next_actions(threat_level, impact_assessment, mitigation_effectiveness)
        
        return DDoSAnalysisResult(
            analysis_id=analysis_id,
            request_id=request.request_id,
            analysis_timestamp=start_time,
            completion_timestamp=datetime.now(),
            overall_status="completed",
            threat_level=threat_level,
            confidence_score=confidence_score,
            traffic_analysis=traffic_analysis,
            source_intelligence=source_intelligence,
            attack_classification=attack_classification,
            impact_assessment=impact_assessment,
            mitigation_effectiveness=mitigation_effectiveness,
            threat_attribution=threat_attribution,
            executive_summary=executive_summary,
            recommendations=recommendations,
            next_actions=next_actions
        )
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for the agent"""
        return {
            "analysis_timeout": 1800,  # 30 minutes
            "confidence_threshold": 0.7,
            "threat_level_thresholds": {
                "critical": 0.9,
                "high": 0.7,
                "medium": 0.5,
                "low": 0.3
            },
            "azure_integration": {
                "ddos_protection": True,
                "application_gateway": True,
                "firewall": True,
                "cdn": True
            },
            "threat_intelligence_feeds": [
                "microsoft_defender_ti",
                "azure_sentinel",
                "third_party_feeds"
            ]
        }
    
    # Placeholder implementations for various helper methods
    def _determine_threat_level(self, attack_classification: AttackClassificationResult,
                              impact_assessment: ImpactAssessmentResult) -> str:
        """Determine overall threat level"""
        # Simplified logic - would be more sophisticated in production
        severity_mapping = {
            "critical": "critical",
            "high": "high", 
            "medium": "medium",
            "low": "low"
        }
        return severity_mapping.get(attack_classification.overall_severity.value, "medium")
    
    def _calculate_overall_confidence(self, *state_results) -> float:
        """Calculate overall confidence score"""
        confidence_scores = [getattr(result, 'confidence_score', 0.5) for result in state_results]
        return sum(confidence_scores) / len(confidence_scores)
    
    def _create_executive_summary_from_states(self, *state_results) -> Dict[str, Any]:
        """Create executive summary from state results"""
        return {
            "attack_detected": True,
            "threat_level": "high", 
            "primary_attack_vectors": ["volumetric"],
            "impact_summary": "Service degradation detected",
            "mitigation_status": "partially_effective",
            "attribution_confidence": "medium"
        }
    
    def _generate_recommendations_from_states(self, *state_results) -> List[Dict[str, Any]]:
        """Generate recommendations from state results"""
        return [
            {"priority": "high", "action": "Enhance DDoS protection thresholds"},
            {"priority": "medium", "action": "Review source IP filtering rules"},
            {"priority": "low", "action": "Update threat intelligence feeds"}
        ]
    
    def _determine_next_actions(self, threat_level: str, impact_assessment: ImpactAssessmentResult,
                              mitigation_effectiveness: MitigationEffectivenessResult) -> List[str]:
        """Determine next actions based on analysis results"""
        actions = [
            "Monitor ongoing mitigation effectiveness",
            "Update security team on current threat status",
            "Review and adjust protection policies"
        ]
        
        if threat_level in ["critical", "high"]:
            actions.insert(0, "Escalate to incident response team")
            
        return actions
    
    # Placeholder implementations for status and optimization methods
    async def _check_azure_ddos_status(self) -> Dict[str, Any]:
        return {"status": "active", "protection_level": "standard"}
    
    async def _check_waf_status(self) -> Dict[str, Any]:
        return {"status": "active", "rules_count": 150}
    
    async def _check_cdn_status(self) -> Dict[str, Any]:
        return {"status": "active", "cache_hit_ratio": 85.0}
    
    async def _check_firewall_status(self) -> Dict[str, Any]:
        return {"status": "active", "policies_active": 25}
    
    async def _get_current_traffic_volume(self) -> Dict[str, Any]:
        return {"requests_per_second": 1000, "bytes_per_second": 10000000}
    
    async def _get_current_attack_indicators(self) -> List[str]:
        return ["elevated_traffic", "geographic_anomaly"]
    
    async def _get_current_mitigation_status(self) -> Dict[str, Any]:
        return {"active_mitigations": 3, "effectiveness": 85.0}
    
    def _assess_current_threat_level(self) -> str:
        return "medium"
    
    def _get_threat_level_distribution(self) -> Dict[str, int]:
        """Get distribution of threat levels from analysis history"""
        distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for analysis in self.analysis_history:
            distribution[analysis.threat_level] = distribution.get(analysis.threat_level, 0) + 1
        return distribution
    
    # Additional placeholder methods for optimization and reporting
    async def _get_current_configuration(self) -> Dict[str, Any]:
        return {"ddos_thresholds": {}, "waf_rules": {}, "firewall_policies": {}}
    
    async def _analyze_historical_patterns(self, historical_data: Dict[str, Any]) -> Dict[str, Any]:
        return {"common_attack_patterns": [], "seasonal_trends": {}}
    
    async def _generate_optimization_recommendations(self, patterns: Dict[str, Any], 
                                                   config: Dict[str, Any]) -> List[Dict[str, Any]]:
        return []
    
    async def _assess_expected_improvements(self, recommendations: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {"performance_improvement": 15.0, "cost_savings": 5000.0}
    
    async def _create_implementation_plan(self, recommendations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return []
    
    async def _assess_optimization_risks(self, recommendations: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {"risk_level": "low", "potential_issues": []}
    
    def _create_executive_summary(self, analysis_result: DDoSAnalysisResult) -> Dict[str, Any]:
        return {}
    
    def _create_attack_overview(self, analysis_result: DDoSAnalysisResult) -> Dict[str, Any]:
        return {}
    
    def _create_risk_assessment(self, analysis_result: DDoSAnalysisResult) -> Dict[str, Any]:
        return {}
    
    def _create_mitigation_recommendations(self, analysis_result: DDoSAnalysisResult) -> List[Dict[str, Any]]:
        return []
    
    def _extract_lessons_learned(self, analysis_result: DDoSAnalysisResult) -> List[Dict[str, Any]]:
        return []
    
    def _compile_technical_details(self, analysis_result: DDoSAnalysisResult) -> Dict[str, Any]:
        return {}
    
    def _document_data_sources(self, analysis_result: DDoSAnalysisResult) -> Dict[str, Any]:
        return {}
    
    def _create_analysis_timeline(self, analysis_result: DDoSAnalysisResult) -> List[Dict[str, Any]]:
        return []
