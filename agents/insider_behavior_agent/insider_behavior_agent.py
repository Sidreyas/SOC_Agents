"""
Insider Behavior Agent Main Module
Orchestrates the 5-state workflow for insider threat detection and analysis
Use Cases: #9 (Anomalous user behavior), #15 (Insider threat detection), #21 (Employee activity monitoring)
"""

import logging
from typing import Dict, Any, List
from datetime import datetime
import json

from .behavioral_extractor import BehavioralExtractor
from .anomaly_detector import AnomalyDetector
from .contextual_enricher import ContextualEnricher
from .risk_correlator import RiskCorrelator
from .threat_classifier import ThreatClassifier

logger = logging.getLogger(__name__)

class InsiderBehaviorAgent:
    """
    Main orchestrator for insider behavior analysis and threat detection
    Implements 5-state workflow: Behavioral Pattern Extraction -> Anomaly Detection -> 
    Contextual Enrichment -> Risk Correlation -> Threat Classification
    """
    
    def __init__(self):
        self.behavioral_extractor = BehavioralExtractor()
        self.anomaly_detector = AnomalyDetector()
        self.contextual_enricher = ContextualEnricher()
        self.risk_correlator = RiskCorrelator()
        self.threat_classifier = ThreatClassifier()
        
        # Workflow state tracking
        self.current_state = "initialized"
        self.workflow_history = []
        self.analysis_context = {}
        
    def analyze_insider_behavior(self, alert_data: Dict[str, Any], user_activity_data: Dict[str, Any], organizational_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point for insider behavior analysis
        
        Args:
            alert_data: Alert data from security systems
            user_activity_data: User activity logs and behavior data
            organizational_data: Organizational context including HR data
            
        Returns:
            Comprehensive insider behavior analysis results
        """
        logger.info("Starting insider behavior analysis workflow")
        
        workflow_results = {
            "workflow_metadata": {
                "analysis_id": f"insider_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                "start_time": datetime.now(),
                "workflow_version": "1.0",
                "use_cases": ["anomalous_user_behavior", "insider_threat_detection", "employee_activity_monitoring"]
            },
            "state_results": {},
            "final_assessment": {},
            "recommendations": {},
            "investigation_packages": {}
        }
        
        try:
            # State 1: Behavioral Pattern Extraction
            logger.info("Executing State 1: Behavioral Pattern Extraction")
            self.current_state = "behavioral_extraction"
            
            state1_results = self._execute_behavioral_extraction(
                alert_data, user_activity_data, organizational_data
            )
            workflow_results["state_results"]["state1_behavioral_extraction"] = state1_results
            
            # State 2: Anomaly Detection
            logger.info("Executing State 2: Anomaly Detection")
            self.current_state = "anomaly_detection"
            
            state2_results = self._execute_anomaly_detection(
                state1_results, user_activity_data
            )
            workflow_results["state_results"]["state2_anomaly_detection"] = state2_results
            
            # State 3: Contextual Enrichment
            logger.info("Executing State 3: Contextual Enrichment")
            self.current_state = "contextual_enrichment"
            
            state3_results = self._execute_contextual_enrichment(
                state2_results, organizational_data
            )
            workflow_results["state_results"]["state3_contextual_enrichment"] = state3_results
            
            # State 4: Risk Correlation
            logger.info("Executing State 4: Risk Correlation")
            self.current_state = "risk_correlation"
            
            state4_results = self._execute_risk_correlation(
                state3_results, organizational_data
            )
            workflow_results["state_results"]["state4_risk_correlation"] = state4_results
            
            # State 5: Threat Classification
            logger.info("Executing State 5: Threat Classification")
            self.current_state = "threat_classification"
            
            state5_results = self._execute_threat_classification(
                state4_results, organizational_data
            )
            workflow_results["state_results"]["state5_threat_classification"] = state5_results
            
            # Generate final assessment
            workflow_results["final_assessment"] = self._generate_final_assessment(
                workflow_results["state_results"]
            )
            
            # Generate recommendations
            workflow_results["recommendations"] = self._generate_recommendations(
                workflow_results["state_results"], workflow_results["final_assessment"]
            )
            
            # Create investigation packages
            workflow_results["investigation_packages"] = self._create_investigation_packages(
                workflow_results["state_results"], alert_data
            )
            
            # Update workflow metadata
            workflow_results["workflow_metadata"]["end_time"] = datetime.now()
            workflow_results["workflow_metadata"]["workflow_status"] = "completed"
            workflow_results["workflow_metadata"]["analysis_duration"] = (
                workflow_results["workflow_metadata"]["end_time"] - 
                workflow_results["workflow_metadata"]["start_time"]
            ).total_seconds()
            
            self.current_state = "completed"
            logger.info("Insider behavior analysis workflow completed successfully")
            
        except Exception as e:
            logger.error(f"Error in insider behavior analysis workflow: {str(e)}")
            workflow_results["workflow_metadata"]["workflow_status"] = "failed"
            workflow_results["workflow_metadata"]["error"] = str(e)
            self.current_state = "failed"
            raise
        
        return workflow_results
    
    def _execute_behavioral_extraction(self, alert_data: Dict[str, Any], user_activity_data: Dict[str, Any], organizational_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute State 1: Behavioral Pattern Extraction"""
        logger.info("Executing behavioral pattern extraction")
        
        # Extract authentication patterns
        auth_patterns = self.behavioral_extractor.extract_authentication_patterns(
            user_activity_data.get("authentication_logs", {}),
            organizational_data.get("baseline_data", {})
        )
        
        # Extract file access patterns
        file_patterns = self.behavioral_extractor.extract_file_access_patterns(
            user_activity_data.get("file_access_logs", {}),
            organizational_data.get("file_classifications", {})
        )
        
        # Extract email patterns
        email_patterns = self.behavioral_extractor.extract_email_patterns(
            user_activity_data.get("email_logs", {}),
            organizational_data.get("communication_policies", {})
        )
        
        # Extract application usage patterns
        app_patterns = self.behavioral_extractor.extract_application_patterns(
            user_activity_data.get("application_logs", {}),
            organizational_data.get("approved_applications", {})
        )
        
        # Combine all patterns
        extraction_results = {
            "authentication_patterns": auth_patterns,
            "file_access_patterns": file_patterns,
            "email_patterns": email_patterns,
            "application_patterns": app_patterns,
            "extraction_metadata": {
                "extraction_timestamp": datetime.now(),
                "data_sources_processed": len(user_activity_data),
                "patterns_extracted": 4,
                "extraction_quality": self._assess_extraction_quality(auth_patterns, file_patterns, email_patterns, app_patterns)
            }
        }
        
        logger.info("Behavioral pattern extraction completed")
        return extraction_results
    
    def _execute_anomaly_detection(self, behavioral_patterns: Dict[str, Any], user_activity_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute State 2: Anomaly Detection"""
        logger.info("Executing anomaly detection on behavioral patterns")
        
        # Perform statistical analysis
        statistical_analysis = self.anomaly_detector.perform_statistical_analysis(
            behavioral_patterns,
            user_activity_data.get("historical_data", {})
        )
        
        # Apply machine learning models
        ml_analysis = self.anomaly_detector.apply_ml_models(
            behavioral_patterns,
            user_activity_data.get("training_data", {})
        )
        
        # Detect baseline deviations
        deviation_analysis = self.anomaly_detector.detect_baseline_deviations(
            behavioral_patterns,
            user_activity_data.get("baseline_data", {})
        )
        
        # Calculate anomaly scores
        anomaly_scores = self.anomaly_detector.calculate_anomaly_scores(
            statistical_analysis, ml_analysis, deviation_analysis
        )
        
        # Combine all anomaly detection results
        anomaly_results = {
            "statistical_analysis": statistical_analysis,
            "ml_analysis": ml_analysis,
            "deviation_analysis": deviation_analysis,
            "anomaly_scores": anomaly_scores,
            "detection_metadata": {
                "detection_timestamp": datetime.now(),
                "models_applied": ["statistical", "isolation_forest", "one_class_svm", "ensemble"],
                "users_analyzed": len(anomaly_scores),
                "anomalies_detected": self._count_anomalies(anomaly_scores),
                "detection_confidence": self._calculate_detection_confidence(statistical_analysis, ml_analysis)
            }
        }
        
        logger.info("Anomaly detection completed")
        return anomaly_results
    
    def _execute_contextual_enrichment(self, anomaly_results: Dict[str, Any], organizational_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute State 3: Contextual Enrichment"""
        logger.info("Executing contextual enrichment")
        
        # Add organizational context
        organizational_context = self.contextual_enricher.add_organizational_context(
            anomaly_results,
            organizational_data.get("hr_data", {}),
            organizational_data.get("organizational_structure", {})
        )
        
        # Correlate with external sources
        external_correlations = self.contextual_enricher.correlate_external_sources(
            organizational_context,
            organizational_data.get("threat_intelligence", {}),
            organizational_data.get("industry_data", {})
        )
        
        # Perform user profiling
        user_profiles = self.contextual_enricher.perform_user_profiling(
            organizational_data.get("user_data", {}),
            anomaly_results,
            organizational_context
        )
        
        # Add temporal context
        temporal_context = self.contextual_enricher.enrich_with_temporal_context(
            anomaly_results,
            organizational_data.get("temporal_events", {})
        )
        
        # Combine all enrichment results
        enrichment_results = {
            "organizational_context": organizational_context,
            "external_correlations": external_correlations,
            "user_profiles": user_profiles,
            "temporal_context": temporal_context,
            "enrichment_metadata": {
                "enrichment_timestamp": datetime.now(),
                "context_sources": ["organizational", "external", "temporal"],
                "users_enriched": len(user_profiles.get("risk_profiles", {})),
                "enrichment_coverage": self._calculate_enrichment_coverage(organizational_context, external_correlations)
            }
        }
        
        logger.info("Contextual enrichment completed")
        return enrichment_results
    
    def _execute_risk_correlation(self, enriched_analysis: Dict[str, Any], organizational_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute State 4: Risk Correlation"""
        logger.info("Executing risk correlation analysis")
        
        # Correlate risk indicators
        risk_correlations = self.risk_correlator.correlate_risk_indicators(
            enriched_analysis.get("organizational_context", {}),
            enriched_analysis.get("external_correlations", {}),
            enriched_analysis.get("user_profiles", {})
        )
        
        # Calculate composite scores
        composite_scores = self.risk_correlator.calculate_composite_scores(
            risk_correlations,
            organizational_data.get("correlation_weights", {})
        )
        
        # Analyze risk patterns
        risk_patterns = self.risk_correlator.analyze_risk_patterns(
            risk_correlations,
            organizational_data.get("historical_risk_data", {})
        )
        
        # Prioritize risks
        risk_prioritization = self.risk_correlator.prioritize_risks(
            composite_scores,
            enriched_analysis.get("organizational_context", {})
        )
        
        # Calculate correlation confidence
        correlation_confidence = self.risk_correlator.calculate_correlation_confidence(
            risk_correlations
        )
        
        # Combine all correlation results
        correlation_results = {
            "risk_correlations": risk_correlations,
            "composite_scores": composite_scores,
            "risk_patterns": risk_patterns,
            "risk_prioritization": risk_prioritization,
            "correlation_confidence": correlation_confidence,
            "correlation_metadata": {
                "correlation_timestamp": datetime.now(),
                "correlation_algorithms": ["individual", "cross_user", "temporal", "organizational"],
                "users_correlated": len(composite_scores.get("user_composite_scores", {})),
                "high_priority_users": len(risk_prioritization.get("high_priority_users", {})),
                "overall_correlation_confidence": correlation_confidence.get("overall_confidence", 0.0)
            }
        }
        
        logger.info("Risk correlation analysis completed")
        return correlation_results
    
    def _execute_threat_classification(self, correlation_results: Dict[str, Any], organizational_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute State 5: Threat Classification"""
        logger.info("Executing threat classification")
        
        # Classify insider threats
        threat_classifications = self.threat_classifier.classify_insider_threats(
            correlation_results.get("risk_correlations", {}),
            correlation_results.get("risk_prioritization", {})
        )
        
        # Generate threat intelligence
        threat_intelligence = self.threat_classifier.generate_threat_intelligence(
            threat_classifications,
            organizational_data
        )
        
        # Create investigation packages
        investigation_packages = self.threat_classifier.create_investigation_packages(
            threat_classifications,
            correlation_results
        )
        
        # Generate classification reports
        classification_reports = self.threat_classifier.generate_classification_reports(
            threat_classifications,
            threat_intelligence
        )
        
        # Update threat models
        model_updates = self.threat_classifier.update_threat_models(
            threat_classifications,
            organizational_data.get("feedback_data", {})
        )
        
        # Combine all classification results
        classification_results = {
            "threat_classifications": threat_classifications,
            "threat_intelligence": threat_intelligence,
            "investigation_packages": investigation_packages,
            "classification_reports": classification_reports,
            "model_updates": model_updates,
            "classification_metadata": {
                "classification_timestamp": datetime.now(),
                "users_classified": len(threat_classifications.get("user_classifications", {})),
                "high_risk_threats": len(threat_classifications.get("user_classifications", {})),
                "investigation_packages_created": len(investigation_packages.get("high_priority_investigations", [])),
                "classification_confidence": threat_intelligence.get("kpi_metrics", {}).get("overall_confidence", 0.0)
            }
        }
        
        logger.info("Threat classification completed")
        return classification_results
    
    def _generate_final_assessment(self, state_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate final assessment from all workflow states"""
        logger.info("Generating final assessment")
        
        # Extract key metrics from each state
        extraction_quality = state_results.get("state1_behavioral_extraction", {}).get("extraction_metadata", {}).get("extraction_quality", 0.0)
        anomalies_detected = state_results.get("state2_anomaly_detection", {}).get("detection_metadata", {}).get("anomalies_detected", 0)
        users_enriched = state_results.get("state3_contextual_enrichment", {}).get("enrichment_metadata", {}).get("users_enriched", 0)
        high_priority_users = state_results.get("state4_risk_correlation", {}).get("correlation_metadata", {}).get("high_priority_users", 0)
        classification_confidence = state_results.get("state5_threat_classification", {}).get("classification_metadata", {}).get("classification_confidence", 0.0)
        
        # Get threat classifications
        threat_classifications = state_results.get("state5_threat_classification", {}).get("threat_classifications", {})
        user_classifications = threat_classifications.get("user_classifications", {})
        
        # Count threat types
        threat_type_counts = {}
        for user, classification in user_classifications.items():
            threat_type = classification.get("primary_threat_type", "unknown")
            threat_type_counts[threat_type] = threat_type_counts.get(threat_type, 0) + 1
        
        final_assessment = {
            "overall_risk_level": self._determine_overall_risk_level(high_priority_users, users_enriched),
            "confidence_score": classification_confidence,
            "threat_summary": {
                "total_users_analyzed": users_enriched,
                "anomalies_detected": anomalies_detected,
                "high_priority_threats": high_priority_users,
                "threat_type_distribution": threat_type_counts,
                "most_common_threat": max(threat_type_counts.items(), key=lambda x: x[1])[0] if threat_type_counts else "none"
            },
            "key_findings": self._extract_key_findings(state_results),
            "risk_indicators": self._summarize_risk_indicators(state_results),
            "organizational_impact": self._assess_organizational_impact(state_results),
            "assessment_quality": {
                "data_completeness": extraction_quality,
                "analysis_confidence": classification_confidence,
                "coverage_score": users_enriched / max(users_enriched, 1)
            }
        }
        
        logger.info("Final assessment generated")
        return final_assessment
    
    def _generate_recommendations(self, state_results: Dict[str, Any], final_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive recommendations"""
        logger.info("Generating comprehensive recommendations")
        
        # Get threat classifications and intelligence
        threat_classifications = state_results.get("state5_threat_classification", {}).get("threat_classifications", {})
        threat_intelligence = state_results.get("state5_threat_classification", {}).get("threat_intelligence", {})
        
        recommendations = {
            "immediate_actions": [],
            "short_term_actions": [],
            "long_term_actions": [],
            "monitoring_enhancements": [],
            "policy_recommendations": [],
            "training_recommendations": [],
            "technology_recommendations": []
        }
        
        # Extract recommended actions from threat classifications
        user_classifications = threat_classifications.get("user_classifications", {})
        recommended_actions = threat_classifications.get("recommended_actions", {})
        
        # Consolidate immediate actions
        for user, actions in recommended_actions.items():
            recommendations["immediate_actions"].extend(actions.get("immediate_actions", []))
            recommendations["short_term_actions"].extend(actions.get("short_term_actions", []))
            recommendations["monitoring_enhancements"].extend(actions.get("monitoring_recommendations", []))
        
        # Remove duplicates
        recommendations["immediate_actions"] = list(set(recommendations["immediate_actions"]))
        recommendations["short_term_actions"] = list(set(recommendations["short_term_actions"]))
        recommendations["monitoring_enhancements"] = list(set(recommendations["monitoring_enhancements"]))
        
        # Add strategic recommendations based on threat intelligence
        mitigation_strategies = threat_intelligence.get("mitigation_strategies", {})
        recommendations["long_term_actions"].extend(mitigation_strategies.get("long_term_mitigations", []))
        
        # Add organizational recommendations
        organizational_vulnerabilities = threat_intelligence.get("organizational_vulnerabilities", {})
        
        if organizational_vulnerabilities.get("policy_gaps"):
            recommendations["policy_recommendations"].extend([
                "Update data handling policies",
                "Strengthen remote access policies",
                "Implement insider threat policies"
            ])
        
        if organizational_vulnerabilities.get("training_needs"):
            recommendations["training_recommendations"].extend([
                "Enhanced security awareness training",
                "Insider threat awareness training",
                "Data protection training"
            ])
        
        # Add technology recommendations
        monitoring_gaps = organizational_vulnerabilities.get("monitoring_gaps", [])
        if monitoring_gaps:
            recommendations["technology_recommendations"].extend([
                "Implement advanced behavioral analytics",
                "Deploy data loss prevention tools",
                "Enhance user activity monitoring"
            ])
        
        logger.info("Comprehensive recommendations generated")
        return recommendations
    
    def _create_investigation_packages(self, state_results: Dict[str, Any], alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create investigation packages for high-priority threats"""
        logger.info("Creating investigation packages")
        
        # Get investigation packages from threat classification
        classification_investigation_packages = state_results.get("state5_threat_classification", {}).get("investigation_packages", {})
        
        # Get high priority users
        high_priority_users = classification_investigation_packages.get("high_priority_investigations", [])
        
        investigation_packages = {
            "total_packages": len(high_priority_users),
            "packages": {},
            "investigation_summary": {},
            "resource_allocation": {}
        }
        
        # Create detailed packages for each high-priority user
        for user in high_priority_users:
            user_evidence = classification_investigation_packages.get("evidence_packages", {}).get(user, {})
            user_procedures = classification_investigation_packages.get("investigation_procedures", {}).get(user, {})
            user_timeline = classification_investigation_packages.get("timeline_recommendations", {}).get(user, {})
            user_resources = classification_investigation_packages.get("resource_requirements", {}).get(user, {})
            
            investigation_packages["packages"][user] = {
                "priority_level": "high",
                "evidence_package": user_evidence,
                "investigation_procedures": user_procedures,
                "timeline": user_timeline,
                "resource_requirements": user_resources,
                "alert_correlation": self._correlate_with_alerts(user, alert_data),
                "package_creation_timestamp": datetime.now()
            }
        
        # Create investigation summary
        investigation_packages["investigation_summary"] = {
            "high_priority_investigations": len(high_priority_users),
            "estimated_investigation_hours": sum([
                pkg.get("resource_requirements", {}).get("estimated_hours", 8) 
                for pkg in investigation_packages["packages"].values()
            ]),
            "required_personnel": list(set([
                person for pkg in investigation_packages["packages"].values()
                for person in pkg.get("resource_requirements", {}).get("personnel", [])
            ])),
            "investigation_categories": list(set([
                pkg.get("evidence_package", {}).get("threat_category", "unknown")
                for pkg in investigation_packages["packages"].values()
            ]))
        }
        
        # Create resource allocation recommendations
        investigation_packages["resource_allocation"] = classification_investigation_packages.get("resource_allocation", {})
        
        logger.info("Investigation packages created")
        return investigation_packages
    
    # Helper methods for assessment and analysis
    def _assess_extraction_quality(self, auth_patterns: Dict, file_patterns: Dict, email_patterns: Dict, app_patterns: Dict) -> float:
        """Assess quality of behavioral pattern extraction"""
        pattern_counts = [
            len(auth_patterns.get("patterns", {})),
            len(file_patterns.get("patterns", {})),
            len(email_patterns.get("patterns", {})),
            len(app_patterns.get("patterns", {}))
        ]
        
        # Calculate quality based on pattern diversity and completeness
        total_patterns = sum(pattern_counts)
        pattern_diversity = len([count for count in pattern_counts if count > 0]) / 4.0
        
        return min(1.0, (total_patterns / 100.0) * pattern_diversity)
    
    def _count_anomalies(self, anomaly_scores: Dict[str, Any]) -> int:
        """Count total anomalies detected"""
        anomaly_count = 0
        for user, scores in anomaly_scores.items():
            if isinstance(scores, dict) and scores.get("risk_level") in ["high", "critical"]:
                anomaly_count += 1
        return anomaly_count
    
    def _calculate_detection_confidence(self, statistical_analysis: Dict, ml_analysis: Dict) -> float:
        """Calculate overall detection confidence"""
        stat_confidence = statistical_analysis.get("analysis_confidence", 0.0)
        ml_confidence = ml_analysis.get("model_confidence", 0.0)
        
        return (stat_confidence + ml_confidence) / 2.0
    
    def _calculate_enrichment_coverage(self, organizational_context: Dict, external_correlations: Dict) -> float:
        """Calculate enrichment coverage score"""
        org_users = len(organizational_context.get("user_profiles", {}))
        ext_users = len(external_correlations.get("contextual_risk_adjustment", {}))
        
        if org_users == 0:
            return 0.0
        
        return min(1.0, ext_users / org_users)
    
    def _determine_overall_risk_level(self, high_priority_users: int, total_users: int) -> str:
        """Determine overall organizational risk level"""
        if total_users == 0:
            return "unknown"
        
        risk_ratio = high_priority_users / total_users
        
        if risk_ratio >= 0.1:
            return "critical"
        elif risk_ratio >= 0.05:
            return "high"
        elif risk_ratio >= 0.02:
            return "medium"
        else:
            return "low"
    
    def _extract_key_findings(self, state_results: Dict[str, Any]) -> List[str]:
        """Extract key findings from analysis"""
        key_findings = []
        
        # Extract from threat intelligence
        threat_intelligence = state_results.get("state5_threat_classification", {}).get("threat_intelligence", {})
        high_risk_insights = threat_intelligence.get("high_risk_insights", {})
        
        if high_risk_insights.get("top_risk_users"):
            key_findings.append(f"Identified {len(high_risk_insights['top_risk_users'])} high-risk users")
        
        if high_risk_insights.get("common_risk_patterns"):
            key_findings.append(f"Common risk patterns: {', '.join(high_risk_insights['common_risk_patterns'][:3])}")
        
        if high_risk_insights.get("department_hotspots"):
            key_findings.append(f"Department risk hotspots: {', '.join(high_risk_insights['department_hotspots'])}")
        
        return key_findings
    
    def _summarize_risk_indicators(self, state_results: Dict[str, Any]) -> List[str]:
        """Summarize key risk indicators"""
        risk_indicators = []
        
        # Extract from anomaly detection
        anomaly_results = state_results.get("state2_anomaly_detection", {})
        statistical_analysis = anomaly_results.get("statistical_analysis", {})
        
        # Mock risk indicators based on statistical analysis
        risk_indicators = [
            "Off-hours access patterns detected",
            "Unusual file download volumes",
            "Anomalous email communication patterns",
            "Deviation from baseline behavior"
        ]
        
        return risk_indicators[:5]  # Return top 5 indicators
    
    def _assess_organizational_impact(self, state_results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess organizational impact of identified threats"""
        return {
            "operational_impact": "medium",
            "financial_impact": "low_to_medium",
            "reputational_impact": "low",
            "regulatory_impact": "medium",
            "data_security_impact": "high"
        }
    
    def _correlate_with_alerts(self, user: str, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate user with original alerts"""
        return {
            "related_alerts": alert_data.get("user_alerts", {}).get(user, []),
            "alert_correlation_score": 0.8,
            "alert_timeframe": "last_30_days",
            "alert_types": ["behavioral_anomaly", "data_access"]
        }
    
    def get_workflow_status(self) -> Dict[str, Any]:
        """Get current workflow status"""
        return {
            "current_state": self.current_state,
            "workflow_history": self.workflow_history,
            "analysis_context": self.analysis_context
        }
    
    def reset_workflow(self):
        """Reset workflow to initial state"""
        self.current_state = "initialized"
        self.workflow_history.clear()
        self.analysis_context.clear()
        logger.info("Workflow reset to initial state")
