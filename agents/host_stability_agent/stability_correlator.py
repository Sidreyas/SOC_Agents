"""
Stability Correlator Module
State 4: Stability Correlation
Correlates host stability issues with security events and threat patterns
"""

import logging
from typing import Dict, Any, List, Tuple, Set
from datetime import datetime, timedelta
import json
from collections import defaultdict
import statistics
from enum import Enum

logger = logging.getLogger(__name__)

class StabilityIndicator(Enum):
    """Enumeration for stability indicators"""
    PERFORMANCE_DEGRADATION = "performance_degradation"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    SERVICE_DISRUPTION = "service_disruption"
    NETWORK_CONNECTIVITY = "network_connectivity"
    APPLICATION_ERRORS = "application_errors"
    SYSTEM_CRASHES = "system_crashes"

class CorrelationStrength(Enum):
    """Enumeration for correlation strength"""
    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"
    NO_CORRELATION = "no_correlation"

class StabilityCorrelator:
    """
    Correlates host stability issues with security events and threat patterns
    Provides comprehensive stability and security correlation analysis
    """
    
    def __init__(self):
        self.correlation_models = self._load_correlation_models()
        self.stability_baselines = {}
        self.correlation_history = []
        
    def correlate_stability_and_security(self, 
                                       lateral_movement_analysis: Dict[str, Any],
                                       endpoint_pattern_analysis: Dict[str, Any],
                                       threat_classification: Dict[str, Any],
                                       system_performance_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Correlate host stability with security events and threats
        
        Args:
            lateral_movement_analysis: Lateral movement detection results
            endpoint_pattern_analysis: Endpoint pattern analysis results
            threat_classification: Threat classification results
            system_performance_data: System performance and stability metrics
            
        Returns:
            Stability-security correlation analysis results
        """
        logger.info("Correlating host stability with security events")
        
        correlation_analysis = {
            "stability_security_correlations": {},
            "performance_threat_correlations": {},
            "resource_impact_analysis": {},
            "service_availability_impact": {},
            "temporal_correlations": {},
            "causal_analysis": {},
            "stability_predictions": {},
            "analysis_metadata": {}
        }
        
        # Correlate stability with security events
        correlation_analysis["stability_security_correlations"] = self._correlate_stability_security_events(
            lateral_movement_analysis, endpoint_pattern_analysis, threat_classification, system_performance_data
        )
        
        # Correlate performance with threats
        correlation_analysis["performance_threat_correlations"] = self._correlate_performance_threats(
            threat_classification, system_performance_data
        )
        
        # Analyze resource impact
        correlation_analysis["resource_impact_analysis"] = self._analyze_resource_impact(
            threat_classification, system_performance_data
        )
        
        # Assess service availability impact
        correlation_analysis["service_availability_impact"] = self._assess_service_availability_impact(
            correlation_analysis["stability_security_correlations"], system_performance_data
        )
        
        # Analyze temporal correlations
        correlation_analysis["temporal_correlations"] = self._analyze_temporal_correlations(
            lateral_movement_analysis, endpoint_pattern_analysis, system_performance_data
        )
        
        # Perform causal analysis
        correlation_analysis["causal_analysis"] = self._perform_causal_analysis(
            correlation_analysis["stability_security_correlations"],
            correlation_analysis["temporal_correlations"]
        )
        
        # Predict stability issues
        correlation_analysis["stability_predictions"] = self._predict_stability_issues(
            correlation_analysis, threat_classification
        )
        
        # Add analysis metadata
        correlation_analysis["analysis_metadata"] = {
            "correlation_timestamp": datetime.now(),
            "hosts_analyzed": len(set(self._extract_hosts_from_analyses(
                lateral_movement_analysis, endpoint_pattern_analysis, threat_classification
            ))),
            "correlations_found": len(correlation_analysis["stability_security_correlations"]),
            "strong_correlations": len([
                corr for corr in correlation_analysis["stability_security_correlations"].values()
                if corr.get("correlation_strength") == CorrelationStrength.STRONG.value
            ]),
            "analysis_confidence": self._calculate_correlation_confidence(correlation_analysis)
        }
        
        logger.info("Stability-security correlation analysis complete")
        return correlation_analysis
    
    def analyze_host_stability_trends(self, 
                                    correlation_analysis: Dict[str, Any],
                                    historical_performance_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze host stability trends and patterns
        
        Args:
            correlation_analysis: Stability-security correlation results
            historical_performance_data: Historical performance metrics
            
        Returns:
            Host stability trend analysis results
        """
        logger.info("Analyzing host stability trends")
        
        trend_analysis = {
            "stability_trends": {},
            "degradation_patterns": {},
            "recovery_patterns": {},
            "stability_baselines": {},
            "anomaly_detection": {},
            "predictive_indicators": {},
            "trend_correlations": {},
            "analysis_metadata": {}
        }
        
        # Analyze stability trends
        trend_analysis["stability_trends"] = self._analyze_stability_trends(
            correlation_analysis, historical_performance_data
        )
        
        # Identify degradation patterns
        trend_analysis["degradation_patterns"] = self._identify_degradation_patterns(
            trend_analysis["stability_trends"]
        )
        
        # Analyze recovery patterns
        trend_analysis["recovery_patterns"] = self._analyze_recovery_patterns(
            trend_analysis["stability_trends"], correlation_analysis
        )
        
        # Establish stability baselines
        trend_analysis["stability_baselines"] = self._establish_stability_baselines(
            historical_performance_data
        )
        
        # Detect stability anomalies
        trend_analysis["anomaly_detection"] = self._detect_stability_anomalies(
            trend_analysis["stability_trends"], trend_analysis["stability_baselines"]
        )
        
        # Identify predictive indicators
        trend_analysis["predictive_indicators"] = self._identify_predictive_indicators(
            trend_analysis["stability_trends"], correlation_analysis
        )
        
        # Correlate trends with security events
        trend_analysis["trend_correlations"] = self._correlate_trends_with_security(
            trend_analysis["stability_trends"], correlation_analysis
        )
        
        # Add analysis metadata
        trend_analysis["analysis_metadata"] = {
            "trend_analysis_timestamp": datetime.now(),
            "trends_analyzed": len(trend_analysis["stability_trends"]),
            "degradation_patterns_found": len(trend_analysis["degradation_patterns"]),
            "recovery_patterns_found": len(trend_analysis["recovery_patterns"]),
            "stability_anomalies_detected": len(trend_analysis["anomaly_detection"])
        }
        
        logger.info("Host stability trend analysis complete")
        return trend_analysis
    
    def assess_stability_impact(self, 
                               correlation_analysis: Dict[str, Any],
                               trend_analysis: Dict[str, Any],
                               business_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess the impact of stability issues on business operations
        
        Args:
            correlation_analysis: Stability-security correlation results
            trend_analysis: Host stability trend analysis results
            business_context: Business context and criticality information
            
        Returns:
            Stability impact assessment results
        """
        logger.info("Assessing stability impact on business operations")
        
        impact_assessment = {
            "business_impact": {},
            "service_impact": {},
            "operational_impact": {},
            "user_impact": {},
            "financial_impact": {},
            "compliance_impact": {},
            "impact_prioritization": {},
            "analysis_metadata": {}
        }
        
        # Assess business impact
        impact_assessment["business_impact"] = self._assess_business_impact(
            correlation_analysis, trend_analysis, business_context
        )
        
        # Assess service impact
        impact_assessment["service_impact"] = self._assess_service_impact(
            correlation_analysis, business_context
        )
        
        # Assess operational impact
        impact_assessment["operational_impact"] = self._assess_operational_impact(
            trend_analysis, business_context
        )
        
        # Assess user impact
        impact_assessment["user_impact"] = self._assess_user_impact(
            correlation_analysis, trend_analysis, business_context
        )
        
        # Estimate financial impact
        impact_assessment["financial_impact"] = self._estimate_financial_impact(
            impact_assessment, business_context
        )
        
        # Assess compliance impact
        impact_assessment["compliance_impact"] = self._assess_compliance_impact(
            correlation_analysis, business_context
        )
        
        # Prioritize impacts
        impact_assessment["impact_prioritization"] = self._prioritize_impacts(
            impact_assessment
        )
        
        # Add analysis metadata
        impact_assessment["analysis_metadata"] = {
            "impact_assessment_timestamp": datetime.now(),
            "critical_impacts_identified": len([
                impact for impact in impact_assessment["impact_prioritization"].values()
                if impact.get("priority_level") == "critical"
            ]),
            "total_estimated_cost": impact_assessment["financial_impact"].get("total_estimated_cost", 0),
            "affected_services": len(impact_assessment["service_impact"]),
            "impact_confidence": self._calculate_impact_confidence(impact_assessment)
        }
        
        logger.info("Stability impact assessment complete")
        return impact_assessment
    
    def generate_stability_recommendations(self, 
                                         all_correlation_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive stability recommendations
        
        Args:
            all_correlation_results: Combined results from all correlation analyses
            
        Returns:
            Stability recommendation results
        """
        logger.info("Generating stability recommendations")
        
        stability_recommendations = {
            "immediate_stabilization": {},
            "performance_optimization": {},
            "security_hardening": {},
            "monitoring_enhancements": {},
            "preventive_measures": {},
            "recovery_procedures": {},
            "capacity_planning": {},
            "analysis_metadata": {}
        }
        
        # Extract data from all analyses
        correlation_analysis = all_correlation_results.get("correlation_analysis", {})
        trend_analysis = all_correlation_results.get("trend_analysis", {})
        impact_assessment = all_correlation_results.get("impact_assessment", {})
        
        # Generate immediate stabilization recommendations
        stability_recommendations["immediate_stabilization"] = self._generate_immediate_stabilization(
            correlation_analysis, impact_assessment
        )
        
        # Recommend performance optimizations
        stability_recommendations["performance_optimization"] = self._recommend_performance_optimization(
            trend_analysis, correlation_analysis
        )
        
        # Recommend security hardening
        stability_recommendations["security_hardening"] = self._recommend_security_hardening(
            correlation_analysis, impact_assessment
        )
        
        # Enhance monitoring capabilities
        stability_recommendations["monitoring_enhancements"] = self._enhance_monitoring_capabilities(
            correlation_analysis, trend_analysis
        )
        
        # Recommend preventive measures
        stability_recommendations["preventive_measures"] = self._recommend_preventive_measures(
            trend_analysis, correlation_analysis
        )
        
        # Define recovery procedures
        stability_recommendations["recovery_procedures"] = self._define_recovery_procedures(
            impact_assessment, correlation_analysis
        )
        
        # Plan capacity improvements
        stability_recommendations["capacity_planning"] = self._plan_capacity_improvements(
            trend_analysis, impact_assessment
        )
        
        # Add analysis metadata
        stability_recommendations["analysis_metadata"] = {
            "recommendation_timestamp": datetime.now(),
            "immediate_actions": len(stability_recommendations["immediate_stabilization"]),
            "optimization_recommendations": len(stability_recommendations["performance_optimization"]),
            "security_recommendations": len(stability_recommendations["security_hardening"]),
            "monitoring_enhancements": len(stability_recommendations["monitoring_enhancements"])
        }
        
        logger.info("Stability recommendations generation complete")
        return stability_recommendations
    
    def _load_correlation_models(self) -> Dict[str, Any]:
        """Load correlation analysis models"""
        return {
            "performance_security_correlations": {
                "cpu_spike_malware": {"threshold": 0.8, "confidence": 0.9},
                "memory_leak_persistence": {"threshold": 0.7, "confidence": 0.8},
                "network_latency_c2": {"threshold": 0.85, "confidence": 0.9},
                "disk_io_exfiltration": {"threshold": 0.75, "confidence": 0.8}
            },
            "temporal_correlation_windows": {
                "immediate": 300,      # 5 minutes
                "short_term": 3600,    # 1 hour
                "medium_term": 86400,  # 24 hours
                "long_term": 604800    # 7 days
            },
            "stability_thresholds": {
                "cpu_utilization": {"normal": 70, "warning": 85, "critical": 95},
                "memory_utilization": {"normal": 80, "warning": 90, "critical": 98},
                "disk_utilization": {"normal": 80, "warning": 90, "critical": 95},
                "network_latency": {"normal": 100, "warning": 500, "critical": 1000}
            }
        }
    
    def _correlate_stability_security_events(self, 
                                           lateral_movement_analysis: Dict[str, Any],
                                           endpoint_pattern_analysis: Dict[str, Any],
                                           threat_classification: Dict[str, Any],
                                           system_performance_data: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate stability issues with security events"""
        correlations = {}
        
        # Extract hosts from all analyses
        hosts = self._extract_hosts_from_analyses(
            lateral_movement_analysis, endpoint_pattern_analysis, threat_classification
        )
        
        # Analyze correlations for each host
        for host in hosts:
            host_correlations = []
            
            # Check for lateral movement correlations
            if host in lateral_movement_analysis.get("suspicious_hosts", {}):
                host_performance = system_performance_data.get("hosts", {}).get(host, {})
                
                # Check CPU correlation with suspicious activity
                cpu_utilization = host_performance.get("cpu_utilization", 0)
                if cpu_utilization > 85:  # High CPU usage
                    host_correlations.append({
                        "correlation_type": "cpu_security",
                        "security_event": "lateral_movement_detected",
                        "stability_indicator": "high_cpu_utilization",
                        "correlation_strength": CorrelationStrength.STRONG.value,
                        "confidence": 0.85,
                        "timestamp": datetime.now()
                    })
                
                # Check memory correlation
                memory_utilization = host_performance.get("memory_utilization", 0)
                if memory_utilization > 90:  # High memory usage
                    host_correlations.append({
                        "correlation_type": "memory_security",
                        "security_event": "suspicious_process_activity",
                        "stability_indicator": "high_memory_utilization",
                        "correlation_strength": CorrelationStrength.MODERATE.value,
                        "confidence": 0.75,
                        "timestamp": datetime.now()
                    })
            
            # Check for endpoint pattern correlations
            endpoint_anomalies = endpoint_pattern_analysis.get("anomaly_detection", {}).get(host, {})
            if endpoint_anomalies:
                host_performance = system_performance_data.get("hosts", {}).get(host, {})
                
                # Network correlation
                network_latency = host_performance.get("network_latency", 0)
                if network_latency > 500:  # High latency
                    host_correlations.append({
                        "correlation_type": "network_security",
                        "security_event": "anomalous_endpoint_behavior",
                        "stability_indicator": "high_network_latency",
                        "correlation_strength": CorrelationStrength.MODERATE.value,
                        "confidence": 0.7,
                        "timestamp": datetime.now()
                    })
            
            # Check for threat classification correlations
            host_threats = [
                threat for threat_id, threat in threat_classification.get("threat_categories", {}).items()
                if host in str(threat.get("affected_endpoints", [])) or 
                   host == threat.get("affected_host", "") or
                   host == threat.get("source_host", "") or
                   host == threat.get("destination_host", "")
            ]
            
            if host_threats:
                host_performance = system_performance_data.get("hosts", {}).get(host, {})
                
                # Disk I/O correlation with threats
                disk_utilization = host_performance.get("disk_utilization", 0)
                if disk_utilization > 90:
                    host_correlations.append({
                        "correlation_type": "disk_security",
                        "security_event": "threat_detected",
                        "stability_indicator": "high_disk_utilization",
                        "correlation_strength": CorrelationStrength.STRONG.value,
                        "confidence": 0.8,
                        "timestamp": datetime.now()
                    })
            
            if host_correlations:
                correlations[host] = {
                    "correlations": host_correlations,
                    "correlation_count": len(host_correlations),
                    "strongest_correlation": max(host_correlations, 
                                               key=lambda x: self._correlation_strength_to_numeric(x["correlation_strength"])),
                    "overall_correlation_strength": self._calculate_overall_correlation_strength(host_correlations)
                }
        
        return correlations
    
    def _correlate_performance_threats(self, threat_classification: Dict[str, Any], 
                                     system_performance_data: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate performance metrics with threat activities"""
        performance_correlations = {}
        
        # Analyze threat categories
        threat_categories = threat_classification.get("threat_categories", {})
        
        for threat_id, threat_data in threat_categories.items():
            threat_category = threat_data.get("category")
            
            # Performance impact by threat category
            if threat_category == "malware":
                affected_hosts = threat_data.get("affected_endpoints", [])
                for host in affected_hosts:
                    host_performance = system_performance_data.get("hosts", {}).get(host, {})
                    
                    performance_correlations[f"{threat_id}_{host}"] = {
                        "threat_type": threat_category,
                        "host": host,
                        "performance_impact": {
                            "cpu_impact": host_performance.get("cpu_utilization", 0) - 50,  # Baseline 50%
                            "memory_impact": host_performance.get("memory_utilization", 0) - 60,  # Baseline 60%
                            "disk_impact": host_performance.get("disk_utilization", 0) - 30,  # Baseline 30%
                            "network_impact": host_performance.get("network_latency", 0) - 100  # Baseline 100ms
                        },
                        "correlation_timestamp": datetime.now()
                    }
            
            elif threat_category == "lateral_movement":
                source_host = threat_data.get("source_host")
                destination_host = threat_data.get("destination_host")
                
                for host in [source_host, destination_host]:
                    if host:
                        host_performance = system_performance_data.get("hosts", {}).get(host, {})
                        
                        performance_correlations[f"{threat_id}_{host}"] = {
                            "threat_type": threat_category,
                            "host": host,
                            "performance_impact": {
                                "network_impact": host_performance.get("network_latency", 0) - 100,
                                "cpu_impact": host_performance.get("cpu_utilization", 0) - 40,
                                "connection_impact": host_performance.get("network_connections", 0) - 20
                            },
                            "correlation_timestamp": datetime.now()
                        }
        
        return performance_correlations
    
    def _analyze_resource_impact(self, threat_classification: Dict[str, Any], 
                               system_performance_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze resource impact of threats"""
        resource_impact = {
            "cpu_impact": {},
            "memory_impact": {},
            "disk_impact": {},
            "network_impact": {},
            "overall_impact": {}
        }
        
        # Analyze impact by resource type
        for resource_type in ["cpu", "memory", "disk", "network"]:
            resource_impact[f"{resource_type}_impact"] = self._analyze_specific_resource_impact(
                threat_classification, system_performance_data, resource_type
            )
        
        # Calculate overall impact
        resource_impact["overall_impact"] = self._calculate_overall_resource_impact(
            resource_impact
        )
        
        return resource_impact
    
    def _analyze_specific_resource_impact(self, threat_classification: Dict[str, Any], 
                                        system_performance_data: Dict[str, Any], 
                                        resource_type: str) -> Dict[str, Any]:
        """Analyze impact on specific resource type"""
        impact_analysis = {}
        
        # Get baseline values for resource type
        baseline_values = {
            "cpu": 50,      # 50% baseline CPU
            "memory": 60,   # 60% baseline memory
            "disk": 30,     # 30% baseline disk
            "network": 100  # 100ms baseline latency
        }
        
        baseline = baseline_values.get(resource_type, 50)
        
        # Analyze threats and their resource impact
        threat_categories = threat_classification.get("threat_categories", {})
        
        for threat_id, threat_data in threat_categories.items():
            affected_hosts = self._extract_affected_hosts_from_threat(threat_data)
            
            for host in affected_hosts:
                host_performance = system_performance_data.get("hosts", {}).get(host, {})
                
                metric_name = f"{resource_type}_utilization" if resource_type != "network" else "network_latency"
                current_value = host_performance.get(metric_name, baseline)
                
                impact = current_value - baseline
                impact_severity = self._assess_resource_impact_severity(impact, resource_type)
                
                impact_analysis[f"{threat_id}_{host}"] = {
                    "threat_id": threat_id,
                    "host": host,
                    "resource_type": resource_type,
                    "current_value": current_value,
                    "baseline_value": baseline,
                    "impact_value": impact,
                    "impact_severity": impact_severity,
                    "impact_percentage": (impact / baseline) * 100 if baseline > 0 else 0
                }
        
        return impact_analysis
