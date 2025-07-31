"""
Endpoint Pattern Analyzer Module
State 2: Endpoint Pattern Analysis
Analyzes patterns in endpoint alerts and repeated security events
"""

import logging
from typing import Dict, Any, List, Tuple, Set
from datetime import datetime, timedelta
import json
from collections import defaultdict, Counter
import statistics
from enum import Enum

logger = logging.getLogger(__name__)

class AlertPattern(Enum):
    """Enumeration for alert patterns"""
    REPETITIVE = "repetitive"
    ESCALATING = "escalating"
    COORDINATED = "coordinated"
    PERSISTENT = "persistent"
    ANOMALOUS = "anomalous"

class EndpointThreatType(Enum):
    """Enumeration for endpoint threat types"""
    MALWARE = "malware"
    SUSPICIOUS_PROCESS = "suspicious_process"
    NETWORK_ANOMALY = "network_anomaly"
    FILE_SYSTEM_ANOMALY = "file_system_anomaly"
    REGISTRY_MANIPULATION = "registry_manipulation"
    PRIVILEGE_ESCALATION = "privilege_escalation"

class EndpointPatternAnalyzer:
    """
    Analyzes patterns in endpoint alerts and repeated security events
    Provides comprehensive endpoint behavior analysis
    """
    
    def __init__(self):
        self.pattern_templates = self._load_pattern_templates()
        self.alert_baselines = {}
        self.pattern_cache = {}
        
    def analyze_endpoint_alert_patterns(self, endpoint_alerts: List[Dict[str, Any]], 
                                       historical_data: Dict[str, Any],
                                       endpoint_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze patterns in endpoint alerts
        
        Args:
            endpoint_alerts: List of endpoint security alerts
            historical_data: Historical alert and behavior data
            endpoint_metadata: Endpoint configuration and context data
            
        Returns:
            Endpoint alert pattern analysis results
        """
        logger.info("Analyzing endpoint alert patterns")
        
        pattern_analysis = {
            "alert_frequency_patterns": {},
            "repetitive_alerts": {},
            "escalation_patterns": {},
            "temporal_patterns": {},
            "endpoint_clustering": {},
            "anomaly_detection": {},
            "pattern_correlations": {},
            "analysis_metadata": {}
        }
        
        # Analyze alert frequency patterns
        pattern_analysis["alert_frequency_patterns"] = self._analyze_alert_frequencies(
            endpoint_alerts, historical_data
        )
        
        # Identify repetitive alerts
        pattern_analysis["repetitive_alerts"] = self._identify_repetitive_alerts(
            endpoint_alerts
        )
        
        # Detect escalation patterns
        pattern_analysis["escalation_patterns"] = self._detect_escalation_patterns(
            endpoint_alerts, historical_data
        )
        
        # Analyze temporal patterns
        pattern_analysis["temporal_patterns"] = self._analyze_temporal_patterns(
            endpoint_alerts
        )
        
        # Perform endpoint clustering
        pattern_analysis["endpoint_clustering"] = self._perform_endpoint_clustering(
            endpoint_alerts, endpoint_metadata
        )
        
        # Detect anomalies
        pattern_analysis["anomaly_detection"] = self._detect_endpoint_anomalies(
            endpoint_alerts, historical_data
        )
        
        # Correlate patterns
        pattern_analysis["pattern_correlations"] = self._correlate_alert_patterns(
            pattern_analysis
        )
        
        # Add analysis metadata
        pattern_analysis["analysis_metadata"] = {
            "analysis_timestamp": datetime.now(),
            "total_alerts_analyzed": len(endpoint_alerts),
            "unique_endpoints": len(set([alert.get("hostname", "") for alert in endpoint_alerts])),
            "analysis_time_window": self._calculate_analysis_window(endpoint_alerts),
            "pattern_confidence": self._calculate_pattern_confidence(pattern_analysis)
        }
        
        logger.info("Endpoint alert pattern analysis complete")
        return pattern_analysis
    
    def analyze_endpoint_behavior(self, endpoint_alerts: List[Dict[str, Any]], 
                                 system_events: List[Dict[str, Any]],
                                 performance_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze endpoint behavior patterns
        
        Args:
            endpoint_alerts: Endpoint security alerts
            system_events: System event logs
            performance_data: Endpoint performance metrics
            
        Returns:
            Endpoint behavior analysis results
        """
        logger.info("Analyzing endpoint behavior patterns")
        
        behavior_analysis = {
            "process_behavior": {},
            "network_behavior": {},
            "file_system_behavior": {},
            "registry_behavior": {},
            "performance_correlation": {},
            "behavior_baselines": {},
            "deviation_analysis": {},
            "analysis_metadata": {}
        }
        
        # Analyze process behavior
        behavior_analysis["process_behavior"] = self._analyze_process_behavior(
            endpoint_alerts, system_events
        )
        
        # Analyze network behavior
        behavior_analysis["network_behavior"] = self._analyze_network_behavior(
            endpoint_alerts, system_events
        )
        
        # Analyze file system behavior
        behavior_analysis["file_system_behavior"] = self._analyze_file_system_behavior(
            endpoint_alerts, system_events
        )
        
        # Analyze registry behavior
        behavior_analysis["registry_behavior"] = self._analyze_registry_behavior(
            endpoint_alerts, system_events
        )
        
        # Correlate with performance data
        behavior_analysis["performance_correlation"] = self._correlate_performance_data(
            behavior_analysis, performance_data
        )
        
        # Establish behavior baselines
        behavior_analysis["behavior_baselines"] = self._establish_behavior_baselines(
            behavior_analysis
        )
        
        # Analyze deviations from baseline
        behavior_analysis["deviation_analysis"] = self._analyze_behavior_deviations(
            behavior_analysis["behavior_baselines"], behavior_analysis
        )
        
        # Add analysis metadata
        behavior_analysis["analysis_metadata"] = {
            "analysis_timestamp": datetime.now(),
            "endpoints_analyzed": len(set([alert.get("hostname", "") for alert in endpoint_alerts])),
            "behavior_categories": len([k for k in behavior_analysis.keys() if k.endswith("_behavior")]),
            "baseline_confidence": self._calculate_baseline_confidence(behavior_analysis["behavior_baselines"])
        }
        
        logger.info("Endpoint behavior analysis complete")
        return behavior_analysis
    
    def detect_persistent_threats(self, pattern_analysis: Dict[str, Any], 
                                 behavior_analysis: Dict[str, Any],
                                 threat_intelligence: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect persistent threats on endpoints
        
        Args:
            pattern_analysis: Alert pattern analysis results
            behavior_analysis: Endpoint behavior analysis results
            threat_intelligence: Threat intelligence data
            
        Returns:
            Persistent threat detection results
        """
        logger.info("Detecting persistent threats on endpoints")
        
        persistent_threat_analysis = {
            "persistence_indicators": {},
            "long_term_patterns": {},
            "stealth_indicators": {},
            "advanced_techniques": {},
            "threat_attribution": {},
            "persistence_timeline": [],
            "containment_recommendations": {},
            "analysis_metadata": {}
        }
        
        # Identify persistence indicators
        persistent_threat_analysis["persistence_indicators"] = self._identify_persistence_indicators(
            pattern_analysis, behavior_analysis
        )
        
        # Detect long-term patterns
        persistent_threat_analysis["long_term_patterns"] = self._detect_long_term_patterns(
            pattern_analysis, behavior_analysis
        )
        
        # Identify stealth indicators
        persistent_threat_analysis["stealth_indicators"] = self._identify_stealth_indicators(
            behavior_analysis
        )
        
        # Detect advanced techniques
        persistent_threat_analysis["advanced_techniques"] = self._detect_advanced_techniques(
            pattern_analysis, behavior_analysis, threat_intelligence
        )
        
        # Attribute threats
        persistent_threat_analysis["threat_attribution"] = self._attribute_threats(
            persistent_threat_analysis, threat_intelligence
        )
        
        # Build persistence timeline
        persistent_threat_analysis["persistence_timeline"] = self._build_persistence_timeline(
            persistent_threat_analysis
        )
        
        # Generate containment recommendations
        persistent_threat_analysis["containment_recommendations"] = self._generate_containment_recommendations(
            persistent_threat_analysis
        )
        
        # Add analysis metadata
        persistent_threat_analysis["analysis_metadata"] = {
            "analysis_timestamp": datetime.now(),
            "persistence_indicators_found": len(persistent_threat_analysis["persistence_indicators"]),
            "stealth_indicators_found": len(persistent_threat_analysis["stealth_indicators"]),
            "advanced_techniques_detected": len(persistent_threat_analysis["advanced_techniques"]),
            "threat_sophistication": self._assess_threat_sophistication(persistent_threat_analysis)
        }
        
        logger.info("Persistent threat detection complete")
        return persistent_threat_analysis
    
    def calculate_endpoint_risk_scores(self, all_analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate comprehensive endpoint risk scores
        
        Args:
            all_analysis_results: Combined results from all endpoint analyses
            
        Returns:
            Endpoint risk scoring results
        """
        logger.info("Calculating comprehensive endpoint risk scores")
        
        risk_scoring = {
            "endpoint_risk_scores": {},
            "risk_categories": {},
            "threat_level_mapping": {},
            "risk_trends": {},
            "prioritization": {},
            "risk_mitigation": {},
            "scoring_metadata": {}
        }
        
        # Extract endpoint data from all analyses
        pattern_analysis = all_analysis_results.get("pattern_analysis", {})
        behavior_analysis = all_analysis_results.get("behavior_analysis", {})
        persistent_threat_analysis = all_analysis_results.get("persistent_threat_analysis", {})
        
        # Get all unique endpoints
        all_endpoints = set()
        
        # Extract endpoints from pattern analysis
        for alert_data in pattern_analysis.get("repetitive_alerts", {}).values():
            all_endpoints.update(alert_data.get("affected_endpoints", []))
        
        # Extract endpoints from behavior analysis
        for behavior_category in ["process_behavior", "network_behavior", "file_system_behavior"]:
            behavior_data = behavior_analysis.get(behavior_category, {})
            for endpoint_data in behavior_data.values():
                if isinstance(endpoint_data, dict) and "hostname" in endpoint_data:
                    all_endpoints.add(endpoint_data["hostname"])
        
        # Calculate risk scores for each endpoint
        for endpoint in all_endpoints:
            endpoint_risk = self._calculate_individual_endpoint_risk(
                endpoint, pattern_analysis, behavior_analysis, persistent_threat_analysis
            )
            risk_scoring["endpoint_risk_scores"][endpoint] = endpoint_risk
        
        # Categorize risks
        risk_scoring["risk_categories"] = self._categorize_endpoint_risks(
            risk_scoring["endpoint_risk_scores"]
        )
        
        # Map threat levels
        risk_scoring["threat_level_mapping"] = self._map_threat_levels(
            risk_scoring["endpoint_risk_scores"]
        )
        
        # Analyze risk trends
        risk_scoring["risk_trends"] = self._analyze_endpoint_risk_trends(
            risk_scoring["endpoint_risk_scores"]
        )
        
        # Prioritize endpoints
        risk_scoring["prioritization"] = self._prioritize_endpoints(
            risk_scoring["endpoint_risk_scores"]
        )
        
        # Generate mitigation recommendations
        risk_scoring["risk_mitigation"] = self._generate_risk_mitigation_recommendations(
            risk_scoring["endpoint_risk_scores"]
        )
        
        # Add scoring metadata
        risk_scoring["scoring_metadata"] = {
            "scoring_timestamp": datetime.now(),
            "endpoints_scored": len(risk_scoring["endpoint_risk_scores"]),
            "high_risk_endpoints": len([
                endpoint for endpoint, score in risk_scoring["endpoint_risk_scores"].items()
                if score.get("composite_risk_score", 0) >= 7.0
            ]),
            "scoring_algorithm": "weighted_composite",
            "risk_factors": ["alert_patterns", "behavior_deviations", "persistence_indicators"]
        }
        
        logger.info("Endpoint risk scoring complete")
        return risk_scoring
    
    def _load_pattern_templates(self) -> Dict[str, Any]:
        """Load pattern recognition templates"""
        return {
            "repetitive_patterns": {
                "min_occurrences": 3,
                "time_window_hours": 24,
                "similarity_threshold": 0.8
            },
            "escalation_patterns": {
                "severity_progression": ["low", "medium", "high", "critical"],
                "escalation_window_hours": 12,
                "min_escalation_steps": 2
            },
            "temporal_patterns": {
                "time_buckets": ["morning", "afternoon", "evening", "night"],
                "pattern_significance_threshold": 0.7
            }
        }
    
    def _analyze_alert_frequencies(self, endpoint_alerts: List[Dict[str, Any]], historical_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze alert frequency patterns"""
        frequency_analysis = {}
        
        # Group alerts by endpoint and alert type
        endpoint_alert_counts = defaultdict(lambda: defaultdict(int))
        
        for alert in endpoint_alerts:
            hostname = alert.get("hostname", "")
            alert_type = alert.get("alert_type", "")
            endpoint_alert_counts[hostname][alert_type] += 1
        
        # Analyze frequencies for each endpoint
        for hostname, alert_counts in endpoint_alert_counts.items():
            total_alerts = sum(alert_counts.values())
            
            # Get historical baseline
            historical_baseline = historical_data.get("baselines", {}).get(hostname, {})
            avg_daily_alerts = historical_baseline.get("avg_daily_alerts", 5)
            
            frequency_analysis[hostname] = {
                "current_alert_count": total_alerts,
                "historical_baseline": avg_daily_alerts,
                "frequency_ratio": total_alerts / avg_daily_alerts if avg_daily_alerts > 0 else 0,
                "alert_type_distribution": dict(alert_counts),
                "frequency_anomaly": total_alerts > avg_daily_alerts * 2,  # 2x baseline
                "anomaly_severity": self._assess_frequency_anomaly_severity(total_alerts, avg_daily_alerts)
            }
        
        return frequency_analysis
    
    def _identify_repetitive_alerts(self, endpoint_alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Identify repetitive alert patterns"""
        repetitive_alerts = {}
        
        # Group alerts by signature/pattern
        alert_signatures = defaultdict(list)
        
        for alert in endpoint_alerts:
            # Create signature from key alert attributes
            signature = f"{alert.get('alert_type', '')}_{alert.get('process', '')}_{alert.get('file_path', '')}"
            alert_signatures[signature].append(alert)
        
        # Identify repetitive patterns
        for signature, alerts in alert_signatures.items():
            if len(alerts) >= 3:  # At least 3 occurrences
                timestamps = [alert.get("timestamp", datetime.now()) for alert in alerts]
                timestamps.sort()
                
                # Calculate time intervals
                intervals = []
                for i in range(1, len(timestamps)):
                    interval = (timestamps[i] - timestamps[i-1]).total_seconds()
                    intervals.append(interval)
                
                # Check for regular patterns
                if intervals:
                    avg_interval = statistics.mean(intervals)
                    interval_std = statistics.stdev(intervals) if len(intervals) > 1 else 0
                    
                    # Regular pattern if low standard deviation
                    is_regular = interval_std < avg_interval * 0.3
                    
                    repetitive_alerts[signature] = {
                        "occurrence_count": len(alerts),
                        "affected_endpoints": list(set([alert.get("hostname", "") for alert in alerts])),
                        "time_span": (timestamps[-1] - timestamps[0]).total_seconds(),
                        "average_interval": avg_interval,
                        "interval_regularity": is_regular,
                        "pattern_type": AlertPattern.REPETITIVE.value,
                        "first_occurrence": timestamps[0],
                        "last_occurrence": timestamps[-1],
                        "repetition_risk": "high" if len(alerts) > 10 else "medium"
                    }
        
        return repetitive_alerts
    
    def _detect_escalation_patterns(self, endpoint_alerts: List[Dict[str, Any]], historical_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect alert escalation patterns"""
        escalation_patterns = {}
        
        # Group alerts by endpoint and sort by timestamp
        endpoint_alerts_sorted = defaultdict(list)
        
        for alert in endpoint_alerts:
            hostname = alert.get("hostname", "")
            endpoint_alerts_sorted[hostname].append(alert)
        
        # Sort alerts by timestamp for each endpoint
        for hostname in endpoint_alerts_sorted:
            endpoint_alerts_sorted[hostname].sort(key=lambda x: x.get("timestamp", datetime.now()))
        
        # Analyze escalation patterns for each endpoint
        for hostname, alerts in endpoint_alerts_sorted.items():
            severity_sequence = []
            
            for alert in alerts:
                severity = alert.get("severity", "low")
                severity_sequence.append(severity)
            
            # Detect escalation
            escalation_detected = self._detect_severity_escalation(severity_sequence)
            
            if escalation_detected:
                escalation_patterns[hostname] = {
                    "escalation_detected": True,
                    "severity_sequence": severity_sequence,
                    "escalation_start": alerts[0].get("timestamp"),
                    "escalation_end": alerts[-1].get("timestamp"),
                    "escalation_speed": self._calculate_escalation_speed(alerts),
                    "max_severity_reached": max(severity_sequence, key=lambda x: self._severity_to_numeric(x)),
                    "escalation_risk": self._assess_escalation_risk(severity_sequence),
                    "pattern_type": AlertPattern.ESCALATING.value
                }
        
        return escalation_patterns
    
    def _analyze_temporal_patterns(self, endpoint_alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze temporal patterns in alerts"""
        temporal_analysis = {}
        
        # Group alerts by time periods
        hourly_distribution = defaultdict(int)
        daily_distribution = defaultdict(int)
        weekly_distribution = defaultdict(int)
        
        for alert in endpoint_alerts:
            timestamp = alert.get("timestamp", datetime.now())
            
            hourly_distribution[timestamp.hour] += 1
            daily_distribution[timestamp.strftime("%A")] += 1
            weekly_distribution[timestamp.isocalendar()[1]] += 1  # Week number
        
        temporal_analysis = {
            "hourly_distribution": dict(hourly_distribution),
            "daily_distribution": dict(daily_distribution),
            "weekly_distribution": dict(weekly_distribution),
            "peak_hours": self._identify_peak_periods(hourly_distribution),
            "off_hours_activity": self._identify_off_hours_activity(hourly_distribution),
            "temporal_anomalies": self._identify_temporal_anomalies(hourly_distribution, daily_distribution),
            "pattern_regularity": self._assess_temporal_regularity(hourly_distribution, daily_distribution)
        }
        
        return temporal_analysis
    
    def _perform_endpoint_clustering(self, endpoint_alerts: List[Dict[str, Any]], endpoint_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Perform endpoint clustering based on alert patterns"""
        clustering_analysis = {}
        
        # Group endpoints by similar characteristics
        endpoint_profiles = {}
        
        for alert in endpoint_alerts:
            hostname = alert.get("hostname", "")
            if hostname not in endpoint_profiles:
                endpoint_profiles[hostname] = {
                    "alert_types": set(),
                    "processes": set(),
                    "file_paths": set(),
                    "severity_levels": set(),
                    "alert_count": 0
                }
            
            profile = endpoint_profiles[hostname]
            profile["alert_types"].add(alert.get("alert_type", ""))
            profile["processes"].add(alert.get("process", ""))
            profile["file_paths"].add(alert.get("file_path", ""))
            profile["severity_levels"].add(alert.get("severity", ""))
            profile["alert_count"] += 1
        
        # Convert sets to lists for serialization
        for hostname, profile in endpoint_profiles.items():
            for key, value in profile.items():
                if isinstance(value, set):
                    profile[key] = list(value)
        
        # Perform simple clustering based on similarity
        clusters = self._cluster_endpoints_by_similarity(endpoint_profiles)
        
        clustering_analysis = {
            "endpoint_profiles": endpoint_profiles,
            "clusters": clusters,
            "cluster_analysis": self._analyze_endpoint_clusters(clusters),
            "outlier_endpoints": self._identify_outlier_endpoints(endpoint_profiles, clusters)
        }
        
        return clustering_analysis
    
    def _detect_endpoint_anomalies(self, endpoint_alerts: List[Dict[str, Any]], historical_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect anomalies in endpoint behavior"""
        anomaly_detection = {}
        
        # Group alerts by endpoint
        endpoint_alert_data = defaultdict(list)
        for alert in endpoint_alerts:
            hostname = alert.get("hostname", "")
            endpoint_alert_data[hostname].append(alert)
        
        # Detect anomalies for each endpoint
        for hostname, alerts in endpoint_alert_data.items():
            anomalies = []
            
            # Volume anomaly
            alert_count = len(alerts)
            historical_avg = historical_data.get("baselines", {}).get(hostname, {}).get("avg_daily_alerts", 5)
            
            if alert_count > historical_avg * 3:  # 3x normal volume
                anomalies.append({
                    "type": "volume_anomaly",
                    "current_count": alert_count,
                    "historical_average": historical_avg,
                    "anomaly_factor": alert_count / historical_avg
                })
            
            # Timing anomaly
            timestamps = [alert.get("timestamp", datetime.now()) for alert in alerts]
            off_hours_count = sum(1 for ts in timestamps if ts.hour < 6 or ts.hour > 22)
            
            if off_hours_count / len(timestamps) > 0.6:  # >60% off-hours
                anomalies.append({
                    "type": "timing_anomaly",
                    "off_hours_percentage": (off_hours_count / len(timestamps)) * 100,
                    "off_hours_count": off_hours_count,
                    "total_alerts": len(timestamps)
                })
            
            # Type diversity anomaly
            alert_types = set([alert.get("alert_type", "") for alert in alerts])
            if len(alert_types) > 5:  # Many different alert types
                anomalies.append({
                    "type": "diversity_anomaly",
                    "unique_alert_types": len(alert_types),
                    "alert_types": list(alert_types)
                })
            
            if anomalies:
                anomaly_detection[hostname] = {
                    "anomalies_detected": anomalies,
                    "anomaly_count": len(anomalies),
                    "anomaly_score": self._calculate_anomaly_score(anomalies),
                    "anomaly_risk": "high" if len(anomalies) > 2 else "medium"
                }
        
        return anomaly_detection
