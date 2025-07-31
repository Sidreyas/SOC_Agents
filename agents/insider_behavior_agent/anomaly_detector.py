"""
Anomaly Detector Module
State 2: Anomaly Detection
Performs statistical analysis and machine learning-based anomaly detection
"""

import logging
from typing import Dict, Any, List, Tuple
from datetime import datetime, timedelta
import json
import statistics
import math

logger = logging.getLogger(__name__)

class AnomalyDetector:
    """
    Performs advanced anomaly detection using statistical analysis and behavioral modeling
    Identifies deviations from normal user behavior patterns
    """
    
    def __init__(self):
        self.baseline_models = {}
        self.anomaly_thresholds = self._initialize_anomaly_thresholds()
        self.detection_algorithms = {}
        self.statistical_models = {}
        
    def perform_statistical_analysis(self, behavioral_patterns: Dict[str, Any], baseline_period: int = 30) -> Dict[str, Any]:
        """
        Perform statistical analysis to identify behavioral anomalies
        
        Args:
            behavioral_patterns: Extracted behavioral patterns from BehavioralExtractor
            baseline_period: Number of days to use for baseline calculation
            
        Returns:
            Statistical anomaly analysis results
        """
        logger.info("Performing statistical anomaly analysis")
        
        statistical_analysis = {
            "authentication_anomalies": {},
            "file_access_anomalies": {},
            "email_anomalies": {},
            "application_anomalies": {},
            "temporal_anomalies": {},
            "statistical_confidence": {},
            "anomaly_scores": {}
        }
        
        # Analyze authentication anomalies
        auth_patterns = behavioral_patterns.get("authentication_patterns", {})
        statistical_analysis["authentication_anomalies"] = self._analyze_authentication_anomalies(auth_patterns)
        
        # Analyze file access anomalies
        file_patterns = behavioral_patterns.get("file_access_patterns", {})
        statistical_analysis["file_access_anomalies"] = self._analyze_file_access_anomalies(file_patterns)
        
        # Analyze email anomalies
        email_patterns = behavioral_patterns.get("email_patterns", {})
        statistical_analysis["email_anomalies"] = self._analyze_email_anomalies(email_patterns)
        
        # Analyze application usage anomalies
        app_patterns = behavioral_patterns.get("application_patterns", {})
        statistical_analysis["application_anomalies"] = self._analyze_application_anomalies(app_patterns)
        
        # Analyze temporal anomalies
        statistical_analysis["temporal_anomalies"] = self._analyze_temporal_anomalies(behavioral_patterns)
        
        # Calculate statistical confidence
        statistical_analysis["statistical_confidence"] = self._calculate_statistical_confidence(behavioral_patterns)
        
        # Calculate overall anomaly scores
        statistical_analysis["anomaly_scores"] = self._calculate_anomaly_scores(statistical_analysis)
        
        logger.info("Statistical anomaly analysis complete")
        return statistical_analysis
    
    def detect_baseline_deviations(self, current_behavior: Dict[str, Any], historical_baselines: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect deviations from established behavioral baselines
        
        Args:
            current_behavior: Current behavioral patterns
            historical_baselines: Historical behavioral baselines
            
        Returns:
            Baseline deviation analysis results
        """
        logger.info("Detecting baseline deviations")
        
        deviation_analysis = {
            "significant_deviations": {},
            "deviation_scores": {},
            "trend_analysis": {},
            "baseline_confidence": {},
            "change_points": {},
            "recommendation": {}
        }
        
        # Analyze deviations by behavioral category
        for behavior_type in ["authentication", "file_access", "email", "application"]:
            current_data = current_behavior.get(f"{behavior_type}_patterns", {})
            baseline_data = historical_baselines.get(f"{behavior_type}_baseline", {})
            
            deviation_analysis["significant_deviations"][behavior_type] = self._calculate_behavioral_deviations(
                current_data, baseline_data, behavior_type
            )
            
            deviation_analysis["deviation_scores"][behavior_type] = self._calculate_deviation_scores(
                current_data, baseline_data
            )
        
        # Perform trend analysis
        deviation_analysis["trend_analysis"] = self._analyze_behavioral_trends(current_behavior, historical_baselines)
        
        # Calculate baseline confidence
        deviation_analysis["baseline_confidence"] = self._calculate_baseline_confidence(historical_baselines)
        
        # Detect change points
        deviation_analysis["change_points"] = self._detect_change_points(current_behavior, historical_baselines)
        
        # Generate recommendations
        deviation_analysis["recommendation"] = self._generate_deviation_recommendations(deviation_analysis)
        
        logger.info("Baseline deviation analysis complete")
        return deviation_analysis
    
    def apply_machine_learning_models(self, behavioral_data: Dict[str, Any], model_type: str = "ensemble") -> Dict[str, Any]:
        """
        Apply machine learning models for advanced anomaly detection
        
        Args:
            behavioral_data: Behavioral data for ML analysis
            model_type: Type of ML model to apply (isolation_forest, one_class_svm, ensemble)
            
        Returns:
            ML-based anomaly detection results
        """
        logger.info(f"Applying {model_type} machine learning models for anomaly detection")
        
        ml_analysis = {
            "anomaly_predictions": {},
            "confidence_scores": {},
            "feature_importance": {},
            "model_performance": {},
            "clustering_results": {},
            "outlier_detection": {}
        }
        
        # Prepare feature vectors from behavioral data
        feature_vectors = self._prepare_feature_vectors(behavioral_data)
        
        # Apply selected ML models
        if model_type == "isolation_forest":
            ml_analysis["anomaly_predictions"] = self._apply_isolation_forest(feature_vectors)
        elif model_type == "one_class_svm":
            ml_analysis["anomaly_predictions"] = self._apply_one_class_svm(feature_vectors)
        elif model_type == "ensemble":
            ml_analysis["anomaly_predictions"] = self._apply_ensemble_models(feature_vectors)
        
        # Calculate confidence scores
        ml_analysis["confidence_scores"] = self._calculate_ml_confidence_scores(
            ml_analysis["anomaly_predictions"], feature_vectors
        )
        
        # Analyze feature importance
        ml_analysis["feature_importance"] = self._analyze_feature_importance(feature_vectors)
        
        # Evaluate model performance
        ml_analysis["model_performance"] = self._evaluate_model_performance(
            ml_analysis["anomaly_predictions"], behavioral_data
        )
        
        # Perform clustering analysis
        ml_analysis["clustering_results"] = self._perform_behavioral_clustering(feature_vectors)
        
        # Enhanced outlier detection
        ml_analysis["outlier_detection"] = self._detect_statistical_outliers(feature_vectors)
        
        logger.info("ML-based anomaly detection complete")
        return ml_analysis
    
    def calculate_risk_scores(self, statistical_analysis: Dict[str, Any], ml_analysis: Dict[str, Any], deviation_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate comprehensive risk scores combining all analysis methods
        
        Args:
            statistical_analysis: Results from statistical analysis
            ml_analysis: Results from ML analysis
            deviation_analysis: Results from baseline deviation analysis
            
        Returns:
            Comprehensive risk scoring results
        """
        logger.info("Calculating comprehensive risk scores")
        
        risk_scoring = {
            "overall_risk_score": 0.0,
            "risk_components": {},
            "user_risk_rankings": {},
            "risk_categories": {},
            "temporal_risk_trends": {},
            "confidence_metrics": {},
            "risk_recommendations": {}
        }
        
        # Calculate component risk scores
        risk_scoring["risk_components"] = {
            "statistical_risk": self._calculate_statistical_risk_score(statistical_analysis),
            "ml_risk": self._calculate_ml_risk_score(ml_analysis),
            "deviation_risk": self._calculate_deviation_risk_score(deviation_analysis),
            "temporal_risk": self._calculate_temporal_risk_score(statistical_analysis, deviation_analysis)
        }
        
        # Calculate overall risk score (weighted combination)
        weights = {"statistical_risk": 0.3, "ml_risk": 0.4, "deviation_risk": 0.2, "temporal_risk": 0.1}
        risk_scoring["overall_risk_score"] = sum(
            score * weights[component] 
            for component, score in risk_scoring["risk_components"].items()
        )
        
        # Rank users by risk
        risk_scoring["user_risk_rankings"] = self._rank_users_by_risk(
            statistical_analysis, ml_analysis, deviation_analysis
        )
        
        # Categorize risks
        risk_scoring["risk_categories"] = self._categorize_risks(
            statistical_analysis, ml_analysis, deviation_analysis
        )
        
        # Analyze temporal risk trends
        risk_scoring["temporal_risk_trends"] = self._analyze_temporal_risk_trends(
            statistical_analysis, deviation_analysis
        )
        
        # Calculate confidence metrics
        risk_scoring["confidence_metrics"] = self._calculate_risk_confidence_metrics(
            statistical_analysis, ml_analysis, deviation_analysis
        )
        
        # Generate risk-based recommendations
        risk_scoring["risk_recommendations"] = self._generate_risk_recommendations(risk_scoring)
        
        logger.info(f"Risk scoring complete. Overall risk score: {risk_scoring['overall_risk_score']:.2f}")
        return risk_scoring
    
    def _initialize_anomaly_thresholds(self) -> Dict[str, float]:
        """Initialize anomaly detection thresholds"""
        return {
            "authentication_frequency_threshold": 2.0,  # Standard deviations
            "file_access_volume_threshold": 2.5,
            "email_volume_threshold": 2.0,
            "application_diversity_threshold": 1.5,
            "temporal_deviation_threshold": 2.0,
            "confidence_threshold": 0.8
        }
    
    def _analyze_authentication_anomalies(self, auth_patterns: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze authentication anomalies using statistical methods"""
        anomalies = {
            "frequency_anomalies": {},
            "temporal_anomalies": {},
            "location_anomalies": {},
            "device_anomalies": {},
            "method_anomalies": {}
        }
        
        # Analyze login frequency anomalies
        for user, patterns in auth_patterns.get("login_frequency", {}).items():
            avg_logins = patterns.get("average_logins_per_day", 0)
            max_logins = patterns.get("max_logins_per_day", 0)
            
            if max_logins > avg_logins * 3 and avg_logins > 0:  # 3x normal frequency
                anomalies["frequency_anomalies"][user] = {
                    "type": "excessive_login_frequency",
                    "baseline": avg_logins,
                    "observed": max_logins,
                    "severity": "medium" if max_logins < avg_logins * 5 else "high"
                }
        
        # Analyze temporal anomalies
        for user, patterns in auth_patterns.get("time_patterns", {}).items():
            business_hours_pct = patterns.get("business_hours_percentage", 100)
            weekend_activity = patterns.get("weekend_activity", {})
            
            if business_hours_pct < 50:  # Less than 50% during business hours
                anomalies["temporal_anomalies"][user] = {
                    "type": "off_hours_activity",
                    "business_hours_percentage": business_hours_pct,
                    "severity": "medium" if business_hours_pct > 25 else "high"
                }
            
            if weekend_activity.get("weekend_percentage", 0) > 30:  # More than 30% weekend activity
                anomalies["temporal_anomalies"][user] = anomalies["temporal_anomalies"].get(user, {})
                anomalies["temporal_anomalies"][user]["weekend_activity"] = {
                    "percentage": weekend_activity.get("weekend_percentage"),
                    "severity": "low"
                }
        
        # Analyze location anomalies
        for user, patterns in auth_patterns.get("location_patterns", {}).items():
            unique_locations = patterns.get("unique_locations", 0)
            suspicious_locations = patterns.get("suspicious_locations", [])
            
            if unique_locations > 5:  # More than 5 different locations
                anomalies["location_anomalies"][user] = {
                    "type": "multiple_locations",
                    "unique_locations": unique_locations,
                    "severity": "medium"
                }
            
            if suspicious_locations:
                anomalies["location_anomalies"][user] = anomalies["location_anomalies"].get(user, {})
                anomalies["location_anomalies"][user]["suspicious_locations"] = {
                    "locations": suspicious_locations,
                    "severity": "high"
                }
        
        # Analyze device anomalies
        for user, patterns in auth_patterns.get("device_patterns", {}).items():
            unique_devices = patterns.get("unique_devices", 0)
            new_devices = patterns.get("new_device_registrations", [])
            
            if unique_devices > 3:  # More than 3 different devices
                anomalies["device_anomalies"][user] = {
                    "type": "multiple_devices",
                    "unique_devices": unique_devices,
                    "severity": "low" if unique_devices <= 5 else "medium"
                }
            
            if len(new_devices) > 2:  # More than 2 new device registrations
                anomalies["device_anomalies"][user] = anomalies["device_anomalies"].get(user, {})
                anomalies["device_anomalies"][user]["new_devices"] = {
                    "count": len(new_devices),
                    "severity": "medium"
                }
        
        return anomalies
    
    def _analyze_file_access_anomalies(self, file_patterns: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze file access anomalies using statistical methods"""
        anomalies = {
            "volume_anomalies": {},
            "sensitive_file_anomalies": {},
            "temporal_anomalies": {},
            "bulk_access_anomalies": {},
            "permission_anomalies": {}
        }
        
        # Analyze volume anomalies
        for user, patterns in file_patterns.get("access_frequency", {}).items():
            avg_access = patterns.get("average_daily_access", 0)
            max_access = patterns.get("max_daily_access", 0)
            
            if max_access > avg_access * 4 and avg_access > 0:  # 4x normal volume
                anomalies["volume_anomalies"][user] = {
                    "type": "excessive_file_access",
                    "baseline": avg_access,
                    "observed": max_access,
                    "severity": "medium" if max_access < avg_access * 6 else "high"
                }
        
        # Analyze sensitive file access anomalies
        for user, patterns in file_patterns.get("sensitive_file_access", {}).items():
            sensitive_count = patterns.get("sensitive_file_access_count", 0)
            sensitive_pct = patterns.get("sensitive_access_percentage", 0)
            off_hours_sensitive = patterns.get("off_hours_sensitive_access", 0)
            
            if sensitive_pct > 20:  # More than 20% sensitive file access
                anomalies["sensitive_file_anomalies"][user] = {
                    "type": "excessive_sensitive_access",
                    "percentage": sensitive_pct,
                    "count": sensitive_count,
                    "severity": "medium" if sensitive_pct < 40 else "high"
                }
            
            if off_hours_sensitive > 5:  # More than 5 off-hours sensitive access
                anomalies["sensitive_file_anomalies"][user] = anomalies["sensitive_file_anomalies"].get(user, {})
                anomalies["sensitive_file_anomalies"][user]["off_hours_access"] = {
                    "count": off_hours_sensitive,
                    "severity": "high"
                }
        
        # Analyze temporal anomalies for file access
        for user, patterns in file_patterns.get("unusual_access_times", {}).items():
            off_hours_pct = patterns.get("off_hours_percentage", 0)
            weekend_count = patterns.get("weekend_access_count", 0)
            
            if off_hours_pct > 25:  # More than 25% off-hours access
                anomalies["temporal_anomalies"][user] = {
                    "type": "off_hours_file_access",
                    "percentage": off_hours_pct,
                    "severity": "medium"
                }
            
            if weekend_count > 10:  # More than 10 weekend access events
                anomalies["temporal_anomalies"][user] = anomalies["temporal_anomalies"].get(user, {})
                anomalies["temporal_anomalies"][user]["weekend_access"] = {
                    "count": weekend_count,
                    "severity": "low"
                }
        
        # Analyze bulk access patterns
        for user, patterns in file_patterns.get("bulk_access_patterns", {}).items():
            bulk_sessions = patterns.get("bulk_access_sessions", 0)
            max_hourly = patterns.get("max_hourly_access", 0)
            
            if bulk_sessions > 3:  # More than 3 bulk access sessions
                anomalies["bulk_access_anomalies"][user] = {
                    "type": "bulk_file_access",
                    "sessions": bulk_sessions,
                    "max_hourly": max_hourly,
                    "severity": "medium" if bulk_sessions < 6 else "high"
                }
        
        return anomalies
    
    def _analyze_email_anomalies(self, email_patterns: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze email anomalies using statistical methods"""
        anomalies = {
            "volume_anomalies": {},
            "external_communication_anomalies": {},
            "attachment_anomalies": {},
            "forwarding_anomalies": {},
            "recipient_anomalies": {}
        }
        
        # Analyze email volume anomalies
        for user, patterns in email_patterns.get("communication_frequency", {}).items():
            avg_emails = patterns.get("average_daily_emails", 0)
            max_emails = patterns.get("max_daily_emails", 0)
            spike_detected = patterns.get("communication_spike_detected", False)
            
            if spike_detected or (max_emails > avg_emails * 3 and avg_emails > 0):
                anomalies["volume_anomalies"][user] = {
                    "type": "email_volume_spike",
                    "baseline": avg_emails,
                    "observed": max_emails,
                    "severity": "medium"
                }
        
        # Analyze external communication anomalies
        for user, patterns in email_patterns.get("external_communications", {}).items():
            external_pct = patterns.get("external_percentage", 0)
            external_spike = patterns.get("external_communication_spike", False)
            suspicious_domains = patterns.get("suspicious_domains", [])
            
            if external_pct > 60:  # More than 60% external communication
                anomalies["external_communication_anomalies"][user] = {
                    "type": "excessive_external_communication",
                    "percentage": external_pct,
                    "severity": "medium"
                }
            
            if external_spike:
                anomalies["external_communication_anomalies"][user] = anomalies["external_communication_anomalies"].get(user, {})
                anomalies["external_communication_anomalies"][user]["spike_detected"] = {
                    "severity": "medium"
                }
            
            if suspicious_domains:
                anomalies["external_communication_anomalies"][user] = anomalies["external_communication_anomalies"].get(user, {})
                anomalies["external_communication_anomalies"][user]["suspicious_domains"] = {
                    "domains": suspicious_domains,
                    "severity": "high"
                }
        
        # Analyze attachment anomalies
        for user, patterns in email_patterns.get("attachment_patterns", {}).items():
            large_attachments = patterns.get("large_attachment_count", 0)
            suspicious_detected = patterns.get("suspicious_attachment_detected", False)
            
            if large_attachments > 5:  # More than 5 large attachments
                anomalies["attachment_anomalies"][user] = {
                    "type": "large_attachment_volume",
                    "count": large_attachments,
                    "severity": "medium"
                }
            
            if suspicious_detected:
                anomalies["attachment_anomalies"][user] = anomalies["attachment_anomalies"].get(user, {})
                anomalies["attachment_anomalies"][user]["suspicious_attachments"] = {
                    "severity": "high"
                }
        
        # Analyze forwarding anomalies
        for user, patterns in email_patterns.get("forwarding_patterns", {}).items():
            external_forwards = patterns.get("external_forward_count", 0)
            bulk_forwarding = patterns.get("bulk_forwarding_detected", False)
            
            if external_forwards > 10:  # More than 10 external forwards
                anomalies["forwarding_anomalies"][user] = {
                    "type": "excessive_external_forwarding",
                    "count": external_forwards,
                    "severity": "high"
                }
            
            if bulk_forwarding:
                anomalies["forwarding_anomalies"][user] = anomalies["forwarding_anomalies"].get(user, {})
                anomalies["forwarding_anomalies"][user]["bulk_forwarding"] = {
                    "severity": "high"
                }
        
        return anomalies
    
    def _analyze_application_anomalies(self, app_patterns: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze application usage anomalies"""
        anomalies = {
            "usage_anomalies": {},
            "privileged_app_anomalies": {},
            "unusual_app_anomalies": {},
            "off_hours_anomalies": {},
            "admin_tool_anomalies": {}
        }
        
        # Analyze privileged application anomalies
        for user, patterns in app_patterns.get("privileged_app_usage", {}).items():
            privileged_count = patterns.get("privileged_app_usage_count", 0)
            privileged_pct = patterns.get("privileged_usage_percentage", 0)
            elevated_pattern = patterns.get("elevated_access_pattern", False)
            
            if privileged_pct > 30:  # More than 30% privileged app usage
                anomalies["privileged_app_anomalies"][user] = {
                    "type": "excessive_privileged_app_usage",
                    "percentage": privileged_pct,
                    "count": privileged_count,
                    "severity": "medium"
                }
            
            if elevated_pattern:
                anomalies["privileged_app_anomalies"][user] = anomalies["privileged_app_anomalies"].get(user, {})
                anomalies["privileged_app_anomalies"][user]["elevated_pattern"] = {
                    "severity": "high"
                }
        
        # Analyze unusual application usage
        for user, patterns in app_patterns.get("unusual_applications", {}).items():
            unusual_count = patterns.get("unusual_app_count", 0)
            suspicious_usage = patterns.get("suspicious_app_usage", False)
            
            if unusual_count > 10:  # More than 10 unusual applications
                anomalies["unusual_app_anomalies"][user] = {
                    "type": "excessive_unusual_app_usage",
                    "count": unusual_count,
                    "severity": "medium"
                }
            
            if suspicious_usage:
                anomalies["unusual_app_anomalies"][user] = anomalies["unusual_app_anomalies"].get(user, {})
                anomalies["unusual_app_anomalies"][user]["suspicious_pattern"] = {
                    "severity": "high"
                }
        
        # Analyze off-hours application usage
        for user, patterns in app_patterns.get("off_hours_usage", {}).items():
            off_hours_pct = patterns.get("off_hours_percentage", 0)
            suspicious_pattern = patterns.get("suspicious_off_hours_pattern", False)
            
            if off_hours_pct > 40:  # More than 40% off-hours usage
                anomalies["off_hours_anomalies"][user] = {
                    "type": "excessive_off_hours_app_usage",
                    "percentage": off_hours_pct,
                    "severity": "medium"
                }
            
            if suspicious_pattern:
                anomalies["off_hours_anomalies"][user] = anomalies["off_hours_anomalies"].get(user, {})
                anomalies["off_hours_anomalies"][user]["suspicious_pattern"] = {
                    "severity": "high"
                }
        
        # Analyze administrative tool usage
        for user, patterns in app_patterns.get("administrative_tools", {}).items():
            admin_count = patterns.get("admin_tool_usage_count", 0)
            suspicious_admin = patterns.get("suspicious_admin_activity", False)
            
            if admin_count > 20:  # More than 20 admin tool usage events
                anomalies["admin_tool_anomalies"][user] = {
                    "type": "excessive_admin_tool_usage",
                    "count": admin_count,
                    "severity": "medium"
                }
            
            if suspicious_admin:
                anomalies["admin_tool_anomalies"][user] = anomalies["admin_tool_anomalies"].get(user, {})
                anomalies["admin_tool_anomalies"][user]["suspicious_activity"] = {
                    "severity": "high"
                }
        
        return anomalies
    
    def _analyze_temporal_anomalies(self, behavioral_patterns: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze temporal anomalies across all behavioral patterns"""
        temporal_anomalies = {
            "cross_pattern_temporal_anomalies": {},
            "activity_clustering": {},
            "time_based_correlations": {},
            "circadian_rhythm_deviations": {}
        }
        
        # Combine temporal data from all patterns
        all_patterns = [
            behavioral_patterns.get("authentication_patterns", {}),
            behavioral_patterns.get("file_access_patterns", {}),
            behavioral_patterns.get("email_patterns", {}),
            behavioral_patterns.get("application_patterns", {})
        ]
        
        # Analyze cross-pattern temporal correlations
        for user in self._get_all_users(behavioral_patterns):
            user_temporal_data = self._extract_user_temporal_data(user, all_patterns)
            
            # Detect unusual activity clustering
            clustering_anomaly = self._detect_activity_clustering(user_temporal_data)
            if clustering_anomaly:
                temporal_anomalies["activity_clustering"][user] = clustering_anomaly
            
            # Detect circadian rhythm deviations
            circadian_deviation = self._detect_circadian_deviations(user_temporal_data)
            if circadian_deviation:
                temporal_anomalies["circadian_rhythm_deviations"][user] = circadian_deviation
        
        return temporal_anomalies
    
    def _calculate_statistical_confidence(self, behavioral_patterns: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate statistical confidence in anomaly detection"""
        confidence_metrics = {
            "data_completeness": {},
            "pattern_stability": {},
            "sample_size_adequacy": {},
            "overall_confidence": 0.0
        }
        
        # Calculate data completeness
        total_users = len(self._get_all_users(behavioral_patterns))
        for pattern_type in ["authentication_patterns", "file_access_patterns", "email_patterns", "application_patterns"]:
            pattern_data = behavioral_patterns.get(pattern_type, {})
            users_with_data = len([user for user in pattern_data if pattern_data[user]])
            completeness = users_with_data / max(total_users, 1)
            confidence_metrics["data_completeness"][pattern_type] = completeness
        
        # Calculate pattern stability (mock implementation)
        confidence_metrics["pattern_stability"] = {
            "authentication": 0.85,
            "file_access": 0.78,
            "email": 0.82,
            "application": 0.75
        }
        
        # Calculate sample size adequacy
        confidence_metrics["sample_size_adequacy"] = {
            "adequate_users": total_users >= 10,
            "user_count": total_users,
            "adequacy_score": min(total_users / 50, 1.0)  # Ideal sample size of 50 users
        }
        
        # Calculate overall confidence
        completeness_avg = statistics.mean(confidence_metrics["data_completeness"].values())
        stability_avg = statistics.mean(confidence_metrics["pattern_stability"].values())
        adequacy_score = confidence_metrics["sample_size_adequacy"]["adequacy_score"]
        
        confidence_metrics["overall_confidence"] = (completeness_avg + stability_avg + adequacy_score) / 3
        
        return confidence_metrics
    
    def _calculate_anomaly_scores(self, statistical_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall anomaly scores for each user"""
        anomaly_scores = {}
        all_users = set()
        
        # Collect all users from different anomaly categories
        for category in ["authentication_anomalies", "file_access_anomalies", "email_anomalies", "application_anomalies"]:
            anomaly_data = statistical_analysis.get(category, {})
            for anomaly_type, users in anomaly_data.items():
                all_users.update(users.keys())
        
        # Calculate scores for each user
        for user in all_users:
            user_score = 0.0
            anomaly_count = 0
            
            # Score authentication anomalies
            auth_anomalies = statistical_analysis.get("authentication_anomalies", {})
            for anomaly_type, users in auth_anomalies.items():
                if user in users:
                    severity = users[user].get("severity", "low")
                    user_score += self._severity_to_score(severity) * 0.25  # 25% weight
                    anomaly_count += 1
            
            # Score file access anomalies
            file_anomalies = statistical_analysis.get("file_access_anomalies", {})
            for anomaly_type, users in file_anomalies.items():
                if user in users:
                    severity = users[user].get("severity", "low")
                    user_score += self._severity_to_score(severity) * 0.30  # 30% weight
                    anomaly_count += 1
            
            # Score email anomalies
            email_anomalies = statistical_analysis.get("email_anomalies", {})
            for anomaly_type, users in email_anomalies.items():
                if user in users:
                    severity = users[user].get("severity", "low")
                    user_score += self._severity_to_score(severity) * 0.25  # 25% weight
                    anomaly_count += 1
            
            # Score application anomalies
            app_anomalies = statistical_analysis.get("application_anomalies", {})
            for anomaly_type, users in app_anomalies.items():
                if user in users:
                    severity = users[user].get("severity", "low")
                    user_score += self._severity_to_score(severity) * 0.20  # 20% weight
                    anomaly_count += 1
            
            anomaly_scores[user] = {
                "total_score": user_score,
                "anomaly_count": anomaly_count,
                "normalized_score": min(user_score / max(anomaly_count, 1), 10.0),
                "risk_level": self._score_to_risk_level(user_score)
            }
        
        return anomaly_scores
    
    def _calculate_behavioral_deviations(self, current_data: Dict[str, Any], baseline_data: Dict[str, Any], behavior_type: str) -> Dict[str, Any]:
        """Calculate behavioral deviations from baseline"""
        deviations = {}
        
        for user in current_data:
            if user not in baseline_data:
                continue
                
            user_deviations = {}
            current_user_data = current_data[user]
            baseline_user_data = baseline_data[user]
            
            # Calculate specific deviations based on behavior type
            if behavior_type == "authentication":
                user_deviations = self._calculate_auth_deviations(current_user_data, baseline_user_data)
            elif behavior_type == "file_access":
                user_deviations = self._calculate_file_deviations(current_user_data, baseline_user_data)
            elif behavior_type == "email":
                user_deviations = self._calculate_email_deviations(current_user_data, baseline_user_data)
            elif behavior_type == "application":
                user_deviations = self._calculate_app_deviations(current_user_data, baseline_user_data)
            
            if user_deviations:
                deviations[user] = user_deviations
        
        return deviations
    
    def _calculate_deviation_scores(self, current_data: Dict[str, Any], baseline_data: Dict[str, Any]) -> Dict[str, float]:
        """Calculate numerical deviation scores"""
        deviation_scores = {}
        
        for user in current_data:
            if user not in baseline_data:
                continue
            
            # Simple deviation calculation (can be enhanced with more sophisticated methods)
            current_metrics = self._extract_numerical_metrics(current_data[user])
            baseline_metrics = self._extract_numerical_metrics(baseline_data[user])
            
            total_deviation = 0.0
            metric_count = 0
            
            for metric, current_value in current_metrics.items():
                if metric in baseline_metrics:
                    baseline_value = baseline_metrics[metric]
                    if baseline_value > 0:
                        deviation = abs(current_value - baseline_value) / baseline_value
                        total_deviation += deviation
                        metric_count += 1
            
            if metric_count > 0:
                deviation_scores[user] = total_deviation / metric_count
            else:
                deviation_scores[user] = 0.0
        
        return deviation_scores
    
    def _analyze_behavioral_trends(self, current_behavior: Dict[str, Any], historical_baselines: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze behavioral trends over time"""
        trends = {
            "increasing_trends": {},
            "decreasing_trends": {},
            "volatile_patterns": {},
            "stable_patterns": {}
        }
        
        # Analyze trends for each user across different behavioral patterns
        all_users = self._get_all_users(current_behavior)
        
        for user in all_users:
            user_trends = {}
            
            # Analyze authentication trends
            auth_trend = self._calculate_trend_direction(
                current_behavior.get("authentication_patterns", {}).get(user, {}),
                historical_baselines.get("authentication_baseline", {}).get(user, {})
            )
            if auth_trend:
                user_trends["authentication"] = auth_trend
            
            # Similar analysis for other behavioral patterns...
            
            if user_trends:
                # Categorize overall trend
                increasing_count = sum(1 for trend in user_trends.values() if trend.get("direction") == "increasing")
                decreasing_count = sum(1 for trend in user_trends.values() if trend.get("direction") == "decreasing")
                
                if increasing_count > decreasing_count:
                    trends["increasing_trends"][user] = user_trends
                elif decreasing_count > increasing_count:
                    trends["decreasing_trends"][user] = user_trends
                else:
                    trends["stable_patterns"][user] = user_trends
        
        return trends
    
    def _calculate_baseline_confidence(self, historical_baselines: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate confidence in baseline data"""
        confidence = {
            "data_quality": {},
            "temporal_coverage": {},
            "consistency_metrics": {},
            "overall_confidence": 0.0
        }
        
        # Mock confidence calculation
        confidence["data_quality"] = {
            "authentication": 0.85,
            "file_access": 0.78,
            "email": 0.82,
            "application": 0.75
        }
        
        confidence["temporal_coverage"] = {
            "days_covered": 30,
            "coverage_adequacy": 0.9
        }
        
        confidence["consistency_metrics"] = {
            "pattern_consistency": 0.8,
            "data_completeness": 0.85
        }
        
        confidence["overall_confidence"] = statistics.mean([
            statistics.mean(confidence["data_quality"].values()),
            confidence["temporal_coverage"]["coverage_adequacy"],
            confidence["consistency_metrics"]["pattern_consistency"]
        ])
        
        return confidence
    
    def _detect_change_points(self, current_behavior: Dict[str, Any], historical_baselines: Dict[str, Any]) -> Dict[str, Any]:
        """Detect significant change points in behavior"""
        change_points = {
            "behavioral_shifts": {},
            "change_significance": {},
            "change_timeline": {}
        }
        
        # Mock change point detection
        change_points["behavioral_shifts"] = {
            "user1@company.com": {
                "change_type": "activity_increase",
                "pattern": "file_access",
                "significance": 0.85,
                "detected_time": datetime.now() - timedelta(days=7)
            }
        }
        
        return change_points
    
    def _generate_deviation_recommendations(self, deviation_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate recommendations based on deviation analysis"""
        recommendations = {
            "immediate_actions": [],
            "monitoring_recommendations": [],
            "baseline_updates": [],
            "investigation_priorities": []
        }
        
        # Analyze significant deviations and generate recommendations
        for behavior_type, deviations in deviation_analysis.get("significant_deviations", {}).items():
            if deviations:
                recommendations["immediate_actions"].append(
                    f"Investigate {behavior_type} deviations for users: {', '.join(deviations.keys())}"
                )
        
        # Check deviation scores for high-risk users
        high_risk_users = []
        for behavior_type, scores in deviation_analysis.get("deviation_scores", {}).items():
            for user, score in scores.items():
                if score > 2.0:  # High deviation threshold
                    high_risk_users.append(user)
        
        if high_risk_users:
            recommendations["investigation_priorities"].append(
                f"Priority investigation for high-deviation users: {', '.join(set(high_risk_users))}"
            )
        
        return recommendations
    
    def _prepare_feature_vectors(self, behavioral_data: Dict[str, Any]) -> Dict[str, List[float]]:
        """Prepare feature vectors for ML analysis"""
        feature_vectors = {}
        
        # Extract numerical features from behavioral data
        all_users = self._get_all_users(behavioral_data)
        
        for user in all_users:
            features = []
            
            # Authentication features
            auth_data = behavioral_data.get("authentication_patterns", {}).get("login_frequency", {}).get(user, {})
            features.extend([
                auth_data.get("average_logins_per_day", 0),
                auth_data.get("max_logins_per_day", 0),
                auth_data.get("login_consistency", 0)
            ])
            
            # File access features
            file_data = behavioral_data.get("file_access_patterns", {}).get("access_frequency", {}).get(user, {})
            features.extend([
                file_data.get("average_daily_access", 0),
                file_data.get("max_daily_access", 0),
                file_data.get("access_consistency", 0)
            ])
            
            # Email features
            email_data = behavioral_data.get("email_patterns", {}).get("communication_frequency", {}).get(user, {})
            features.extend([
                email_data.get("average_daily_emails", 0),
                email_data.get("max_daily_emails", 0),
                email_data.get("email_consistency", 0)
            ])
            
            # Application features
            app_data = behavioral_data.get("application_patterns", {}).get("application_frequency", {}).get(user, {})
            features.extend([
                app_data.get("applications_used", 0),
                app_data.get("application_diversity", 0)
            ])
            
            feature_vectors[user] = features
        
        return feature_vectors
    
    def _apply_isolation_forest(self, feature_vectors: Dict[str, List[float]]) -> Dict[str, Any]:
        """Apply Isolation Forest algorithm for anomaly detection"""
        # Mock implementation - in practice, would use sklearn.ensemble.IsolationForest
        predictions = {}
        
        for user, features in feature_vectors.items():
            # Simple outlier detection based on feature magnitude
            feature_sum = sum(features)
            feature_mean = statistics.mean(features) if features else 0
            
            # Simple anomaly scoring
            if feature_sum > 100 or feature_mean > 20:
                predictions[user] = {
                    "anomaly_score": 0.8,
                    "is_anomaly": True,
                    "confidence": 0.75
                }
            else:
                predictions[user] = {
                    "anomaly_score": 0.2,
                    "is_anomaly": False,
                    "confidence": 0.85
                }
        
        return predictions
    
    def _apply_one_class_svm(self, feature_vectors: Dict[str, List[float]]) -> Dict[str, Any]:
        """Apply One-Class SVM for anomaly detection"""
        # Mock implementation
        predictions = {}
        
        for user, features in feature_vectors.items():
            # Simple outlier detection
            feature_variance = statistics.variance(features) if len(features) > 1 else 0
            
            if feature_variance > 50:
                predictions[user] = {
                    "anomaly_score": 0.7,
                    "is_anomaly": True,
                    "confidence": 0.8
                }
            else:
                predictions[user] = {
                    "anomaly_score": 0.3,
                    "is_anomaly": False,
                    "confidence": 0.9
                }
        
        return predictions
    
    def _apply_ensemble_models(self, feature_vectors: Dict[str, List[float]]) -> Dict[str, Any]:
        """Apply ensemble of ML models for anomaly detection"""
        # Combine results from multiple models
        isolation_results = self._apply_isolation_forest(feature_vectors)
        svm_results = self._apply_one_class_svm(feature_vectors)
        
        ensemble_predictions = {}
        
        for user in feature_vectors.keys():
            iso_score = isolation_results[user]["anomaly_score"]
            svm_score = svm_results[user]["anomaly_score"]
            
            # Ensemble averaging
            ensemble_score = (iso_score + svm_score) / 2
            
            ensemble_predictions[user] = {
                "anomaly_score": ensemble_score,
                "is_anomaly": ensemble_score > 0.5,
                "confidence": min(isolation_results[user]["confidence"], svm_results[user]["confidence"]),
                "component_scores": {
                    "isolation_forest": iso_score,
                    "one_class_svm": svm_score
                }
            }
        
        return ensemble_predictions
    
    # Additional helper methods would continue here...
    # For brevity, including representative examples of the remaining methods
    
    def _get_all_users(self, behavioral_patterns: Dict[str, Any]) -> set:
        """Get all users from behavioral patterns"""
        users = set()
        
        for pattern_type, pattern_data in behavioral_patterns.items():
            if isinstance(pattern_data, dict):
                for category, category_data in pattern_data.items():
                    if isinstance(category_data, dict):
                        users.update(category_data.keys())
        
        return users
    
    def _severity_to_score(self, severity: str) -> float:
        """Convert severity level to numerical score"""
        severity_map = {"low": 2.0, "medium": 5.0, "high": 8.0, "critical": 10.0}
        return severity_map.get(severity, 1.0)
    
    def _score_to_risk_level(self, score: float) -> str:
        """Convert numerical score to risk level"""
        if score >= 8.0:
            return "critical"
        elif score >= 6.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        else:
            return "low"
    
    def _extract_numerical_metrics(self, data: Dict[str, Any]) -> Dict[str, float]:
        """Extract numerical metrics from behavioral data"""
        metrics = {}
        
        for key, value in data.items():
            if isinstance(value, (int, float)):
                metrics[key] = float(value)
            elif isinstance(value, dict):
                # Recursively extract nested numerical values
                nested_metrics = self._extract_numerical_metrics(value)
                for nested_key, nested_value in nested_metrics.items():
                    metrics[f"{key}_{nested_key}"] = nested_value
        
        return metrics
