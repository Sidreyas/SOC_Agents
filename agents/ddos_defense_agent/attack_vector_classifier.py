"""
DDoS Defense Agent - State 3: Attack Vector Classification
Attack type determination and Azure Monitor analysis for DDoS attack classification
"""

import logging
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict, Counter
from enum import Enum
import re

# Configure logger
logger = logging.getLogger(__name__)

class AttackType(Enum):
    """DDoS attack type classifications"""
    VOLUMETRIC_UDP = "volumetric_udp"
    VOLUMETRIC_ICMP = "volumetric_icmp"
    PROTOCOL_SYN = "protocol_syn"
    PROTOCOL_FRAGMENT = "protocol_fragment"
    APPLICATION_HTTP = "application_http"
    APPLICATION_DNS = "application_dns"
    APPLICATION_SLOWLORIS = "application_slowloris"
    MIXED_VECTOR = "mixed_vector"
    UNKNOWN = "unknown"

class AttackSeverity(Enum):
    """Attack severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

@dataclass
class AttackVector:
    """Attack vector classification result"""
    vector_type: AttackType
    confidence_score: float
    volume_metrics: Dict[str, float]
    protocol_analysis: Dict[str, Any]
    application_impact: Dict[str, Any]
    severity: AttackSeverity

@dataclass
class AttackClassificationResult:
    """Container for attack vector classification results"""
    analysis_id: str
    analysis_timestamp: datetime
    primary_attack_vectors: List[AttackVector]
    attack_characteristics: Dict[str, Any]
    protocol_analysis: Dict[str, Any]
    application_analysis: Dict[str, Any]
    volumetric_analysis: Dict[str, Any]
    attack_sophistication: str
    overall_severity: AttackSeverity
    confidence_score: float

class AttackVectorClassifier:
    """
    State 3: Attack Vector Classification
    Classifies DDoS attack types and analyzes attack characteristics
    """
    
    def __init__(self):
        """Initialize the Attack Vector Classifier"""
        self.classification_config = self._initialize_classification_config()
        self.azure_monitor_client = self._initialize_azure_monitor_client()
        self.attack_signatures = self._initialize_attack_signatures()
        self.protocol_analyzers = self._initialize_protocol_analyzers()
        self.application_monitors = self._initialize_application_monitors()
        
        logger.info("Attack Vector Classifier initialized")
    
    def classify_attack_vectors(self, traffic_data: Dict[str, Any],
                              source_intelligence: Dict[str, Any],
                              azure_monitor_data: Dict[str, Any]) -> AttackClassificationResult:
        """
        Classify DDoS attack vectors and characteristics
        
        Args:
            traffic_data: Traffic pattern analysis data
            source_intelligence: Source IP intelligence data
            azure_monitor_data: Azure Monitor logs and metrics
            
        Returns:
            Comprehensive attack vector classification results
        """
        logger.info("Starting attack vector classification")
        
        analysis_id = f"attack-class-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        start_time = datetime.now()
        
        try:
            # Analyze attack characteristics
            attack_characteristics = self._analyze_attack_characteristics(
                traffic_data, source_intelligence, azure_monitor_data
            )
            
            # Perform protocol analysis
            protocol_analysis = self._perform_protocol_analysis(
                traffic_data, azure_monitor_data
            )
            
            # Analyze application layer impacts
            application_analysis = self._analyze_application_layer(
                azure_monitor_data, attack_characteristics
            )
            
            # Perform volumetric analysis
            volumetric_analysis = self._perform_volumetric_analysis(
                traffic_data, protocol_analysis
            )
            
            # Classify primary attack vectors
            primary_attack_vectors = self._classify_primary_vectors(
                attack_characteristics, protocol_analysis, application_analysis, volumetric_analysis
            )
            
            # Determine attack sophistication
            attack_sophistication = self._determine_attack_sophistication(
                primary_attack_vectors, source_intelligence
            )
            
            # Calculate overall severity
            overall_severity = self._calculate_overall_severity(
                primary_attack_vectors, attack_characteristics
            )
            
            # Calculate confidence score
            confidence_score = self._calculate_classification_confidence(
                primary_attack_vectors, attack_characteristics
            )
            
            result = AttackClassificationResult(
                analysis_id=analysis_id,
                analysis_timestamp=start_time,
                primary_attack_vectors=primary_attack_vectors,
                attack_characteristics=attack_characteristics,
                protocol_analysis=protocol_analysis,
                application_analysis=application_analysis,
                volumetric_analysis=volumetric_analysis,
                attack_sophistication=attack_sophistication,
                overall_severity=overall_severity,
                confidence_score=confidence_score
            )
            
            logger.info(f"Attack vector classification completed: {analysis_id}")
            return result
            
        except Exception as e:
            logger.error(f"Error in attack vector classification: {str(e)}")
            raise
    
    def analyze_volumetric_attacks(self, traffic_metrics: Dict[str, Any],
                                 baseline_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze volumetric attack patterns (UDP/ICMP floods)
        
        Args:
            traffic_metrics: Current traffic metrics
            baseline_data: Historical baseline data
            
        Returns:
            Volumetric attack analysis results
        """
        logger.info("Analyzing volumetric attack patterns")
        
        volumetric_analysis = {
            "udp_flood_analysis": {},
            "icmp_flood_analysis": {},
            "amplification_attacks": {},
            "volume_metrics": {},
            "attack_intensity": {},
            "geographic_correlation": {},
            "analysis_metadata": {
                "analysis_timestamp": datetime.now(),
                "attack_detected": False,
                "primary_protocol": "unknown",
                "volume_multiplier": 1.0
            }
        }
        
        try:
            # Analyze UDP flood patterns
            volumetric_analysis["udp_flood_analysis"] = self._analyze_udp_floods(
                traffic_metrics, baseline_data
            )
            
            # Analyze ICMP flood patterns
            volumetric_analysis["icmp_flood_analysis"] = self._analyze_icmp_floods(
                traffic_metrics, baseline_data
            )
            
            # Detect amplification attacks
            volumetric_analysis["amplification_attacks"] = self._detect_amplification_attacks(
                traffic_metrics, volumetric_analysis["udp_flood_analysis"]
            )
            
            # Calculate volume metrics
            volumetric_analysis["volume_metrics"] = self._calculate_volume_metrics(
                traffic_metrics, baseline_data
            )
            
            # Assess attack intensity
            volumetric_analysis["attack_intensity"] = self._assess_attack_intensity(
                volumetric_analysis["volume_metrics"]
            )
            
            # Correlate with geographic data
            volumetric_analysis["geographic_correlation"] = self._correlate_volumetric_geography(
                volumetric_analysis
            )
            
            # Update metadata
            volumetric_analysis["analysis_metadata"].update({
                "attack_detected": self._is_volumetric_attack_detected(volumetric_analysis),
                "primary_protocol": self._determine_primary_protocol(volumetric_analysis),
                "volume_multiplier": volumetric_analysis["volume_metrics"].get("multiplier", 1.0)
            })
            
            return volumetric_analysis
            
        except Exception as e:
            logger.error(f"Error analyzing volumetric attacks: {str(e)}")
            raise
    
    def analyze_protocol_attacks(self, network_data: Dict[str, Any],
                               firewall_logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze protocol-level attacks (SYN floods, fragmented packets)
        
        Args:
            network_data: Network traffic data
            firewall_logs: Azure Firewall logs
            
        Returns:
            Protocol attack analysis results
        """
        logger.info("Analyzing protocol-level attacks")
        
        protocol_analysis = {
            "syn_flood_analysis": {},
            "fragmentation_attacks": {},
            "tcp_state_exhaustion": {},
            "connection_analysis": {},
            "protocol_anomalies": {},
            "firewall_impact": {},
            "analysis_metadata": {
                "analysis_timestamp": datetime.now(),
                "protocol_attacks_detected": 0,
                "primary_attack_type": "none",
                "severity": "low"
            }
        }
        
        try:
            # Analyze SYN flood attacks
            protocol_analysis["syn_flood_analysis"] = self._analyze_syn_floods(
                network_data, firewall_logs
            )
            
            # Detect fragmentation attacks
            protocol_analysis["fragmentation_attacks"] = self._analyze_fragmentation_attacks(
                network_data, firewall_logs
            )
            
            # Analyze TCP state exhaustion
            protocol_analysis["tcp_state_exhaustion"] = self._analyze_tcp_state_exhaustion(
                network_data
            )
            
            # Perform connection analysis
            protocol_analysis["connection_analysis"] = self._analyze_connection_patterns(
                network_data, firewall_logs
            )
            
            # Detect protocol anomalies
            protocol_analysis["protocol_anomalies"] = self._detect_protocol_anomalies(
                network_data
            )
            
            # Assess firewall impact
            protocol_analysis["firewall_impact"] = self._assess_firewall_impact(
                firewall_logs, protocol_analysis
            )
            
            # Update metadata
            attacks_detected = sum([
                len(protocol_analysis["syn_flood_analysis"].get("attacks", [])),
                len(protocol_analysis["fragmentation_attacks"].get("attacks", [])),
                len(protocol_analysis["tcp_state_exhaustion"].get("attacks", []))
            ])
            
            protocol_analysis["analysis_metadata"].update({
                "protocol_attacks_detected": attacks_detected,
                "primary_attack_type": self._determine_primary_protocol_attack(protocol_analysis),
                "severity": self._assess_protocol_attack_severity(protocol_analysis)
            })
            
            return protocol_analysis
            
        except Exception as e:
            logger.error(f"Error analyzing protocol attacks: {str(e)}")
            raise
    
    def analyze_application_layer_attacks(self, application_logs: Dict[str, Any],
                                        performance_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze application layer attacks (HTTP floods, slowloris)
        
        Args:
            application_logs: Application server logs
            performance_metrics: Application performance metrics
            
        Returns:
            Application layer attack analysis results
        """
        logger.info("Analyzing application layer attacks")
        
        application_analysis = {
            "http_flood_analysis": {},
            "slowloris_detection": {},
            "dns_attacks": {},
            "ssl_attacks": {},
            "application_exhaustion": {},
            "performance_impact": {},
            "analysis_metadata": {
                "analysis_timestamp": datetime.now(),
                "application_attacks_detected": 0,
                "services_affected": 0,
                "performance_degradation": 0.0
            }
        }
        
        try:
            # Analyze HTTP flood attacks
            application_analysis["http_flood_analysis"] = self._analyze_http_floods(
                application_logs, performance_metrics
            )
            
            # Detect slowloris attacks
            application_analysis["slowloris_detection"] = self._detect_slowloris_attacks(
                application_logs
            )
            
            # Analyze DNS attacks
            application_analysis["dns_attacks"] = self._analyze_dns_attacks(
                application_logs
            )
            
            # Detect SSL/TLS attacks
            application_analysis["ssl_attacks"] = self._analyze_ssl_attacks(
                application_logs, performance_metrics
            )
            
            # Assess application exhaustion
            application_analysis["application_exhaustion"] = self._assess_application_exhaustion(
                performance_metrics
            )
            
            # Analyze performance impact
            application_analysis["performance_impact"] = self._analyze_performance_impact(
                performance_metrics, application_analysis
            )
            
            # Update metadata
            attacks_detected = sum([
                len(application_analysis["http_flood_analysis"].get("attacks", [])),
                len(application_analysis["slowloris_detection"].get("attacks", [])),
                len(application_analysis["dns_attacks"].get("attacks", [])),
                len(application_analysis["ssl_attacks"].get("attacks", []))
            ])
            
            application_analysis["analysis_metadata"].update({
                "application_attacks_detected": attacks_detected,
                "services_affected": len(application_analysis["performance_impact"].get("affected_services", [])),
                "performance_degradation": application_analysis["performance_impact"].get("degradation_percentage", 0.0)
            })
            
            return application_analysis
            
        except Exception as e:
            logger.error(f"Error analyzing application layer attacks: {str(e)}")
            raise
    
    def generate_attack_classification_report(self, classification_result: AttackClassificationResult,
                                            volumetric_analysis: Dict[str, Any],
                                            protocol_analysis: Dict[str, Any],
                                            application_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive attack vector classification report
        
        Args:
            classification_result: Attack classification results
            volumetric_analysis: Volumetric attack analysis
            protocol_analysis: Protocol attack analysis
            application_analysis: Application layer analysis
            
        Returns:
            Comprehensive attack classification report
        """
        logger.info("Generating attack vector classification report")
        
        report = {
            "executive_summary": {},
            "attack_overview": {},
            "vector_analysis": {},
            "attack_characteristics": {},
            "impact_assessment": {},
            "sophistication_analysis": {},
            "mitigation_recommendations": [],
            "technical_details": {},
            "report_metadata": {
                "report_id": f"ATTACK-CLASS-RPT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                "generation_timestamp": datetime.now(),
                "analysis_id": classification_result.analysis_id,
                "overall_severity": classification_result.overall_severity.value
            }
        }
        
        try:
            # Executive summary
            report["executive_summary"] = self._create_attack_executive_summary(
                classification_result, volumetric_analysis, protocol_analysis, application_analysis
            )
            
            # Attack overview
            report["attack_overview"] = self._create_attack_overview(
                classification_result.primary_attack_vectors
            )
            
            # Vector analysis
            report["vector_analysis"] = self._create_vector_analysis(
                classification_result.primary_attack_vectors,
                volumetric_analysis, protocol_analysis, application_analysis
            )
            
            # Attack characteristics
            report["attack_characteristics"] = self._create_characteristics_summary(
                classification_result.attack_characteristics
            )
            
            # Impact assessment
            report["impact_assessment"] = self._create_impact_assessment(
                classification_result, application_analysis
            )
            
            # Sophistication analysis
            report["sophistication_analysis"] = self._create_sophistication_analysis(
                classification_result.attack_sophistication, classification_result.primary_attack_vectors
            )
            
            # Mitigation recommendations
            report["mitigation_recommendations"] = self._generate_mitigation_recommendations(
                classification_result, volumetric_analysis, protocol_analysis, application_analysis
            )
            
            # Technical details
            report["technical_details"] = self._compile_technical_details(
                classification_result, volumetric_analysis, protocol_analysis, application_analysis
            )
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating attack classification report: {str(e)}")
            raise
    
    def _initialize_classification_config(self) -> Dict[str, Any]:
        """Initialize attack classification configuration"""
        return {
            "attack_thresholds": {
                "volumetric": {
                    "udp_pps": 100000,  # packets per second
                    "icmp_pps": 50000,
                    "bytes_per_second": 1000000000  # 1 Gbps
                },
                "protocol": {
                    "syn_ratio": 0.8,  # SYN to SYN-ACK ratio
                    "fragment_ratio": 0.3,
                    "connection_rate": 10000
                },
                "application": {
                    "http_requests_per_second": 10000,
                    "dns_queries_per_second": 50000,
                    "ssl_handshakes_per_second": 1000
                }
            },
            "severity_weights": {
                "volume": 0.4,
                "duration": 0.2,
                "sophistication": 0.2,
                "impact": 0.2
            },
            "confidence_factors": {
                "multiple_vectors": 0.3,
                "clear_signatures": 0.4,
                "source_correlation": 0.2,
                "temporal_patterns": 0.1
            }
        }
    
    def _initialize_azure_monitor_client(self) -> Dict[str, Any]:
        """Initialize Azure Monitor client configuration"""
        return {
            "workspace_id": "log_analytics_workspace_id",
            "subscription_id": "azure_subscription_id",
            "api_version": "2021-05-01-preview",
            "base_url": "https://api.loganalytics.io/",
            "auth_endpoint": "https://login.microsoftonline.com/"
        }
    
    def _initialize_attack_signatures(self) -> Dict[str, Dict[str, Any]]:
        """Initialize attack signature patterns"""
        return {
            "udp_flood": {
                "packet_size_patterns": [64, 128, 512, 1024],
                "port_patterns": [53, 123, 161, 1900],
                "amplification_ratios": {"dns": 28, "ntp": 556, "snmp": 6.3}
            },
            "syn_flood": {
                "flag_patterns": ["SYN"],
                "window_sizes": [0, 8192, 16384],
                "options_patterns": ["mss", "nop", "timestamp"]
            },
            "http_flood": {
                "user_agent_patterns": ["curl", "wget", "python", "bot"],
                "request_patterns": ["GET /", "POST /", "HEAD /"],
                "header_anomalies": ["missing_host", "invalid_content_length"]
            },
            "slowloris": {
                "connection_patterns": ["partial_headers", "slow_headers"],
                "timing_patterns": {"header_delay": 10, "connection_hold": 300}
            }
        }
    
    def _initialize_protocol_analyzers(self) -> Dict[str, Any]:
        """Initialize protocol analysis tools"""
        return {
            "tcp_analyzer": {"state_tracking": True, "sequence_analysis": True},
            "udp_analyzer": {"port_scanning": True, "amplification_detection": True},
            "icmp_analyzer": {"type_analysis": True, "rate_limiting": True},
            "dns_analyzer": {"query_analysis": True, "response_validation": True}
        }
    
    def _initialize_application_monitors(self) -> Dict[str, Any]:
        """Initialize application monitoring configuration"""
        return {
            "http_monitor": {"status_code_tracking": True, "response_time_analysis": True},
            "ssl_monitor": {"handshake_analysis": True, "cipher_tracking": True},
            "dns_monitor": {"query_type_analysis": True, "response_analysis": True},
            "performance_thresholds": {
                "response_time_ms": 5000,
                "error_rate_percent": 10,
                "throughput_reduction_percent": 50
            }
        }
    
    # Placeholder implementations for comprehensive functionality
    def _analyze_attack_characteristics(self, traffic_data: Dict[str, Any],
                                      source_intelligence: Dict[str, Any],
                                      azure_monitor_data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "attack_duration": timedelta(minutes=30),
            "peak_intensity": 1000000,
            "geographic_spread": "global",
            "coordination_level": "high"
        }
    
    def _perform_protocol_analysis(self, traffic_data: Dict[str, Any],
                                 azure_monitor_data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "dominant_protocols": ["TCP", "UDP"],
            "anomalous_patterns": ["syn_flood"],
            "protocol_distribution": {"TCP": 0.6, "UDP": 0.4}
        }
    
    def _analyze_application_layer(self, azure_monitor_data: Dict[str, Any],
                                 attack_characteristics: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "affected_services": ["HTTP", "HTTPS"],
            "service_degradation": {"HTTP": 0.8, "HTTPS": 0.5},
            "application_errors": 1500
        }
    
    def _perform_volumetric_analysis(self, traffic_data: Dict[str, Any],
                                   protocol_analysis: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "peak_pps": 500000,
            "peak_bps": 2000000000,
            "amplification_factor": 10.5,
            "volume_classification": "high"
        }
    
    def _classify_primary_vectors(self, attack_characteristics: Dict[str, Any],
                                protocol_analysis: Dict[str, Any],
                                application_analysis: Dict[str, Any],
                                volumetric_analysis: Dict[str, Any]) -> List[AttackVector]:
        return [
            AttackVector(
                vector_type=AttackType.VOLUMETRIC_UDP,
                confidence_score=0.9,
                volume_metrics={"pps": 500000, "bps": 2000000000},
                protocol_analysis={"udp_dominant": True},
                application_impact={"service_degradation": 0.8},
                severity=AttackSeverity.HIGH
            )
        ]
    
    def _determine_attack_sophistication(self, attack_vectors: List[AttackVector],
                                       source_intelligence: Dict[str, Any]) -> str:
        return "medium"
    
    def _calculate_overall_severity(self, attack_vectors: List[AttackVector],
                                  attack_characteristics: Dict[str, Any]) -> AttackSeverity:
        return AttackSeverity.HIGH
    
    def _calculate_classification_confidence(self, attack_vectors: List[AttackVector],
                                           attack_characteristics: Dict[str, Any]) -> float:
        return 0.85
    
    # Additional placeholder methods for comprehensive functionality
    def _analyze_udp_floods(self, traffic_metrics: Dict[str, Any],
                          baseline_data: Dict[str, Any]) -> Dict[str, Any]:
        return {}
    
    def _analyze_icmp_floods(self, traffic_metrics: Dict[str, Any],
                           baseline_data: Dict[str, Any]) -> Dict[str, Any]:
        return {}
    
    def _detect_amplification_attacks(self, traffic_metrics: Dict[str, Any],
                                    udp_analysis: Dict[str, Any]) -> Dict[str, Any]:
        return {}
    
    def _calculate_volume_metrics(self, traffic_metrics: Dict[str, Any],
                                baseline_data: Dict[str, Any]) -> Dict[str, Any]:
        return {"multiplier": 10.0}
    
    def _assess_attack_intensity(self, volume_metrics: Dict[str, Any]) -> Dict[str, Any]:
        return {}
    
    def _correlate_volumetric_geography(self, volumetric_analysis: Dict[str, Any]) -> Dict[str, Any]:
        return {}
    
    def _is_volumetric_attack_detected(self, analysis: Dict[str, Any]) -> bool:
        return True
    
    def _determine_primary_protocol(self, analysis: Dict[str, Any]) -> str:
        return "UDP"
    
    # Protocol analysis placeholder methods
    def _analyze_syn_floods(self, network_data: Dict[str, Any],
                          firewall_logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {"attacks": []}
    
    def _analyze_fragmentation_attacks(self, network_data: Dict[str, Any],
                                     firewall_logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {"attacks": []}
    
    def _analyze_tcp_state_exhaustion(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        return {"attacks": []}
    
    def _analyze_connection_patterns(self, network_data: Dict[str, Any],
                                   firewall_logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {}
    
    def _detect_protocol_anomalies(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        return {}
    
    def _assess_firewall_impact(self, firewall_logs: List[Dict[str, Any]],
                              protocol_analysis: Dict[str, Any]) -> Dict[str, Any]:
        return {}
    
    def _determine_primary_protocol_attack(self, analysis: Dict[str, Any]) -> str:
        return "none"
    
    def _assess_protocol_attack_severity(self, analysis: Dict[str, Any]) -> str:
        return "low"
    
    # Application analysis placeholder methods
    def _analyze_http_floods(self, application_logs: Dict[str, Any],
                           performance_metrics: Dict[str, Any]) -> Dict[str, Any]:
        return {"attacks": []}
    
    def _detect_slowloris_attacks(self, application_logs: Dict[str, Any]) -> Dict[str, Any]:
        return {"attacks": []}
    
    def _analyze_dns_attacks(self, application_logs: Dict[str, Any]) -> Dict[str, Any]:
        return {"attacks": []}
    
    def _analyze_ssl_attacks(self, application_logs: Dict[str, Any],
                           performance_metrics: Dict[str, Any]) -> Dict[str, Any]:
        return {"attacks": []}
    
    def _assess_application_exhaustion(self, performance_metrics: Dict[str, Any]) -> Dict[str, Any]:
        return {}
    
    def _analyze_performance_impact(self, performance_metrics: Dict[str, Any],
                                  application_analysis: Dict[str, Any]) -> Dict[str, Any]:
        return {"affected_services": [], "degradation_percentage": 0.0}
    
    # Report generation placeholder methods
    def _create_attack_executive_summary(self, *args) -> Dict[str, Any]:
        return {}
    def _create_attack_overview(self, *args) -> Dict[str, Any]:
        return {}
    def _create_vector_analysis(self, *args) -> Dict[str, Any]:
        return {}
    def _create_characteristics_summary(self, *args) -> Dict[str, Any]:
        return {}
    def _create_impact_assessment(self, *args) -> Dict[str, Any]:
        return {}
    def _create_sophistication_analysis(self, *args) -> Dict[str, Any]:
        return {}
    def _generate_mitigation_recommendations(self, *args) -> List[Dict[str, Any]]:
        return []
    def _compile_technical_details(self, *args) -> Dict[str, Any]:
        return {}
