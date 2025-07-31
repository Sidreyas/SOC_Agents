"""
Host Threat Classifier Module
State 3: Host Threat Classification
Classifies and categorizes host-based threats and security incidents
"""

import logging
from typing import Dict, Any, List, Tuple, Set
from datetime import datetime, timedelta
import json
from collections import defaultdict
import statistics
from enum import Enum

logger = logging.getLogger(__name__)

class HostThreatCategory(Enum):
    """Enumeration for host threat categories"""
    MALWARE = "malware"
    INSIDER_THREAT = "insider_threat"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    RECONNAISSANCE = "reconnaissance"
    PERSISTENCE = "persistence"
    DEFENSE_EVASION = "defense_evasion"

class ThreatSeverity(Enum):
    """Enumeration for threat severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

class AttackStage(Enum):
    """Enumeration for attack stages"""
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"

class HostThreatClassifier:
    """
    Classifies and categorizes host-based threats and security incidents
    Provides comprehensive threat classification and risk assessment
    """
    
    def __init__(self):
        self.threat_signatures = self._load_threat_signatures()
        self.classification_rules = self._load_classification_rules()
        self.threat_taxonomy = self._load_threat_taxonomy()
        self.mitre_mapping = self._load_mitre_attack_mapping()
        
    def classify_host_threats(self, lateral_movement_analysis: Dict[str, Any],
                             endpoint_pattern_analysis: Dict[str, Any],
                             threat_intelligence: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify host-based threats and security incidents
        
        Args:
            lateral_movement_analysis: Results from lateral movement detection
            endpoint_pattern_analysis: Results from endpoint pattern analysis
            threat_intelligence: External threat intelligence data
            
        Returns:
            Host threat classification results
        """
        logger.info("Classifying host-based threats")
        
        threat_classification = {
            "threat_categories": {},
            "severity_assessments": {},
            "attack_stage_mapping": {},
            "mitre_att_mapping": {},
            "threat_correlations": {},
            "classification_confidence": {},
            "threat_evolution": {},
            "analysis_metadata": {}
        }
        
        # Classify threats by category
        threat_classification["threat_categories"] = self._classify_threat_categories(
            lateral_movement_analysis, endpoint_pattern_analysis
        )
        
        # Assess threat severity
        threat_classification["severity_assessments"] = self._assess_threat_severity(
            threat_classification["threat_categories"],
            lateral_movement_analysis,
            endpoint_pattern_analysis
        )
        
        # Map to attack stages
        threat_classification["attack_stage_mapping"] = self._map_attack_stages(
            threat_classification["threat_categories"],
            lateral_movement_analysis
        )
        
        # Map to MITRE ATT&CK framework
        threat_classification["mitre_att_mapping"] = self._map_mitre_attack(
            threat_classification["threat_categories"],
            threat_classification["attack_stage_mapping"]
        )
        
        # Correlate threats
        threat_classification["threat_correlations"] = self._correlate_threats(
            threat_classification["threat_categories"],
            threat_intelligence
        )
        
        # Calculate classification confidence
        threat_classification["classification_confidence"] = self._calculate_classification_confidence(
            threat_classification
        )
        
        # Analyze threat evolution
        threat_classification["threat_evolution"] = self._analyze_threat_evolution(
            threat_classification["threat_categories"],
            lateral_movement_analysis
        )
        
        # Add analysis metadata
        threat_classification["analysis_metadata"] = {
            "classification_timestamp": datetime.now(),
            "threats_classified": len(threat_classification["threat_categories"]),
            "high_severity_threats": len([
                threat for threat in threat_classification["severity_assessments"].values()
                if threat.get("severity_level") in ["critical", "high"]
            ]),
            "mitre_techniques_mapped": len(threat_classification["mitre_att_mapping"]),
            "classification_algorithm": "rule_based_with_ml_enhancement"
        }
        
        logger.info("Host threat classification complete")
        return threat_classification
    
    def generate_threat_intelligence(self, threat_classification: Dict[str, Any],
                                   external_intelligence: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate enhanced threat intelligence from classification results
        
        Args:
            threat_classification: Host threat classification results
            external_intelligence: External threat intelligence feeds
            
        Returns:
            Enhanced threat intelligence results
        """
        logger.info("Generating enhanced threat intelligence")
        
        threat_intelligence = {
            "ioc_extraction": {},
            "threat_attribution": {},
            "campaign_correlation": {},
            "threat_actor_profiling": {},
            "tactical_analysis": {},
            "strategic_implications": {},
            "intelligence_gaps": {},
            "analysis_metadata": {}
        }
        
        # Extract IOCs from classified threats
        threat_intelligence["ioc_extraction"] = self._extract_indicators_of_compromise(
            threat_classification
        )
        
        # Attribute threats to known actors/groups
        threat_intelligence["threat_attribution"] = self._attribute_threats(
            threat_classification, external_intelligence
        )
        
        # Correlate with known campaigns
        threat_intelligence["campaign_correlation"] = self._correlate_campaigns(
            threat_classification, external_intelligence
        )
        
        # Profile threat actors
        threat_intelligence["threat_actor_profiling"] = self._profile_threat_actors(
            threat_intelligence["threat_attribution"],
            threat_classification
        )
        
        # Analyze tactics, techniques, and procedures (TTPs)
        threat_intelligence["tactical_analysis"] = self._analyze_ttps(
            threat_classification,
            threat_intelligence["threat_attribution"]
        )
        
        # Assess strategic implications
        threat_intelligence["strategic_implications"] = self._assess_strategic_implications(
            threat_intelligence
        )
        
        # Identify intelligence gaps
        threat_intelligence["intelligence_gaps"] = self._identify_intelligence_gaps(
            threat_classification, threat_intelligence
        )
        
        # Add analysis metadata
        threat_intelligence["analysis_metadata"] = {
            "intelligence_timestamp": datetime.now(),
            "iocs_extracted": len(threat_intelligence["ioc_extraction"]),
            "threat_actors_identified": len(threat_intelligence["threat_attribution"]),
            "campaigns_correlated": len(threat_intelligence["campaign_correlation"]),
            "intelligence_confidence": self._calculate_intelligence_confidence(threat_intelligence)
        }
        
        logger.info("Threat intelligence generation complete")
        return threat_intelligence
    
    def assess_business_impact(self, threat_classification: Dict[str, Any],
                              organizational_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess business impact of classified threats
        
        Args:
            threat_classification: Host threat classification results
            organizational_context: Organizational structure and asset information
            
        Returns:
            Business impact assessment results
        """
        logger.info("Assessing business impact of threats")
        
        impact_assessment = {
            "asset_impact": {},
            "operational_impact": {},
            "financial_impact": {},
            "compliance_impact": {},
            "reputational_impact": {},
            "recovery_estimates": {},
            "impact_prioritization": {},
            "analysis_metadata": {}
        }
        
        # Assess impact on assets
        impact_assessment["asset_impact"] = self._assess_asset_impact(
            threat_classification, organizational_context
        )
        
        # Assess operational impact
        impact_assessment["operational_impact"] = self._assess_operational_impact(
            threat_classification, organizational_context
        )
        
        # Estimate financial impact
        impact_assessment["financial_impact"] = self._estimate_financial_impact(
            impact_assessment["asset_impact"],
            impact_assessment["operational_impact"]
        )
        
        # Assess compliance impact
        impact_assessment["compliance_impact"] = self._assess_compliance_impact(
            threat_classification, organizational_context
        )
        
        # Assess reputational impact
        impact_assessment["reputational_impact"] = self._assess_reputational_impact(
            threat_classification, impact_assessment["asset_impact"]
        )
        
        # Estimate recovery time and costs
        impact_assessment["recovery_estimates"] = self._estimate_recovery_parameters(
            threat_classification, impact_assessment
        )
        
        # Prioritize based on business impact
        impact_assessment["impact_prioritization"] = self._prioritize_by_business_impact(
            impact_assessment
        )
        
        # Add analysis metadata
        impact_assessment["analysis_metadata"] = {
            "assessment_timestamp": datetime.now(),
            "assets_assessed": len(impact_assessment["asset_impact"]),
            "high_impact_threats": len([
                threat for threat in impact_assessment["impact_prioritization"].values()
                if threat.get("impact_level") == "high"
            ]),
            "total_estimated_cost": impact_assessment["financial_impact"].get("total_estimated_cost", 0),
            "assessment_confidence": self._calculate_impact_confidence(impact_assessment)
        }
        
        logger.info("Business impact assessment complete")
        return impact_assessment
    
    def generate_response_recommendations(self, all_classification_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive response recommendations
        
        Args:
            all_classification_results: Combined results from all classification analyses
            
        Returns:
            Response recommendation results
        """
        logger.info("Generating response recommendations")
        
        response_recommendations = {
            "immediate_actions": {},
            "containment_strategies": {},
            "eradication_procedures": {},
            "recovery_plans": {},
            "prevention_measures": {},
            "monitoring_enhancements": {},
            "resource_requirements": {},
            "timeline_estimates": {},
            "analysis_metadata": {}
        }
        
        # Extract data from all analyses
        threat_classification = all_classification_results.get("threat_classification", {})
        threat_intelligence = all_classification_results.get("threat_intelligence", {})
        impact_assessment = all_classification_results.get("impact_assessment", {})
        
        # Generate immediate actions
        response_recommendations["immediate_actions"] = self._generate_immediate_actions(
            threat_classification, impact_assessment
        )
        
        # Develop containment strategies
        response_recommendations["containment_strategies"] = self._develop_containment_strategies(
            threat_classification, threat_intelligence
        )
        
        # Define eradication procedures
        response_recommendations["eradication_procedures"] = self._define_eradication_procedures(
            threat_classification, threat_intelligence
        )
        
        # Create recovery plans
        response_recommendations["recovery_plans"] = self._create_recovery_plans(
            impact_assessment, threat_classification
        )
        
        # Recommend prevention measures
        response_recommendations["prevention_measures"] = self._recommend_prevention_measures(
            threat_classification, threat_intelligence
        )
        
        # Enhance monitoring capabilities
        response_recommendations["monitoring_enhancements"] = self._enhance_monitoring_capabilities(
            threat_classification, threat_intelligence
        )
        
        # Estimate resource requirements
        response_recommendations["resource_requirements"] = self._estimate_resource_requirements(
            response_recommendations
        )
        
        # Provide timeline estimates
        response_recommendations["timeline_estimates"] = self._estimate_response_timelines(
            response_recommendations, threat_classification
        )
        
        # Add analysis metadata
        response_recommendations["analysis_metadata"] = {
            "recommendation_timestamp": datetime.now(),
            "immediate_actions_count": len(response_recommendations["immediate_actions"]),
            "containment_strategies_count": len(response_recommendations["containment_strategies"]),
            "recovery_procedures_count": len(response_recommendations["recovery_plans"]),
            "estimated_total_recovery_time": response_recommendations["timeline_estimates"].get("total_recovery_time", "unknown")
        }
        
        logger.info("Response recommendations generation complete")
        return response_recommendations
    
    def _load_threat_signatures(self) -> Dict[str, Any]:
        """Load threat detection signatures"""
        return {
            "malware_signatures": {
                "processes": ["mimikatz.exe", "psexec.exe", "procdump.exe"],
                "file_patterns": ["*.tmp.exe", "temp\\*.bat"],
                "registry_keys": ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]
            },
            "lateral_movement_signatures": {
                "network_patterns": ["rdp_brute_force", "smb_enumeration"],
                "authentication_patterns": ["multiple_failed_logins", "credential_reuse"],
                "process_patterns": ["wmi_execution", "powershell_remoting"]
            },
            "privilege_escalation_signatures": {
                "event_ids": [4672, 4673, 4674],
                "processes": ["runas.exe", "elevate.exe"],
                "techniques": ["uac_bypass", "token_manipulation"]
            }
        }
    
    def _load_classification_rules(self) -> Dict[str, Any]:
        """Load threat classification rules"""
        return {
            "severity_rules": {
                "critical": {
                    "indicators": ["active_c2", "data_exfiltration", "system_compromise"],
                    "min_confidence": 0.8
                },
                "high": {
                    "indicators": ["lateral_movement", "privilege_escalation", "persistence"],
                    "min_confidence": 0.7
                },
                "medium": {
                    "indicators": ["suspicious_activity", "anomalous_behavior"],
                    "min_confidence": 0.6
                }
            },
            "category_rules": {
                "malware": ["malicious_process", "suspicious_file", "c2_communication"],
                "insider_threat": ["off_hours_access", "data_hoarding", "policy_violation"],
                "lateral_movement": ["credential_reuse", "remote_execution", "network_enumeration"]
            }
        }
    
    def _load_threat_taxonomy(self) -> Dict[str, Any]:
        """Load threat taxonomy and categorization"""
        return {
            "threat_families": {
                "apt": ["apt1", "apt28", "apt29", "lazarus"],
                "ransomware": ["wannacry", "notpetya", "ryuk", "conti"],
                "banking": ["emotet", "trickbot", "qakbot"],
                "commodity": ["metasploit", "cobalt_strike", "empire"]
            },
            "attack_vectors": {
                "email": ["phishing", "spear_phishing", "malicious_attachment"],
                "web": ["drive_by_download", "watering_hole", "exploit_kit"],
                "network": ["lateral_movement", "remote_exploit", "brute_force"],
                "physical": ["usb_infection", "physical_access"]
            }
        }
    
    def _load_mitre_attack_mapping(self) -> Dict[str, Any]:
        """Load MITRE ATT&CK framework mapping"""
        return {
            "tactics": {
                "initial_access": ["T1078", "T1190", "T1566"],
                "execution": ["T1059", "T1106", "T1204"],
                "persistence": ["T1053", "T1547", "T1574"],
                "privilege_escalation": ["T1055", "T1068", "T1134"],
                "defense_evasion": ["T1027", "T1070", "T1112"],
                "credential_access": ["T1003", "T1110", "T1555"],
                "discovery": ["T1018", "T1033", "T1082"],
                "lateral_movement": ["T1021", "T1091", "T1550"],
                "collection": ["T1005", "T1039", "T1560"],
                "exfiltration": ["T1041", "T1048", "T1567"],
                "impact": ["T1485", "T1486", "T1490"]
            }
        }
    
    def _classify_threat_categories(self, lateral_movement_analysis: Dict[str, Any], 
                                  endpoint_pattern_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Classify threats into categories"""
        threat_categories = {}
        
        # Analyze lateral movement for classification
        movement_chains = lateral_movement_analysis.get("movement_chains", {})
        suspicious_hosts = lateral_movement_analysis.get("suspicious_hosts", {})
        
        # Classify lateral movement threats
        if movement_chains:
            for chain_id, chain_data in movement_chains.items():
                threat_categories[f"lateral_movement_{chain_id}"] = {
                    "category": HostThreatCategory.LATERAL_MOVEMENT.value,
                    "source_host": chain_data.get("source_host"),
                    "destination_host": chain_data.get("destination_host"),
                    "techniques": chain_data.get("movement_techniques", []),
                    "risk_score": chain_data.get("risk_score", 0),
                    "confidence": 0.8
                }
        
        # Analyze endpoint patterns for classification
        repetitive_alerts = endpoint_pattern_analysis.get("repetitive_alerts", {})
        anomaly_detection = endpoint_pattern_analysis.get("anomaly_detection", {})
        
        # Classify repetitive pattern threats
        for pattern_id, pattern_data in repetitive_alerts.items():
            if "malware" in pattern_id.lower() or "suspicious_process" in pattern_id.lower():
                threat_categories[f"malware_{pattern_id}"] = {
                    "category": HostThreatCategory.MALWARE.value,
                    "affected_endpoints": pattern_data.get("affected_endpoints", []),
                    "occurrence_count": pattern_data.get("occurrence_count", 0),
                    "pattern_type": pattern_data.get("pattern_type"),
                    "confidence": 0.7
                }
        
        # Classify anomaly-based threats
        for hostname, anomaly_data in anomaly_detection.items():
            anomalies = anomaly_data.get("anomalies_detected", [])
            for anomaly in anomalies:
                if anomaly["type"] == "volume_anomaly":
                    threat_categories[f"reconnaissance_{hostname}"] = {
                        "category": HostThreatCategory.RECONNAISSANCE.value,
                        "affected_host": hostname,
                        "anomaly_factor": anomaly.get("anomaly_factor", 1),
                        "confidence": 0.6
                    }
        
        return threat_categories
    
    def _assess_threat_severity(self, threat_categories: Dict[str, Any],
                               lateral_movement_analysis: Dict[str, Any],
                               endpoint_pattern_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Assess severity of classified threats"""
        severity_assessments = {}
        
        for threat_id, threat_data in threat_categories.items():
            severity_score = 0.0
            severity_factors = []
            
            category = threat_data.get("category")
            confidence = threat_data.get("confidence", 0.5)
            
            # Base severity by category
            if category == HostThreatCategory.LATERAL_MOVEMENT.value:
                severity_score += 6.0
                severity_factors.append("lateral_movement_detected")
                
                # Add score based on techniques
                techniques = threat_data.get("techniques", [])
                if "credential_dumping" in techniques:
                    severity_score += 2.0
                    severity_factors.append("credential_dumping")
                
            elif category == HostThreatCategory.MALWARE.value:
                severity_score += 5.0
                severity_factors.append("malware_detected")
                
                # Add score based on occurrence
                occurrence_count = threat_data.get("occurrence_count", 1)
                if occurrence_count > 10:
                    severity_score += 2.0
                    severity_factors.append("high_occurrence_rate")
                    
            elif category == HostThreatCategory.RECONNAISSANCE.value:
                severity_score += 3.0
                severity_factors.append("reconnaissance_activity")
                
                # Add score based on anomaly factor
                anomaly_factor = threat_data.get("anomaly_factor", 1)
                if anomaly_factor > 5:
                    severity_score += 2.0
                    severity_factors.append("high_anomaly_factor")
            
            # Adjust for confidence
            severity_score *= confidence
            
            # Determine severity level
            if severity_score >= 8.0:
                severity_level = ThreatSeverity.CRITICAL.value
            elif severity_score >= 6.0:
                severity_level = ThreatSeverity.HIGH.value
            elif severity_score >= 4.0:
                severity_level = ThreatSeverity.MEDIUM.value
            elif severity_score >= 2.0:
                severity_level = ThreatSeverity.LOW.value
            else:
                severity_level = ThreatSeverity.INFORMATIONAL.value
            
            severity_assessments[threat_id] = {
                "severity_level": severity_level,
                "severity_score": severity_score,
                "severity_factors": severity_factors,
                "confidence_adjusted_score": severity_score,
                "assessment_confidence": confidence
            }
        
        return severity_assessments
