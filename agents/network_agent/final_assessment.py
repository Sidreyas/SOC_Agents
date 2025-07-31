"""
Final Assessment Module
State 6: Final Assessment for Network & Exfiltration Agent
Provides comprehensive assessment and response recommendations
"""

import logging
import asyncio
from typing import Dict, Any, List, Optional, Set, Tuple
from datetime import datetime, timedelta
import json
from enum import Enum

logger = logging.getLogger(__name__)

class ThreatSeverity(Enum):
    """Threat severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ResponseAction(Enum):
    """Response action types"""
    BLOCK = "block"
    MONITOR = "monitor"
    INVESTIGATE = "investigate"
    ESCALATE = "escalate"
    QUARANTINE = "quarantine"
    ALERT = "alert"

class FinalAssessment:
    """
    Final Assessment System
    Provides comprehensive threat assessment and response recommendations
    for network and exfiltration activities
    """
    
    def __init__(self):
        self.severity_weights = self._load_severity_weights()
        self.response_matrix = self._load_response_matrix()
        self.escalation_thresholds = self._load_escalation_thresholds()
        
    async def perform_final_assessment(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform final assessment of network threats
        
        Args:
            analysis_results: Combined results from all analysis modules
            
        Returns:
            Final assessment with recommendations
        """
        logger.info("Starting final assessment")
        
        assessment_results = {
            "executive_summary": {},
            "threat_classification": {},
            "severity_assessment": {},
            "confidence_analysis": {},
            "impact_analysis": {},
            "attribution_summary": {},
            "ioc_summary": {},
            "response_recommendations": {},
            "containment_actions": {},
            "investigation_priorities": {},
            "long_term_recommendations": {},
            "assessment_metadata": {
                "timestamp": datetime.now(),
                "analysis_duration": None,
                "data_sources": [],
                "analyst_notes": []
            }
        }
        
        try:
            # Executive summary
            assessment_results["executive_summary"] = await self._generate_executive_summary(analysis_results)
            
            # Threat classification
            assessment_results["threat_classification"] = await self._classify_threats(analysis_results)
            
            # Severity assessment
            assessment_results["severity_assessment"] = await self._assess_severity(analysis_results)
            
            # Confidence analysis
            assessment_results["confidence_analysis"] = await self._analyze_confidence(analysis_results)
            
            # Impact analysis
            assessment_results["impact_analysis"] = await self._analyze_impact(analysis_results)
            
            # Attribution summary
            assessment_results["attribution_summary"] = await self._summarize_attribution(analysis_results)
            
            # IOC summary
            assessment_results["ioc_summary"] = await self._summarize_iocs(analysis_results)
            
            # Response recommendations
            assessment_results["response_recommendations"] = await self._generate_response_recommendations(assessment_results)
            
            # Containment actions
            assessment_results["containment_actions"] = await self._recommend_containment_actions(assessment_results)
            
            # Investigation priorities
            assessment_results["investigation_priorities"] = await self._prioritize_investigations(assessment_results)
            
            # Long-term recommendations
            assessment_results["long_term_recommendations"] = await self._generate_long_term_recommendations(assessment_results)
            
            logger.info("Final assessment completed")
            
        except Exception as e:
            logger.error(f"Error in final assessment: {str(e)}")
            assessment_results["error"] = str(e)
            
        return assessment_results
    
    async def _generate_executive_summary(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary"""
        summary = {
            "key_findings": [],
            "threat_overview": "",
            "business_impact": "",
            "urgency_level": "medium",
            "recommended_actions": [],
            "timeline": {},
            "affected_systems": []
        }
        
        # Analyze key findings from each module
        traffic_analysis = analysis_results.get("traffic_analysis", {})
        exfiltration_detection = analysis_results.get("exfiltration_detection", {})
        lateral_movement = analysis_results.get("lateral_movement", {})
        c2_analysis = analysis_results.get("c2_analysis", {})
        threat_intel = analysis_results.get("threat_intelligence", {})
        
        # Traffic analysis findings
        if traffic_analysis.get("anomaly_detection", {}).get("volume_anomalies"):
            summary["key_findings"].append("Unusual network traffic volume detected")
        
        # Exfiltration findings
        dns_tunneling = exfiltration_detection.get("dns_tunneling", {})
        if dns_tunneling.get("suspicious_queries"):
            summary["key_findings"].append("Potential DNS tunneling activity detected")
        
        http_exfiltration = exfiltration_detection.get("http_exfiltration", {})
        if http_exfiltration.get("large_responses"):
            summary["key_findings"].append("Large HTTP data transfers indicating potential exfiltration")
        
        # Lateral movement findings
        credential_attacks = lateral_movement.get("credential_attacks", {})
        if credential_attacks.get("pass_the_hash"):
            summary["key_findings"].append("Pass-the-Hash attacks detected")
        
        # C2 findings
        beacon_analysis = c2_analysis.get("beacon_analysis", {})
        if beacon_analysis.get("beacon_sessions"):
            summary["key_findings"].append("Command and control beacon activity identified")
        
        # Threat intelligence findings
        risk_scoring = threat_intel.get("risk_scoring", {})
        overall_risk = risk_scoring.get("overall_risk_score", 0)
        
        # Generate threat overview
        if overall_risk >= 80:
            summary["threat_overview"] = "Critical threat detected with high confidence. Immediate action required."
            summary["urgency_level"] = "critical"
        elif overall_risk >= 60:
            summary["threat_overview"] = "Significant threat activity identified requiring prompt response."
            summary["urgency_level"] = "high"
        elif overall_risk >= 40:
            summary["threat_overview"] = "Moderate threat indicators detected. Investigation recommended."
            summary["urgency_level"] = "medium"
        else:
            summary["threat_overview"] = "Low-level suspicious activity observed. Monitoring advised."
            summary["urgency_level"] = "low"
        
        # Business impact assessment
        if overall_risk >= 80:
            summary["business_impact"] = "High risk of data loss, system compromise, and business disruption."
        elif overall_risk >= 60:
            summary["business_impact"] = "Moderate risk of data compromise and operational impact."
        elif overall_risk >= 40:
            summary["business_impact"] = "Low to moderate risk of security incidents."
        else:
            summary["business_impact"] = "Minimal business impact anticipated."
        
        return summary
    
    async def _classify_threats(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Classify identified threats"""
        classification = {
            "primary_threats": [],
            "secondary_threats": [],
            "threat_categories": {},
            "attack_stages": [],
            "tactics_techniques": {},
            "threat_actors": []
        }
        
        # Analyze each module for threat indicators
        
        # Data exfiltration threats
        exfiltration_detection = analysis_results.get("exfiltration_detection", {})
        if exfiltration_detection.get("dns_tunneling", {}).get("suspicious_queries"):
            classification["primary_threats"].append({
                "type": "Data Exfiltration",
                "method": "DNS Tunneling",
                "severity": "high",
                "confidence": "medium"
            })
        
        if exfiltration_detection.get("http_exfiltration", {}).get("large_responses"):
            classification["primary_threats"].append({
                "type": "Data Exfiltration", 
                "method": "HTTP",
                "severity": "high",
                "confidence": "high"
            })
        
        # Lateral movement threats
        lateral_movement = analysis_results.get("lateral_movement", {})
        if lateral_movement.get("credential_attacks", {}).get("pass_the_hash"):
            classification["primary_threats"].append({
                "type": "Lateral Movement",
                "method": "Pass-the-Hash",
                "severity": "high",
                "confidence": "high"
            })
        
        # C2 communication threats
        c2_analysis = analysis_results.get("c2_analysis", {})
        if c2_analysis.get("beacon_analysis", {}).get("beacon_sessions"):
            classification["primary_threats"].append({
                "type": "Command & Control",
                "method": "Beaconing",
                "severity": "high",
                "confidence": "high"
            })
        
        # Map to MITRE ATT&CK framework
        classification["tactics_techniques"] = await self._map_mitre_attack(classification["primary_threats"])
        
        # Identify attack stages
        classification["attack_stages"] = await self._identify_attack_stages(analysis_results)
        
        return classification
    
    async def _assess_severity(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall threat severity"""
        severity_assessment = {
            "overall_severity": ThreatSeverity.LOW,
            "severity_factors": [],
            "severity_score": 0,
            "confidence_level": "low",
            "escalation_required": False,
            "time_sensitivity": "normal"
        }
        
        total_score = 0
        confidence_scores = []
        
        # Traffic analysis severity
        traffic_analysis = analysis_results.get("traffic_analysis", {})
        traffic_score = await self._calculate_traffic_severity(traffic_analysis)
        total_score += traffic_score * self.severity_weights["traffic_analysis"]
        
        # Exfiltration detection severity
        exfiltration_detection = analysis_results.get("exfiltration_detection", {})
        exfiltration_score = await self._calculate_exfiltration_severity(exfiltration_detection)
        total_score += exfiltration_score * self.severity_weights["exfiltration_detection"]
        confidence_scores.append(0.8 if exfiltration_score > 60 else 0.5)
        
        # Lateral movement severity
        lateral_movement = analysis_results.get("lateral_movement", {})
        lateral_score = await self._calculate_lateral_movement_severity(lateral_movement)
        total_score += lateral_score * self.severity_weights["lateral_movement"]
        confidence_scores.append(0.9 if lateral_score > 70 else 0.6)
        
        # C2 analysis severity
        c2_analysis = analysis_results.get("c2_analysis", {})
        c2_score = await self._calculate_c2_severity(c2_analysis)
        total_score += c2_score * self.severity_weights["c2_analysis"]
        confidence_scores.append(0.85 if c2_score > 65 else 0.6)
        
        # Threat intelligence severity
        threat_intel = analysis_results.get("threat_intelligence", {})
        ti_score = threat_intel.get("risk_scoring", {}).get("overall_risk_score", 0)
        total_score += ti_score * self.severity_weights["threat_intelligence"]
        confidence_scores.append(0.9 if ti_score > 70 else 0.7)
        
        # Normalize score
        severity_assessment["severity_score"] = min(total_score, 100)
        
        # Determine overall severity
        if severity_assessment["severity_score"] >= 80:
            severity_assessment["overall_severity"] = ThreatSeverity.CRITICAL
            severity_assessment["escalation_required"] = True
            severity_assessment["time_sensitivity"] = "immediate"
        elif severity_assessment["severity_score"] >= 60:
            severity_assessment["overall_severity"] = ThreatSeverity.HIGH
            severity_assessment["escalation_required"] = True
            severity_assessment["time_sensitivity"] = "urgent"
        elif severity_assessment["severity_score"] >= 40:
            severity_assessment["overall_severity"] = ThreatSeverity.MEDIUM
            severity_assessment["time_sensitivity"] = "prompt"
        else:
            severity_assessment["overall_severity"] = ThreatSeverity.LOW
        
        # Calculate confidence level
        if confidence_scores:
            avg_confidence = sum(confidence_scores) / len(confidence_scores)
            if avg_confidence >= 0.8:
                severity_assessment["confidence_level"] = "high"
            elif avg_confidence >= 0.6:
                severity_assessment["confidence_level"] = "medium"
            else:
                severity_assessment["confidence_level"] = "low"
        
        return severity_assessment
    
    async def _analyze_impact(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze potential business impact"""
        impact_analysis = {
            "data_impact": {},
            "system_impact": {},
            "business_impact": {},
            "compliance_impact": {},
            "financial_impact": {},
            "reputation_impact": {}
        }
        
        # Data impact assessment
        exfiltration_detection = analysis_results.get("exfiltration_detection", {})
        data_staging = exfiltration_detection.get("data_staging", {})
        
        impact_analysis["data_impact"] = {
            "confidentiality": "high" if data_staging else "medium",
            "integrity": "medium",
            "availability": "low",
            "data_types_at_risk": ["sensitive", "confidential", "personal"]
        }
        
        # System impact assessment
        lateral_movement = analysis_results.get("lateral_movement", {})
        admin_tool_abuse = lateral_movement.get("admin_tool_abuse", {})
        
        impact_analysis["system_impact"] = {
            "affected_systems": ["workstations", "servers"] if admin_tool_abuse else ["workstations"],
            "service_disruption": "medium" if admin_tool_abuse else "low",
            "recovery_complexity": "high" if admin_tool_abuse else "medium"
        }
        
        # Business impact assessment
        c2_analysis = analysis_results.get("c2_analysis", {})
        persistence_c2 = c2_analysis.get("persistence_c2", {})
        
        impact_analysis["business_impact"] = {
            "operational_disruption": "high" if persistence_c2 else "medium",
            "productivity_loss": "medium",
            "customer_impact": "low to medium"
        }
        
        return impact_analysis
    
    async def _generate_response_recommendations(self, assessment_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate response recommendations"""
        recommendations = {
            "immediate_actions": [],
            "short_term_actions": [],
            "medium_term_actions": [],
            "long_term_actions": [],
            "technical_recommendations": [],
            "process_recommendations": [],
            "training_recommendations": []
        }
        
        severity = assessment_results.get("severity_assessment", {}).get("overall_severity", ThreatSeverity.LOW)
        
        # Immediate actions based on severity
        if severity == ThreatSeverity.CRITICAL:
            recommendations["immediate_actions"].extend([
                "Activate incident response team",
                "Isolate affected systems",
                "Block identified IOCs",
                "Notify executive leadership",
                "Engage external incident response support"
            ])
        elif severity == ThreatSeverity.HIGH:
            recommendations["immediate_actions"].extend([
                "Initiate incident response procedures",
                "Block malicious IPs and domains",
                "Monitor identified systems closely",
                "Collect forensic evidence"
            ])
        elif severity == ThreatSeverity.MEDIUM:
            recommendations["immediate_actions"].extend([
                "Investigate suspicious activities",
                "Monitor network traffic",
                "Review security logs",
                "Update security controls"
            ])
        
        # Technical recommendations
        recommendations["technical_recommendations"] = [
            "Implement DNS monitoring and filtering",
            "Deploy network segmentation",
            "Enhance endpoint detection capabilities",
            "Improve network traffic analysis",
            "Strengthen access controls"
        ]
        
        # Process recommendations
        recommendations["process_recommendations"] = [
            "Review incident response procedures",
            "Enhance threat hunting capabilities",
            "Improve security monitoring processes",
            "Conduct regular security assessments",
            "Develop playbooks for network threats"
        ]
        
        return recommendations
    
    async def _recommend_containment_actions(self, assessment_results: Dict[str, Any]) -> Dict[str, Any]:
        """Recommend containment actions"""
        containment_actions = {
            "network_isolation": [],
            "access_restrictions": [],
            "system_quarantine": [],
            "traffic_blocking": [],
            "account_actions": [],
            "service_actions": []
        }
        
        severity = assessment_results.get("severity_assessment", {}).get("overall_severity", ThreatSeverity.LOW)
        threat_classification = assessment_results.get("threat_classification", {})
        
        # Network isolation recommendations
        if severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH]:
            containment_actions["network_isolation"] = [
                "Isolate affected network segments",
                "Block external network access for compromised systems",
                "Implement emergency firewall rules"
            ]
        
        # Traffic blocking
        ioc_summary = assessment_results.get("ioc_summary", {})
        malicious_ips = ioc_summary.get("ip_addresses", {}).get("malicious", [])
        malicious_domains = ioc_summary.get("domains", {}).get("malicious", [])
        
        if malicious_ips:
            containment_actions["traffic_blocking"].append(f"Block {len(malicious_ips)} malicious IP addresses")
        if malicious_domains:
            containment_actions["traffic_blocking"].append(f"Block {len(malicious_domains)} malicious domains")
        
        return containment_actions
    
    async def _summarize_iocs(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Summarize indicators of compromise"""
        ioc_summary = {
            "ip_addresses": {"total": 0, "malicious": [], "suspicious": []},
            "domains": {"total": 0, "malicious": [], "suspicious": []},
            "urls": {"total": 0, "malicious": [], "suspicious": []},
            "file_hashes": {"total": 0, "malicious": [], "suspicious": []},
            "network_indicators": [],
            "behavioral_indicators": []
        }
        
        # Extract IOCs from threat intelligence
        threat_intel = analysis_results.get("threat_intelligence", {})
        
        # IP addresses
        ip_intel = threat_intel.get("ip_intelligence", {})
        malicious_ips = ip_intel.get("malicious_ips", [])
        ioc_summary["ip_addresses"]["malicious"] = [ip["ip"] for ip in malicious_ips]
        ioc_summary["ip_addresses"]["total"] = len(ioc_summary["ip_addresses"]["malicious"])
        
        # Domains
        domain_intel = threat_intel.get("domain_intelligence", {})
        malicious_domains = domain_intel.get("malicious_domains", [])
        ioc_summary["domains"]["malicious"] = [domain["domain"] for domain in malicious_domains]
        ioc_summary["domains"]["total"] = len(ioc_summary["domains"]["malicious"])
        
        # Network indicators from various analyses
        c2_analysis = analysis_results.get("c2_analysis", {})
        beacon_sessions = c2_analysis.get("beacon_analysis", {}).get("beacon_sessions", [])
        for beacon in beacon_sessions:
            ioc_summary["network_indicators"].append({
                "type": "beacon_communication",
                "description": f"Beacon activity to {beacon.get('connection_pair')}",
                "confidence": beacon.get("confidence", "medium")
            })
        
        return ioc_summary
    
    # Helper methods for severity calculations
    async def _calculate_traffic_severity(self, traffic_analysis: Dict[str, Any]) -> int:
        """Calculate severity score for traffic analysis"""
        score = 0
        
        anomalies = traffic_analysis.get("anomaly_detection", {})
        if anomalies.get("volume_anomalies"):
            score += 30
        if anomalies.get("timing_anomalies"):
            score += 20
        if anomalies.get("protocol_anomalies"):
            score += 25
        
        return min(score, 100)
    
    async def _calculate_exfiltration_severity(self, exfiltration_detection: Dict[str, Any]) -> int:
        """Calculate severity score for exfiltration detection"""
        score = 0
        
        if exfiltration_detection.get("dns_tunneling", {}).get("suspicious_queries"):
            score += 40
        if exfiltration_detection.get("http_exfiltration", {}).get("large_responses"):
            score += 35
        if exfiltration_detection.get("cloud_exfiltration", {}).get("cloud_uploads"):
            score += 30
        
        return min(score, 100)
    
    async def _calculate_lateral_movement_severity(self, lateral_movement: Dict[str, Any]) -> int:
        """Calculate severity score for lateral movement"""
        score = 0
        
        credential_attacks = lateral_movement.get("credential_attacks", {})
        if credential_attacks.get("pass_the_hash"):
            score += 45
        if credential_attacks.get("golden_ticket"):
            score += 50
        
        service_exploitation = lateral_movement.get("service_exploitation", {})
        if service_exploitation.get("psexec_usage"):
            score += 35
        
        return min(score, 100)
    
    async def _calculate_c2_severity(self, c2_analysis: Dict[str, Any]) -> int:
        """Calculate severity score for C2 analysis"""
        score = 0
        
        beacon_analysis = c2_analysis.get("beacon_analysis", {})
        if beacon_analysis.get("beacon_sessions"):
            score += 40
        
        dga_detection = c2_analysis.get("dga_detection", {})
        if dga_detection.get("dga_domains"):
            score += 35
        
        return min(score, 100)
    
    def _load_severity_weights(self) -> Dict[str, float]:
        """Load severity calculation weights"""
        return {
            "traffic_analysis": 0.15,
            "exfiltration_detection": 0.25,
            "lateral_movement": 0.25,
            "c2_analysis": 0.20,
            "threat_intelligence": 0.15
        }
    
    def _load_response_matrix(self) -> Dict[str, Any]:
        """Load response action matrix"""
        return {
            ThreatSeverity.CRITICAL: {
                "timeframe": "immediate",
                "actions": [ResponseAction.BLOCK, ResponseAction.ESCALATE, ResponseAction.QUARANTINE],
                "stakeholders": ["CISO", "IR_Team", "Executive_Leadership"]
            },
            ThreatSeverity.HIGH: {
                "timeframe": "within_1_hour",
                "actions": [ResponseAction.INVESTIGATE, ResponseAction.MONITOR, ResponseAction.BLOCK],
                "stakeholders": ["SOC_Manager", "IR_Team", "Network_Team"]
            },
            ThreatSeverity.MEDIUM: {
                "timeframe": "within_4_hours",
                "actions": [ResponseAction.INVESTIGATE, ResponseAction.MONITOR],
                "stakeholders": ["SOC_Analyst", "Network_Team"]
            },
            ThreatSeverity.LOW: {
                "timeframe": "within_24_hours", 
                "actions": [ResponseAction.MONITOR, ResponseAction.ALERT],
                "stakeholders": ["SOC_Analyst"]
            }
        }
    
    def _load_escalation_thresholds(self) -> Dict[str, Any]:
        """Load escalation thresholds"""
        return {
            "severity_score": 70,
            "confidence_level": 0.7,
            "business_impact": "high",
            "data_sensitivity": "confidential"
        }

# Factory function
def create_final_assessment() -> FinalAssessment:
    """Create and return FinalAssessment instance"""
    return FinalAssessment()
