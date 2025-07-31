"""
Incident Classifier Module
Implements the 3-tier classification system:
- Tier 1 (70%): Rule-based routing using incident metadata patterns
- Tier 2 (25%): GPT-4 powered analysis with MITRE ATT&CK mapping  
- Tier 3 (5%): Multi-agent coordination for complex incidents
"""

import logging
import json
from typing import Dict, Any, Optional, List, Tuple
from enum import Enum
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)

class IncidentSeverity(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class MITRETactic(Enum):
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"

class AgentType(Enum):
    PHISHING = "phishing_agent"
    LOGIN_IDENTITY = "login_identity_agent"
    POWERSHELL_EXPLOITATION = "powershell_exploitation_agent"
    MALWARE_THREAT_INTEL = "malware_threat_intel_agent"
    ACCESS_CONTROL = "access_control_agent"
    INSIDER_BEHAVIOR = "insider_behavior_agent"
    NETWORK_EXFILTRATION = "network_exfiltration_agent"
    HOST_STABILITY = "host_stability_agent"
    DDOS_DEFENSE = "ddos_defense_agent"

@dataclass
class ClassificationResult:
    """Result of incident classification"""
    assigned_agent: AgentType
    confidence_score: float  # 0.0 - 1.0
    tier_used: int  # 1, 2, or 3
    reasoning: str
    mitre_tactics: List[MITRETactic]
    requires_human_review: bool
    fallback_agents: List[AgentType]

@dataclass
class SentinelIncident:
    """Sentinel incident structure (mocked for development)"""
    incident_id: str
    title: str
    description: str
    severity: IncidentSeverity
    status: str
    created_time: datetime
    alert_rule_name: str
    entities: List[Dict[str, Any]]
    tactics: List[str]
    techniques: List[str]
    raw_data: Dict[str, Any]

class IncidentClassifier:
    """
    Multi-tier incident classification system
    Prioritizes accuracy over speed with conservative routing
    """
    
    def __init__(self):
        self.tier1_rules = self._load_tier1_rules()
        self.confidence_threshold = 0.85  # High threshold for accuracy
        self.human_review_threshold = 0.70  # Conservative escalation
    
    def classify_incident(self, incident: SentinelIncident) -> ClassificationResult:
        """
        Main classification entry point
        Returns classification with agent assignment and confidence
        """
        logger.info(f"Classifying incident {incident.incident_id}: {incident.title}")
        
        # Tier 1: Rule-based classification (70% of cases)
        tier1_result = self._tier1_classification(incident)
        if tier1_result and tier1_result.confidence_score >= self.confidence_threshold:
            logger.info(f"Tier 1 classification successful: {tier1_result.assigned_agent}")
            return tier1_result
        
        # Tier 2: GPT-4 powered analysis (25% of cases)
        tier2_result = self._tier2_classification(incident)
        if tier2_result and tier2_result.confidence_score >= self.confidence_threshold:
            logger.info(f"Tier 2 classification successful: {tier2_result.assigned_agent}")
            return tier2_result
        
        # Tier 3: Multi-agent coordination (5% of cases)
        tier3_result = self._tier3_classification(incident)
        logger.info(f"Tier 3 classification required: {tier3_result.assigned_agent}")
        return tier3_result
    
    def _tier1_classification(self, incident: SentinelIncident) -> Optional[ClassificationResult]:
        """
        Rule-based classification using incident metadata patterns
        Fast and accurate for common incident types
        """
        confidence = 0.0
        assigned_agent = None
        reasoning = ""
        mitre_tactics = []
        
        # Extract MITRE tactics from incident
        for tactic in incident.tactics:
            try:
                mitre_tactics.append(MITRETactic(tactic))
            except ValueError:
                continue
        
        # Rule 1: Phishing detection
        if self._is_phishing_incident(incident):
            assigned_agent = AgentType.PHISHING
            confidence = 0.90
            reasoning = "Email-based threat detected via rule-based analysis"
        
        # Rule 2: Login/Identity threats
        elif self._is_login_identity_incident(incident):
            assigned_agent = AgentType.LOGIN_IDENTITY
            confidence = 0.88
            reasoning = "Authentication or identity-related threat detected"
        
        # Rule 3: PowerShell exploitation
        elif self._is_powershell_incident(incident):
            assigned_agent = AgentType.POWERSHELL_EXPLOITATION
            confidence = 0.85
            reasoning = "PowerShell-based attack pattern identified"
        
        # Rule 4: Malware detection
        elif self._is_malware_incident(incident):
            assigned_agent = AgentType.MALWARE_THREAT_INTEL
            confidence = 0.87
            reasoning = "Malware indicators detected in incident"
        
        # Rule 5: DDoS attacks
        elif self._is_ddos_incident(incident):
            assigned_agent = AgentType.DDOS_DEFENSE
            confidence = 0.92
            reasoning = "DDoS attack pattern identified"
        
        if assigned_agent:
            return ClassificationResult(
                assigned_agent=assigned_agent,
                confidence_score=confidence,
                tier_used="rule_based",
                reasoning=reasoning,
                mitre_tactics=mitre_tactics,
                requires_human_review=confidence < self.human_review_threshold,
                fallback_agents=self._get_fallback_agents(assigned_agent)
            )
        
        return None
    
    def _tier2_classification(self, incident: SentinelIncident) -> Optional[ClassificationResult]:
        """
        GPT-4 powered analysis with MITRE ATT&CK mapping
        Used when rule-based classification is insufficient
        """
        # TODO: Implement GPT-4 classification
        # For now, return a conservative classification
        
        logger.info("Tier 2 GPT-4 classification not yet implemented - using conservative fallback")
        
        # Conservative fallback to multi-purpose agent
        return ClassificationResult(
            assigned_agent=AgentType.HOST_STABILITY,  # Most general agent
            confidence_score=0.60,  # Low confidence triggers human review
            tier_used="gpt4_enhanced",
            reasoning="GPT-4 analysis pending - conservative routing applied",
            mitre_tactics=[],
            requires_human_review=True,
            fallback_agents=[AgentType.MALWARE_THREAT_INTEL, AgentType.NETWORK_EXFILTRATION]
        )
    
    def _tier3_classification(self, incident: SentinelIncident) -> ClassificationResult:
        """
        Multi-agent coordination for complex incidents
        Most conservative approach - always requires human review
        """
        logger.warning(f"Complex incident requiring multi-agent coordination: {incident.incident_id}")
        
        return ClassificationResult(
            assigned_agent=AgentType.HOST_STABILITY,  # Primary investigator
            confidence_score=0.50,  # Force human review
            tier_used="multi_agent",
            reasoning="Complex incident requiring multi-agent investigation",
            mitre_tactics=[],
            requires_human_review=True,
            fallback_agents=[
                AgentType.MALWARE_THREAT_INTEL,
                AgentType.NETWORK_EXFILTRATION,
                AgentType.INSIDER_BEHAVIOR
            ]
        )
    
    def _is_phishing_incident(self, incident: SentinelIncident) -> bool:
        """Check if incident matches phishing patterns"""
        phishing_keywords = [
            "phishing", "email", "malicious attachment", "suspicious link",
            "office 365", "outlook", "email security", "spam"
        ]
        
        text_content = f"{incident.title} {incident.description} {incident.alert_rule_name}".lower()
        return any(keyword in text_content for keyword in phishing_keywords)
    
    def _is_login_identity_incident(self, incident: SentinelIncident) -> bool:
        """Check if incident matches login/identity patterns"""
        identity_keywords = [
            "login", "authentication", "identity", "credential", "brute force",
            "impossible travel", "suspicious sign-in", "azure ad", "mfa"
        ]
        
        text_content = f"{incident.title} {incident.description} {incident.alert_rule_name}".lower()
        return any(keyword in text_content for keyword in identity_keywords)
    
    def _is_powershell_incident(self, incident: SentinelIncident) -> bool:
        """Check if incident matches PowerShell exploitation patterns"""
        powershell_keywords = [
            "powershell", "script", "execution", "cmdlet", "invoke-expression",
            "base64", "encoded command", "suspicious script"
        ]
        
        text_content = f"{incident.title} {incident.description} {incident.alert_rule_name}".lower()
        return any(keyword in text_content for keyword in powershell_keywords)
    
    def _is_malware_incident(self, incident: SentinelIncident) -> bool:
        """Check if incident matches malware patterns"""
        malware_keywords = [
            "malware", "virus", "trojan", "ransomware", "suspicious file",
            "file hash", "malicious process", "defender alert"
        ]
        
        text_content = f"{incident.title} {incident.description} {incident.alert_rule_name}".lower()
        return any(keyword in text_content for keyword in malware_keywords)
    
    def _is_ddos_incident(self, incident: SentinelIncident) -> bool:
        """Check if incident matches DDoS patterns"""
        ddos_keywords = [
            "ddos", "denial of service", "network flood", "traffic spike",
            "bandwidth", "network congestion", "syn flood"
        ]
        
        text_content = f"{incident.title} {incident.description} {incident.alert_rule_name}".lower()
        return any(keyword in text_content for keyword in ddos_keywords)
    
    def _get_fallback_agents(self, primary_agent: AgentType) -> List[AgentType]:
        """Get fallback agents for a given primary agent"""
        fallback_map = {
            AgentType.PHISHING: [AgentType.MALWARE_THREAT_INTEL, AgentType.NETWORK_EXFILTRATION],
            AgentType.LOGIN_IDENTITY: [AgentType.INSIDER_BEHAVIOR, AgentType.ACCESS_CONTROL],
            AgentType.POWERSHELL_EXPLOITATION: [AgentType.MALWARE_THREAT_INTEL, AgentType.HOST_STABILITY],
            AgentType.MALWARE_THREAT_INTEL: [AgentType.HOST_STABILITY, AgentType.NETWORK_EXFILTRATION],
            AgentType.DDOS_DEFENSE: [AgentType.NETWORK_EXFILTRATION, AgentType.HOST_STABILITY],
        }
        
        return fallback_map.get(primary_agent, [AgentType.HOST_STABILITY])
    
    def _load_tier1_rules(self) -> Dict[str, Any]:
        """Load rule-based classification patterns"""
        # In production, this would load from configuration
        return {
            "phishing_patterns": ["phishing", "email", "malicious attachment"],
            "identity_patterns": ["login", "authentication", "brute force"],
            "powershell_patterns": ["powershell", "script", "execution"],
            "malware_patterns": ["malware", "virus", "trojan", "ransomware"],
            "ddos_patterns": ["ddos", "denial of service", "network flood"]
        }
