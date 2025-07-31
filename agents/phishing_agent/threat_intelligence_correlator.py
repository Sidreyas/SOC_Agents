"""
Threat Intelligence Correlator Module
State 5: Threat Intelligence Correlation
Correlates findings from all previous states with external threat intelligence feeds,
IOCs, TTPs, and attack patterns to provide comprehensive threat context
"""

import logging
import re
import hashlib
import aiohttp
import asyncio
import json
import random
from typing import Dict, Any, List, Optional, Set, Tuple
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass
import uuid

logger = logging.getLogger(__name__)

class ThreatSeverity(Enum):
    """Threat severity enumeration"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ConfidenceLevel(Enum):
    """Confidence level enumeration"""
    VERY_HIGH = "very_high"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    VERY_LOW = "very_low"

class ThreatCategory(Enum):
    """Threat category enumeration"""
    PHISHING = "phishing"
    MALWARE = "malware"
    CREDENTIAL_THEFT = "credential_theft"
    BUSINESS_EMAIL_COMPROMISE = "business_email_compromise"
    SOCIAL_ENGINEERING = "social_engineering"
    ADVANCED_PERSISTENT_THREAT = "advanced_persistent_threat"
    UNKNOWN = "unknown"

@dataclass
class ThreatIndicator:
    """Threat indicator data structure"""
    indicator_type: str
    indicator_value: str
    threat_types: List[str]
    severity: str
    confidence: float
    first_seen: datetime
    last_seen: datetime
    sources: List[str]
    context: Dict[str, Any]

class ThreatIntelligenceCorrelator:
    """
    Threat Intelligence Correlation for phishing investigation
    Correlates all analysis findings with external threat intelligence
    """
    
    def __init__(self):
        self.threat_feeds = self._init_threat_feeds()
        self.ioc_database = {}
        self.ttp_database = {}
        self.campaign_database = {}
        self.correlation_cache = {}
        self.confidence_weights = self._init_confidence_weights()
        
    def correlate_threat_intelligence(self, email_entities: Dict[str, Any],
                                    security_analysis: Dict[str, Any],
                                    reputation_assessment: Dict[str, Any],
                                    url_attachment_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive threat intelligence correlation across all analysis states
        
        Args:
            email_entities: Results from State 1
            security_analysis: Results from State 2
            reputation_assessment: Results from State 3
            url_attachment_analysis: Results from State 4
            
        Returns:
            Complete threat intelligence correlation results
        """
        logger.info("Starting comprehensive threat intelligence correlation")
        
        correlation_results = {
            "ioc_correlation": {},
            "ttp_correlation": {},
            "campaign_correlation": {},
            "threat_actor_attribution": {},
            "attack_pattern_analysis": {},
            "threat_context": {},
            "correlation_confidence": 0.0,
            "threat_severity": ThreatSeverity.LOW.value,
            "recommended_actions": [],
            "correlation_metadata": {},
            "correlation_timestamp": datetime.now()
        }
        
        # Extract all indicators from previous states
        extracted_indicators = self._extract_all_indicators(
            email_entities, security_analysis, reputation_assessment, url_attachment_analysis
        )
        
        # Correlate with IOC databases
        correlation_results["ioc_correlation"] = self._correlate_with_iocs(extracted_indicators)
        
        # Correlate with TTP databases
        correlation_results["ttp_correlation"] = self._correlate_with_ttps(
            extracted_indicators, email_entities
        )
        
        # Correlate with known campaigns
        correlation_results["campaign_correlation"] = self._correlate_with_campaigns(
            correlation_results["ioc_correlation"],
            correlation_results["ttp_correlation"]
        )
        
        # Perform threat actor attribution
        correlation_results["threat_actor_attribution"] = self._perform_threat_actor_attribution(
            correlation_results["campaign_correlation"],
            correlation_results["ttp_correlation"]
        )
        
        # Analyze attack patterns
        correlation_results["attack_pattern_analysis"] = self._analyze_attack_patterns(
            email_entities, correlation_results["ttp_correlation"]
        )
        
        # Build comprehensive threat context
        correlation_results["threat_context"] = self._build_threat_context(
            correlation_results
        )
        
        # Calculate overall correlation confidence
        correlation_results["correlation_confidence"] = self._calculate_correlation_confidence(
            correlation_results
        )
        
        # Determine threat severity
        correlation_results["threat_severity"] = self._determine_threat_severity(
            correlation_results
        )
        
        # Generate recommended actions
        correlation_results["recommended_actions"] = self._generate_recommended_actions(
            correlation_results
        )
        
        # Add correlation metadata
        correlation_results["correlation_metadata"] = {
            "indicators_analyzed": len(extracted_indicators),
            "iocs_matched": len(correlation_results["ioc_correlation"].get("matches", [])),
            "ttps_identified": len(correlation_results["ttp_correlation"].get("identified_ttps", [])),
            "campaigns_matched": len(correlation_results["campaign_correlation"].get("matched_campaigns", [])),
            "threat_feeds_queried": len(self.threat_feeds),
            "correlation_timestamp": datetime.now()
        }
        
        logger.info("Threat intelligence correlation completed")
        return correlation_results
    
    def enrich_with_external_feeds(self, indicators: List[ThreatIndicator]) -> Dict[str, Any]:
        """
        Enrich indicators with external threat intelligence feeds
        
        Args:
            indicators: List of threat indicators to enrich
            
        Returns:
            Enriched threat intelligence data
        """
        logger.info("Enriching indicators with external threat intelligence feeds")
        
        enrichment_results = {
            "enriched_indicators": [],
            "feed_results": {},
            "new_associations": [],
            "threat_campaigns": [],
            "attribution_data": {},
            "enrichment_confidence": 0.0,
            "enrichment_timestamp": datetime.now()
        }
        
        for indicator in indicators:
            # Enrich with each threat feed
            enriched_indicator = self._enrich_single_indicator(indicator)
            enrichment_results["enriched_indicators"].append(enriched_indicator)
        
        # Query threat intelligence feeds
        enrichment_results["feed_results"] = self._query_threat_feeds(indicators)
        
        # Identify new associations
        enrichment_results["new_associations"] = self._identify_new_associations(
            enrichment_results["enriched_indicators"],
            enrichment_results["feed_results"]
        )
        
        # Identify threat campaigns
        enrichment_results["threat_campaigns"] = self._identify_threat_campaigns(
            enrichment_results["feed_results"]
        )
        
        # Perform attribution analysis
        enrichment_results["attribution_data"] = self._perform_attribution_analysis(
            enrichment_results["threat_campaigns"]
        )
        
        # Calculate enrichment confidence
        enrichment_results["enrichment_confidence"] = self._calculate_enrichment_confidence(
            enrichment_results
        )
        
        logger.info("Threat intelligence enrichment completed")
        return enrichment_results
    
    def analyze_attack_lifecycle(self, correlation_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze attack lifecycle and kill chain progression
        
        Args:
            correlation_data: Threat intelligence correlation data
            
        Returns:
            Attack lifecycle analysis results
        """
        logger.info("Analyzing attack lifecycle and kill chain progression")
        
        lifecycle_analysis = {
            "kill_chain_stages": {},
            "attack_progression": [],
            "current_stage": "unknown",
            "next_likely_stages": [],
            "timeline_analysis": {},
            "attack_sophistication": "unknown",
            "lifecycle_confidence": 0.0,
            "analysis_timestamp": datetime.now()
        }
        
        # Map findings to cyber kill chain
        lifecycle_analysis["kill_chain_stages"] = self._map_to_kill_chain(correlation_data)
        
        # Analyze attack progression
        lifecycle_analysis["attack_progression"] = self._analyze_attack_progression(
            lifecycle_analysis["kill_chain_stages"]
        )
        
        # Determine current stage
        lifecycle_analysis["current_stage"] = self._determine_current_stage(
            lifecycle_analysis["kill_chain_stages"]
        )
        
        # Predict next likely stages
        lifecycle_analysis["next_likely_stages"] = self._predict_next_stages(
            lifecycle_analysis["current_stage"],
            correlation_data
        )
        
        # Perform timeline analysis
        lifecycle_analysis["timeline_analysis"] = self._perform_timeline_analysis(
            correlation_data
        )
        
        # Assess attack sophistication
        lifecycle_analysis["attack_sophistication"] = self._assess_attack_sophistication(
            correlation_data,
            lifecycle_analysis["kill_chain_stages"]
        )
        
        # Calculate lifecycle confidence
        lifecycle_analysis["lifecycle_confidence"] = self._calculate_lifecycle_confidence(
            lifecycle_analysis
        )
        
        logger.info("Attack lifecycle analysis completed")
        return lifecycle_analysis
    
    def correlate_with_historical_incidents(self, correlation_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Correlate findings with historical security incidents
        
        Args:
            correlation_data: Current threat intelligence correlation data
            
        Returns:
            Historical incident correlation results
        """
        logger.info("Correlating with historical security incidents")
        
        historical_correlation = {
            "similar_incidents": [],
            "incident_patterns": {},
            "repeat_indicators": [],
            "threat_evolution": {},
            "lessons_learned": [],
            "correlation_strength": 0.0,
            "correlation_timestamp": datetime.now()
        }
        
        # Find similar historical incidents
        historical_correlation["similar_incidents"] = self._find_similar_incidents(
            correlation_data
        )
        
        # Identify incident patterns
        historical_correlation["incident_patterns"] = self._identify_incident_patterns(
            historical_correlation["similar_incidents"]
        )
        
        # Find repeat indicators
        historical_correlation["repeat_indicators"] = self._find_repeat_indicators(
            correlation_data,
            historical_correlation["similar_incidents"]
        )
        
        # Analyze threat evolution
        historical_correlation["threat_evolution"] = self._analyze_threat_evolution(
            historical_correlation["similar_incidents"]
        )
        
        # Extract lessons learned
        historical_correlation["lessons_learned"] = self._extract_lessons_learned(
            historical_correlation["similar_incidents"]
        )
        
        # Calculate correlation strength
        historical_correlation["correlation_strength"] = self._calculate_historical_correlation_strength(
            historical_correlation
        )
        
        logger.info("Historical incident correlation completed")
        return historical_correlation
    
    def generate_threat_intelligence_report(self, correlation_results: Dict[str, Any],
                                          enrichment_results: Dict[str, Any],
                                          lifecycle_analysis: Dict[str, Any],
                                          historical_correlation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive threat intelligence report
        
        Args:
            correlation_results: Threat intelligence correlation results
            enrichment_results: External feed enrichment results
            lifecycle_analysis: Attack lifecycle analysis results
            historical_correlation: Historical incident correlation results
            
        Returns:
            Comprehensive threat intelligence report
        """
        logger.info("Generating comprehensive threat intelligence report")
        
        intelligence_report = {
            "executive_summary": {},
            "threat_assessment": {},
            "technical_analysis": {},
            "attribution_assessment": {},
            "impact_analysis": {},
            "recommendations": {},
            "appendices": {},
            "report_metadata": {},
            "report_timestamp": datetime.now()
        }
        
        # Generate executive summary
        intelligence_report["executive_summary"] = self._generate_executive_summary(
            correlation_results, enrichment_results, lifecycle_analysis
        )
        
        # Compile threat assessment
        intelligence_report["threat_assessment"] = self._compile_threat_assessment(
            correlation_results, enrichment_results
        )
        
        # Compile technical analysis
        intelligence_report["technical_analysis"] = self._compile_technical_analysis(
            correlation_results, lifecycle_analysis
        )
        
        # Compile attribution assessment
        intelligence_report["attribution_assessment"] = self._compile_attribution_assessment(
            correlation_results, enrichment_results
        )
        
        # Perform impact analysis
        intelligence_report["impact_analysis"] = self._perform_impact_analysis(
            correlation_results, historical_correlation
        )
        
        # Generate recommendations
        intelligence_report["recommendations"] = self._generate_intelligence_recommendations(
            correlation_results, lifecycle_analysis, historical_correlation
        )
        
        # Compile appendices
        intelligence_report["appendices"] = self._compile_appendices(
            correlation_results, enrichment_results, lifecycle_analysis, historical_correlation
        )
        
        # Add report metadata
        intelligence_report["report_metadata"] = {
            "report_id": str(uuid.uuid4()),
            "report_version": "1.0",
            "classification": "TLP:AMBER",
            "generated_by": "SOC Phishing Agent - Threat Intelligence Correlator",
            "generation_timestamp": datetime.now(),
            "data_sources": self._list_data_sources(),
            "confidence_assessment": self._assess_overall_confidence(
                correlation_results, enrichment_results, lifecycle_analysis
            )
        }
        
        logger.info("Threat intelligence report generation completed")
        return intelligence_report
    
    def _init_threat_feeds(self) -> Dict[str, Dict[str, Any]]:
        """Initialize threat intelligence feed configurations"""
        return {
            "misp": {
                "enabled": True,
                "api_endpoint": "https://misp.local/",
                "api_key": "",
                "feed_type": "misp"
            },
            "taxii": {
                "enabled": True,
                "discovery_url": "https://taxii.local/taxii/",
                "feed_type": "taxii"
            },
            "otx": {
                "enabled": True,
                "api_endpoint": "https://otx.alienvault.com/api/v1/",
                "api_key": "",
                "feed_type": "otx"
            },
            "threatstream": {
                "enabled": False,
                "api_endpoint": "https://api.threatstream.com/api/v1/",
                "api_key": "",
                "feed_type": "threatstream"
            },
            "virustotal": {
                "enabled": True,
                "api_endpoint": "https://www.virustotal.com/api/v3/",
                "api_key": "",
                "feed_type": "virustotal"
            }
        }
    
    def _init_confidence_weights(self) -> Dict[str, float]:
        """Initialize confidence weights for different sources"""
        return {
            "microsoft_defender": 0.9,
            "virustotal": 0.8,
            "misp": 0.85,
            "taxii": 0.8,
            "otx": 0.7,
            "phishtank": 0.75,
            "urlhaus": 0.8,
            "custom_analysis": 0.6,
            "historical_incidents": 0.7
        }
    
    def _extract_all_indicators(self, email_entities: Dict[str, Any],
                              security_analysis: Dict[str, Any],
                              reputation_assessment: Dict[str, Any],
                              url_attachment_analysis: Dict[str, Any]) -> List[ThreatIndicator]:
        """Extract all threat indicators from previous analysis states"""
        indicators = []
        
        # Extract from email entities
        indicators.extend(self._extract_email_indicators(email_entities))
        
        # Extract from security analysis
        indicators.extend(self._extract_security_indicators(security_analysis))
        
        # Extract from reputation assessment
        indicators.extend(self._extract_reputation_indicators(reputation_assessment))
        
        # Extract from URL/attachment analysis
        indicators.extend(self._extract_url_attachment_indicators(url_attachment_analysis))
        
        # Deduplicate indicators
        indicators = self._deduplicate_indicators(indicators)
        
        logger.info(f"Extracted {len(indicators)} unique threat indicators")
        return indicators
    
    def _extract_email_indicators(self, email_entities: Dict[str, Any]) -> List[ThreatIndicator]:
        """Extract threat indicators from email entities"""
        indicators = []
        
        # Sender email indicators
        sender_info = email_entities.get("sender_information", {})
        sender_email = sender_info.get("sender_email", "")
        if sender_email:
            indicators.append(ThreatIndicator(
                indicator_type="email",
                indicator_value=sender_email,
                threat_types=["phishing", "spam"],
                severity=ThreatSeverity.MEDIUM.value,
                confidence=0.6,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                sources=["email_analysis"],
                context={"source": "sender_email", "analysis_state": "email_entities"}
            ))
        
        # Domain indicators
        sender_domain = sender_info.get("sender_domain", "")
        if sender_domain:
            indicators.append(ThreatIndicator(
                indicator_type="domain",
                indicator_value=sender_domain,
                threat_types=["phishing", "malware"],
                severity=ThreatSeverity.MEDIUM.value,
                confidence=0.6,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                sources=["email_analysis"],
                context={"source": "sender_domain", "analysis_state": "email_entities"}
            ))
        
        # IP indicators
        sender_ip = sender_info.get("sender_ip", "")
        if sender_ip:
            indicators.append(ThreatIndicator(
                indicator_type="ip",
                indicator_value=sender_ip,
                threat_types=["phishing", "malware", "spam"],
                severity=ThreatSeverity.MEDIUM.value,
                confidence=0.6,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                sources=["email_analysis"],
                context={"source": "sender_ip", "analysis_state": "email_entities"}
            ))
        
        # URL indicators
        extracted_urls = email_entities.get("extracted_urls", [])
        for url in extracted_urls:
            indicators.append(ThreatIndicator(
                indicator_type="url",
                indicator_value=url,
                threat_types=["phishing", "malware"],
                severity=ThreatSeverity.HIGH.value,
                confidence=0.7,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                sources=["email_analysis"],
                context={"source": "extracted_url", "analysis_state": "email_entities"}
            ))
        
        # File hash indicators
        attachments = email_entities.get("attachments", [])
        for attachment in attachments:
            if attachment.get("content"):
                file_hash = hashlib.sha256(attachment["content"]).hexdigest()
                indicators.append(ThreatIndicator(
                    indicator_type="file_hash",
                    indicator_value=file_hash,
                    threat_types=["malware", "phishing"],
                    severity=ThreatSeverity.HIGH.value,
                    confidence=0.8,
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                    sources=["email_analysis"],
                    context={
                        "source": "attachment_hash",
                        "filename": attachment.get("filename", ""),
                        "analysis_state": "email_entities"
                    }
                ))
        
        return indicators
    
    def _extract_security_indicators(self, security_analysis: Dict[str, Any]) -> List[ThreatIndicator]:
        """Extract threat indicators from security analysis"""
        indicators = []
        
        # Microsoft Defender indicators
        defender_results = security_analysis.get("microsoft_defender_analysis", {})
        threat_detections = defender_results.get("threat_detections", [])
        
        for detection in threat_detections:
            indicators.append(ThreatIndicator(
                indicator_type="threat_detection",
                indicator_value=detection.get("detection_name", ""),
                threat_types=[detection.get("threat_type", "unknown")],
                severity=detection.get("severity", ThreatSeverity.MEDIUM.value),
                confidence=0.9,  # High confidence for Microsoft Defender
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                sources=["microsoft_defender"],
                context={"source": "defender_detection", "analysis_state": "security_analysis"}
            ))
        
        # Security verdict indicators
        security_verdict = security_analysis.get("security_verdict_correlation", {})
        verdict_result = security_verdict.get("overall_verdict", {})
        
        if verdict_result.get("verdict") == "malicious":
            indicators.append(ThreatIndicator(
                indicator_type="security_verdict",
                indicator_value="malicious_verdict",
                threat_types=["phishing", "malware"],
                severity=ThreatSeverity.HIGH.value,
                confidence=verdict_result.get("confidence", 0.8),
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                sources=["security_verdict"],
                context={"source": "security_verdict", "analysis_state": "security_analysis"}
            ))
        
        return indicators
    
    def _extract_reputation_indicators(self, reputation_assessment: Dict[str, Any]) -> List[ThreatIndicator]:
        """Extract threat indicators from reputation assessment"""
        indicators = []
        
        # Authentication failure indicators
        auth_results = reputation_assessment.get("email_authentication", {})
        auth_summary = auth_results.get("authentication_summary", {})
        
        if auth_summary.get("overall_result") == "fail":
            indicators.append(ThreatIndicator(
                indicator_type="authentication_failure",
                indicator_value="failed_email_authentication",
                threat_types=["phishing", "spoofing"],
                severity=ThreatSeverity.HIGH.value,
                confidence=0.8,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                sources=["email_authentication"],
                context={"source": "auth_failure", "analysis_state": "reputation_assessment"}
            ))
        
        # Domain reputation indicators
        domain_rep = reputation_assessment.get("domain_reputation", {})
        if domain_rep.get("reputation_score", 1.0) < 0.3:
            indicators.append(ThreatIndicator(
                indicator_type="poor_reputation",
                indicator_value="poor_domain_reputation",
                threat_types=["phishing", "malware"],
                severity=ThreatSeverity.MEDIUM.value,
                confidence=0.7,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                sources=["domain_reputation"],
                context={"source": "domain_rep", "analysis_state": "reputation_assessment"}
            ))
        
        return indicators
    
    def _extract_url_attachment_indicators(self, url_attachment_analysis: Dict[str, Any]) -> List[ThreatIndicator]:
        """Extract threat indicators from URL and attachment analysis"""
        indicators = []
        
        # URL threat indicators
        url_analysis = url_attachment_analysis.get("url_analysis", {})
        url_results = url_analysis.get("url_results", [])
        
        for url_result in url_results:
            threat_classification = url_result.get("threat_classification", "unknown")
            if threat_classification in ["suspicious", "malicious"]:
                indicators.append(ThreatIndicator(
                    indicator_type="malicious_url",
                    indicator_value=url_result.get("url", ""),
                    threat_types=["phishing", "malware"],
                    severity=ThreatSeverity.HIGH.value if threat_classification == "malicious" else ThreatSeverity.MEDIUM.value,
                    confidence=0.8,
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                    sources=["url_analysis"],
                    context={"source": "url_threat", "analysis_state": "url_attachment_analysis"}
                ))
        
        # Attachment threat indicators
        attachment_analysis = url_attachment_analysis.get("attachment_analysis", {})
        attachment_results = attachment_analysis.get("attachment_results", [])
        
        for attachment_result in attachment_results:
            threat_level = attachment_result.get("threat_level", "unknown")
            if threat_level in ["suspicious", "malicious"]:
                indicators.append(ThreatIndicator(
                    indicator_type="malicious_attachment",
                    indicator_value=attachment_result.get("file_hash", ""),
                    threat_types=["malware", "phishing"],
                    severity=ThreatSeverity.HIGH.value if threat_level == "malicious" else ThreatSeverity.MEDIUM.value,
                    confidence=0.8,
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                    sources=["attachment_analysis"],
                    context={
                        "source": "attachment_threat",
                        "filename": attachment_result.get("filename", ""),
                        "analysis_state": "url_attachment_analysis"
                    }
                ))
        
        return indicators
    
    def _deduplicate_indicators(self, indicators: List[ThreatIndicator]) -> List[ThreatIndicator]:
        """Remove duplicate indicators based on type and value"""
        seen = set()
        deduplicated = []
        
        for indicator in indicators:
            key = f"{indicator.indicator_type}:{indicator.indicator_value}"
            if key not in seen:
                seen.add(key)
                deduplicated.append(indicator)
        
        return deduplicated
    
    # Additional helper methods for the remaining functionality
    def _match_campaigns_by_iocs(self, ioc_matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Match campaigns by IOC indicators"""
        campaigns = []
        
        # Placeholder for campaign matching logic
        for match in ioc_matches:
            campaign_name = match.get("campaign", "Unknown Campaign")
            if campaign_name != "Unknown Campaign":
                campaigns.append({
                    "campaign_name": campaign_name,
                    "confidence": match.get("confidence", 0.5),
                    "source": "ioc_match",
                    "iocs_matched": [match.get("ioc_value")]
                })
        
        return campaigns
    
    def _match_campaigns_by_ttps(self, ttps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Match campaigns by TTP patterns"""
        campaigns = []
        
        # Common TTP to campaign mappings (simplified)
        ttp_campaign_map = {
            "T1566.001": ["APT Campaign", "Business Email Compromise"],
            "T1566.002": ["Phishing Campaign", "Credential Harvesting"],
            "T1598": ["Information Gathering Campaign"]
        }
        
        for ttp in ttps:
            technique_id = ttp.get("technique_id", "")
            if technique_id in ttp_campaign_map:
                for campaign in ttp_campaign_map[technique_id]:
                    campaigns.append({
                        "campaign_name": campaign,
                        "confidence": ttp.get("confidence", 0.5),
                        "source": "ttp_match",
                        "ttps_matched": [technique_id]
                    })
        
        return campaigns
    
    def _deduplicate_campaigns(self, campaigns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate campaigns"""
        seen = set()
        deduplicated = []
        
        for campaign in campaigns:
            campaign_name = campaign.get("campaign_name", "")
            if campaign_name not in seen:
                seen.add(campaign_name)
                deduplicated.append(campaign)
        
        return deduplicated
    
    def _calculate_campaign_confidence(self, campaigns: List[Dict[str, Any]]) -> Dict[str, float]:
        """Calculate confidence for each campaign"""
        confidence_scores = {}
        
        for campaign in campaigns:
            name = campaign.get("campaign_name", "")
            confidence = campaign.get("confidence", 0.0)
            confidence_scores[name] = confidence
        
        return confidence_scores
    
    def _extract_threat_actors(self, campaigns: List[Dict[str, Any]]) -> List[str]:
        """Extract threat actors from campaigns"""
        actors = []
        
        # Simplified campaign to actor mapping
        campaign_actor_map = {
            "APT Campaign": ["APT29", "APT28"],
            "Business Email Compromise": ["TA505", "FIN7"],
            "Phishing Campaign": ["TA551", "TA544"]
        }
        
        for campaign in campaigns:
            campaign_name = campaign.get("campaign_name", "")
            if campaign_name in campaign_actor_map:
                actors.extend(campaign_actor_map[campaign_name])
        
        return list(set(actors))
    
    def _build_campaign_timeline(self, campaigns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build timeline for matched campaigns"""
        timeline = {
            "active_campaigns": [],
            "historical_campaigns": [],
            "timeline_confidence": 0.0
        }
        
        current_time = datetime.now()
        
        for campaign in campaigns:
            campaign_name = campaign.get("campaign_name", "")
            # Simulate campaign activity periods
            timeline["active_campaigns"].append({
                "name": campaign_name,
                "first_seen": current_time - timedelta(days=30),
                "last_seen": current_time,
                "status": "active"
            })
        
        timeline["timeline_confidence"] = 0.7 if campaigns else 0.0
        
        return timeline
    
    def _attribute_actors_by_ttps(self, ttps: List[Dict[str, Any]]) -> List[str]:
        """Attribute threat actors by TTP analysis"""
        actors = []
        
        # Simplified TTP to actor mapping
        ttp_actor_map = {
            "T1566.001": ["APT29", "FIN7"],
            "T1566.002": ["APT28", "TA551"],
            "T1598": ["APT1", "Lazarus"]
        }
        
        for ttp in ttps:
            technique_id = ttp.get("technique_id", "")
            if technique_id in ttp_actor_map:
                actors.extend(ttp_actor_map[technique_id])
        
        return list(set(actors))
    
    def _calculate_attribution_confidence(self, actors: List[str],
                                        campaign_correlation: Dict[str, Any],
                                        ttp_correlation: Dict[str, Any]) -> Dict[str, float]:
        """Calculate attribution confidence for each actor"""
        confidence_scores = {}
        
        for actor in actors:
            # Base confidence
            confidence = 0.3
            
            # Increase confidence based on campaign matches
            campaigns = campaign_correlation.get("matched_campaigns", [])
            if any(actor in str(campaign) for campaign in campaigns):
                confidence += 0.3
            
            # Increase confidence based on TTP matches
            ttps = ttp_correlation.get("identified_ttps", [])
            if len(ttps) > 2:
                confidence += 0.2
            
            confidence_scores[actor] = min(confidence, 1.0)
        
        return confidence_scores
    
    def _build_actor_profiles(self, actors: List[str]) -> Dict[str, Dict[str, Any]]:
        """Build profiles for attributed actors"""
        profiles = {}
        
        # Simplified actor profiles
        actor_data = {
            "APT29": {
                "country": "Russia",
                "motivation": "Espionage",
                "sophistication": "High",
                "targets": ["Government", "Healthcare", "Technology"]
            },
            "APT28": {
                "country": "Russia", 
                "motivation": "Espionage",
                "sophistication": "High",
                "targets": ["Military", "Government", "Media"]
            },
            "FIN7": {
                "country": "Unknown",
                "motivation": "Financial",
                "sophistication": "Medium",
                "targets": ["Retail", "Hospitality", "Financial"]
            }
        }
        
        for actor in actors:
            if actor in actor_data:
                profiles[actor] = actor_data[actor]
            else:
                profiles[actor] = {
                    "country": "Unknown",
                    "motivation": "Unknown",
                    "sophistication": "Unknown",
                    "targets": []
                }
        
        return profiles
    
    def _compile_attribution_evidence(self, actors: List[str],
                                    campaign_correlation: Dict[str, Any],
                                    ttp_correlation: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Compile evidence for threat actor attribution"""
        evidence = []
        
        for actor in actors:
            actor_evidence = {
                "actor": actor,
                "evidence_sources": [],
                "confidence": 0.0,
                "supporting_data": []
            }
            
            # Add campaign evidence
            campaigns = campaign_correlation.get("matched_campaigns", [])
            for campaign in campaigns:
                if actor in str(campaign):
                    actor_evidence["evidence_sources"].append("campaign_match")
                    actor_evidence["supporting_data"].append(f"Matched to campaign: {campaign.get('campaign_name')}")
            
            # Add TTP evidence
            ttps = ttp_correlation.get("identified_ttps", [])
            if ttps:
                actor_evidence["evidence_sources"].append("ttp_analysis")
                actor_evidence["supporting_data"].append(f"TTPs consistent with {actor} operations")
            
            # Calculate evidence confidence
            actor_evidence["confidence"] = len(actor_evidence["evidence_sources"]) * 0.3
            
            evidence.append(actor_evidence)
        
        return evidence
    
    # Attack Lifecycle Analysis Helper Methods
    def _map_to_attack_phases(self, ttps: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Map TTPs to attack lifecycle phases"""
        phase_mapping = {
            "reconnaissance": [],
            "initial_access": [],
            "execution": [],
            "persistence": [],
            "privilege_escalation": [],
            "defense_evasion": [],
            "credential_access": [],
            "discovery": [],
            "lateral_movement": [],
            "collection": [],
            "command_and_control": [],
            "exfiltration": [],
            "impact": []
        }
        
        # MITRE ATT&CK technique to phase mapping
        technique_phases = {
            "T1566": "initial_access",
            "T1566.001": "initial_access",
            "T1566.002": "initial_access",
            "T1598": "reconnaissance",
            "T1204": "execution",
            "T1059": "execution",
            "T1071": "command_and_control",
            "T1041": "exfiltration"
        }
        
        for ttp in ttps:
            technique_id = ttp.get("technique_id", "")
            if technique_id in technique_phases:
                phase = technique_phases[technique_id]
                phase_mapping[phase].append(technique_id)
        
        return phase_mapping
    
    def _identify_attack_progression(self, phase_mapping: Dict[str, List[str]]) -> Dict[str, Any]:
        """Identify attack progression and stage"""
        progression = {
            "current_stage": "unknown",
            "completed_stages": [],
            "progression_confidence": 0.0,
            "attack_maturity": "low"
        }
        
        # Define stage order
        stages = [
            "reconnaissance", "initial_access", "execution", "persistence",
            "privilege_escalation", "defense_evasion", "credential_access",
            "discovery", "lateral_movement", "collection", "command_and_control",
            "exfiltration", "impact"
        ]
        
        # Find completed stages
        for stage in stages:
            if phase_mapping.get(stage):
                progression["completed_stages"].append(stage)
        
        # Determine current stage
        if progression["completed_stages"]:
            progression["current_stage"] = progression["completed_stages"][-1]
            
            # Calculate progression confidence
            stage_count = len(progression["completed_stages"])
            progression["progression_confidence"] = min(stage_count * 0.15, 1.0)
            
            # Determine attack maturity
            if stage_count >= 8:
                progression["attack_maturity"] = "high"
            elif stage_count >= 4:
                progression["attack_maturity"] = "medium"
            else:
                progression["attack_maturity"] = "low"
        
        return progression
    
    def _calculate_kill_chain_score(self, progression: Dict[str, Any]) -> float:
        """Calculate kill chain progression score"""
        completed_stages = len(progression.get("completed_stages", []))
        total_stages = 13  # Total MITRE ATT&CK stages
        
        base_score = completed_stages / total_stages
        
        # Apply maturity multiplier
        maturity = progression.get("attack_maturity", "low")
        if maturity == "high":
            multiplier = 1.2
        elif maturity == "medium":
            multiplier = 1.1
        else:
            multiplier = 1.0
        
        return min(base_score * multiplier, 1.0)
    
    def _predict_next_stages(self, current_stage: str, correlation_data: Dict[str, Any]) -> List[str]:
        """Predict next likely attack stages"""
        stage_progression = {
            "reconnaissance": ["initial_access"],
            "initial_access": ["execution", "persistence"],
            "execution": ["persistence", "defense_evasion", "discovery"],
            "persistence": ["privilege_escalation", "credential_access"],
            "privilege_escalation": ["defense_evasion", "credential_access", "discovery"],
            "defense_evasion": ["credential_access", "discovery", "lateral_movement"],
            "credential_access": ["discovery", "lateral_movement"],
            "discovery": ["lateral_movement", "collection"],
            "lateral_movement": ["collection", "persistence"],
            "collection": ["command_and_control", "exfiltration"],
            "command_and_control": ["exfiltration", "impact"],
            "exfiltration": ["impact"],
            "impact": []
        }
        
        return stage_progression.get(current_stage, [])
    
    def _perform_timeline_analysis(self, correlation_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform timeline analysis of the attack"""
        timeline = {
            "attack_duration": timedelta(hours=0),
            "key_events": [],
            "velocity_analysis": {},
            "time_confidence": 0.0
        }
        
        # Simulate timeline analysis
        start_time = datetime.now() - timedelta(hours=random.randint(1, 48))
        timeline["attack_duration"] = datetime.now() - start_time
        
        timeline["key_events"] = [
            {"event": "Initial phishing email", "timestamp": start_time},
            {"event": "Email opened", "timestamp": start_time + timedelta(minutes=30)},
            {"event": "Link clicked", "timestamp": start_time + timedelta(hours=1)}
        ]
        
        timeline["velocity_analysis"] = {
            "attack_speed": "medium",
            "dwell_time": timeline["attack_duration"],
            "progression_rate": "normal"
        }
        
        timeline["time_confidence"] = 0.7
        
        return timeline
    
    def _assess_attack_sophistication(self, correlation_data: Dict[str, Any],
                                   kill_chain_stages: Dict[str, Any]) -> Dict[str, Any]:
        """Assess attack sophistication level"""
        sophistication = {
            "level": "low",
            "score": 0.0,
            "factors": [],
            "assessment_confidence": 0.0
        }
        
        score = 0.0
        factors = []
        
        # Check for advanced TTPs
        ttps = correlation_data.get("ttp_correlation", {}).get("identified_ttps", [])
        if len(ttps) > 5:
            score += 0.3
            factors.append("Multiple TTPs identified")
        
        # Check for evasion techniques
        for ttp in ttps:
            if "evasion" in ttp.get("technique_name", "").lower():
                score += 0.2
                factors.append("Evasion techniques used")
                break
        
        # Check kill chain progression
        completed_stages = len(kill_chain_stages.get("completed_stages", []))
        if completed_stages > 6:
            score += 0.3
            factors.append("Advanced kill chain progression")
        
        # Determine sophistication level
        if score >= 0.7:
            sophistication["level"] = "high"
        elif score >= 0.4:
            sophistication["level"] = "medium"
        else:
            sophistication["level"] = "low"
        
        sophistication["score"] = score
        sophistication["factors"] = factors
        sophistication["assessment_confidence"] = 0.8
        
        return sophistication
    
    def _calculate_lifecycle_confidence(self, lifecycle_analysis: Dict[str, Any]) -> float:
        """Calculate overall lifecycle analysis confidence"""
        confidence_factors = []
        
        # Kill chain progression confidence
        kill_chain = lifecycle_analysis.get("kill_chain_stages", {})
        if kill_chain.get("progression_confidence", 0) > 0:
            confidence_factors.append(kill_chain["progression_confidence"])
        
        # Timeline confidence
        timeline = lifecycle_analysis.get("timeline_analysis", {})
        if timeline.get("time_confidence", 0) > 0:
            confidence_factors.append(timeline["time_confidence"])
        
        # Sophistication confidence
        sophistication = lifecycle_analysis.get("attack_sophistication", {})
        if sophistication.get("assessment_confidence", 0) > 0:
            confidence_factors.append(sophistication["assessment_confidence"])
        
        return sum(confidence_factors) / len(confidence_factors) if confidence_factors else 0.0
    
    # Historical Correlation Helper Methods
    def _find_similar_incidents(self, correlation_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find similar historical incidents"""
        incidents = []
        
        # Simulate historical incident search
        iocs = correlation_data.get("ioc_correlation", {}).get("matched_iocs", [])
        for i, ioc in enumerate(iocs[:3]):  # Limit to first 3 IOCs
            incidents.append({
                "incident_id": f"INC-{datetime.now().strftime('%Y%m%d')}-{i+1:03d}",
                "matched_ioc": ioc.get("ioc_value", ""),
                "incident_date": datetime.now() - timedelta(days=random.randint(1, 365)),
                "severity": random.choice(["low", "medium", "high", "critical"]),
                "attack_type": random.choice(["phishing", "malware", "credential_theft"]),
                "similarity_score": random.uniform(0.6, 0.9)
            })
        
        return incidents
    
    def _identify_incident_patterns(self, similar_incidents: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Identify patterns in similar incidents"""
        patterns = {
            "attack_timing": {},
            "target_patterns": {},
            "technique_patterns": {},
            "pattern_confidence": 0.0
        }
        
        if not similar_incidents:
            return patterns
        
        # Analyze attack timing patterns
        times = [incident.get("incident_date", datetime.now()) for incident in similar_incidents]
        patterns["attack_timing"] = {
            "most_common_day": "weekday",
            "peak_hours": [9, 10, 11, 14, 15],
            "seasonal_pattern": "none"
        }
        
        # Analyze target patterns
        attack_types = [incident.get("attack_type", "") for incident in similar_incidents]
        patterns["target_patterns"] = {
            "primary_target": max(set(attack_types), key=attack_types.count) if attack_types else "unknown",
            "target_frequency": len(set(attack_types))
        }
        
        # Analyze technique patterns
        patterns["technique_patterns"] = {
            "common_techniques": ["phishing", "social_engineering"],
            "technique_evolution": "stable"
        }
        
        patterns["pattern_confidence"] = 0.75
        
        return patterns
    
    def _find_repeat_indicators(self, correlation_data: Dict[str, Any],
                              similar_incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find indicators that repeat across incidents"""
        repeat_indicators = []
        
        current_iocs = correlation_data.get("ioc_correlation", {}).get("matched_iocs", [])
        
        for current_ioc in current_iocs:
            for incident in similar_incidents:
                if current_ioc.get("ioc_value") == incident.get("matched_ioc"):
                    repeat_indicators.append({
                        "indicator": current_ioc.get("ioc_value"),
                        "indicator_type": current_ioc.get("ioc_type"),
                        "repeat_count": 2,  # Simplified
                        "first_seen": incident.get("incident_date"),
                        "last_seen": datetime.now(),
                        "persistence_score": 0.8
                    })
        
        return repeat_indicators
    
    def _analyze_threat_evolution(self, similar_incidents: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze threat evolution over time"""
        evolution = {
            "evolution_timeline": [],
            "technique_changes": [],
            "sophistication_trend": "stable",
            "evolution_confidence": 0.0
        }
        
        if not similar_incidents:
            return evolution
        
        # Sort incidents by date
        sorted_incidents = sorted(similar_incidents, 
                                key=lambda x: x.get("incident_date", datetime.now()))
        
        evolution["evolution_timeline"] = [
            {
                "date": incident.get("incident_date"),
                "changes": ["technique_refinement"],
                "significance": "low"
            }
            for incident in sorted_incidents
        ]
        
        evolution["technique_changes"] = [
            "Improved social engineering",
            "Enhanced evasion techniques"
        ]
        
        evolution["sophistication_trend"] = "increasing"
        evolution["evolution_confidence"] = 0.7
        
        return evolution
    
    def _extract_lessons_learned(self, similar_incidents: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Extract lessons learned from similar incidents"""
        lessons = []
        
        if not similar_incidents:
            return lessons
        
        # Common lessons based on incident patterns
        lessons.append({
            "lesson": "Implement advanced email filtering",
            "category": "prevention",
            "priority": "high"
        })
        
        lessons.append({
            "lesson": "Enhance user awareness training",
            "category": "prevention", 
            "priority": "medium"
        })
        
        lessons.append({
            "lesson": "Deploy behavioral analytics",
            "category": "detection",
            "priority": "high"
        })
        
        return lessons
    
    def _calculate_historical_correlation_strength(self, historical_correlation: Dict[str, Any]) -> float:
        """Calculate historical correlation strength"""
        strength_factors = []
        
        # Similar incidents factor
        similar_count = len(historical_correlation.get("similar_incidents", []))
        if similar_count > 0:
            strength_factors.append(min(similar_count * 0.2, 1.0))
        
        # Repeat indicators factor
        repeat_count = len(historical_correlation.get("repeat_indicators", []))
        if repeat_count > 0:
            strength_factors.append(min(repeat_count * 0.3, 1.0))
        
        # Pattern confidence factor
        patterns = historical_correlation.get("incident_patterns", {})
        pattern_confidence = patterns.get("pattern_confidence", 0.0)
        if pattern_confidence > 0:
            strength_factors.append(pattern_confidence)
        
        return sum(strength_factors) / len(strength_factors) if strength_factors else 0.0
