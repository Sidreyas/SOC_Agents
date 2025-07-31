"""
DDoS Defense Agent - State 2: Source IP Intelligence
Geographic analysis and IP reputation assessment using Azure Traffic Analytics
"""

import logging
import json
import requests
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass
from collections import defaultdict, Counter
import ipaddress
import geoip2.database
import re

# Configure logger
logger = logging.getLogger(__name__)

@dataclass
class IPIntelligenceResult:
    """IP intelligence analysis result"""
    ip_address: str
    geographic_info: Dict[str, Any]
    reputation_score: float
    threat_classification: str
    botnet_membership: Optional[str]
    asn_info: Dict[str, Any]
    historical_activity: Dict[str, Any]
    confidence_score: float

@dataclass
class SourceIntelligenceResult:
    """Container for source IP intelligence results"""
    analysis_id: str
    analysis_timestamp: datetime
    ip_analysis_results: List[IPIntelligenceResult]
    geographic_distribution: Dict[str, Any]
    reputation_assessment: Dict[str, Any]
    botnet_correlation: Dict[str, Any]
    attack_infrastructure: Dict[str, Any]
    threat_actor_attribution: Dict[str, Any]
    confidence_score: float

class SourceIPIntelligenceAnalyzer:
    """
    State 2: Source IP Intelligence
    Analyzes source IPs for geographic patterns, reputation, and botnet correlation
    """
    
    def __init__(self):
        """Initialize the Source IP Intelligence Analyzer"""
        self.intelligence_config = self._initialize_intelligence_config()
        self.azure_traffic_client = self._initialize_azure_traffic_client()
        self.reputation_sources = self._initialize_reputation_sources()
        self.geographic_databases = self._initialize_geographic_databases()
        self.botnet_intelligence = self._initialize_botnet_intelligence()
        
        logger.info("Source IP Intelligence Analyzer initialized")
    
    def analyze_source_intelligence(self, source_ips: List[str],
                                  traffic_data: Dict[str, Any],
                                  incident_context: Dict[str, Any]) -> SourceIntelligenceResult:
        """
        Perform comprehensive source IP intelligence analysis
        
        Args:
            source_ips: List of source IP addresses to analyze
            traffic_data: Azure Traffic Analytics data
            incident_context: Incident context information
            
        Returns:
            Comprehensive source IP intelligence results
        """
        logger.info(f"Starting source IP intelligence analysis for {len(source_ips)} IPs")
        
        analysis_id = f"source-intel-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        start_time = datetime.now()
        
        try:
            # Analyze individual IPs
            ip_analysis_results = []
            for ip in source_ips:
                ip_result = self._analyze_single_ip(ip, traffic_data, incident_context)
                ip_analysis_results.append(ip_result)
            
            # Analyze geographic distribution
            geographic_distribution = self._analyze_geographic_distribution(ip_analysis_results)
            
            # Assess overall reputation
            reputation_assessment = self._assess_overall_reputation(ip_analysis_results)
            
            # Correlate with botnet intelligence
            botnet_correlation = self._correlate_with_botnets(ip_analysis_results)
            
            # Analyze attack infrastructure
            attack_infrastructure = self._analyze_attack_infrastructure(
                ip_analysis_results, traffic_data
            )
            
            # Attempt threat actor attribution
            threat_actor_attribution = self._perform_threat_actor_attribution(
                ip_analysis_results, attack_infrastructure
            )
            
            # Calculate overall confidence
            confidence_score = self._calculate_overall_confidence(ip_analysis_results)
            
            result = SourceIntelligenceResult(
                analysis_id=analysis_id,
                analysis_timestamp=start_time,
                ip_analysis_results=ip_analysis_results,
                geographic_distribution=geographic_distribution,
                reputation_assessment=reputation_assessment,
                botnet_correlation=botnet_correlation,
                attack_infrastructure=attack_infrastructure,
                threat_actor_attribution=threat_actor_attribution,
                confidence_score=confidence_score
            )
            
            logger.info(f"Source IP intelligence analysis completed: {analysis_id}")
            return result
            
        except Exception as e:
            logger.error(f"Error in source IP intelligence analysis: {str(e)}")
            raise
    
    def query_azure_traffic_analytics(self, time_range: timedelta,
                                     source_filter: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Query Azure Traffic Analytics for source IP patterns
        
        Args:
            time_range: Time range for traffic analysis
            source_filter: Optional filter for specific source IPs
            
        Returns:
            Azure Traffic Analytics results
        """
        logger.info("Querying Azure Traffic Analytics")
        
        traffic_analytics = {
            "source_distributions": {},
            "geographic_patterns": {},
            "temporal_analysis": {},
            "connection_patterns": {},
            "firewall_interactions": {},
            "nsg_flow_logs": {},
            "analysis_metadata": {
                "query_timestamp": datetime.now(),
                "time_range_hours": time_range.total_seconds() / 3600,
                "sources_filtered": len(source_filter) if source_filter else 0
            }
        }
        
        try:
            # Query source IP distributions
            traffic_analytics["source_distributions"] = self._query_source_distributions(
                time_range, source_filter
            )
            
            # Analyze geographic patterns
            traffic_analytics["geographic_patterns"] = self._analyze_geographic_patterns(
                traffic_analytics["source_distributions"]
            )
            
            # Perform temporal analysis
            traffic_analytics["temporal_analysis"] = self._perform_temporal_analysis(
                time_range, source_filter
            )
            
            # Analyze connection patterns
            traffic_analytics["connection_patterns"] = self._analyze_connection_patterns(
                time_range, source_filter
            )
            
            # Query firewall interactions
            traffic_analytics["firewall_interactions"] = self._query_firewall_interactions(
                time_range, source_filter
            )
            
            # Analyze NSG flow logs
            traffic_analytics["nsg_flow_logs"] = self._analyze_nsg_flow_logs(
                time_range, source_filter
            )
            
            return traffic_analytics
            
        except Exception as e:
            logger.error(f"Error querying Azure Traffic Analytics: {str(e)}")
            raise
    
    def correlate_with_threat_intelligence(self, ip_addresses: List[str],
                                         threat_feeds: List[str]) -> Dict[str, Any]:
        """
        Correlate source IPs with threat intelligence feeds
        
        Args:
            ip_addresses: List of IP addresses to check
            threat_feeds: List of threat intelligence feed names
            
        Returns:
            Threat intelligence correlation results
        """
        logger.info(f"Correlating {len(ip_addresses)} IPs with threat intelligence")
        
        threat_correlation = {
            "feed_results": {},
            "malicious_ips": [],
            "botnet_associations": {},
            "campaign_correlations": {},
            "actor_attributions": {},
            "confidence_scores": {},
            "analysis_metadata": {
                "correlation_timestamp": datetime.now(),
                "ips_analyzed": len(ip_addresses),
                "feeds_queried": len(threat_feeds),
                "malicious_ips_found": 0
            }
        }
        
        try:
            # Query each threat intelligence feed
            for feed_name in threat_feeds:
                feed_results = self._query_threat_feed(ip_addresses, feed_name)
                threat_correlation["feed_results"][feed_name] = feed_results
            
            # Identify malicious IPs
            threat_correlation["malicious_ips"] = self._identify_malicious_ips(
                threat_correlation["feed_results"]
            )
            
            # Correlate with botnet databases
            threat_correlation["botnet_associations"] = self._correlate_with_botnets_detailed(
                ip_addresses, threat_correlation["malicious_ips"]
            )
            
            # Identify campaign correlations
            threat_correlation["campaign_correlations"] = self._identify_campaign_correlations(
                threat_correlation["feed_results"], threat_correlation["malicious_ips"]
            )
            
            # Attempt actor attribution
            threat_correlation["actor_attributions"] = self._correlate_threat_actors(
                threat_correlation["campaign_correlations"], threat_correlation["botnet_associations"]
            )
            
            # Calculate confidence scores
            threat_correlation["confidence_scores"] = self._calculate_threat_confidence_scores(
                threat_correlation
            )
            
            # Update metadata
            threat_correlation["analysis_metadata"]["malicious_ips_found"] = len(
                threat_correlation["malicious_ips"]
            )
            
            return threat_correlation
            
        except Exception as e:
            logger.error(f"Error correlating with threat intelligence: {str(e)}")
            raise
    
    def analyze_geographic_distribution(self, ip_data: List[IPIntelligenceResult]) -> Dict[str, Any]:
        """
        Analyze geographic distribution of source IPs
        
        Args:
            ip_data: List of IP intelligence results
            
        Returns:
            Geographic distribution analysis
        """
        logger.info("Analyzing geographic distribution of source IPs")
        
        geographic_analysis = {
            "country_distribution": {},
            "city_distribution": {},
            "asn_distribution": {},
            "suspicious_patterns": [],
            "geographic_clustering": {},
            "impossible_geography": [],
            "analysis_metadata": {
                "analysis_timestamp": datetime.now(),
                "ips_analyzed": len(ip_data),
                "countries_identified": 0,
                "suspicious_patterns_found": 0
            }
        }
        
        try:
            # Analyze country distribution
            geographic_analysis["country_distribution"] = self._analyze_country_distribution(ip_data)
            
            # Analyze city distribution
            geographic_analysis["city_distribution"] = self._analyze_city_distribution(ip_data)
            
            # Analyze ASN distribution
            geographic_analysis["asn_distribution"] = self._analyze_asn_distribution(ip_data)
            
            # Identify suspicious patterns
            geographic_analysis["suspicious_patterns"] = self._identify_suspicious_geographic_patterns(
                geographic_analysis
            )
            
            # Perform geographic clustering
            geographic_analysis["geographic_clustering"] = self._perform_geographic_clustering(
                ip_data
            )
            
            # Detect impossible geography
            geographic_analysis["impossible_geography"] = self._detect_impossible_geography(
                ip_data
            )
            
            # Update metadata
            geographic_analysis["analysis_metadata"].update({
                "countries_identified": len(geographic_analysis["country_distribution"]),
                "suspicious_patterns_found": len(geographic_analysis["suspicious_patterns"])
            })
            
            return geographic_analysis
            
        except Exception as e:
            logger.error(f"Error analyzing geographic distribution: {str(e)}")
            raise
    
    def assess_ip_reputation(self, ip_addresses: List[str]) -> Dict[str, Any]:
        """
        Assess reputation of IP addresses using multiple sources
        
        Args:
            ip_addresses: List of IP addresses to assess
            
        Returns:
            IP reputation assessment results
        """
        logger.info(f"Assessing reputation for {len(ip_addresses)} IP addresses")
        
        reputation_assessment = {
            "individual_scores": {},
            "aggregated_scores": {},
            "reputation_sources": {},
            "malicious_indicators": {},
            "clean_indicators": {},
            "confidence_levels": {},
            "analysis_metadata": {
                "assessment_timestamp": datetime.now(),
                "ips_assessed": len(ip_addresses),
                "sources_queried": 0,
                "malicious_ips": 0
            }
        }
        
        try:
            # Query reputation sources
            for source_name, source_config in self.reputation_sources.items():
                source_results = self._query_reputation_source(ip_addresses, source_name, source_config)
                reputation_assessment["reputation_sources"][source_name] = source_results
            
            # Calculate individual scores
            for ip in ip_addresses:
                individual_score = self._calculate_individual_reputation_score(
                    ip, reputation_assessment["reputation_sources"]
                )
                reputation_assessment["individual_scores"][ip] = individual_score
            
            # Calculate aggregated scores
            reputation_assessment["aggregated_scores"] = self._calculate_aggregated_scores(
                reputation_assessment["individual_scores"]
            )
            
            # Identify malicious indicators
            reputation_assessment["malicious_indicators"] = self._identify_malicious_indicators(
                reputation_assessment["individual_scores"]
            )
            
            # Identify clean indicators
            reputation_assessment["clean_indicators"] = self._identify_clean_indicators(
                reputation_assessment["individual_scores"]
            )
            
            # Calculate confidence levels
            reputation_assessment["confidence_levels"] = self._calculate_reputation_confidence(
                reputation_assessment
            )
            
            # Update metadata
            reputation_assessment["analysis_metadata"].update({
                "sources_queried": len(self.reputation_sources),
                "malicious_ips": len(reputation_assessment["malicious_indicators"])
            })
            
            return reputation_assessment
            
        except Exception as e:
            logger.error(f"Error assessing IP reputation: {str(e)}")
            raise
    
    def generate_source_intelligence_report(self, analysis_result: SourceIntelligenceResult,
                                          traffic_analytics: Dict[str, Any],
                                          threat_correlation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive source IP intelligence report
        
        Args:
            analysis_result: Source intelligence analysis results
            traffic_analytics: Azure Traffic Analytics data
            threat_correlation: Threat intelligence correlation results
            
        Returns:
            Comprehensive source intelligence report
        """
        logger.info("Generating source IP intelligence report")
        
        report = {
            "executive_summary": {},
            "source_overview": {},
            "geographic_analysis": {},
            "reputation_assessment": {},
            "threat_intelligence": {},
            "botnet_analysis": {},
            "attack_infrastructure": {},
            "recommendations": [],
            "report_metadata": {
                "report_id": f"SOURCE-RPT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                "generation_timestamp": datetime.now(),
                "analysis_id": analysis_result.analysis_id,
                "confidence_level": analysis_result.confidence_score
            }
        }
        
        try:
            # Executive summary
            report["executive_summary"] = self._create_source_executive_summary(
                analysis_result, traffic_analytics, threat_correlation
            )
            
            # Source overview
            report["source_overview"] = self._create_source_overview(
                analysis_result.ip_analysis_results
            )
            
            # Geographic analysis
            report["geographic_analysis"] = self._create_geographic_analysis_summary(
                analysis_result.geographic_distribution
            )
            
            # Reputation assessment
            report["reputation_assessment"] = self._create_reputation_assessment_summary(
                analysis_result.reputation_assessment
            )
            
            # Threat intelligence
            report["threat_intelligence"] = self._create_threat_intelligence_summary(
                threat_correlation
            )
            
            # Botnet analysis
            report["botnet_analysis"] = self._create_botnet_analysis_summary(
                analysis_result.botnet_correlation
            )
            
            # Attack infrastructure
            report["attack_infrastructure"] = self._create_infrastructure_analysis_summary(
                analysis_result.attack_infrastructure
            )
            
            # Recommendations
            report["recommendations"] = self._generate_source_recommendations(
                analysis_result, traffic_analytics, threat_correlation
            )
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating source intelligence report: {str(e)}")
            raise
    
    def _initialize_intelligence_config(self) -> Dict[str, Any]:
        """Initialize source intelligence configuration"""
        return {
            "reputation_thresholds": {
                "clean": 0.2,
                "suspicious": 0.5,
                "malicious": 0.8
            },
            "geographic_risk_countries": [
                "CN", "RU", "KP", "IR", "SY"  # High-risk countries
            ],
            "botnet_databases": [
                "spamhaus", "malwaredomainlist", "zeus_tracker", "feodo_tracker"
            ],
            "reputation_sources": [
                "virustotal", "abuseipdb", "talos", "emerging_threats"
            ],
            "confidence_weights": {
                "reputation": 0.4,
                "geographic": 0.2,
                "botnet": 0.3,
                "temporal": 0.1
            }
        }
    
    def _initialize_azure_traffic_client(self) -> Dict[str, Any]:
        """Initialize Azure Traffic Analytics client"""
        return {
            "workspace_id": "log_analytics_workspace_id",
            "subscription_id": "azure_subscription_id",
            "resource_group": "network_watcher_resource_group",
            "api_version": "2022-10-01",
            "base_url": "https://management.azure.com/"
        }
    
    def _initialize_reputation_sources(self) -> Dict[str, Dict[str, Any]]:
        """Initialize IP reputation sources"""
        return {
            "virustotal": {
                "api_url": "https://www.virustotal.com/vtapi/v2/ip-address/report",
                "api_key": "virustotal_api_key",
                "weight": 0.3
            },
            "abuseipdb": {
                "api_url": "https://api.abuseipdb.com/api/v2/check",
                "api_key": "abuseipdb_api_key",
                "weight": 0.3
            },
            "talos": {
                "api_url": "https://talosintelligence.com/reputation_center/lookup",
                "weight": 0.2
            },
            "emerging_threats": {
                "api_url": "https://rules.emergingthreats.net/open/suricata/rules/",
                "weight": 0.2
            }
        }
    
    def _initialize_geographic_databases(self) -> Dict[str, Any]:
        """Initialize geographic IP databases"""
        return {
            "maxmind_db": "/opt/geoip/GeoLite2-City.mmdb",
            "ip2location_db": "/opt/geoip/IP2LOCATION.BIN",
            "ipinfo_api": "https://ipinfo.io/",
            "backup_services": ["ip-api.com", "freegeoip.app"]
        }
    
    def _initialize_botnet_intelligence(self) -> Dict[str, Any]:
        """Initialize botnet intelligence sources"""
        return {
            "spamhaus": {
                "api_url": "https://www.spamhaus.org/query/ip/",
                "list_types": ["sbl", "pbl", "xbl"]
            },
            "malwaredomainlist": {
                "api_url": "http://www.malwaredomainlist.com/hostslist/ip.txt"
            },
            "zeus_tracker": {
                "api_url": "https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist"
            },
            "feodo_tracker": {
                "api_url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
            }
        }
    
    # Placeholder implementations for comprehensive functionality
    def _analyze_single_ip(self, ip: str, traffic_data: Dict[str, Any], 
                          incident_context: Dict[str, Any]) -> IPIntelligenceResult:
        return IPIntelligenceResult(
            ip_address=ip,
            geographic_info={"country": "US", "city": "Unknown"},
            reputation_score=0.5,
            threat_classification="unknown",
            botnet_membership=None,
            asn_info={"asn": "AS12345", "org": "Example ISP"},
            historical_activity={},
            confidence_score=0.7
        )
    
    def _analyze_geographic_distribution(self, ip_results: List[IPIntelligenceResult]) -> Dict[str, Any]:
        return {"countries": {"US": 10, "CN": 5}, "risk_assessment": "medium"}
    
    def _assess_overall_reputation(self, ip_results: List[IPIntelligenceResult]) -> Dict[str, Any]:
        return {"overall_score": 0.6, "malicious_count": 2}
    
    def _correlate_with_botnets(self, ip_results: List[IPIntelligenceResult]) -> Dict[str, Any]:
        return {"botnet_members": [], "confidence": 0.5}
    
    def _analyze_attack_infrastructure(self, ip_results: List[IPIntelligenceResult], 
                                     traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        return {"infrastructure_type": "distributed", "coordination_level": "medium"}
    
    def _perform_threat_actor_attribution(self, ip_results: List[IPIntelligenceResult], 
                                        infrastructure: Dict[str, Any]) -> Dict[str, Any]:
        return {"attributed_actor": "unknown", "confidence": 0.3}
    
    def _calculate_overall_confidence(self, ip_results: List[IPIntelligenceResult]) -> float:
        return 0.75
    
    # Additional placeholder methods for comprehensive functionality
    def _query_source_distributions(self, time_range: timedelta, 
                                   source_filter: Optional[List[str]]) -> Dict[str, Any]:
        return {}
    
    def _analyze_geographic_patterns(self, distributions: Dict[str, Any]) -> Dict[str, Any]:
        return {}
    
    def _perform_temporal_analysis(self, time_range: timedelta, 
                                 source_filter: Optional[List[str]]) -> Dict[str, Any]:
        return {}
    
    def _analyze_connection_patterns(self, time_range: timedelta, 
                                   source_filter: Optional[List[str]]) -> Dict[str, Any]:
        return {}
    
    def _query_firewall_interactions(self, time_range: timedelta, 
                                   source_filter: Optional[List[str]]) -> Dict[str, Any]:
        return {}
    
    def _analyze_nsg_flow_logs(self, time_range: timedelta, 
                             source_filter: Optional[List[str]]) -> Dict[str, Any]:
        return {}
    
    def _query_threat_feed(self, ip_addresses: List[str], feed_name: str) -> Dict[str, Any]:
        return {}
    
    def _identify_malicious_ips(self, feed_results: Dict[str, Any]) -> List[str]:
        return []
    
    def _correlate_with_botnets_detailed(self, ip_addresses: List[str], 
                                       malicious_ips: List[str]) -> Dict[str, Any]:
        return {}
    
    def _identify_campaign_correlations(self, feed_results: Dict[str, Any], 
                                      malicious_ips: List[str]) -> Dict[str, Any]:
        return {}
    
    def _correlate_threat_actors(self, campaigns: Dict[str, Any], 
                               botnets: Dict[str, Any]) -> Dict[str, Any]:
        return {}
    
    def _calculate_threat_confidence_scores(self, correlation_data: Dict[str, Any]) -> Dict[str, Any]:
        return {}
    
    # Geographic analysis placeholder methods
    def _analyze_country_distribution(self, ip_data: List[IPIntelligenceResult]) -> Dict[str, Any]:
        return {}
    
    def _analyze_city_distribution(self, ip_data: List[IPIntelligenceResult]) -> Dict[str, Any]:
        return {}
    
    def _analyze_asn_distribution(self, ip_data: List[IPIntelligenceResult]) -> Dict[str, Any]:
        return {}
    
    def _identify_suspicious_geographic_patterns(self, geographic_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        return []
    
    def _perform_geographic_clustering(self, ip_data: List[IPIntelligenceResult]) -> Dict[str, Any]:
        return {}
    
    def _detect_impossible_geography(self, ip_data: List[IPIntelligenceResult]) -> List[Dict[str, Any]]:
        return []
    
    # Reputation assessment placeholder methods
    def _query_reputation_source(self, ip_addresses: List[str], source_name: str, 
                               source_config: Dict[str, Any]) -> Dict[str, Any]:
        return {}
    
    def _calculate_individual_reputation_score(self, ip: str, 
                                             source_results: Dict[str, Any]) -> Dict[str, Any]:
        return {"score": 0.5, "confidence": 0.7}
    
    def _calculate_aggregated_scores(self, individual_scores: Dict[str, Any]) -> Dict[str, Any]:
        return {}
    
    def _identify_malicious_indicators(self, scores: Dict[str, Any]) -> List[str]:
        return []
    
    def _identify_clean_indicators(self, scores: Dict[str, Any]) -> List[str]:
        return []
    
    def _calculate_reputation_confidence(self, assessment_data: Dict[str, Any]) -> Dict[str, Any]:
        return {}
    
    # Report generation placeholder methods
    def _create_source_executive_summary(self, *args) -> Dict[str, Any]:
        return {}
    def _create_source_overview(self, *args) -> Dict[str, Any]:
        return {}
    def _create_geographic_analysis_summary(self, *args) -> Dict[str, Any]:
        return {}
    def _create_reputation_assessment_summary(self, *args) -> Dict[str, Any]:
        return {}
    def _create_threat_intelligence_summary(self, *args) -> Dict[str, Any]:
        return {}
    def _create_botnet_analysis_summary(self, *args) -> Dict[str, Any]:
        return {}
    def _create_infrastructure_analysis_summary(self, *args) -> Dict[str, Any]:
        return {}
    def _generate_source_recommendations(self, *args) -> List[Dict[str, Any]]:
        return []
