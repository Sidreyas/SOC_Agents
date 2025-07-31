"""
Threat Intelligence Correlator Module
State 5: Threat Intelligence Correlation for Network & Exfiltration Agent
Correlates network indicators with threat intelligence feeds
"""

import logging
import asyncio
import aiohttp
from typing import Dict, Any, List, Optional, Set, Tuple
from datetime import datetime, timedelta
import json
import hashlib
import ipaddress
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class ThreatIntelligenceCorrelator:
    """
    Threat Intelligence Correlation System
    Correlates network indicators with various threat intelligence sources
    """
    
    def __init__(self):
        self.ti_sources = self._load_ti_sources()
        self.ioc_cache = {}
        self.reputation_thresholds = self._load_reputation_thresholds()
        self.feed_priorities = self._load_feed_priorities()
        
    async def correlate_threat_intelligence(self, network_indicators: Dict[str, Any]) -> Dict[str, Any]:
        """
        Correlate network indicators with threat intelligence
        
        Args:
            network_indicators: Network indicators to correlate
            
        Returns:
            Threat intelligence correlation results
        """
        logger.info("Starting threat intelligence correlation")
        
        correlation_results = {
            "ip_intelligence": {},
            "domain_intelligence": {},
            "url_intelligence": {},
            "file_intelligence": {},
            "malware_attribution": {},
            "campaign_correlation": {},
            "actor_attribution": {},
            "contextual_analysis": {},
            "risk_scoring": {},
            "correlation_timestamp": datetime.now()
        }
        
        try:
            # Extract indicators
            ips = network_indicators.get("ip_addresses", [])
            domains = network_indicators.get("domains", [])
            urls = network_indicators.get("urls", [])
            file_hashes = network_indicators.get("file_hashes", [])
            
            # IP address intelligence
            correlation_results["ip_intelligence"] = await self._correlate_ip_intelligence(ips)
            
            # Domain intelligence
            correlation_results["domain_intelligence"] = await self._correlate_domain_intelligence(domains)
            
            # URL intelligence
            correlation_results["url_intelligence"] = await self._correlate_url_intelligence(urls)
            
            # File intelligence
            correlation_results["file_intelligence"] = await self._correlate_file_intelligence(file_hashes)
            
            # Malware family attribution
            correlation_results["malware_attribution"] = await self._correlate_malware_attribution(network_indicators)
            
            # Campaign correlation
            correlation_results["campaign_correlation"] = await self._correlate_campaigns(network_indicators)
            
            # Threat actor attribution
            correlation_results["actor_attribution"] = await self._correlate_threat_actors(network_indicators)
            
            # Contextual analysis
            correlation_results["contextual_analysis"] = await self._perform_contextual_analysis(network_indicators)
            
            # Risk scoring
            correlation_results["risk_scoring"] = await self._calculate_risk_scores(correlation_results)
            
            logger.info("Threat intelligence correlation completed")
            
        except Exception as e:
            logger.error(f"Error in threat intelligence correlation: {str(e)}")
            correlation_results["error"] = str(e)
            
        return correlation_results
    
    async def _correlate_ip_intelligence(self, ip_addresses: List[str]) -> Dict[str, Any]:
        """Correlate IP addresses with threat intelligence"""
        ip_intelligence = {
            "malicious_ips": [],
            "reputation_scores": {},
            "geolocation_data": {},
            "asn_information": {},
            "blacklist_matches": {},
            "botnet_membership": {},
            "c2_infrastructure": {},
            "scanning_sources": {}
        }
        
        for ip in ip_addresses:
            if not self._is_valid_ip(ip):
                continue
            
            # Check reputation databases
            reputation = await self._check_ip_reputation(ip)
            ip_intelligence["reputation_scores"][ip] = reputation
            
            # Geolocation lookup
            geolocation = await self._get_ip_geolocation(ip)
            ip_intelligence["geolocation_data"][ip] = geolocation
            
            # ASN information
            asn_info = await self._get_asn_information(ip)
            ip_intelligence["asn_information"][ip] = asn_info
            
            # Blacklist checks
            blacklist_results = await self._check_ip_blacklists(ip)
            ip_intelligence["blacklist_matches"][ip] = blacklist_results
            
            # Botnet membership
            botnet_info = await self._check_botnet_membership(ip)
            if botnet_info:
                ip_intelligence["botnet_membership"][ip] = botnet_info
            
            # C2 infrastructure checks
            c2_info = await self._check_c2_infrastructure(ip)
            if c2_info:
                ip_intelligence["c2_infrastructure"][ip] = c2_info
            
            # Scanning source checks
            scanning_info = await self._check_scanning_sources(ip)
            if scanning_info:
                ip_intelligence["scanning_sources"][ip] = scanning_info
            
            # Mark as malicious if reputation is poor
            if reputation.get("score", 0) > self.reputation_thresholds["ip"]["malicious"]:
                ip_intelligence["malicious_ips"].append({
                    "ip": ip,
                    "reputation": reputation,
                    "confidence": "high" if reputation.get("score", 0) > 80 else "medium"
                })
        
        return ip_intelligence
    
    async def _correlate_domain_intelligence(self, domains: List[str]) -> Dict[str, Any]:
        """Correlate domains with threat intelligence"""
        domain_intelligence = {
            "malicious_domains": [],
            "reputation_scores": {},
            "whois_data": {},
            "dns_history": {},
            "blacklist_matches": {},
            "dga_classification": {},
            "parked_domains": {},
            "typosquatting": {}
        }
        
        for domain in domains:
            if not self._is_valid_domain(domain):
                continue
            
            # Domain reputation
            reputation = await self._check_domain_reputation(domain)
            domain_intelligence["reputation_scores"][domain] = reputation
            
            # WHOIS information
            whois_data = await self._get_whois_data(domain)
            domain_intelligence["whois_data"][domain] = whois_data
            
            # DNS history
            dns_history = await self._get_dns_history(domain)
            domain_intelligence["dns_history"][domain] = dns_history
            
            # Blacklist checks
            blacklist_results = await self._check_domain_blacklists(domain)
            domain_intelligence["blacklist_matches"][domain] = blacklist_results
            
            # DGA classification
            dga_analysis = await self._classify_dga_domain(domain)
            if dga_analysis:
                domain_intelligence["dga_classification"][domain] = dga_analysis
            
            # Parked domain detection
            parked_info = await self._check_parked_domain(domain)
            if parked_info:
                domain_intelligence["parked_domains"][domain] = parked_info
            
            # Typosquatting detection
            typosquat_info = await self._check_typosquatting(domain)
            if typosquat_info:
                domain_intelligence["typosquatting"][domain] = typosquat_info
            
            # Mark as malicious if reputation is poor
            if reputation.get("score", 0) > self.reputation_thresholds["domain"]["malicious"]:
                domain_intelligence["malicious_domains"].append({
                    "domain": domain,
                    "reputation": reputation,
                    "confidence": "high" if reputation.get("score", 0) > 80 else "medium"
                })
        
        return domain_intelligence
    
    async def _correlate_url_intelligence(self, urls: List[str]) -> Dict[str, Any]:
        """Correlate URLs with threat intelligence"""
        url_intelligence = {
            "malicious_urls": [],
            "reputation_scores": {},
            "url_analysis": {},
            "phishing_detection": {},
            "malware_hosting": {},
            "exploit_kits": {},
            "suspicious_parameters": {},
            "redirect_chains": {}
        }
        
        for url in urls:
            if not self._is_valid_url(url):
                continue
            
            # URL reputation
            reputation = await self._check_url_reputation(url)
            url_intelligence["reputation_scores"][url] = reputation
            
            # URL analysis
            analysis = await self._analyze_url_structure(url)
            url_intelligence["url_analysis"][url] = analysis
            
            # Phishing detection
            phishing_info = await self._check_phishing_url(url)
            if phishing_info:
                url_intelligence["phishing_detection"][url] = phishing_info
            
            # Malware hosting detection
            malware_info = await self._check_malware_hosting(url)
            if malware_info:
                url_intelligence["malware_hosting"][url] = malware_info
            
            # Exploit kit detection
            exploit_info = await self._check_exploit_kits(url)
            if exploit_info:
                url_intelligence["exploit_kits"][url] = exploit_info
            
            # Suspicious parameter analysis
            suspicious_params = await self._analyze_url_parameters(url)
            if suspicious_params:
                url_intelligence["suspicious_parameters"][url] = suspicious_params
            
            # Redirect chain analysis
            redirect_info = await self._analyze_redirect_chains(url)
            if redirect_info:
                url_intelligence["redirect_chains"][url] = redirect_info
            
            # Mark as malicious if reputation is poor
            if reputation.get("score", 0) > self.reputation_thresholds["url"]["malicious"]:
                url_intelligence["malicious_urls"].append({
                    "url": url,
                    "reputation": reputation,
                    "confidence": "high" if reputation.get("score", 0) > 80 else "medium"
                })
        
        return url_intelligence
    
    async def _correlate_file_intelligence(self, file_hashes: List[str]) -> Dict[str, Any]:
        """Correlate file hashes with threat intelligence"""
        file_intelligence = {
            "malicious_files": [],
            "reputation_scores": {},
            "malware_families": {},
            "antivirus_results": {},
            "behavioral_analysis": {},
            "packer_detection": {},
            "file_relationships": {},
            "distribution_campaigns": {}
        }
        
        for file_hash in file_hashes:
            if not self._is_valid_hash(file_hash):
                continue
            
            # File reputation
            reputation = await self._check_file_reputation(file_hash)
            file_intelligence["reputation_scores"][file_hash] = reputation
            
            # Malware family classification
            family_info = await self._classify_malware_family(file_hash)
            if family_info:
                file_intelligence["malware_families"][file_hash] = family_info
            
            # Antivirus scan results
            av_results = await self._get_antivirus_results(file_hash)
            file_intelligence["antivirus_results"][file_hash] = av_results
            
            # Behavioral analysis
            behavioral_info = await self._get_behavioral_analysis(file_hash)
            if behavioral_info:
                file_intelligence["behavioral_analysis"][file_hash] = behavioral_info
            
            # Packer detection
            packer_info = await self._detect_packers(file_hash)
            if packer_info:
                file_intelligence["packer_detection"][file_hash] = packer_info
            
            # File relationships
            relationships = await self._get_file_relationships(file_hash)
            if relationships:
                file_intelligence["file_relationships"][file_hash] = relationships
            
            # Distribution campaigns
            campaign_info = await self._get_distribution_campaigns(file_hash)
            if campaign_info:
                file_intelligence["distribution_campaigns"][file_hash] = campaign_info
            
            # Mark as malicious if reputation is poor
            if reputation.get("score", 0) > self.reputation_thresholds["file"]["malicious"]:
                file_intelligence["malicious_files"].append({
                    "hash": file_hash,
                    "reputation": reputation,
                    "confidence": "high" if reputation.get("score", 0) > 80 else "medium"
                })
        
        return file_intelligence
    
    async def _correlate_malware_attribution(self, network_indicators: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate indicators with malware families"""
        malware_attribution = {
            "identified_families": [],
            "family_confidence": {},
            "technique_mapping": {},
            "campaign_associations": {},
            "variant_analysis": {},
            "evolution_tracking": {}
        }
        
        # Collect all indicators
        all_indicators = []
        all_indicators.extend(network_indicators.get("ip_addresses", []))
        all_indicators.extend(network_indicators.get("domains", []))
        all_indicators.extend(network_indicators.get("urls", []))
        all_indicators.extend(network_indicators.get("file_hashes", []))
        
        # Check against malware family databases
        for indicator in all_indicators:
            family_matches = await self._match_malware_families(indicator)
            for family_match in family_matches:
                family_name = family_match["family"]
                
                if family_name not in malware_attribution["family_confidence"]:
                    malware_attribution["family_confidence"][family_name] = {
                        "indicators": [],
                        "confidence_score": 0,
                        "techniques": [],
                        "campaigns": []
                    }
                
                malware_attribution["family_confidence"][family_name]["indicators"].append({
                    "indicator": indicator,
                    "match_confidence": family_match["confidence"],
                    "match_type": family_match["type"]
                })
                
                # Update confidence score
                current_score = malware_attribution["family_confidence"][family_name]["confidence_score"]
                new_score = max(current_score, family_match["confidence"])
                malware_attribution["family_confidence"][family_name]["confidence_score"] = new_score
        
        # Identify high-confidence families
        for family_name, family_data in malware_attribution["family_confidence"].items():
            if family_data["confidence_score"] > 70:
                malware_attribution["identified_families"].append({
                    "family": family_name,
                    "confidence": family_data["confidence_score"],
                    "indicator_count": len(family_data["indicators"])
                })
        
        return malware_attribution
    
    async def _correlate_campaigns(self, network_indicators: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate indicators with threat campaigns"""
        campaign_correlation = {
            "active_campaigns": [],
            "campaign_confidence": {},
            "timeline_analysis": {},
            "target_analysis": {},
            "infrastructure_overlap": {},
            "ttps_correlation": {}
        }
        
        # Check indicators against campaign databases
        for indicator_type, indicators in network_indicators.items():
            for indicator in indicators:
                campaign_matches = await self._match_campaigns(indicator, indicator_type)
                
                for campaign_match in campaign_matches:
                    campaign_name = campaign_match["campaign"]
                    
                    if campaign_name not in campaign_correlation["campaign_confidence"]:
                        campaign_correlation["campaign_confidence"][campaign_name] = {
                            "indicators": [],
                            "confidence_score": 0,
                            "first_seen": None,
                            "last_seen": None,
                            "targets": []
                        }
                    
                    campaign_data = campaign_correlation["campaign_confidence"][campaign_name]
                    campaign_data["indicators"].append({
                        "indicator": indicator,
                        "type": indicator_type,
                        "confidence": campaign_match["confidence"]
                    })
                    
                    # Update confidence score
                    current_score = campaign_data["confidence_score"]
                    new_score = max(current_score, campaign_match["confidence"])
                    campaign_data["confidence_score"] = new_score
        
        # Identify active campaigns
        for campaign_name, campaign_data in campaign_correlation["campaign_confidence"].items():
            if campaign_data["confidence_score"] > 60:
                campaign_correlation["active_campaigns"].append({
                    "campaign": campaign_name,
                    "confidence": campaign_data["confidence_score"],
                    "indicator_count": len(campaign_data["indicators"])
                })
        
        return campaign_correlation
    
    async def _correlate_threat_actors(self, network_indicators: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate indicators with threat actors"""
        actor_attribution = {
            "suspected_actors": [],
            "actor_confidence": {},
            "motivation_analysis": {},
            "capability_assessment": {},
            "geographic_attribution": {},
            "targeting_patterns": {}
        }
        
        # Check indicators against threat actor databases
        for indicator_type, indicators in network_indicators.items():
            for indicator in indicators:
                actor_matches = await self._match_threat_actors(indicator, indicator_type)
                
                for actor_match in actor_matches:
                    actor_name = actor_match["actor"]
                    
                    if actor_name not in actor_attribution["actor_confidence"]:
                        actor_attribution["actor_confidence"][actor_name] = {
                            "indicators": [],
                            "confidence_score": 0,
                            "motivation": [],
                            "capabilities": [],
                            "geography": []
                        }
                    
                    actor_data = actor_attribution["actor_confidence"][actor_name]
                    actor_data["indicators"].append({
                        "indicator": indicator,
                        "type": indicator_type,
                        "confidence": actor_match["confidence"]
                    })
                    
                    # Update confidence score
                    current_score = actor_data["confidence_score"]
                    new_score = max(current_score, actor_match["confidence"])
                    actor_data["confidence_score"] = new_score
        
        # Identify suspected actors
        for actor_name, actor_data in actor_attribution["actor_confidence"].items():
            if actor_data["confidence_score"] > 50:
                actor_attribution["suspected_actors"].append({
                    "actor": actor_name,
                    "confidence": actor_data["confidence_score"],
                    "indicator_count": len(actor_data["indicators"])
                })
        
        return actor_attribution
    
    async def _perform_contextual_analysis(self, network_indicators: Dict[str, Any]) -> Dict[str, Any]:
        """Perform contextual analysis of threat intelligence"""
        contextual_analysis = {
            "temporal_correlation": {},
            "geographic_correlation": {},
            "infrastructure_correlation": {},
            "technique_correlation": {},
            "victim_correlation": {},
            "industry_targeting": {}
        }
        
        # Temporal correlation
        contextual_analysis["temporal_correlation"] = await self._analyze_temporal_context(network_indicators)
        
        # Geographic correlation
        contextual_analysis["geographic_correlation"] = await self._analyze_geographic_context(network_indicators)
        
        # Infrastructure correlation
        contextual_analysis["infrastructure_correlation"] = await self._analyze_infrastructure_context(network_indicators)
        
        # Technique correlation
        contextual_analysis["technique_correlation"] = await self._analyze_technique_context(network_indicators)
        
        # Victim correlation
        contextual_analysis["victim_correlation"] = await self._analyze_victim_context(network_indicators)
        
        # Industry targeting analysis
        contextual_analysis["industry_targeting"] = await self._analyze_industry_targeting(network_indicators)
        
        return contextual_analysis
    
    async def _calculate_risk_scores(self, correlation_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate risk scores based on threat intelligence correlation"""
        risk_scoring = {
            "overall_risk_score": 0,
            "risk_factors": [],
            "severity_assessment": "low",
            "confidence_level": "low",
            "recommended_actions": [],
            "priority_score": 0
        }
        
        total_score = 0
        confidence_factors = []
        
        # IP intelligence scoring
        ip_intel = correlation_results.get("ip_intelligence", {})
        malicious_ips = len(ip_intel.get("malicious_ips", []))
        if malicious_ips > 0:
            ip_score = min(malicious_ips * 20, 100)
            total_score += ip_score
            risk_scoring["risk_factors"].append(f"Malicious IPs detected: {malicious_ips}")
            confidence_factors.append(0.8)
        
        # Domain intelligence scoring
        domain_intel = correlation_results.get("domain_intelligence", {})
        malicious_domains = len(domain_intel.get("malicious_domains", []))
        if malicious_domains > 0:
            domain_score = min(malicious_domains * 25, 100)
            total_score += domain_score
            risk_scoring["risk_factors"].append(f"Malicious domains detected: {malicious_domains}")
            confidence_factors.append(0.9)
        
        # Malware attribution scoring
        malware_attr = correlation_results.get("malware_attribution", {})
        identified_families = len(malware_attr.get("identified_families", []))
        if identified_families > 0:
            malware_score = min(identified_families * 30, 100)
            total_score += malware_score
            risk_scoring["risk_factors"].append(f"Malware families identified: {identified_families}")
            confidence_factors.append(0.95)
        
        # Campaign correlation scoring
        campaign_corr = correlation_results.get("campaign_correlation", {})
        active_campaigns = len(campaign_corr.get("active_campaigns", []))
        if active_campaigns > 0:
            campaign_score = min(active_campaigns * 40, 100)
            total_score += campaign_score
            risk_scoring["risk_factors"].append(f"Active campaigns detected: {active_campaigns}")
            confidence_factors.append(0.85)
        
        # Actor attribution scoring
        actor_attr = correlation_results.get("actor_attribution", {})
        suspected_actors = len(actor_attr.get("suspected_actors", []))
        if suspected_actors > 0:
            actor_score = min(suspected_actors * 35, 100)
            total_score += actor_score
            risk_scoring["risk_factors"].append(f"Threat actors suspected: {suspected_actors}")
            confidence_factors.append(0.75)
        
        # Calculate overall risk score (max 100)
        risk_scoring["overall_risk_score"] = min(total_score, 100)
        
        # Determine severity
        if risk_scoring["overall_risk_score"] >= 80:
            risk_scoring["severity_assessment"] = "critical"
        elif risk_scoring["overall_risk_score"] >= 60:
            risk_scoring["severity_assessment"] = "high"
        elif risk_scoring["overall_risk_score"] >= 40:
            risk_scoring["severity_assessment"] = "medium"
        else:
            risk_scoring["severity_assessment"] = "low"
        
        # Calculate confidence level
        if confidence_factors:
            avg_confidence = sum(confidence_factors) / len(confidence_factors)
            if avg_confidence >= 0.8:
                risk_scoring["confidence_level"] = "high"
            elif avg_confidence >= 0.6:
                risk_scoring["confidence_level"] = "medium"
            else:
                risk_scoring["confidence_level"] = "low"
        
        # Generate recommended actions
        risk_scoring["recommended_actions"] = await self._generate_recommended_actions(
            risk_scoring["severity_assessment"], 
            risk_scoring["risk_factors"]
        )
        
        # Priority score (0-10)
        risk_scoring["priority_score"] = min(risk_scoring["overall_risk_score"] / 10, 10)
        
        return risk_scoring
    
    # Helper methods for threat intelligence lookups
    async def _check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation in threat feeds"""
        reputation = {
            "score": 0,
            "sources": [],
            "categories": [],
            "first_seen": None,
            "last_seen": None
        }
        
        # Simulate reputation check (in production, use actual TI APIs)
        if ip in self.ioc_cache:
            return self.ioc_cache[ip]
        
        # Mock reputation data
        reputation["score"] = 25  # Default low score
        reputation["sources"] = ["mock_feed"]
        reputation["categories"] = ["unknown"]
        
        self.ioc_cache[ip] = reputation
        return reputation
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain format"""
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        return bool(re.match(domain_pattern, domain))
    
    def _is_valid_url(self, url: str) -> bool:
        """Validate URL format"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def _is_valid_hash(self, hash_value: str) -> bool:
        """Validate hash format"""
        if len(hash_value) == 32:  # MD5
            return bool(re.match(r'^[a-fA-F0-9]{32}$', hash_value))
        elif len(hash_value) == 40:  # SHA1
            return bool(re.match(r'^[a-fA-F0-9]{40}$', hash_value))
        elif len(hash_value) == 64:  # SHA256
            return bool(re.match(r'^[a-fA-F0-9]{64}$', hash_value))
        return False
    
    def _load_ti_sources(self) -> Dict[str, Any]:
        """Load threat intelligence source configurations"""
        return {
            "commercial_feeds": {
                "virustotal": {"api_key": "mock_key", "rate_limit": 4},
                "threatcrowd": {"base_url": "https://www.threatcrowd.org/searchApi/v2/"},
                "alienvault": {"api_key": "mock_key", "base_url": "https://otx.alienvault.com/api/v1/"}
            },
            "open_source_feeds": {
                "abuse_ch": {"base_url": "https://feodotracker.abuse.ch/"},
                "malware_domains": {"base_url": "http://www.malwaredomains.com/"},
                "emerging_threats": {"base_url": "https://rules.emergingthreats.net/"}
            },
            "government_feeds": {
                "us_cert": {"base_url": "https://www.us-cert.gov/"},
                "cisa": {"base_url": "https://www.cisa.gov/"}
            }
        }
    
    def _load_reputation_thresholds(self) -> Dict[str, Any]:
        """Load reputation scoring thresholds"""
        return {
            "ip": {"clean": 20, "suspicious": 50, "malicious": 70},
            "domain": {"clean": 25, "suspicious": 55, "malicious": 75},
            "url": {"clean": 30, "suspicious": 60, "malicious": 80},
            "file": {"clean": 15, "suspicious": 45, "malicious": 65}
        }
    
    def _load_feed_priorities(self) -> Dict[str, int]:
        """Load feed priority weights"""
        return {
            "virustotal": 10,
            "threatcrowd": 8,
            "alienvault": 9,
            "abuse_ch": 7,
            "emerging_threats": 6,
            "us_cert": 9,
            "cisa": 8
        }

# Factory function
def create_threat_intelligence_correlator() -> ThreatIntelligenceCorrelator:
    """Create and return ThreatIntelligenceCorrelator instance"""
    return ThreatIntelligenceCorrelator()
