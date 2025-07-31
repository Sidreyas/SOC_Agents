"""
Command Control Analyzer Module
State 4: Command & Control Analysis for Network & Exfiltration Agent
Analyzes C2 infrastructure, communication patterns, and command execution
"""

import logging
import asyncio
import re
import base64
from typing import Dict, Any, List, Optional, Set, Tuple
from datetime import datetime, timedelta
import json
from collections import defaultdict, Counter
import dns.resolver
import ipaddress
import hashlib

logger = logging.getLogger(__name__)

class CommandControlAnalyzer:
    """
    Command & Control Analysis System
    Analyzes C2 communication patterns, infrastructure, and command execution
    """
    
    def __init__(self):
        self.c2_patterns = self._load_c2_patterns()
        self.communication_patterns = self._load_communication_patterns()
        self.malware_families = self._load_malware_families()
        self.dga_algorithms = self._load_dga_algorithms()
        
    async def analyze_command_control(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze command and control activities
        
        Args:
            network_data: Network traffic and communication data
            
        Returns:
            Command & control analysis results
        """
        logger.info("Starting command & control analysis")
        
        analysis_results = {
            "c2_infrastructure": {},
            "communication_patterns": {},
            "beacon_analysis": {},
            "dga_detection": {},
            "protocol_analysis": {},
            "command_execution": {},
            "data_staging": {},
            "persistence_c2": {},
            "evasion_techniques": {},
            "analysis_timestamp": datetime.now()
        }
        
        try:
            # C2 infrastructure analysis
            analysis_results["c2_infrastructure"] = await self._analyze_c2_infrastructure(network_data)
            
            # Communication pattern analysis
            analysis_results["communication_patterns"] = await self._analyze_communication_patterns(network_data)
            
            # Beacon analysis
            analysis_results["beacon_analysis"] = await self._analyze_beacon_activity(network_data)
            
            # DGA detection
            analysis_results["dga_detection"] = await self._detect_dga_activity(network_data)
            
            # Protocol analysis
            analysis_results["protocol_analysis"] = await self._analyze_c2_protocols(network_data)
            
            # Command execution analysis
            analysis_results["command_execution"] = await self._analyze_command_execution(network_data)
            
            # Data staging analysis
            analysis_results["data_staging"] = await self._analyze_data_staging(network_data)
            
            # Persistence mechanisms
            analysis_results["persistence_c2"] = await self._analyze_c2_persistence(network_data)
            
            # Evasion techniques
            analysis_results["evasion_techniques"] = await self._analyze_evasion_techniques(network_data)
            
            logger.info("Command & control analysis completed")
            
        except Exception as e:
            logger.error(f"Error in command & control analysis: {str(e)}")
            analysis_results["error"] = str(e)
            
        return analysis_results
    
    async def _analyze_c2_infrastructure(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze C2 infrastructure components"""
        c2_infrastructure = {
            "domains": [],
            "ip_addresses": [],
            "certificates": [],
            "redirectors": [],
            "cdn_usage": [],
            "bulletproof_hosting": [],
            "fast_flux": [],
            "domain_fronting": []
        }
        
        dns_queries = network_data.get("dns_queries", [])
        flows = network_data.get("flows", [])
        tls_data = network_data.get("tls_data", [])
        
        # Suspicious domain analysis
        c2_infrastructure["domains"] = await self._analyze_suspicious_domains(dns_queries)
        
        # IP address analysis
        c2_infrastructure["ip_addresses"] = await self._analyze_suspicious_ips(flows)
        
        # Certificate analysis
        c2_infrastructure["certificates"] = await self._analyze_tls_certificates(tls_data)
        
        # Redirector detection
        c2_infrastructure["redirectors"] = await self._detect_redirectors(flows, dns_queries)
        
        # CDN usage analysis
        c2_infrastructure["cdn_usage"] = await self._analyze_cdn_usage(dns_queries, flows)
        
        # Bulletproof hosting detection
        c2_infrastructure["bulletproof_hosting"] = await self._detect_bulletproof_hosting(flows)
        
        # Fast flux detection
        c2_infrastructure["fast_flux"] = await self._detect_fast_flux(dns_queries)
        
        # Domain fronting detection
        c2_infrastructure["domain_fronting"] = await self._detect_domain_fronting(flows, tls_data)
        
        return c2_infrastructure
    
    async def _analyze_communication_patterns(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze C2 communication patterns"""
        communication_patterns = {
            "periodic_beacons": [],
            "jitter_analysis": {},
            "sleep_patterns": {},
            "user_agent_analysis": {},
            "uri_patterns": {},
            "payload_analysis": {},
            "encryption_analysis": {},
            "steganography": []
        }
        
        flows = network_data.get("flows", [])
        http_requests = network_data.get("http_requests", [])
        
        # Periodic beacon detection
        communication_patterns["periodic_beacons"] = await self._detect_periodic_beacons(flows)
        
        # Jitter analysis
        communication_patterns["jitter_analysis"] = await self._analyze_jitter_patterns(flows)
        
        # Sleep pattern analysis
        communication_patterns["sleep_patterns"] = await self._analyze_sleep_patterns(flows)
        
        # User agent analysis
        communication_patterns["user_agent_analysis"] = await self._analyze_user_agents(http_requests)
        
        # URI pattern analysis
        communication_patterns["uri_patterns"] = await self._analyze_uri_patterns(http_requests)
        
        # Payload analysis
        communication_patterns["payload_analysis"] = await self._analyze_c2_payloads(http_requests)
        
        # Encryption analysis
        communication_patterns["encryption_analysis"] = await self._analyze_c2_encryption(flows, http_requests)
        
        # Steganography detection
        communication_patterns["steganography"] = await self._detect_c2_steganography(http_requests)
        
        return communication_patterns
    
    async def _analyze_beacon_activity(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze beacon activity patterns"""
        beacon_analysis = {
            "beacon_sessions": [],
            "timing_analysis": {},
            "frequency_analysis": {},
            "callback_analysis": {},
            "heartbeat_detection": [],
            "irregular_beacons": [],
            "beacon_profiling": {}
        }
        
        flows = network_data.get("flows", [])
        
        # Beacon session identification
        beacon_analysis["beacon_sessions"] = await self._identify_beacon_sessions(flows)
        
        # Timing analysis
        beacon_analysis["timing_analysis"] = await self._analyze_beacon_timing(flows)
        
        # Frequency analysis
        beacon_analysis["frequency_analysis"] = await self._analyze_beacon_frequency(flows)
        
        # Callback analysis
        beacon_analysis["callback_analysis"] = await self._analyze_beacon_callbacks(flows)
        
        # Heartbeat detection
        beacon_analysis["heartbeat_detection"] = await self._detect_heartbeat_beacons(flows)
        
        # Irregular beacon detection
        beacon_analysis["irregular_beacons"] = await self._detect_irregular_beacons(flows)
        
        # Beacon profiling
        beacon_analysis["beacon_profiling"] = await self._profile_beacon_behavior(flows)
        
        return beacon_analysis
    
    async def _detect_dga_activity(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect Domain Generation Algorithm activity"""
        dga_detection = {
            "dga_domains": [],
            "entropy_analysis": {},
            "ngram_analysis": {},
            "dictionary_analysis": {},
            "length_analysis": {},
            "character_analysis": {},
            "family_classification": {},
            "temporal_patterns": {}
        }
        
        dns_queries = network_data.get("dns_queries", [])
        
        # DGA domain identification
        dga_detection["dga_domains"] = await self._identify_dga_domains(dns_queries)
        
        # Entropy analysis
        dga_detection["entropy_analysis"] = await self._analyze_domain_entropy(dns_queries)
        
        # N-gram analysis
        dga_detection["ngram_analysis"] = await self._analyze_domain_ngrams(dns_queries)
        
        # Dictionary word analysis
        dga_detection["dictionary_analysis"] = await self._analyze_dictionary_words(dns_queries)
        
        # Length analysis
        dga_detection["length_analysis"] = await self._analyze_domain_lengths(dns_queries)
        
        # Character analysis
        dga_detection["character_analysis"] = await self._analyze_character_patterns(dns_queries)
        
        # Malware family classification
        dga_detection["family_classification"] = await self._classify_dga_families(dns_queries)
        
        # Temporal pattern analysis
        dga_detection["temporal_patterns"] = await self._analyze_dga_temporal_patterns(dns_queries)
        
        return dga_detection
    
    async def _analyze_c2_protocols(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze C2 protocol usage"""
        protocol_analysis = {
            "http_c2": {},
            "https_c2": {},
            "dns_c2": {},
            "icmp_c2": {},
            "custom_protocols": {},
            "protocol_tunneling": {},
            "port_analysis": {},
            "encrypted_channels": {}
        }
        
        flows = network_data.get("flows", [])
        http_requests = network_data.get("http_requests", [])
        dns_queries = network_data.get("dns_queries", [])
        
        # HTTP C2 analysis
        protocol_analysis["http_c2"] = await self._analyze_http_c2(http_requests, flows)
        
        # HTTPS C2 analysis
        protocol_analysis["https_c2"] = await self._analyze_https_c2(flows)
        
        # DNS C2 analysis
        protocol_analysis["dns_c2"] = await self._analyze_dns_c2(dns_queries)
        
        # ICMP C2 analysis
        protocol_analysis["icmp_c2"] = await self._analyze_icmp_c2(flows)
        
        # Custom protocol analysis
        protocol_analysis["custom_protocols"] = await self._analyze_custom_protocols(flows)
        
        # Protocol tunneling
        protocol_analysis["protocol_tunneling"] = await self._detect_protocol_tunneling(flows)
        
        # Port analysis
        protocol_analysis["port_analysis"] = await self._analyze_c2_ports(flows)
        
        # Encrypted channel analysis
        protocol_analysis["encrypted_channels"] = await self._analyze_encrypted_c2(flows)
        
        return protocol_analysis
    
    async def _analyze_command_execution(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze command execution patterns"""
        command_execution = {
            "remote_commands": [],
            "powershell_activity": [],
            "script_execution": [],
            "file_operations": [],
            "process_creation": [],
            "registry_operations": [],
            "service_operations": [],
            "scheduled_tasks": []
        }
        
        process_logs = network_data.get("process_logs", [])
        powershell_logs = network_data.get("powershell_logs", [])
        
        # Remote command execution
        command_execution["remote_commands"] = await self._detect_remote_commands(process_logs)
        
        # PowerShell activity
        command_execution["powershell_activity"] = await self._analyze_powershell_c2(powershell_logs)
        
        # Script execution
        command_execution["script_execution"] = await self._analyze_script_execution(process_logs)
        
        # File operations
        command_execution["file_operations"] = await self._analyze_c2_file_operations(network_data.get("file_logs", []))
        
        # Process creation
        command_execution["process_creation"] = await self._analyze_c2_process_creation(process_logs)
        
        # Registry operations
        command_execution["registry_operations"] = await self._analyze_c2_registry_ops(network_data.get("registry_logs", []))
        
        # Service operations
        command_execution["service_operations"] = await self._analyze_c2_service_ops(network_data.get("service_logs", []))
        
        # Scheduled task operations
        command_execution["scheduled_tasks"] = await self._analyze_c2_scheduled_tasks(network_data.get("task_logs", []))
        
        return command_execution
    
    async def _analyze_data_staging(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze data staging activities"""
        data_staging = {
            "staging_locations": [],
            "compression_activity": [],
            "encryption_activity": [],
            "file_collection": [],
            "archive_creation": [],
            "temporary_files": [],
            "staging_timing": {},
            "staging_patterns": {}
        }
        
        file_logs = network_data.get("file_logs", [])
        process_logs = network_data.get("process_logs", [])
        
        # Staging location identification
        data_staging["staging_locations"] = await self._identify_staging_locations(file_logs)
        
        # Compression activity
        data_staging["compression_activity"] = await self._detect_compression_activity(process_logs, file_logs)
        
        # Encryption activity
        data_staging["encryption_activity"] = await self._detect_encryption_activity(process_logs, file_logs)
        
        # File collection patterns
        data_staging["file_collection"] = await self._analyze_file_collection(file_logs)
        
        # Archive creation
        data_staging["archive_creation"] = await self._detect_archive_creation(process_logs, file_logs)
        
        # Temporary file usage
        data_staging["temporary_files"] = await self._analyze_temporary_files(file_logs)
        
        # Staging timing analysis
        data_staging["staging_timing"] = await self._analyze_staging_timing(file_logs)
        
        # Staging pattern analysis
        data_staging["staging_patterns"] = await self._analyze_staging_patterns(file_logs)
        
        return data_staging
    
    async def _analyze_c2_persistence(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze C2 persistence mechanisms"""
        persistence_c2 = {
            "scheduled_beacons": [],
            "service_persistence": [],
            "registry_persistence": [],
            "wmi_persistence": [],
            "task_persistence": [],
            "startup_persistence": [],
            "dll_persistence": [],
            "rootkit_persistence": []
        }
        
        task_logs = network_data.get("task_logs", [])
        service_logs = network_data.get("service_logs", [])
        registry_logs = network_data.get("registry_logs", [])
        
        # Scheduled beacon persistence
        persistence_c2["scheduled_beacons"] = await self._detect_scheduled_beacons(task_logs)
        
        # Service-based persistence
        persistence_c2["service_persistence"] = await self._detect_c2_service_persistence(service_logs)
        
        # Registry persistence
        persistence_c2["registry_persistence"] = await self._detect_c2_registry_persistence(registry_logs)
        
        # WMI persistence
        persistence_c2["wmi_persistence"] = await self._detect_c2_wmi_persistence(network_data.get("wmi_logs", []))
        
        # Task persistence
        persistence_c2["task_persistence"] = await self._detect_c2_task_persistence(task_logs)
        
        # Startup persistence
        persistence_c2["startup_persistence"] = await self._detect_c2_startup_persistence(registry_logs)
        
        # DLL persistence
        persistence_c2["dll_persistence"] = await self._detect_c2_dll_persistence(registry_logs)
        
        # Rootkit persistence
        persistence_c2["rootkit_persistence"] = await self._detect_c2_rootkit_persistence(network_data.get("kernel_logs", []))
        
        return persistence_c2
    
    async def _analyze_evasion_techniques(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze C2 evasion techniques"""
        evasion_techniques = {
            "domain_fronting": [],
            "cdn_fronting": [],
            "fast_flux": [],
            "dns_over_https": [],
            "encrypted_dns": [],
            "proxy_chains": [],
            "tor_usage": [],
            "timing_evasion": []
        }
        
        flows = network_data.get("flows", [])
        dns_queries = network_data.get("dns_queries", [])
        tls_data = network_data.get("tls_data", [])
        
        # Domain fronting
        evasion_techniques["domain_fronting"] = await self._detect_domain_fronting(flows, tls_data)
        
        # CDN fronting
        evasion_techniques["cdn_fronting"] = await self._detect_cdn_fronting(flows, dns_queries)
        
        # Fast flux networks
        evasion_techniques["fast_flux"] = await self._detect_fast_flux(dns_queries)
        
        # DNS over HTTPS
        evasion_techniques["dns_over_https"] = await self._detect_dns_over_https(flows)
        
        # Encrypted DNS
        evasion_techniques["encrypted_dns"] = await self._detect_encrypted_dns(flows)
        
        # Proxy chain usage
        evasion_techniques["proxy_chains"] = await self._detect_proxy_chains(flows)
        
        # Tor usage
        evasion_techniques["tor_usage"] = await self._detect_tor_usage(flows, dns_queries)
        
        # Timing-based evasion
        evasion_techniques["timing_evasion"] = await self._detect_timing_evasion(flows)
        
        return evasion_techniques
    
    # Helper methods for specific analysis techniques
    async def _identify_beacon_sessions(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify beacon communication sessions"""
        beacon_sessions = []
        
        # Group flows by source-destination pairs
        connection_pairs = defaultdict(list)
        for flow in flows:
            source_ip = flow.get("source_ip")
            dest_ip = flow.get("destination_ip")
            dest_port = flow.get("destination_port")
            
            if source_ip and dest_ip and dest_port:
                pair_key = f"{source_ip}-{dest_ip}:{dest_port}"
                connection_pairs[pair_key].append(flow)
        
        # Analyze each connection pair for beacon patterns
        for pair_key, pair_flows in connection_pairs.items():
            if len(pair_flows) < 3:  # Need multiple connections for beacon analysis
                continue
            
            # Sort by timestamp
            sorted_flows = sorted(pair_flows, key=lambda x: x.get("timestamp", datetime.min))
            
            # Calculate intervals between connections
            intervals = []
            for i in range(1, len(sorted_flows)):
                prev_time = sorted_flows[i-1].get("timestamp", datetime.min)
                curr_time = sorted_flows[i].get("timestamp", datetime.min)
                if isinstance(prev_time, datetime) and isinstance(curr_time, datetime):
                    interval = (curr_time - prev_time).total_seconds()
                    intervals.append(interval)
            
            if intervals:
                # Check for regular intervals (beacon behavior)
                avg_interval = sum(intervals) / len(intervals)
                
                # Calculate variance
                variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                coefficient_of_variation = (variance ** 0.5) / avg_interval if avg_interval > 0 else float('inf')
                
                # Low coefficient of variation indicates regular beaconing
                if coefficient_of_variation < 0.3 and avg_interval > 30:  # Regular intervals > 30 seconds
                    beacon_sessions.append({
                        "connection_pair": pair_key,
                        "flow_count": len(sorted_flows),
                        "average_interval": avg_interval,
                        "coefficient_of_variation": coefficient_of_variation,
                        "total_duration": (sorted_flows[-1].get("timestamp", datetime.min) - 
                                         sorted_flows[0].get("timestamp", datetime.min)).total_seconds(),
                        "beacon_type": "regular",
                        "confidence": "high" if coefficient_of_variation < 0.1 else "medium"
                    })
        
        return beacon_sessions
    
    async def _identify_dga_domains(self, dns_queries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify potential DGA domains"""
        dga_domains = []
        
        for query in dns_queries:
            domain = query.get("query_name", "")
            if not domain:
                continue
            
            # Extract the domain part (remove subdomains for analysis)
            domain_parts = domain.split('.')
            if len(domain_parts) < 2:
                continue
            
            # Analyze the second-level domain
            sld = domain_parts[-2] if len(domain_parts) >= 2 else ""
            
            # DGA characteristics
            dga_score = 0
            indicators = []
            
            # Length analysis
            if len(sld) > 12:
                dga_score += 2
                indicators.append("long_domain")
            
            # Entropy analysis
            entropy = self._calculate_domain_entropy(sld)
            if entropy > 3.5:
                dga_score += 3
                indicators.append("high_entropy")
            
            # Character pattern analysis
            if self._has_suspicious_char_patterns(sld):
                dga_score += 2
                indicators.append("suspicious_patterns")
            
            # Dictionary word analysis
            if not self._contains_dictionary_words(sld):
                dga_score += 2
                indicators.append("no_dictionary_words")
            
            # Consonant/vowel ratio
            consonant_ratio = self._calculate_consonant_ratio(sld)
            if consonant_ratio > 0.8 or consonant_ratio < 0.2:
                dga_score += 1
                indicators.append("unusual_consonant_ratio")
            
            # Known DGA family patterns
            family = self._classify_dga_family(sld)
            if family:
                dga_score += 3
                indicators.append(f"known_family_{family}")
            
            # If score is high enough, consider it a potential DGA domain
            if dga_score >= 4:
                dga_domains.append({
                    "domain": domain,
                    "sld": sld,
                    "dga_score": dga_score,
                    "entropy": entropy,
                    "indicators": indicators,
                    "family": family,
                    "query": query,
                    "confidence": "high" if dga_score >= 7 else "medium"
                })
        
        return dga_domains
    
    def _calculate_domain_entropy(self, domain: str) -> float:
        """Calculate Shannon entropy of domain name"""
        if not domain:
            return 0
        
        char_counts = Counter(domain.lower())
        domain_len = len(domain)
        
        entropy = 0
        for count in char_counts.values():
            probability = count / domain_len
            if probability > 0:
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def _has_suspicious_char_patterns(self, domain: str) -> bool:
        """Check for suspicious character patterns in domain"""
        # Check for excessive repetition
        for i in range(len(domain) - 2):
            if domain[i] == domain[i+1] == domain[i+2]:
                return True
        
        # Check for alternating patterns
        alternating_count = 0
        for i in range(len(domain) - 1):
            if i > 0 and domain[i-1] != domain[i] != domain[i+1]:
                alternating_count += 1
        
        if alternating_count > len(domain) * 0.7:
            return True
        
        return False
    
    def _contains_dictionary_words(self, domain: str) -> bool:
        """Check if domain contains dictionary words"""
        # Simple check for common English words
        common_words = [
            "the", "and", "for", "are", "but", "not", "you", "all", "can", "had",
            "her", "was", "one", "our", "out", "day", "get", "has", "him", "his",
            "how", "its", "may", "new", "now", "old", "see", "two", "way", "who",
            "boy", "did", "man", "men", "run", "say", "she", "too", "use"
        ]
        
        domain_lower = domain.lower()
        for word in common_words:
            if word in domain_lower:
                return True
        
        return False
    
    def _calculate_consonant_ratio(self, domain: str) -> float:
        """Calculate consonant to total character ratio"""
        vowels = set('aeiou')
        consonants = 0
        vowel_count = 0
        
        for char in domain.lower():
            if char.isalpha():
                if char in vowels:
                    vowel_count += 1
                else:
                    consonants += 1
        
        total_letters = consonants + vowel_count
        if total_letters == 0:
            return 0
        
        return consonants / total_letters
    
    def _classify_dga_family(self, domain: str) -> Optional[str]:
        """Classify DGA family based on domain characteristics"""
        # Simple pattern matching for known DGA families
        if re.match(r'^[a-z]{12,16}$', domain):
            return "conficker"
        elif re.match(r'^[a-z]{6,10}\d{1,3}$', domain):
            return "cryptolocker"
        elif len(domain) == 16 and domain.isalnum():
            return "necurs"
        elif re.match(r'^[a-z]{8}[0-9]{4}$', domain):
            return "locky"
        
        return None
    
    def _load_c2_patterns(self) -> Dict[str, Any]:
        """Load C2 communication patterns"""
        return {
            "beacon_intervals": {
                "short": (30, 300),    # 30 seconds to 5 minutes
                "medium": (300, 3600), # 5 minutes to 1 hour
                "long": (3600, 86400)  # 1 hour to 1 day
            },
            "jitter_patterns": {
                "low": (0, 0.1),      # 0-10% jitter
                "medium": (0.1, 0.3), # 10-30% jitter
                "high": (0.3, 1.0)    # 30-100% jitter
            },
            "user_agents": [
                "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
                "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0)",
                "python-requests", "curl", "wget"
            ],
            "suspicious_uris": [
                "/admin", "/panel", "/gate", "/cmd", "/shell",
                "/bot", "/c2", "/command", "/control"
            ]
        }
    
    def _load_communication_patterns(self) -> Dict[str, Any]:
        """Load communication pattern signatures"""
        return {
            "protocols": {
                "http": {"ports": [80, 8080, 8000], "encrypted": False},
                "https": {"ports": [443, 8443], "encrypted": True},
                "dns": {"ports": [53], "tunneling": True},
                "icmp": {"protocol": "icmp", "covert": True}
            },
            "payload_patterns": {
                "base64": r"^[A-Za-z0-9+/]+=*$",
                "hex": r"^[0-9a-fA-F]+$",
                "encrypted": r"^[A-Za-z0-9+/]{100,}$"
            }
        }
    
    def _load_malware_families(self) -> Dict[str, Any]:
        """Load malware family signatures"""
        return {
            "cobalt_strike": {
                "user_agents": ["Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)"],
                "uris": ["/api/v1/", "/admin/get.php"],
                "sleep_patterns": [60000, 120000, 180000]
            },
            "empire": {
                "user_agents": ["Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0)"],
                "uris": ["/admin/get.php", "/news.php"],
                "encryption": "rc4"
            },
            "meterpreter": {
                "user_agents": ["Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"],
                "uris": ["/", "/admin"],
                "protocols": ["https", "tcp"]
            }
        }
    
    def _load_dga_algorithms(self) -> Dict[str, Any]:
        """Load DGA algorithm signatures"""
        return {
            "conficker": {
                "pattern": r"^[a-z]{5,12}\.(com|net|org|info|biz)$",
                "length_range": (5, 12),
                "entropy_range": (3.0, 4.5)
            },
            "cryptolocker": {
                "pattern": r"^[a-z]{6,10}\d{1,3}\.(com|net|org|ru|co\.uk)$",
                "length_range": (7, 13),
                "entropy_range": (3.5, 4.8)
            },
            "necurs": {
                "pattern": r"^[a-z0-9]{16}\.(com|net|org)$",
                "length_range": (16, 16),
                "entropy_range": (4.0, 5.0)
            }
        }

# Factory function
def create_command_control_analyzer() -> CommandControlAnalyzer:
    """Create and return CommandControlAnalyzer instance"""
    return CommandControlAnalyzer()
