"""
Data Exfiltration Detector Module
State 2: Data Exfiltration Detection for Network & Exfiltration Agent
Detects various data exfiltration methods and patterns
"""

import logging
import asyncio
import re
from typing import Dict, Any, List, Optional, Set, Tuple
from datetime import datetime, timedelta
import json
import base64
import hashlib
from collections import defaultdict, Counter
import statistics

logger = logging.getLogger(__name__)

class DataExfiltrationDetector:
    """
    Data Exfiltration Detection System
    Detects various methods of data exfiltration including DNS tunneling,
    HTTP POST exfiltration, email-based exfiltration, and covert channels
    """
    
    def __init__(self):
        self.exfiltration_patterns = self._load_exfiltration_patterns()
        self.covert_channels = self._load_covert_channel_signatures()
        self.data_classifiers = self._load_data_classifiers()
        
    async def detect_data_exfiltration(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect data exfiltration activities
        
        Args:
            network_data: Network traffic and communication data
            
        Returns:
            Data exfiltration detection results
        """
        logger.info("Starting data exfiltration detection")
        
        detection_results = {
            "dns_tunneling": {},
            "http_exfiltration": {},
            "email_exfiltration": {},
            "ftp_exfiltration": {},
            "covert_channels": {},
            "steganography": {},
            "cloud_exfiltration": {},
            "social_media_exfiltration": {},
            "statistical_analysis": {},
            "detection_timestamp": datetime.now()
        }
        
        try:
            # DNS tunneling detection
            detection_results["dns_tunneling"] = await self._detect_dns_tunneling(network_data)
            
            # HTTP-based exfiltration
            detection_results["http_exfiltration"] = await self._detect_http_exfiltration(network_data)
            
            # Email-based exfiltration
            detection_results["email_exfiltration"] = await self._detect_email_exfiltration(network_data)
            
            # FTP exfiltration
            detection_results["ftp_exfiltration"] = await self._detect_ftp_exfiltration(network_data)
            
            # Covert channel detection
            detection_results["covert_channels"] = await self._detect_covert_channels(network_data)
            
            # Steganography detection
            detection_results["steganography"] = await self._detect_steganography(network_data)
            
            # Cloud service exfiltration
            detection_results["cloud_exfiltration"] = await self._detect_cloud_exfiltration(network_data)
            
            # Social media exfiltration
            detection_results["social_media_exfiltration"] = await self._detect_social_media_exfiltration(network_data)
            
            # Statistical analysis
            detection_results["statistical_analysis"] = await self._perform_statistical_analysis(network_data)
            
            logger.info("Data exfiltration detection completed")
            
        except Exception as e:
            logger.error(f"Error in data exfiltration detection: {str(e)}")
            detection_results["error"] = str(e)
            
        return detection_results
    
    async def _detect_dns_tunneling(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect DNS tunneling activities"""
        dns_tunneling = {
            "suspicious_queries": [],
            "tunnel_indicators": [],
            "entropy_analysis": {},
            "subdomain_analysis": {},
            "query_patterns": {},
            "volume_analysis": {}
        }
        
        dns_queries = network_data.get("dns_queries", [])
        
        # Analyze query patterns
        dns_tunneling["suspicious_queries"] = await self._analyze_suspicious_dns_queries(dns_queries)
        
        # Detect tunnel indicators
        dns_tunneling["tunnel_indicators"] = await self._detect_dns_tunnel_indicators(dns_queries)
        
        # Entropy analysis
        dns_tunneling["entropy_analysis"] = await self._analyze_dns_entropy(dns_queries)
        
        # Subdomain analysis
        dns_tunneling["subdomain_analysis"] = await self._analyze_dns_subdomains(dns_queries)
        
        # Query pattern analysis
        dns_tunneling["query_patterns"] = await self._analyze_dns_query_patterns(dns_queries)
        
        # Volume analysis
        dns_tunneling["volume_analysis"] = await self._analyze_dns_volume(dns_queries)
        
        return dns_tunneling
    
    async def _detect_http_exfiltration(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect HTTP-based data exfiltration"""
        http_exfiltration = {
            "post_analysis": {},
            "upload_detection": {},
            "base64_transfers": [],
            "large_responses": [],
            "suspicious_user_agents": [],
            "file_uploads": [],
            "compression_analysis": {}
        }
        
        http_requests = network_data.get("http_requests", [])
        flows = network_data.get("flows", [])
        
        # POST request analysis
        http_exfiltration["post_analysis"] = await self._analyze_http_posts(http_requests)
        
        # Upload detection
        http_exfiltration["upload_detection"] = await self._detect_http_uploads(http_requests, flows)
        
        # Base64 encoded transfers
        http_exfiltration["base64_transfers"] = await self._detect_base64_transfers(http_requests)
        
        # Large HTTP responses
        http_exfiltration["large_responses"] = await self._detect_large_http_responses(http_requests)
        
        # Suspicious user agents
        http_exfiltration["suspicious_user_agents"] = await self._analyze_user_agents(http_requests)
        
        # File upload detection
        http_exfiltration["file_uploads"] = await self._detect_file_uploads(http_requests)
        
        # Compression analysis
        http_exfiltration["compression_analysis"] = await self._analyze_compression_patterns(http_requests)
        
        return http_exfiltration
    
    async def _detect_email_exfiltration(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect email-based data exfiltration"""
        email_exfiltration = {
            "large_attachments": [],
            "frequent_emails": [],
            "external_recipients": [],
            "suspicious_subjects": [],
            "attachment_analysis": {},
            "volume_anomalies": [],
            "timing_patterns": {}
        }
        
        email_logs = network_data.get("email_logs", [])
        smtp_flows = network_data.get("smtp_flows", [])
        
        # Large attachment detection
        email_exfiltration["large_attachments"] = await self._detect_large_email_attachments(email_logs)
        
        # Frequent email analysis
        email_exfiltration["frequent_emails"] = await self._analyze_frequent_emails(email_logs)
        
        # External recipient analysis
        email_exfiltration["external_recipients"] = await self._analyze_external_recipients(email_logs)
        
        # Suspicious subject lines
        email_exfiltration["suspicious_subjects"] = await self._analyze_email_subjects(email_logs)
        
        # Attachment analysis
        email_exfiltration["attachment_analysis"] = await self._analyze_email_attachments(email_logs)
        
        # Volume anomalies
        email_exfiltration["volume_anomalies"] = await self._detect_email_volume_anomalies(email_logs)
        
        # Timing pattern analysis
        email_exfiltration["timing_patterns"] = await self._analyze_email_timing(email_logs)
        
        return email_exfiltration
    
    async def _detect_ftp_exfiltration(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect FTP-based data exfiltration"""
        ftp_exfiltration = {
            "large_transfers": [],
            "external_servers": [],
            "anonymous_ftp": [],
            "upload_patterns": {},
            "compressed_transfers": [],
            "timing_analysis": {}
        }
        
        ftp_logs = network_data.get("ftp_logs", [])
        flows = [f for f in network_data.get("flows", []) if f.get("destination_port") in [21, 20]]
        
        # Large transfer detection
        ftp_exfiltration["large_transfers"] = await self._detect_large_ftp_transfers(ftp_logs, flows)
        
        # External server analysis
        ftp_exfiltration["external_servers"] = await self._analyze_external_ftp_servers(ftp_logs)
        
        # Anonymous FTP usage
        ftp_exfiltration["anonymous_ftp"] = await self._detect_anonymous_ftp(ftp_logs)
        
        # Upload pattern analysis
        ftp_exfiltration["upload_patterns"] = await self._analyze_ftp_upload_patterns(ftp_logs)
        
        # Compressed transfer detection
        ftp_exfiltration["compressed_transfers"] = await self._detect_compressed_ftp_transfers(ftp_logs)
        
        # Timing analysis
        ftp_exfiltration["timing_analysis"] = await self._analyze_ftp_timing(ftp_logs)
        
        return ftp_exfiltration
    
    async def _detect_covert_channels(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect covert communication channels"""
        covert_channels = {
            "icmp_tunneling": [],
            "tcp_timing": [],
            "packet_size_modulation": [],
            "protocol_field_manipulation": [],
            "steganographic_protocols": [],
            "timing_channels": []
        }
        
        flows = network_data.get("flows", [])
        packets = network_data.get("packet_data", [])
        
        # ICMP tunneling
        covert_channels["icmp_tunneling"] = await self._detect_icmp_tunneling(packets)
        
        # TCP timing channels
        covert_channels["tcp_timing"] = await self._detect_tcp_timing_channels(flows)
        
        # Packet size modulation
        covert_channels["packet_size_modulation"] = await self._detect_packet_size_modulation(packets)
        
        # Protocol field manipulation
        covert_channels["protocol_field_manipulation"] = await self._detect_protocol_field_manipulation(packets)
        
        # Steganographic protocols
        covert_channels["steganographic_protocols"] = await self._detect_steganographic_protocols(flows)
        
        # Timing channels
        covert_channels["timing_channels"] = await self._detect_timing_channels(flows)
        
        return covert_channels
    
    async def _detect_steganography(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect steganographic data hiding"""
        steganography = {
            "image_steganography": [],
            "audio_steganography": [],
            "document_steganography": [],
            "network_steganography": [],
            "frequency_analysis": {},
            "statistical_tests": {}
        }
        
        file_transfers = network_data.get("file_transfers", [])
        http_requests = network_data.get("http_requests", [])
        
        # Image steganography
        steganography["image_steganography"] = await self._detect_image_steganography(file_transfers)
        
        # Audio steganography
        steganography["audio_steganography"] = await self._detect_audio_steganography(file_transfers)
        
        # Document steganography
        steganography["document_steganography"] = await self._detect_document_steganography(file_transfers)
        
        # Network steganography
        steganography["network_steganography"] = await self._detect_network_steganography(http_requests)
        
        # Frequency analysis
        steganography["frequency_analysis"] = await self._perform_frequency_analysis(file_transfers)
        
        # Statistical tests
        steganography["statistical_tests"] = await self._perform_steganography_tests(file_transfers)
        
        return steganography
    
    async def _detect_cloud_exfiltration(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect cloud service-based exfiltration"""
        cloud_exfiltration = {
            "cloud_uploads": [],
            "api_abuse": [],
            "personal_accounts": [],
            "bulk_downloads": [],
            "sync_abuse": [],
            "shadow_it": []
        }
        
        http_requests = network_data.get("http_requests", [])
        dns_queries = network_data.get("dns_queries", [])
        
        # Cloud upload detection
        cloud_exfiltration["cloud_uploads"] = await self._detect_cloud_uploads(http_requests)
        
        # API abuse detection
        cloud_exfiltration["api_abuse"] = await self._detect_cloud_api_abuse(http_requests)
        
        # Personal account usage
        cloud_exfiltration["personal_accounts"] = await self._detect_personal_cloud_accounts(http_requests)
        
        # Bulk download detection
        cloud_exfiltration["bulk_downloads"] = await self._detect_bulk_cloud_downloads(http_requests)
        
        # Sync service abuse
        cloud_exfiltration["sync_abuse"] = await self._detect_sync_service_abuse(http_requests)
        
        # Shadow IT detection
        cloud_exfiltration["shadow_it"] = await self._detect_shadow_it_usage(dns_queries, http_requests)
        
        return cloud_exfiltration
    
    async def _detect_social_media_exfiltration(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect social media-based exfiltration"""
        social_media_exfiltration = {
            "file_sharing": [],
            "message_uploads": [],
            "image_uploads": [],
            "video_uploads": [],
            "document_sharing": [],
            "coded_messages": []
        }
        
        http_requests = network_data.get("http_requests", [])
        dns_queries = network_data.get("dns_queries", [])
        
        # Social media file sharing
        social_media_exfiltration["file_sharing"] = await self._detect_social_media_file_sharing(http_requests)
        
        # Message-based uploads
        social_media_exfiltration["message_uploads"] = await self._detect_message_uploads(http_requests)
        
        # Image uploads to social platforms
        social_media_exfiltration["image_uploads"] = await self._detect_social_image_uploads(http_requests)
        
        # Video uploads
        social_media_exfiltration["video_uploads"] = await self._detect_social_video_uploads(http_requests)
        
        # Document sharing
        social_media_exfiltration["document_sharing"] = await self._detect_social_document_sharing(http_requests)
        
        # Coded message detection
        social_media_exfiltration["coded_messages"] = await self._detect_coded_messages(http_requests)
        
        return social_media_exfiltration
    
    async def _perform_statistical_analysis(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform statistical analysis for exfiltration detection"""
        statistical_analysis = {
            "entropy_analysis": {},
            "frequency_analysis": {},
            "compression_ratios": {},
            "timing_statistics": {},
            "volume_statistics": {},
            "pattern_analysis": {}
        }
        
        # Entropy analysis of data transfers
        statistical_analysis["entropy_analysis"] = await self._calculate_transfer_entropy(network_data)
        
        # Frequency analysis
        statistical_analysis["frequency_analysis"] = await self._perform_transfer_frequency_analysis(network_data)
        
        # Compression ratio analysis
        statistical_analysis["compression_ratios"] = await self._analyze_compression_ratios(network_data)
        
        # Timing statistics
        statistical_analysis["timing_statistics"] = await self._calculate_timing_statistics(network_data)
        
        # Volume statistics
        statistical_analysis["volume_statistics"] = await self._calculate_volume_statistics(network_data)
        
        # Pattern analysis
        statistical_analysis["pattern_analysis"] = await self._analyze_transfer_patterns(network_data)
        
        return statistical_analysis
    
    # Helper methods for specific detection techniques
    async def _analyze_suspicious_dns_queries(self, dns_queries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze DNS queries for suspicious patterns"""
        suspicious_queries = []
        
        for query in dns_queries:
            query_name = query.get("query_name", "")
            
            # Check for long subdomain names (potential data encoding)
            if len(query_name) > 63:  # DNS label limit
                suspicious_queries.append({
                    "query": query,
                    "reason": "Unusually long domain name",
                    "suspicion_level": "high"
                })
            
            # Check for base64-like patterns in subdomains
            subdomains = query_name.split('.')
            for subdomain in subdomains:
                if len(subdomain) > 20 and self._looks_like_base64(subdomain):
                    suspicious_queries.append({
                        "query": query,
                        "reason": "Base64-like encoding in subdomain",
                        "suspicion_level": "medium"
                    })
            
            # Check for high entropy in domain names
            entropy = self._calculate_string_entropy(query_name)
            if entropy > 4.5:  # High entropy threshold
                suspicious_queries.append({
                    "query": query,
                    "reason": "High entropy domain name",
                    "entropy": entropy,
                    "suspicion_level": "medium"
                })
        
        return suspicious_queries
    
    async def _analyze_http_posts(self, http_requests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze HTTP POST requests for data exfiltration"""
        post_analysis = {
            "large_posts": [],
            "frequent_posts": [],
            "base64_posts": [],
            "compressed_posts": [],
            "unusual_content_types": []
        }
        
        post_requests = [req for req in http_requests if req.get("method") == "POST"]
        
        # Large POST requests
        for request in post_requests:
            content_length = request.get("content_length", 0)
            if content_length > 1000000:  # 1MB threshold
                post_analysis["large_posts"].append({
                    "request": request,
                    "size": content_length,
                    "suspicion_level": "high"
                })
        
        # Frequent POST patterns
        url_counts = Counter(req.get("url") for req in post_requests)
        for url, count in url_counts.items():
            if count > 100:  # High frequency threshold
                post_analysis["frequent_posts"].append({
                    "url": url,
                    "count": count,
                    "suspicion_level": "medium"
                })
        
        # Base64 encoded content detection
        for request in post_requests:
            content = request.get("content", "")
            if self._looks_like_base64(content):
                post_analysis["base64_posts"].append({
                    "request": request,
                    "reason": "Base64 encoded content",
                    "suspicion_level": "medium"
                })
        
        return post_analysis
    
    def _calculate_string_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not data:
            return 0
        
        # Count character frequencies
        char_counts = Counter(data)
        data_len = len(data)
        
        # Calculate entropy
        entropy = 0
        for count in char_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def _looks_like_base64(self, data: str) -> bool:
        """Check if string looks like base64 encoding"""
        if len(data) < 4 or len(data) % 4 != 0:
            return False
        
        base64_pattern = re.compile(r'^[A-Za-z0-9+/]*={0,2}$')
        return bool(base64_pattern.match(data))
    
    def _load_exfiltration_patterns(self) -> Dict[str, Any]:
        """Load known exfiltration patterns"""
        return {
            "dns_tunnel_domains": [
                "dnscat", "iodine", "dns2tcp", "ozymandns"
            ],
            "file_extensions": [
                ".zip", ".rar", ".7z", ".tar", ".gz", ".doc", ".pdf", ".xls"
            ],
            "suspicious_user_agents": [
                "curl", "wget", "python-requests", "powershell"
            ],
            "cloud_services": [
                "dropbox.com", "googledrive.com", "onedrive.com", "box.com",
                "mega.nz", "mediafire.com", "rapidshare.com"
            ],
            "social_media": [
                "facebook.com", "twitter.com", "instagram.com", "linkedin.com",
                "telegram.org", "discord.com", "slack.com"
            ]
        }
    
    def _load_covert_channel_signatures(self) -> Dict[str, Any]:
        """Load covert channel signatures"""
        return {
            "icmp_patterns": {
                "data_size_variations": [32, 64, 128, 256],
                "timing_intervals": [1000, 2000, 5000]  # milliseconds
            },
            "tcp_patterns": {
                "window_size_modulation": True,
                "sequence_number_encoding": True,
                "ack_timing_channels": True
            },
            "steganographic_ports": [
                8080, 8443, 9000, 9090, 9999
            ]
        }
    
    def _load_data_classifiers(self) -> Dict[str, Any]:
        """Load data classification patterns"""
        return {
            "sensitive_keywords": [
                "confidential", "secret", "password", "credit card",
                "ssn", "social security", "financial", "personal"
            ],
            "file_signatures": {
                "pdf": b"%PDF",
                "doc": b"\xd0\xcf\x11\xe0",
                "zip": b"PK\x03\x04",
                "excel": b"\x50\x4b\x03\x04"
            },
            "data_patterns": {
                "credit_card": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
                "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
                "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
            }
        }

# Factory function
def create_data_exfiltration_detector() -> DataExfiltrationDetector:
    """Create and return DataExfiltrationDetector instance"""
    return DataExfiltrationDetector()
