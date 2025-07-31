"""
URL and Attachment Analyzer Module
State 4: URL and Attachment Analysis
Performs comprehensive analysis of URLs and attachments via VirusTotal, PhishTank,
URLhaus, Microsoft Defender, and custom analysis engines
"""

import logging
import re
import hashlib
import aiohttp
import asyncio
import mimetypes
import base64
import zipfile
import tempfile
import os
from typing import Dict, Any, List, Optional, Set, Tuple
from datetime import datetime, timedelta
from enum import Enum
from urllib.parse import urlparse, unquote
import json
import magic
import yara
from pathlib import Path

logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    """Threat level enumeration for URLs and attachments"""
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"

class AnalysisType(Enum):
    """Analysis type enumeration"""
    STATIC = "static"
    DYNAMIC = "dynamic"
    BEHAVIORAL = "behavioral"
    REPUTATION = "reputation"

class URLAndAttachmentAnalyzer:
    """
    URL and Attachment Analysis for phishing investigation
    Provides comprehensive analysis of URLs and file attachments
    """
    
    def __init__(self):
        self.virustotal_api_config = self._init_virustotal_config()
        self.phishtank_api_config = self._init_phishtank_config()
        self.urlhaus_api_config = self._init_urlhaus_config()
        self.analysis_cache = {}
        self.yara_rules = self._load_yara_rules()
        self.suspicious_file_types = self._init_suspicious_file_types()
        
    def analyze_urls_and_attachments(self, email_entities: Dict[str, Any],
                                   security_analysis: Dict[str, Any],
                                   reputation_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive analysis of URLs and attachments in email
        
        Args:
            email_entities: Extracted email entities from State 1
            security_analysis: Security analysis results from State 2
            reputation_assessment: Reputation assessment from State 3
            
        Returns:
            Complete URL and attachment analysis results
        """
        logger.info("Starting comprehensive URL and attachment analysis")
        
        analysis_results = {
            "url_analysis": {},
            "attachment_analysis": {},
            "threat_indicators": [],
            "security_recommendations": [],
            "overall_threat_level": ThreatLevel.UNKNOWN.value,
            "analysis_confidence": 0.0,
            "analysis_metadata": {},
            "analysis_timestamp": datetime.now()
        }
        
        # Extract URLs and attachments from email entities
        extracted_urls = email_entities.get("extracted_urls", [])
        attachments = email_entities.get("attachments", [])
        
        # Analyze URLs
        if extracted_urls:
            analysis_results["url_analysis"] = self._analyze_urls(extracted_urls)
        
        # Analyze attachments
        if attachments:
            analysis_results["attachment_analysis"] = self._analyze_attachments(attachments)
        
        # Identify threat indicators
        analysis_results["threat_indicators"] = self._identify_threat_indicators(
            analysis_results["url_analysis"],
            analysis_results["attachment_analysis"]
        )
        
        # Generate security recommendations
        analysis_results["security_recommendations"] = self._generate_security_recommendations(
            analysis_results["threat_indicators"]
        )
        
        # Determine overall threat level
        analysis_results["overall_threat_level"] = self._determine_overall_threat_level(
            analysis_results["url_analysis"],
            analysis_results["attachment_analysis"]
        )
        
        # Calculate analysis confidence
        analysis_results["analysis_confidence"] = self._calculate_analysis_confidence(
            analysis_results
        )
        
        # Add analysis metadata
        analysis_results["analysis_metadata"] = {
            "urls_analyzed": len(extracted_urls),
            "attachments_analyzed": len(attachments),
            "threat_indicators_found": len(analysis_results["threat_indicators"]),
            "external_apis_used": self._count_external_apis_used(),
            "analysis_duration": 0,  # To be calculated
            "analysis_timestamp": datetime.now()
        }
        
        logger.info("URL and attachment analysis completed")
        return analysis_results
    
    def analyze_url_reputation(self, url: str) -> Dict[str, Any]:
        """
        Analyze URL reputation using multiple threat intelligence sources
        
        Args:
            url: URL to analyze
            
        Returns:
            URL reputation analysis results
        """
        logger.info(f"Analyzing URL reputation: {url}")
        
        reputation_analysis = {
            "url": url,
            "virustotal_results": {},
            "phishtank_results": {},
            "urlhaus_results": {},
            "microsoft_defender_results": {},
            "custom_analysis": {},
            "reputation_score": 0.0,
            "threat_classification": ThreatLevel.UNKNOWN.value,
            "analysis_timestamp": datetime.now()
        }
        
        # Check cache first
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        if url_hash in self.analysis_cache:
            cached_result = self.analysis_cache[url_hash]
            if (datetime.now() - cached_result["timestamp"]).seconds < 3600:  # 1 hour cache
                logger.info("Using cached URL analysis result")
                return cached_result["data"]
        
        # Analyze with VirusTotal
        reputation_analysis["virustotal_results"] = self._analyze_url_virustotal(url)
        
        # Analyze with PhishTank
        reputation_analysis["phishtank_results"] = self._analyze_url_phishtank(url)
        
        # Analyze with URLhaus
        reputation_analysis["urlhaus_results"] = self._analyze_url_urlhaus(url)
        
        # Analyze with Microsoft Defender
        reputation_analysis["microsoft_defender_results"] = self._analyze_url_microsoft_defender(url)
        
        # Perform custom analysis
        reputation_analysis["custom_analysis"] = self._perform_custom_url_analysis(url)
        
        # Calculate reputation score
        reputation_analysis["reputation_score"] = self._calculate_url_reputation_score(
            reputation_analysis
        )
        
        # Classify threat level
        reputation_analysis["threat_classification"] = self._classify_url_threat_level(
            reputation_analysis["reputation_score"]
        )
        
        # Cache results
        self.analysis_cache[url_hash] = {
            "data": reputation_analysis,
            "timestamp": datetime.now()
        }
        
        logger.info(f"URL reputation analysis completed for: {url}")
        return reputation_analysis
    
    def analyze_attachment_security(self, attachment: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze attachment security using multiple analysis methods
        
        Args:
            attachment: Attachment metadata and content
            
        Returns:
            Attachment security analysis results
        """
        logger.info(f"Analyzing attachment security: {attachment.get('filename', 'unknown')}")
        
        security_analysis = {
            "filename": attachment.get("filename", ""),
            "file_size": attachment.get("file_size", 0),
            "mime_type": attachment.get("mime_type", ""),
            "file_hash": "",
            "static_analysis": {},
            "dynamic_analysis": {},
            "virustotal_results": {},
            "yara_scan_results": {},
            "custom_analysis": {},
            "threat_level": ThreatLevel.UNKNOWN.value,
            "security_score": 0.0,
            "analysis_timestamp": datetime.now()
        }
        
        # Calculate file hash
        file_content = attachment.get("content", b"")
        if file_content:
            security_analysis["file_hash"] = hashlib.sha256(file_content).hexdigest()
        
        # Check cache
        if security_analysis["file_hash"] in self.analysis_cache:
            cached_result = self.analysis_cache[security_analysis["file_hash"]]
            if (datetime.now() - cached_result["timestamp"]).seconds < 3600:
                logger.info("Using cached attachment analysis result")
                return cached_result["data"]
        
        # Perform static analysis
        security_analysis["static_analysis"] = self._perform_static_analysis(attachment)
        
        # Perform YARA scanning
        security_analysis["yara_scan_results"] = self._perform_yara_scan(attachment)
        
        # Analyze with VirusTotal
        security_analysis["virustotal_results"] = self._analyze_attachment_virustotal(
            security_analysis["file_hash"], file_content
        )
        
        # Perform dynamic analysis (sandbox simulation)
        security_analysis["dynamic_analysis"] = self._perform_dynamic_analysis(attachment)
        
        # Perform custom security analysis
        security_analysis["custom_analysis"] = self._perform_custom_attachment_analysis(attachment)
        
        # Calculate security score
        security_analysis["security_score"] = self._calculate_attachment_security_score(
            security_analysis
        )
        
        # Determine threat level
        security_analysis["threat_level"] = self._determine_attachment_threat_level(
            security_analysis["security_score"]
        )
        
        # Cache results
        if security_analysis["file_hash"]:
            self.analysis_cache[security_analysis["file_hash"]] = {
                "data": security_analysis,
                "timestamp": datetime.now()
            }
        
        logger.info(f"Attachment security analysis completed: {attachment.get('filename')}")
        return security_analysis
    
    def perform_deep_content_analysis(self, urls: List[str], 
                                    attachments: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Perform deep content analysis of URLs and attachments
        
        Args:
            urls: List of URLs to analyze
            attachments: List of attachments to analyze
            
        Returns:
            Deep content analysis results
        """
        logger.info("Performing deep content analysis")
        
        deep_analysis = {
            "url_content_analysis": {},
            "attachment_content_analysis": {},
            "cross_reference_analysis": {},
            "behavioral_patterns": {},
            "threat_correlation": {},
            "analysis_confidence": 0.0,
            "analysis_timestamp": datetime.now()
        }
        
        # Analyze URL content
        deep_analysis["url_content_analysis"] = self._analyze_url_content(urls)
        
        # Analyze attachment content
        deep_analysis["attachment_content_analysis"] = self._analyze_attachment_content(attachments)
        
        # Cross-reference URLs and attachments
        deep_analysis["cross_reference_analysis"] = self._cross_reference_content(
            deep_analysis["url_content_analysis"],
            deep_analysis["attachment_content_analysis"]
        )
        
        # Identify behavioral patterns
        deep_analysis["behavioral_patterns"] = self._identify_behavioral_patterns(
            deep_analysis["url_content_analysis"],
            deep_analysis["attachment_content_analysis"]
        )
        
        # Correlate threats
        deep_analysis["threat_correlation"] = self._correlate_threats(
            deep_analysis["url_content_analysis"],
            deep_analysis["attachment_content_analysis"]
        )
        
        # Calculate analysis confidence
        deep_analysis["analysis_confidence"] = self._calculate_deep_analysis_confidence(
            deep_analysis
        )
        
        logger.info("Deep content analysis completed")
        return deep_analysis
    
    def validate_url_safety(self, url: str) -> Dict[str, Any]:
        """
        Validate URL safety using comprehensive checks
        
        Args:
            url: URL to validate
            
        Returns:
            URL safety validation results
        """
        logger.info(f"Validating URL safety: {url}")
        
        safety_validation = {
            "url": url,
            "url_structure_analysis": {},
            "domain_analysis": {},
            "ssl_certificate_analysis": {},
            "content_analysis": {},
            "redirect_analysis": {},
            "safety_score": 0.0,
            "safety_verdict": "unknown",
            "validation_timestamp": datetime.now()
        }
        
        # Analyze URL structure
        safety_validation["url_structure_analysis"] = self._analyze_url_structure(url)
        
        # Analyze domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        safety_validation["domain_analysis"] = self._analyze_url_domain(domain)
        
        # Analyze SSL certificate
        if url.startswith("https://"):
            safety_validation["ssl_certificate_analysis"] = self._analyze_ssl_certificate(url)
        
        # Analyze content (if accessible)
        safety_validation["content_analysis"] = self._analyze_url_content_safety(url)
        
        # Analyze redirects
        safety_validation["redirect_analysis"] = self._analyze_url_redirects(url)
        
        # Calculate safety score
        safety_validation["safety_score"] = self._calculate_url_safety_score(safety_validation)
        
        # Determine safety verdict
        safety_validation["safety_verdict"] = self._determine_url_safety_verdict(
            safety_validation["safety_score"]
        )
        
        logger.info(f"URL safety validation completed: {url}")
        return safety_validation
    
    def correlate_analysis_findings(self, url_analysis: Dict[str, Any],
                                  attachment_analysis: Dict[str, Any],
                                  deep_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Correlate findings from all analysis components
        
        Args:
            url_analysis: URL analysis results
            attachment_analysis: Attachment analysis results
            deep_analysis: Deep content analysis results
            
        Returns:
            Correlated analysis findings
        """
        logger.info("Correlating analysis findings")
        
        correlation_results = {
            "threat_consensus": {},
            "conflicting_indicators": [],
            "high_confidence_threats": [],
            "suspicious_patterns": [],
            "final_threat_assessment": {},
            "correlation_confidence": 0.0,
            "correlation_timestamp": datetime.now()
        }
        
        # Build threat consensus
        correlation_results["threat_consensus"] = self._build_threat_consensus(
            url_analysis, attachment_analysis, deep_analysis
        )
        
        # Identify conflicting indicators
        correlation_results["conflicting_indicators"] = self._identify_conflicting_indicators(
            url_analysis, attachment_analysis
        )
        
        # Extract high confidence threats
        correlation_results["high_confidence_threats"] = self._extract_high_confidence_threats(
            url_analysis, attachment_analysis, deep_analysis
        )
        
        # Identify suspicious patterns
        correlation_results["suspicious_patterns"] = self._identify_suspicious_patterns(
            deep_analysis["behavioral_patterns"]
        )
        
        # Generate final threat assessment
        correlation_results["final_threat_assessment"] = self._generate_final_threat_assessment(
            correlation_results["threat_consensus"],
            correlation_results["high_confidence_threats"],
            correlation_results["suspicious_patterns"]
        )
        
        # Calculate correlation confidence
        correlation_results["correlation_confidence"] = self._calculate_correlation_confidence(
            correlation_results
        )
        
        logger.info("Analysis findings correlation completed")
        return correlation_results
    
    def _init_virustotal_config(self) -> Dict[str, Any]:
        """Initialize VirusTotal API configuration"""
        return {
            "api_key": os.getenv("VIRUSTOTAL_API_KEY", ""),
            "base_url": "https://www.virustotal.com/api/v3",
            "timeout": 30,
            "rate_limit": 4  # requests per minute for free tier
        }
    
    def _init_phishtank_config(self) -> Dict[str, Any]:
        """Initialize PhishTank API configuration"""
        return {
            "api_key": os.getenv("PHISHTANK_API_KEY", ""),
            "base_url": "https://phishtank.org/api/v2",
            "timeout": 30
        }
    
    def _init_urlhaus_config(self) -> Dict[str, Any]:
        """Initialize URLhaus API configuration"""
        return {
            "base_url": "https://urlhaus-api.abuse.ch/v1",
            "timeout": 30
        }
    
    def _load_yara_rules(self) -> Optional[Any]:
        """Load YARA rules for malware detection"""
        try:
            # Placeholder for YARA rules loading
            # In production, load actual YARA rules from files
            logger.info("Loading YARA rules for malware detection")
            return None  # Placeholder
        except Exception as e:
            logger.error(f"Error loading YARA rules: {e}")
            return None
    
    def _init_suspicious_file_types(self) -> Set[str]:
        """Initialize set of suspicious file types"""
        return {
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js',
            '.jar', '.app', '.deb', '.pkg', '.dmg', '.zip', '.rar', '.7z',
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf',
            '.rtf', '.hta', '.html', '.htm', '.url', '.lnk'
        }
    
    def _analyze_urls(self, urls: List[str]) -> Dict[str, Any]:
        """Analyze all URLs in the email"""
        url_analysis = {
            "total_urls": len(urls),
            "url_results": [],
            "threat_summary": {},
            "highest_threat_level": ThreatLevel.SAFE.value,
            "analysis_timestamp": datetime.now()
        }
        
        for url in urls:
            # Analyze each URL
            url_result = self.analyze_url_reputation(url)
            url_analysis["url_results"].append(url_result)
            
            # Update highest threat level
            threat_level = url_result.get("threat_classification", ThreatLevel.UNKNOWN.value)
            if self._is_higher_threat(threat_level, url_analysis["highest_threat_level"]):
                url_analysis["highest_threat_level"] = threat_level
        
        # Generate threat summary
        url_analysis["threat_summary"] = self._generate_url_threat_summary(
            url_analysis["url_results"]
        )
        
        return url_analysis
    
    def _analyze_attachments(self, attachments: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze all attachments in the email"""
        attachment_analysis = {
            "total_attachments": len(attachments),
            "attachment_results": [],
            "threat_summary": {},
            "highest_threat_level": ThreatLevel.SAFE.value,
            "analysis_timestamp": datetime.now()
        }
        
        for attachment in attachments:
            # Analyze each attachment
            attachment_result = self.analyze_attachment_security(attachment)
            attachment_analysis["attachment_results"].append(attachment_result)
            
            # Update highest threat level
            threat_level = attachment_result.get("threat_level", ThreatLevel.UNKNOWN.value)
            if self._is_higher_threat(threat_level, attachment_analysis["highest_threat_level"]):
                attachment_analysis["highest_threat_level"] = threat_level
        
        # Generate threat summary
        attachment_analysis["threat_summary"] = self._generate_attachment_threat_summary(
            attachment_analysis["attachment_results"]
        )
        
        return attachment_analysis
    
    def _analyze_url_virustotal(self, url: str) -> Dict[str, Any]:
        """Analyze URL with VirusTotal API"""
        vt_results = {
            "url_scanned": False,
            "detection_ratio": "0/0",
            "positives": 0,
            "total": 0,
            "scan_date": None,
            "report_available": False,
            "malicious_vendors": [],
            "suspicious_vendors": [],
            "clean_vendors": []
        }
        
        # Placeholder for VirusTotal API integration
        logger.info(f"Analyzing URL with VirusTotal: {url}")
        
        try:
            # In production, make actual API call to VirusTotal
            # For now, simulate response
            vt_results["url_scanned"] = True
            vt_results["detection_ratio"] = "2/70"
            vt_results["positives"] = 2
            vt_results["total"] = 70
            vt_results["scan_date"] = datetime.now()
            vt_results["report_available"] = True
            
            if vt_results["positives"] > 0:
                vt_results["malicious_vendors"] = ["Vendor1", "Vendor2"]
            
        except Exception as e:
            logger.error(f"Error analyzing URL with VirusTotal: {e}")
        
        return vt_results
    
    def _analyze_url_phishtank(self, url: str) -> Dict[str, Any]:
        """Analyze URL with PhishTank API"""
        pt_results = {
            "url_checked": False,
            "phish_detected": False,
            "phish_id": None,
            "submission_time": None,
            "verification_status": "unknown",
            "target": "",
            "details_available": False
        }
        
        # Placeholder for PhishTank API integration
        logger.info(f"Analyzing URL with PhishTank: {url}")
        
        try:
            # In production, make actual API call to PhishTank
            pt_results["url_checked"] = True
            pt_results["phish_detected"] = False  # Simulate clean result
            
        except Exception as e:
            logger.error(f"Error analyzing URL with PhishTank: {e}")
        
        return pt_results
    
    def _analyze_url_urlhaus(self, url: str) -> Dict[str, Any]:
        """Analyze URL with URLhaus API"""
        uh_results = {
            "url_found": False,
            "threat_detected": False,
            "malware_families": [],
            "tags": [],
            "first_seen": None,
            "last_online": None,
            "url_status": "unknown"
        }
        
        # Placeholder for URLhaus API integration
        logger.info(f"Analyzing URL with URLhaus: {url}")
        
        try:
            # In production, make actual API call to URLhaus
            uh_results["url_found"] = False  # Simulate not found
            
        except Exception as e:
            logger.error(f"Error analyzing URL with URLhaus: {e}")
        
        return uh_results
    
    def _analyze_url_microsoft_defender(self, url: str) -> Dict[str, Any]:
        """Analyze URL with Microsoft Defender Threat Intelligence"""
        md_results = {
            "analysis_available": False,
            "threat_assessment": "unknown",
            "reputation_score": 0,
            "categories": [],
            "blocked_by_smartscreen": False,
            "threat_types": []
        }
        
        # Placeholder for Microsoft Defender integration
        logger.info(f"Analyzing URL with Microsoft Defender: {url}")
        
        try:
            # In production, integrate with Microsoft Defender APIs
            md_results["analysis_available"] = True
            md_results["threat_assessment"] = "clean"
            md_results["reputation_score"] = 80
            
        except Exception as e:
            logger.error(f"Error analyzing URL with Microsoft Defender: {e}")
        
        return md_results
    
    def _perform_custom_url_analysis(self, url: str) -> Dict[str, Any]:
        """Perform custom URL analysis"""
        custom_analysis = {
            "url_structure_suspicious": False,
            "domain_age_analysis": {},
            "redirect_analysis": {},
            "content_analysis": {},
            "suspicious_patterns": [],
            "risk_indicators": []
        }
        
        # Analyze URL structure
        custom_analysis["url_structure_suspicious"] = self._is_url_structure_suspicious(url)
        
        # Analyze domain age
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        custom_analysis["domain_age_analysis"] = self._analyze_domain_age(domain)
        
        # Check for suspicious patterns
        custom_analysis["suspicious_patterns"] = self._identify_url_suspicious_patterns(url)
        
        # Identify risk indicators
        custom_analysis["risk_indicators"] = self._identify_url_risk_indicators(url)
        
        return custom_analysis
    
    def _calculate_url_reputation_score(self, reputation_analysis: Dict[str, Any]) -> float:
        """Calculate overall URL reputation score"""
        score = 0.5  # Base score
        
        # VirusTotal results
        vt_results = reputation_analysis.get("virustotal_results", {})
        if vt_results.get("url_scanned"):
            positives = vt_results.get("positives", 0)
            total = vt_results.get("total", 1)
            if total > 0:
                detection_rate = positives / total
                score -= detection_rate * 0.5
        
        # PhishTank results
        pt_results = reputation_analysis.get("phishtank_results", {})
        if pt_results.get("phish_detected"):
            score -= 0.4
        
        # URLhaus results
        uh_results = reputation_analysis.get("urlhaus_results", {})
        if uh_results.get("threat_detected"):
            score -= 0.3
        
        # Microsoft Defender results
        md_results = reputation_analysis.get("microsoft_defender_results", {})
        if md_results.get("blocked_by_smartscreen"):
            score -= 0.3
        
        # Custom analysis results
        custom_results = reputation_analysis.get("custom_analysis", {})
        if custom_results.get("url_structure_suspicious"):
            score -= 0.2
        
        risk_indicators = custom_results.get("risk_indicators", [])
        score -= len(risk_indicators) * 0.1
        
        return max(0.0, min(1.0, score))
    
    def _classify_url_threat_level(self, reputation_score: float) -> str:
        """Classify URL threat level based on reputation score"""
        if reputation_score >= 0.8:
            return ThreatLevel.SAFE.value
        elif reputation_score >= 0.5:
            return ThreatLevel.SUSPICIOUS.value
        else:
            return ThreatLevel.MALICIOUS.value
    
    def _perform_static_analysis(self, attachment: Dict[str, Any]) -> Dict[str, Any]:
        """Perform static analysis on attachment"""
        static_analysis = {
            "file_type_analysis": {},
            "header_analysis": {},
            "entropy_analysis": {},
            "string_analysis": {},
            "metadata_analysis": {},
            "suspicious_indicators": []
        }
        
        filename = attachment.get("filename", "")
        file_content = attachment.get("content", b"")
        file_size = attachment.get("file_size", 0)
        
        # File type analysis
        static_analysis["file_type_analysis"] = self._analyze_file_type(filename, file_content)
        
        # Header analysis
        static_analysis["header_analysis"] = self._analyze_file_header(file_content)
        
        # Entropy analysis
        static_analysis["entropy_analysis"] = self._calculate_file_entropy(file_content)
        
        # String analysis
        static_analysis["string_analysis"] = self._analyze_file_strings(file_content)
        
        # Metadata analysis
        static_analysis["metadata_analysis"] = self._analyze_file_metadata(attachment)
        
        # Identify suspicious indicators
        static_analysis["suspicious_indicators"] = self._identify_static_analysis_indicators(
            static_analysis
        )
        
        return static_analysis
    
    def _perform_yara_scan(self, attachment: Dict[str, Any]) -> Dict[str, Any]:
        """Perform YARA rule scanning on attachment"""
        yara_results = {
            "rules_loaded": bool(self.yara_rules),
            "matches": [],
            "threat_families": [],
            "confidence_scores": [],
            "scan_completed": False
        }
        
        if not self.yara_rules:
            logger.warning("YARA rules not loaded, skipping scan")
            return yara_results
        
        try:
            file_content = attachment.get("content", b"")
            if file_content:
                # Placeholder for YARA scanning
                # In production, use actual YARA library
                logger.info(f"Performing YARA scan on: {attachment.get('filename')}")
                yara_results["scan_completed"] = True
                
        except Exception as e:
            logger.error(f"Error performing YARA scan: {e}")
        
        return yara_results
    
    def _analyze_attachment_virustotal(self, file_hash: str, file_content: bytes) -> Dict[str, Any]:
        """Analyze attachment with VirusTotal API"""
        vt_results = {
            "file_scanned": False,
            "scan_id": "",
            "detection_ratio": "0/0",
            "positives": 0,
            "total": 0,
            "scan_date": None,
            "malware_families": [],
            "av_detections": {}
        }
        
        # Placeholder for VirusTotal file analysis
        logger.info(f"Analyzing file with VirusTotal: {file_hash}")
        
        try:
            # In production, upload file to VirusTotal or check by hash
            vt_results["file_scanned"] = True
            vt_results["detection_ratio"] = "0/70"
            vt_results["positives"] = 0
            vt_results["total"] = 70
            vt_results["scan_date"] = datetime.now()
            
        except Exception as e:
            logger.error(f"Error analyzing file with VirusTotal: {e}")
        
        return vt_results
    
    def _perform_dynamic_analysis(self, attachment: Dict[str, Any]) -> Dict[str, Any]:
        """Perform dynamic analysis (sandbox simulation)"""
        dynamic_analysis = {
            "sandbox_available": False,
            "analysis_completed": False,
            "behavioral_analysis": {},
            "network_activity": {},
            "file_activity": {},
            "registry_activity": {},
            "threat_behaviors": []
        }
        
        # Placeholder for sandbox analysis
        logger.info(f"Performing dynamic analysis: {attachment.get('filename')}")
        
        # Simulate sandbox analysis
        dynamic_analysis["sandbox_available"] = True
        dynamic_analysis["analysis_completed"] = True
        
        # Simulate behavioral analysis
        dynamic_analysis["behavioral_analysis"] = {
            "process_creation": False,
            "network_connections": False,
            "file_modifications": False,
            "registry_modifications": False
        }
        
        return dynamic_analysis
    
    def _perform_custom_attachment_analysis(self, attachment: Dict[str, Any]) -> Dict[str, Any]:
        """Perform custom attachment analysis"""
        custom_analysis = {
            "file_extension_analysis": {},
            "size_analysis": {},
            "name_analysis": {},
            "content_analysis": {},
            "risk_assessment": {}
        }
        
        filename = attachment.get("filename", "")
        file_size = attachment.get("file_size", 0)
        
        # Analyze file extension
        custom_analysis["file_extension_analysis"] = self._analyze_file_extension(filename)
        
        # Analyze file size
        custom_analysis["size_analysis"] = self._analyze_file_size(file_size)
        
        # Analyze filename
        custom_analysis["name_analysis"] = self._analyze_filename_patterns(filename)
        
        # Analyze content patterns
        custom_analysis["content_analysis"] = self._analyze_attachment_content_patterns(attachment)
        
        # Assess overall risk
        custom_analysis["risk_assessment"] = self._assess_attachment_risk(custom_analysis)
        
        return custom_analysis
    
    def _calculate_attachment_security_score(self, security_analysis: Dict[str, Any]) -> float:
        """Calculate attachment security score"""
        score = 0.8  # Start with safe assumption
        
        # Static analysis results
        static_results = security_analysis.get("static_analysis", {})
        suspicious_indicators = static_results.get("suspicious_indicators", [])
        score -= len(suspicious_indicators) * 0.1
        
        # YARA scan results
        yara_results = security_analysis.get("yara_scan_results", {})
        if yara_results.get("matches"):
            score -= 0.4
        
        # VirusTotal results
        vt_results = security_analysis.get("virustotal_results", {})
        if vt_results.get("positives", 0) > 0:
            detection_rate = vt_results.get("positives", 0) / max(vt_results.get("total", 1), 1)
            score -= detection_rate * 0.5
        
        # Dynamic analysis results
        dynamic_results = security_analysis.get("dynamic_analysis", {})
        behavioral = dynamic_results.get("behavioral_analysis", {})
        if any(behavioral.values()):
            score -= 0.3
        
        # Custom analysis results
        custom_results = security_analysis.get("custom_analysis", {})
        risk_level = custom_results.get("risk_assessment", {}).get("risk_level", "low")
        if risk_level == "high":
            score -= 0.3
        elif risk_level == "medium":
            score -= 0.2
        
        return max(0.0, min(1.0, score))
    
    def _determine_attachment_threat_level(self, security_score: float) -> str:
        """Determine attachment threat level"""
        if security_score >= 0.7:
            return ThreatLevel.SAFE.value
        elif security_score >= 0.4:
            return ThreatLevel.SUSPICIOUS.value
        else:
            return ThreatLevel.MALICIOUS.value
    
    def _analyze_url_content(self, urls: List[str]) -> Dict[str, Any]:
        """Analyze content of URLs"""
        content_analysis = {
            "urls_analyzed": 0,
            "content_results": [],
            "common_patterns": [],
            "suspicious_content": [],
            "redirect_chains": []
        }
        
        for url in urls:
            try:
                # Placeholder for URL content analysis
                logger.info(f"Analyzing URL content: {url}")
                
                url_content = {
                    "url": url,
                    "content_accessible": False,
                    "content_type": "",
                    "page_title": "",
                    "suspicious_elements": [],
                    "redirect_detected": False
                }
                
                content_analysis["content_results"].append(url_content)
                content_analysis["urls_analyzed"] += 1
                
            except Exception as e:
                logger.error(f"Error analyzing URL content {url}: {e}")
        
        return content_analysis
    
    def _analyze_attachment_content(self, attachments: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze content of attachments"""
        content_analysis = {
            "attachments_analyzed": 0,
            "content_results": [],
            "file_type_distribution": {},
            "embedded_content": [],
            "suspicious_patterns": []
        }
        
        for attachment in attachments:
            try:
                filename = attachment.get("filename", "")
                logger.info(f"Analyzing attachment content: {filename}")
                
                attachment_content = {
                    "filename": filename,
                    "content_extracted": False,
                    "embedded_urls": [],
                    "embedded_files": [],
                    "macros_detected": False,
                    "scripts_detected": False
                }
                
                # Analyze embedded content
                if filename.lower().endswith(('.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx')):
                    attachment_content = self._analyze_office_document(attachment)
                elif filename.lower().endswith('.pdf'):
                    attachment_content = self._analyze_pdf_document(attachment)
                elif filename.lower().endswith(('.zip', '.rar', '.7z')):
                    attachment_content = self._analyze_archive_content(attachment)
                
                content_analysis["content_results"].append(attachment_content)
                content_analysis["attachments_analyzed"] += 1
                
            except Exception as e:
                logger.error(f"Error analyzing attachment content: {e}")
        
        return content_analysis
    
    def _cross_reference_content(self, url_content: Dict[str, Any],
                               attachment_content: Dict[str, Any]) -> Dict[str, Any]:
        """Cross-reference URLs and attachment content"""
        cross_reference = {
            "url_attachment_correlations": [],
            "shared_indicators": [],
            "connected_threats": [],
            "correlation_score": 0.0
        }
        
        # Look for correlations between URLs and attachments
        url_results = url_content.get("content_results", [])
        attachment_results = attachment_content.get("content_results", [])
        
        for url_result in url_results:
            for attachment_result in attachment_results:
                correlation = self._find_url_attachment_correlation(url_result, attachment_result)
                if correlation["correlation_found"]:
                    cross_reference["url_attachment_correlations"].append(correlation)
        
        # Calculate correlation score
        if url_results and attachment_results:
            correlation_count = len(cross_reference["url_attachment_correlations"])
            total_combinations = len(url_results) * len(attachment_results)
            cross_reference["correlation_score"] = correlation_count / total_combinations
        
        return cross_reference
    
    def _identify_behavioral_patterns(self, url_content: Dict[str, Any],
                                    attachment_content: Dict[str, Any]) -> Dict[str, Any]:
        """Identify behavioral patterns in content"""
        patterns = {
            "phishing_patterns": [],
            "malware_patterns": [],
            "social_engineering_patterns": [],
            "evasion_techniques": [],
            "pattern_confidence": 0.0
        }
        
        # Analyze URL patterns
        url_results = url_content.get("content_results", [])
        for url_result in url_results:
            patterns["phishing_patterns"].extend(
                self._identify_phishing_patterns_in_url(url_result)
            )
        
        # Analyze attachment patterns
        attachment_results = attachment_content.get("content_results", [])
        for attachment_result in attachment_results:
            patterns["malware_patterns"].extend(
                self._identify_malware_patterns_in_attachment(attachment_result)
            )
        
        # Calculate pattern confidence
        total_patterns = (len(patterns["phishing_patterns"]) + 
                         len(patterns["malware_patterns"]) +
                         len(patterns["social_engineering_patterns"]))
        patterns["pattern_confidence"] = min(total_patterns * 0.2, 1.0)
        
        return patterns
    
    def _correlate_threats(self, url_content: Dict[str, Any],
                          attachment_content: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate threats across URLs and attachments"""
        threat_correlation = {
            "correlated_threats": [],
            "threat_families": [],
            "attack_chains": [],
            "correlation_confidence": 0.0
        }
        
        # Look for correlated threats
        url_threats = self._extract_url_threats(url_content)
        attachment_threats = self._extract_attachment_threats(attachment_content)
        
        # Find correlations
        for url_threat in url_threats:
            for attachment_threat in attachment_threats:
                if self._are_threats_correlated(url_threat, attachment_threat):
                    threat_correlation["correlated_threats"].append({
                        "url_threat": url_threat,
                        "attachment_threat": attachment_threat,
                        "correlation_type": "family_match"
                    })
        
        return threat_correlation
    
    def _count_external_apis_used(self) -> int:
        """Count number of external APIs configured"""
        apis = 0
        if self.virustotal_api_config.get("api_key"):
            apis += 1
        if self.phishtank_api_config.get("api_key"):
            apis += 1
        # URLhaus doesn't require API key
        apis += 1
        return apis
    
    def _identify_threat_indicators(self, url_analysis: Dict[str, Any],
                                  attachment_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify threat indicators from analysis results"""
        threat_indicators = []
        
        # URL threat indicators
        url_results = url_analysis.get("url_results", [])
        for url_result in url_results:
            threat_level = url_result.get("threat_classification", ThreatLevel.UNKNOWN.value)
            if threat_level in [ThreatLevel.SUSPICIOUS.value, ThreatLevel.MALICIOUS.value]:
                threat_indicators.append({
                    "type": "malicious_url",
                    "severity": "high" if threat_level == ThreatLevel.MALICIOUS.value else "medium",
                    "description": f"Suspicious URL detected: {url_result.get('url')}",
                    "details": url_result
                })
        
        # Attachment threat indicators
        attachment_results = attachment_analysis.get("attachment_results", [])
        for attachment_result in attachment_results:
            threat_level = attachment_result.get("threat_level", ThreatLevel.UNKNOWN.value)
            if threat_level in [ThreatLevel.SUSPICIOUS.value, ThreatLevel.MALICIOUS.value]:
                threat_indicators.append({
                    "type": "malicious_attachment",
                    "severity": "high" if threat_level == ThreatLevel.MALICIOUS.value else "medium",
                    "description": f"Suspicious attachment detected: {attachment_result.get('filename')}",
                    "details": attachment_result
                })
        
        return threat_indicators
    
    def _generate_security_recommendations(self, threat_indicators: List[Dict[str, Any]]) -> List[str]:
        """Generate security recommendations based on threat indicators"""
        recommendations = []
        
        for indicator in threat_indicators:
            if indicator.get("type") == "malicious_url":
                recommendations.append("Block access to identified malicious URLs")
                recommendations.append("Implement URL filtering and web protection")
            elif indicator.get("type") == "malicious_attachment":
                recommendations.append("Quarantine suspicious attachments")
                recommendations.append("Implement advanced attachment scanning")
        
        if not threat_indicators:
            recommendations.append("Continue monitoring - no immediate threats detected")
        
        return list(set(recommendations))  # Remove duplicates
    
    def _determine_overall_threat_level(self, url_analysis: Dict[str, Any],
                                      attachment_analysis: Dict[str, Any]) -> str:
        """Determine overall threat level"""
        url_threat = url_analysis.get("highest_threat_level", ThreatLevel.SAFE.value)
        attachment_threat = attachment_analysis.get("highest_threat_level", ThreatLevel.SAFE.value)
        
        # Return the higher threat level
        if url_threat == ThreatLevel.MALICIOUS.value or attachment_threat == ThreatLevel.MALICIOUS.value:
            return ThreatLevel.MALICIOUS.value
        elif url_threat == ThreatLevel.SUSPICIOUS.value or attachment_threat == ThreatLevel.SUSPICIOUS.value:
            return ThreatLevel.SUSPICIOUS.value
        elif url_threat == ThreatLevel.SAFE.value and attachment_threat == ThreatLevel.SAFE.value:
            return ThreatLevel.SAFE.value
        else:
            return ThreatLevel.UNKNOWN.value
    
    def _calculate_analysis_confidence(self, analysis_results: Dict[str, Any]) -> float:
        """Calculate confidence score for analysis"""
        confidence_factors = []
        
        # URL analysis confidence
        url_analysis = analysis_results.get("url_analysis", {})
        if url_analysis.get("url_results"):
            confidence_factors.append(0.3)
        
        # Attachment analysis confidence
        attachment_analysis = analysis_results.get("attachment_analysis", {})
        if attachment_analysis.get("attachment_results"):
            confidence_factors.append(0.3)
        
        # External API availability
        apis_used = self._count_external_apis_used()
        confidence_factors.append(min(apis_used * 0.1, 0.4))
        
        return min(sum(confidence_factors), 1.0)
    
    def _is_higher_threat(self, threat1: str, threat2: str) -> bool:
        """Compare threat levels and return if threat1 is higher than threat2"""
        threat_hierarchy = {
            ThreatLevel.SAFE.value: 0,
            ThreatLevel.UNKNOWN.value: 1,
            ThreatLevel.SUSPICIOUS.value: 2,
            ThreatLevel.MALICIOUS.value: 3
        }
        
        return threat_hierarchy.get(threat1, 0) > threat_hierarchy.get(threat2, 0)
    
    def _generate_url_threat_summary(self, url_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate threat summary for URLs"""
        summary = {
            "total_urls": len(url_results),
            "safe_urls": 0,
            "suspicious_urls": 0,
            "malicious_urls": 0,
            "unknown_urls": 0,
            "threat_distribution": {}
        }
        
        for result in url_results:
            threat_level = result.get("threat_classification", ThreatLevel.UNKNOWN.value)
            if threat_level == ThreatLevel.SAFE.value:
                summary["safe_urls"] += 1
            elif threat_level == ThreatLevel.SUSPICIOUS.value:
                summary["suspicious_urls"] += 1
            elif threat_level == ThreatLevel.MALICIOUS.value:
                summary["malicious_urls"] += 1
            else:
                summary["unknown_urls"] += 1
        
        if summary["total_urls"] > 0:
            summary["threat_distribution"] = {
                "safe_percentage": (summary["safe_urls"] / summary["total_urls"]) * 100,
                "suspicious_percentage": (summary["suspicious_urls"] / summary["total_urls"]) * 100,
                "malicious_percentage": (summary["malicious_urls"] / summary["total_urls"]) * 100
            }
        
        return summary
    
    def _generate_attachment_threat_summary(self, attachment_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate threat summary for attachments"""
        summary = {
            "total_attachments": len(attachment_results),
            "safe_attachments": 0,
            "suspicious_attachments": 0,
            "malicious_attachments": 0,
            "unknown_attachments": 0,
            "file_type_analysis": {}
        }
        
        file_types = {}
        
        for result in attachment_results:
            threat_level = result.get("threat_level", ThreatLevel.UNKNOWN.value)
            filename = result.get("filename", "")
            
            # Count by threat level
            if threat_level == ThreatLevel.SAFE.value:
                summary["safe_attachments"] += 1
            elif threat_level == ThreatLevel.SUSPICIOUS.value:
                summary["suspicious_attachments"] += 1
            elif threat_level == ThreatLevel.MALICIOUS.value:
                summary["malicious_attachments"] += 1
            else:
                summary["unknown_attachments"] += 1
            
            # Count by file type
            if filename:
                ext = Path(filename).suffix.lower()
                file_types[ext] = file_types.get(ext, 0) + 1
        
        summary["file_type_analysis"] = file_types
        
        return summary
    
    def _is_url_structure_suspicious(self, url: str) -> bool:
        """Check if URL structure is suspicious"""
        suspicious_indicators = [
            # Long URLs
            len(url) > 200,
            # Multiple subdomains
            url.count('.') > 4,
            # IP addresses instead of domains
            re.search(r'https?://\d+\.\d+\.\d+\.\d+', url),
            # URL shorteners
            any(shortener in url for shortener in ['bit.ly', 'tinyurl', 'short.link']),
            # Suspicious patterns
            re.search(r'[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}', url),
            # Homograph attacks
            any(char in url for char in ['а', 'е', 'о', 'р', 'с', 'х']),
        ]
        
        return any(suspicious_indicators)
    
    def _analyze_domain_age(self, domain: str) -> Dict[str, Any]:
        """Analyze domain age"""
        domain_age = {
            "domain": domain,
            "age_days": 0,
            "creation_date": None,
            "is_newly_registered": False,
            "age_risk_level": "unknown"
        }
        
        # Placeholder for domain age analysis
        # In production, use WHOIS data
        logger.info(f"Analyzing domain age: {domain}")
        
        # Simulate domain age
        domain_age["age_days"] = 365  # Placeholder
        domain_age["is_newly_registered"] = domain_age["age_days"] < 30
        
        if domain_age["age_days"] < 30:
            domain_age["age_risk_level"] = "high"
        elif domain_age["age_days"] < 365:
            domain_age["age_risk_level"] = "medium"
        else:
            domain_age["age_risk_level"] = "low"
        
        return domain_age
    
    def _identify_url_suspicious_patterns(self, url: str) -> List[str]:
        """Identify suspicious patterns in URL"""
        patterns = []
        
        # Check for suspicious keywords
        suspicious_keywords = [
            'login', 'account', 'security', 'verify', 'update', 'confirm',
            'bank', 'paypal', 'amazon', 'microsoft', 'google', 'apple'
        ]
        
        url_lower = url.lower()
        for keyword in suspicious_keywords:
            if keyword in url_lower and keyword not in urlparse(url).netloc:
                patterns.append(f"suspicious_keyword_{keyword}")
        
        # Check for URL encoding
        if '%' in url:
            patterns.append("url_encoding_detected")
        
        # Check for multiple redirects
        if url.count('http') > 1:
            patterns.append("multiple_protocols")
        
        return patterns
    
    def _identify_url_risk_indicators(self, url: str) -> List[str]:
        """Identify risk indicators in URL"""
        indicators = []
        
        parsed_url = urlparse(url)
        
        # No HTTPS
        if parsed_url.scheme != 'https':
            indicators.append("no_https")
        
        # Suspicious TLD
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.click']
        if any(parsed_url.netloc.endswith(tld) for tld in suspicious_tlds):
            indicators.append("suspicious_tld")
        
        # Port number in URL
        if ':' in parsed_url.netloc and not parsed_url.netloc.endswith(':443'):
            indicators.append("non_standard_port")
        
        return indicators
    
    def _analyze_file_type(self, filename: str, file_content: bytes) -> Dict[str, Any]:
        """Analyze file type and verify against extension"""
        file_type_analysis = {
            "declared_type": "",
            "actual_type": "",
            "type_mismatch": False,
            "suspicious_extension": False,
            "mime_type": ""
        }
        
        if filename:
            # Get declared type from extension
            file_type_analysis["declared_type"] = Path(filename).suffix.lower()
            file_type_analysis["suspicious_extension"] = (
                file_type_analysis["declared_type"] in self.suspicious_file_types
            )
        
        if file_content:
            # Analyze actual file type
            try:
                file_type_analysis["mime_type"] = magic.from_buffer(file_content, mime=True)
                file_type_analysis["actual_type"] = magic.from_buffer(file_content)
            except Exception as e:
                logger.error(f"Error analyzing file type: {e}")
        
        # Check for type mismatch
        if (file_type_analysis["declared_type"] and 
            file_type_analysis["mime_type"]):
            expected_mime = mimetypes.guess_type(filename)[0]
            if expected_mime and expected_mime != file_type_analysis["mime_type"]:
                file_type_analysis["type_mismatch"] = True
        
        return file_type_analysis
    
    def _analyze_file_header(self, file_content: bytes) -> Dict[str, Any]:
        """Analyze file header for signatures"""
        header_analysis = {
            "header_signature": "",
            "recognized_format": False,
            "header_anomalies": []
        }
        
        if len(file_content) >= 16:
            # Get first 16 bytes as hex
            header_analysis["header_signature"] = file_content[:16].hex()
            
            # Common file signatures
            signatures = {
                "504b0304": "ZIP/Office",
                "25504446": "PDF",
                "d0cf11e0": "MS Office",
                "4d5a9000": "PE Executable",
                "7f454c46": "ELF Executable"
            }
            
            header_hex = header_analysis["header_signature"][:8]
            if header_hex in signatures:
                header_analysis["recognized_format"] = True
            else:
                header_analysis["header_anomalies"].append("unrecognized_signature")
        
        return header_analysis
    
    def _calculate_file_entropy(self, file_content: bytes) -> Dict[str, Any]:
        """Calculate file entropy to detect compression/encryption"""
        entropy_analysis = {
            "entropy_value": 0.0,
            "entropy_assessment": "normal",
            "high_entropy_sections": []
        }
        
        if file_content:
            # Calculate Shannon entropy
            entropy = 0.0
            byte_counts = [0] * 256
            
            for byte in file_content:
                byte_counts[byte] += 1
            
            file_length = len(file_content)
            for count in byte_counts:
                if count > 0:
                    probability = count / file_length
                    entropy -= probability * (probability.bit_length() - 1)
            
            entropy_analysis["entropy_value"] = entropy
            
            # Assess entropy
            if entropy > 7.5:
                entropy_analysis["entropy_assessment"] = "very_high"
            elif entropy > 6.5:
                entropy_analysis["entropy_assessment"] = "high"
            elif entropy > 4.0:
                entropy_analysis["entropy_assessment"] = "normal"
            else:
                entropy_analysis["entropy_assessment"] = "low"
        
        return entropy_analysis
    
    def _analyze_file_strings(self, file_content: bytes) -> Dict[str, Any]:
        """Analyze strings in file content"""
        string_analysis = {
            "suspicious_strings": [],
            "urls_found": [],
            "email_addresses": [],
            "ip_addresses": [],
            "registry_keys": []
        }
        
        try:
            # Extract printable strings
            text_content = file_content.decode('utf-8', errors='ignore')
            
            # Find URLs
            url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|ftp://[^\s<>"\']+'
            string_analysis["urls_found"] = re.findall(url_pattern, text_content, re.IGNORECASE)
            
            # Find email addresses
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            string_analysis["email_addresses"] = re.findall(email_pattern, text_content)
            
            # Find IP addresses
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            string_analysis["ip_addresses"] = re.findall(ip_pattern, text_content)
            
            # Find suspicious strings
            suspicious_patterns = [
                'password', 'credential', 'token', 'api_key', 'secret',
                'cmd.exe', 'powershell', 'eval', 'exec', 'system'
            ]
            
            for pattern in suspicious_patterns:
                if pattern.lower() in text_content.lower():
                    string_analysis["suspicious_strings"].append(pattern)
        
        except Exception as e:
            logger.error(f"Error analyzing file strings: {e}")
        
        return string_analysis
    
    def _analyze_file_metadata(self, attachment: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze file metadata"""
        metadata_analysis = {
            "filename_analysis": {},
            "size_analysis": {},
            "timestamp_analysis": {},
            "metadata_anomalies": []
        }
        
        filename = attachment.get("filename", "")
        file_size = attachment.get("file_size", 0)
        
        # Analyze filename
        if filename:
            metadata_analysis["filename_analysis"] = {
                "length": len(filename),
                "contains_spaces": ' ' in filename,
                "contains_unicode": any(ord(char) > 127 for char in filename),
                "multiple_extensions": filename.count('.') > 1,
                "suspicious_name": any(word in filename.lower() for word in 
                                     ['invoice', 'payment', 'urgent', 'document'])
            }
        
        # Analyze file size
        metadata_analysis["size_analysis"] = {
            "size_bytes": file_size,
            "size_category": self._categorize_file_size(file_size),
            "suspicious_size": file_size == 0 or file_size > 50 * 1024 * 1024  # >50MB
        }
        
        return metadata_analysis
    
    def _categorize_file_size(self, size: int) -> str:
        """Categorize file size"""
        if size == 0:
            return "empty"
        elif size < 1024:
            return "very_small"
        elif size < 1024 * 1024:
            return "small"
        elif size < 10 * 1024 * 1024:
            return "medium"
        elif size < 50 * 1024 * 1024:
            return "large"
        else:
            return "very_large"
    
    def _identify_static_analysis_indicators(self, static_analysis: Dict[str, Any]) -> List[str]:
        """Identify suspicious indicators from static analysis"""
        indicators = []
        
        # File type indicators
        file_type = static_analysis.get("file_type_analysis", {})
        if file_type.get("type_mismatch"):
            indicators.append("file_type_mismatch")
        if file_type.get("suspicious_extension"):
            indicators.append("suspicious_file_extension")
        
        # Header indicators
        header = static_analysis.get("header_analysis", {})
        if header.get("header_anomalies"):
            indicators.extend(header["header_anomalies"])
        
        # Entropy indicators
        entropy = static_analysis.get("entropy_analysis", {})
        if entropy.get("entropy_assessment") in ["very_high", "high"]:
            indicators.append("high_entropy_content")
        
        # String indicators
        strings = static_analysis.get("string_analysis", {})
        if strings.get("suspicious_strings"):
            indicators.append("suspicious_strings_found")
        if strings.get("urls_found"):
            indicators.append("embedded_urls_found")
        
        return indicators
