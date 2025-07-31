"""
Email Entity Extractor Module
State 1: Email Entity Extraction
Parses Sentinel incidents to extract email-specific entities including message IDs, 
sender addresses, recipient lists, subject lines, and attachment hashes
"""

import logging
import re
import hashlib
from typing import Dict, Any, List, Optional, Set
from datetime import datetime
import json
from email.header import decode_header
from email.utils import parseaddr, getaddresses
import base64
import quopri

logger = logging.getLogger(__name__)

class EmailEntityExtractor:
    """
    Email Entity Extraction for phishing analysis
    Extracts and validates email entities from Sentinel incidents
    """
    
    def __init__(self):
        self.entity_patterns = self._load_entity_patterns()
        self.validation_rules = self._load_validation_rules()
        
    def extract_email_entities(self, sentinel_incident: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract email entities from Sentinel incident data
        
        Args:
            sentinel_incident: Sentinel incident containing email alert data
            
        Returns:
            Extracted email entities and metadata
        """
        logger.info("Starting email entity extraction")
        
        extraction_results = {
            "message_identifiers": {},
            "sender_information": {},
            "recipient_information": {},
            "subject_analysis": {},
            "attachment_metadata": {},
            "email_headers": {},
            "content_metadata": {},
            "extraction_quality": {},
            "validation_results": {},
            "extraction_timestamp": datetime.now()
        }
        
        # Extract message identifiers
        extraction_results["message_identifiers"] = self._extract_message_identifiers(sentinel_incident)
        
        # Extract sender information
        extraction_results["sender_information"] = self._extract_sender_information(sentinel_incident)
        
        # Extract recipient information
        extraction_results["recipient_information"] = self._extract_recipient_information(sentinel_incident)
        
        # Analyze subject line
        extraction_results["subject_analysis"] = self._analyze_subject_line(sentinel_incident)
        
        # Extract attachment metadata
        extraction_results["attachment_metadata"] = self._extract_attachment_metadata(sentinel_incident)
        
        # Extract email headers
        extraction_results["email_headers"] = self._extract_email_headers(sentinel_incident)
        
        # Extract content metadata
        extraction_results["content_metadata"] = self._extract_content_metadata(sentinel_incident)
        
        # Assess extraction quality
        extraction_results["extraction_quality"] = self._assess_extraction_quality(extraction_results)
        
        # Validate entity completeness
        extraction_results["validation_results"] = self._validate_entity_completeness(extraction_results)
        
        logger.info("Email entity extraction completed")
        return extraction_results
    
    def determine_investigation_scope(self, extracted_entities: Dict[str, Any]) -> Dict[str, Any]:
        """
        Determine investigation scope based on available indicators
        
        Args:
            extracted_entities: Results from email entity extraction
            
        Returns:
            Investigation scope and priority indicators
        """
        logger.info("Determining investigation scope")
        
        scope_analysis = {
            "scope_indicators": {},
            "priority_factors": {},
            "investigation_complexity": "",
            "required_integrations": [],
            "scope_confidence": 0.0,
            "scope_metadata": {}
        }
        
        # Analyze scope indicators
        scope_analysis["scope_indicators"] = self._analyze_scope_indicators(extracted_entities)
        
        # Identify priority factors
        scope_analysis["priority_factors"] = self._identify_priority_factors(extracted_entities)
        
        # Assess investigation complexity
        scope_analysis["investigation_complexity"] = self._assess_investigation_complexity(
            scope_analysis["scope_indicators"], scope_analysis["priority_factors"]
        )
        
        # Determine required integrations
        scope_analysis["required_integrations"] = self._determine_required_integrations(extracted_entities)
        
        # Calculate scope confidence
        scope_analysis["scope_confidence"] = self._calculate_scope_confidence(scope_analysis)
        
        # Add scope metadata
        scope_analysis["scope_metadata"] = {
            "scope_timestamp": datetime.now(),
            "entities_analyzed": len(extracted_entities),
            "high_priority_indicators": len([
                indicator for indicator in scope_analysis["scope_indicators"].values()
                if isinstance(indicator, dict) and indicator.get("priority") == "high"
            ])
        }
        
        logger.info("Investigation scope determination completed")
        return scope_analysis
    
    def _load_entity_patterns(self) -> Dict[str, Any]:
        """Load patterns for entity extraction"""
        return {
            "email_patterns": {
                "email_address": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                "message_id": r'<[^>]+@[^>]+>',
                "ip_address": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                "domain": r'\b[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                "url": r'https?://[^\s<>"{}|\\^`\[\]]+',
                "attachment_hash": r'\b[a-fA-F0-9]{32,64}\b'
            },
            "header_patterns": {
                "received": r'Received:\s*(.*?)(?=\nReceived:|\n[A-Z][a-z-]*:|\n\s*$)',
                "authentication_results": r'Authentication-Results:\s*(.*?)(?=\n[A-Z][a-z-]*:|\n\s*$)',
                "message_id": r'Message-ID:\s*(<.*?>)',
                "date": r'Date:\s*(.*?)(?=\n[A-Z][a-z-]*:|\n\s*$)'
            },
            "content_patterns": {
                "urgency_keywords": [
                    "urgent", "immediate", "asap", "emergency", "critical",
                    "expires", "deadline", "final notice", "act now", "limited time"
                ],
                "suspicious_keywords": [
                    "verify", "confirm", "update", "suspend", "locked",
                    "click here", "download", "install", "prize", "winner"
                ]
            }
        }
    
    def _load_validation_rules(self) -> Dict[str, Any]:
        """Load validation rules for entity extraction"""
        return {
            "required_entities": [
                "message_id", "sender_email", "recipient_email", "subject"
            ],
            "quality_thresholds": {
                "minimum_headers": 5,
                "minimum_entity_confidence": 0.7,
                "required_metadata_fields": 3
            },
            "validation_checks": {
                "email_format_validation": True,
                "header_completeness_check": True,
                "attachment_hash_validation": True,
                "recipient_validation": True
            }
        }
    
    def _extract_message_identifiers(self, sentinel_incident: Dict[str, Any]) -> Dict[str, Any]:
        """Extract message identifiers from incident data"""
        identifiers = {
            "message_id": "",
            "network_message_id": "",
            "correlation_id": "",
            "tenant_id": "",
            "exchange_message_id": "",
            "defender_message_id": "",
            "identifier_sources": [],
            "identifier_confidence": 0.0
        }
        
        # Extract from incident properties
        incident_properties = sentinel_incident.get("properties", {})
        
        # Look for message ID in various fields
        message_id_sources = [
            incident_properties.get("MessageId"),
            incident_properties.get("message_id"),
            incident_properties.get("MessageID"),
        ]
        
        for source in message_id_sources:
            if source:
                identifiers["message_id"] = str(source)
                identifiers["identifier_sources"].append("incident_properties")
                break
        
        # Extract from entities if available
        entities = incident_properties.get("entities", [])
        for entity in entities:
            if entity.get("kind") == "Email":
                email_data = entity.get("properties", {})
                if email_data.get("messageId"):
                    identifiers["network_message_id"] = email_data["messageId"]
                    identifiers["identifier_sources"].append("entity_email")
        
        # Extract from custom fields
        custom_details = incident_properties.get("customDetails", {})
        for key, value in custom_details.items():
            if "message" in key.lower() and "id" in key.lower():
                if not identifiers["correlation_id"]:
                    identifiers["correlation_id"] = str(value)
                    identifiers["identifier_sources"].append("custom_details")
        
        # Calculate identifier confidence
        identifiers["identifier_confidence"] = self._calculate_identifier_confidence(identifiers)
        
        return identifiers
    
    def _extract_sender_information(self, sentinel_incident: Dict[str, Any]) -> Dict[str, Any]:
        """Extract sender information from incident data"""
        sender_info = {
            "sender_email": "",
            "sender_display_name": "",
            "sender_domain": "",
            "return_path": "",
            "reply_to": "",
            "sender_ip": "",
            "envelope_sender": "",
            "sender_validation": {},
            "sender_confidence": 0.0
        }
        
        incident_properties = sentinel_incident.get("properties", {})
        
        # Extract sender email from various sources
        sender_sources = [
            incident_properties.get("SenderFromAddress"),
            incident_properties.get("sender_email"),
            incident_properties.get("from_address"),
            incident_properties.get("SenderMailFromAddress")
        ]
        
        for source in sender_sources:
            if source and self._validate_email_format(source):
                sender_info["sender_email"] = source
                sender_info["sender_domain"] = source.split("@")[-1] if "@" in source else ""
                break
        
        # Extract sender display name
        display_name_sources = [
            incident_properties.get("SenderDisplayName"),
            incident_properties.get("sender_name"),
            incident_properties.get("from_name")
        ]
        
        for source in display_name_sources:
            if source:
                sender_info["sender_display_name"] = str(source)
                break
        
        # Extract additional sender fields
        sender_info["return_path"] = incident_properties.get("ReturnPath", "")
        sender_info["reply_to"] = incident_properties.get("ReplyTo", "")
        sender_info["sender_ip"] = incident_properties.get("SenderIPv4", "")
        
        # Validate sender information
        sender_info["sender_validation"] = self._validate_sender_information(sender_info)
        
        # Calculate sender confidence
        sender_info["sender_confidence"] = self._calculate_sender_confidence(sender_info)
        
        return sender_info
    
    def _extract_recipient_information(self, sentinel_incident: Dict[str, Any]) -> Dict[str, Any]:
        """Extract recipient information from incident data"""
        recipient_info = {
            "primary_recipients": [],
            "cc_recipients": [],
            "bcc_recipients": [],
            "total_recipient_count": 0,
            "internal_recipients": [],
            "external_recipients": [],
            "recipient_domains": [],
            "recipient_validation": {},
            "recipient_confidence": 0.0
        }
        
        incident_properties = sentinel_incident.get("properties", {})
        
        # Extract primary recipients
        recipient_sources = [
            incident_properties.get("RecipientEmailAddress"),
            incident_properties.get("recipients"),
            incident_properties.get("to_address"),
            incident_properties.get("RecipientDisplayName")
        ]
        
        for source in recipient_sources:
            if source:
                if isinstance(source, str):
                    recipients = self._parse_recipient_string(source)
                    recipient_info["primary_recipients"].extend(recipients)
                elif isinstance(source, list):
                    recipient_info["primary_recipients"].extend(source)
        
        # Remove duplicates and validate
        recipient_info["primary_recipients"] = list(set([
            email for email in recipient_info["primary_recipients"]
            if self._validate_email_format(email)
        ]))
        
        # Extract CC and BCC if available
        cc_recipients = incident_properties.get("CcRecipients", [])
        if isinstance(cc_recipients, str):
            cc_recipients = self._parse_recipient_string(cc_recipients)
        recipient_info["cc_recipients"] = cc_recipients
        
        bcc_recipients = incident_properties.get("BccRecipients", [])
        if isinstance(bcc_recipients, str):
            bcc_recipients = self._parse_recipient_string(bcc_recipients)
        recipient_info["bcc_recipients"] = bcc_recipients
        
        # Calculate total recipient count
        recipient_info["total_recipient_count"] = (
            len(recipient_info["primary_recipients"]) +
            len(recipient_info["cc_recipients"]) +
            len(recipient_info["bcc_recipients"])
        )
        
        # Categorize recipients by domain
        all_recipients = (
            recipient_info["primary_recipients"] +
            recipient_info["cc_recipients"] +
            recipient_info["bcc_recipients"]
        )
        
        for recipient in all_recipients:
            if "@" in recipient:
                domain = recipient.split("@")[-1]
                recipient_info["recipient_domains"].append(domain)
                
                # Categorize as internal/external (basic heuristic)
                if self._is_internal_domain(domain):
                    recipient_info["internal_recipients"].append(recipient)
                else:
                    recipient_info["external_recipients"].append(recipient)
        
        # Remove duplicate domains
        recipient_info["recipient_domains"] = list(set(recipient_info["recipient_domains"]))
        
        # Validate recipient information
        recipient_info["recipient_validation"] = self._validate_recipient_information(recipient_info)
        
        # Calculate recipient confidence
        recipient_info["recipient_confidence"] = self._calculate_recipient_confidence(recipient_info)
        
        return recipient_info
    
    def _analyze_subject_line(self, sentinel_incident: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze email subject line"""
        subject_analysis = {
            "subject_text": "",
            "decoded_subject": "",
            "subject_length": 0,
            "urgency_indicators": [],
            "suspicious_keywords": [],
            "encoding_analysis": {},
            "language_detection": "",
            "subject_confidence": 0.0
        }
        
        incident_properties = sentinel_incident.get("properties", {})
        
        # Extract subject from various sources
        subject_sources = [
            incident_properties.get("EmailSubject"),
            incident_properties.get("subject"),
            incident_properties.get("Subject"),
            incident_properties.get("email_subject")
        ]
        
        for source in subject_sources:
            if source:
                subject_analysis["subject_text"] = str(source)
                break
        
        if subject_analysis["subject_text"]:
            # Decode subject if encoded
            subject_analysis["decoded_subject"] = self._decode_subject_line(
                subject_analysis["subject_text"]
            )
            
            # Calculate subject length
            subject_analysis["subject_length"] = len(subject_analysis["decoded_subject"])
            
            # Detect urgency indicators
            subject_analysis["urgency_indicators"] = self._detect_urgency_indicators(
                subject_analysis["decoded_subject"]
            )
            
            # Detect suspicious keywords
            subject_analysis["suspicious_keywords"] = self._detect_suspicious_keywords(
                subject_analysis["decoded_subject"]
            )
            
            # Analyze encoding
            subject_analysis["encoding_analysis"] = self._analyze_subject_encoding(
                subject_analysis["subject_text"]
            )
            
            # Basic language detection
            subject_analysis["language_detection"] = self._detect_subject_language(
                subject_analysis["decoded_subject"]
            )
        
        # Calculate subject confidence
        subject_analysis["subject_confidence"] = self._calculate_subject_confidence(subject_analysis)
        
        return subject_analysis
    
    def _extract_attachment_metadata(self, sentinel_incident: Dict[str, Any]) -> Dict[str, Any]:
        """Extract attachment metadata from incident data"""
        attachment_metadata = {
            "attachment_count": 0,
            "attachment_list": [],
            "attachment_hashes": [],
            "attachment_names": [],
            "attachment_extensions": [],
            "attachment_sizes": [],
            "suspicious_attachments": [],
            "attachment_confidence": 0.0
        }
        
        incident_properties = sentinel_incident.get("properties", {})
        
        # Extract attachment information from various sources
        attachment_sources = [
            incident_properties.get("AttachmentCount"),
            incident_properties.get("attachments"),
            incident_properties.get("Attachments"),
            incident_properties.get("FileAttachments")
        ]
        
        # Process attachment count
        for source in attachment_sources:
            if isinstance(source, (int, str)) and str(source).isdigit():
                attachment_metadata["attachment_count"] = int(source)
                break
        
        # Extract attachment details
        attachment_details = incident_properties.get("AttachmentDetails", [])
        if isinstance(attachment_details, str):
            try:
                attachment_details = json.loads(attachment_details)
            except json.JSONDecodeError:
                attachment_details = []
        
        for attachment in attachment_details:
            if isinstance(attachment, dict):
                attachment_info = {
                    "name": attachment.get("name", ""),
                    "hash": attachment.get("hash", ""),
                    "size": attachment.get("size", 0),
                    "extension": "",
                    "is_suspicious": False
                }
                
                # Extract file extension
                if attachment_info["name"]:
                    parts = attachment_info["name"].split(".")
                    if len(parts) > 1:
                        attachment_info["extension"] = parts[-1].lower()
                
                # Check for suspicious characteristics
                attachment_info["is_suspicious"] = self._is_suspicious_attachment(attachment_info)
                
                attachment_metadata["attachment_list"].append(attachment_info)
                
                if attachment_info["hash"]:
                    attachment_metadata["attachment_hashes"].append(attachment_info["hash"])
                if attachment_info["name"]:
                    attachment_metadata["attachment_names"].append(attachment_info["name"])
                if attachment_info["extension"]:
                    attachment_metadata["attachment_extensions"].append(attachment_info["extension"])
                if attachment_info["size"]:
                    attachment_metadata["attachment_sizes"].append(attachment_info["size"])
                if attachment_info["is_suspicious"]:
                    attachment_metadata["suspicious_attachments"].append(attachment_info)
        
        # Calculate attachment confidence
        attachment_metadata["attachment_confidence"] = self._calculate_attachment_confidence(
            attachment_metadata
        )
        
        return attachment_metadata
    
    def _extract_email_headers(self, sentinel_incident: Dict[str, Any]) -> Dict[str, Any]:
        """Extract email headers from incident data"""
        header_data = {
            "raw_headers": "",
            "parsed_headers": {},
            "authentication_headers": {},
            "routing_headers": [],
            "timestamp_headers": {},
            "header_completeness": 0.0,
            "header_confidence": 0.0
        }
        
        incident_properties = sentinel_incident.get("properties", {})
        
        # Extract raw headers
        header_sources = [
            incident_properties.get("EmailHeaders"),
            incident_properties.get("headers"),
            incident_properties.get("raw_headers"),
            incident_properties.get("InternetMessageHeaders")
        ]
        
        for source in header_sources:
            if source:
                header_data["raw_headers"] = str(source)
                break
        
        if header_data["raw_headers"]:
            # Parse headers
            header_data["parsed_headers"] = self._parse_email_headers(header_data["raw_headers"])
            
            # Extract authentication headers
            header_data["authentication_headers"] = self._extract_authentication_headers(
                header_data["parsed_headers"]
            )
            
            # Extract routing headers
            header_data["routing_headers"] = self._extract_routing_headers(
                header_data["parsed_headers"]
            )
            
            # Extract timestamp headers
            header_data["timestamp_headers"] = self._extract_timestamp_headers(
                header_data["parsed_headers"]
            )
            
            # Assess header completeness
            header_data["header_completeness"] = self._assess_header_completeness(
                header_data["parsed_headers"]
            )
        
        # Calculate header confidence
        header_data["header_confidence"] = self._calculate_header_confidence(header_data)
        
        return header_data
    
    def _extract_content_metadata(self, sentinel_incident: Dict[str, Any]) -> Dict[str, Any]:
        """Extract content metadata from incident data"""
        content_metadata = {
            "body_text": "",
            "body_html": "",
            "content_length": 0,
            "content_type": "",
            "character_encoding": "",
            "url_count": 0,
            "extracted_urls": [],
            "content_analysis": {},
            "content_confidence": 0.0
        }
        
        incident_properties = sentinel_incident.get("properties", {})
        
        # Extract email body
        body_sources = [
            incident_properties.get("EmailBody"),
            incident_properties.get("body"),
            incident_properties.get("email_content"),
            incident_properties.get("BodyPreview")
        ]
        
        for source in body_sources:
            if source:
                content_metadata["body_text"] = str(source)
                break
        
        # Extract HTML body if available
        html_sources = [
            incident_properties.get("EmailBodyHtml"),
            incident_properties.get("body_html"),
            incident_properties.get("html_content")
        ]
        
        for source in html_sources:
            if source:
                content_metadata["body_html"] = str(source)
                break
        
        # Analyze content
        if content_metadata["body_text"] or content_metadata["body_html"]:
            content_to_analyze = content_metadata["body_text"] or content_metadata["body_html"]
            
            content_metadata["content_length"] = len(content_to_analyze)
            content_metadata["extracted_urls"] = self._extract_urls_from_content(content_to_analyze)
            content_metadata["url_count"] = len(content_metadata["extracted_urls"])
            content_metadata["content_analysis"] = self._analyze_content_characteristics(content_to_analyze)
        
        # Calculate content confidence
        content_metadata["content_confidence"] = self._calculate_content_confidence(content_metadata)
        
        return content_metadata
    
    def _assess_extraction_quality(self, extraction_results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess the quality of entity extraction"""
        quality_assessment = {
            "completeness_score": 0.0,
            "confidence_score": 0.0,
            "data_quality_score": 0.0,
            "missing_entities": [],
            "quality_issues": [],
            "overall_quality": ""
        }
        
        # Check completeness
        required_entities = self.validation_rules["required_entities"]
        missing_entities = []
        
        for entity in required_entities:
            if entity == "message_id" and not extraction_results["message_identifiers"].get("message_id"):
                missing_entities.append("message_id")
            elif entity == "sender_email" and not extraction_results["sender_information"].get("sender_email"):
                missing_entities.append("sender_email")
            elif entity == "recipient_email" and not extraction_results["recipient_information"].get("primary_recipients"):
                missing_entities.append("recipient_email")
            elif entity == "subject" and not extraction_results["subject_analysis"].get("subject_text"):
                missing_entities.append("subject")
        
        quality_assessment["missing_entities"] = missing_entities
        quality_assessment["completeness_score"] = 1.0 - (len(missing_entities) / len(required_entities))
        
        # Calculate average confidence
        confidence_scores = [
            extraction_results["message_identifiers"].get("identifier_confidence", 0),
            extraction_results["sender_information"].get("sender_confidence", 0),
            extraction_results["recipient_information"].get("recipient_confidence", 0),
            extraction_results["subject_analysis"].get("subject_confidence", 0),
            extraction_results["attachment_metadata"].get("attachment_confidence", 0),
            extraction_results["email_headers"].get("header_confidence", 0),
            extraction_results["content_metadata"].get("content_confidence", 0)
        ]
        
        quality_assessment["confidence_score"] = sum(confidence_scores) / len(confidence_scores)
        
        # Assess data quality
        quality_assessment["data_quality_score"] = min(
            quality_assessment["completeness_score"],
            quality_assessment["confidence_score"]
        )
        
        # Determine overall quality
        if quality_assessment["data_quality_score"] >= 0.8:
            quality_assessment["overall_quality"] = "high"
        elif quality_assessment["data_quality_score"] >= 0.6:
            quality_assessment["overall_quality"] = "medium"
        else:
            quality_assessment["overall_quality"] = "low"
        
        return quality_assessment
    
    def _validate_entity_completeness(self, extraction_results: Dict[str, Any]) -> Dict[str, Any]:
        """Validate entity completeness and consistency"""
        validation_results = {
            "validation_passed": False,
            "validation_score": 0.0,
            "validation_errors": [],
            "validation_warnings": [],
            "entity_consistency": {},
            "data_integrity": {}
        }
        
        # Check entity consistency
        validation_results["entity_consistency"] = self._check_entity_consistency(extraction_results)
        
        # Check data integrity
        validation_results["data_integrity"] = self._check_data_integrity(extraction_results)
        
        # Calculate validation score
        consistency_score = validation_results["entity_consistency"].get("consistency_score", 0)
        integrity_score = validation_results["data_integrity"].get("integrity_score", 0)
        validation_results["validation_score"] = (consistency_score + integrity_score) / 2
        
        # Determine if validation passed
        validation_results["validation_passed"] = validation_results["validation_score"] >= 0.7
        
        return validation_results
    
    # Helper methods for various extraction and validation tasks
    def _validate_email_format(self, email: str) -> bool:
        """Validate email address format"""
        pattern = self.entity_patterns["email_patterns"]["email_address"]
        return bool(re.match(pattern, email))
    
    def _parse_recipient_string(self, recipient_str: str) -> List[str]:
        """Parse recipient string into individual email addresses"""
        # Handle comma-separated and semicolon-separated lists
        recipients = re.split(r'[,;]', recipient_str)
        return [email.strip() for email in recipients if self._validate_email_format(email.strip())]
    
    def _is_internal_domain(self, domain: str) -> bool:
        """Basic heuristic to determine if domain is internal"""
        internal_indicators = ['.local', '.internal', '.corp', '.company']
        return any(indicator in domain.lower() for indicator in internal_indicators)
    
    def _decode_subject_line(self, subject: str) -> str:
        """Decode encoded subject line"""
        try:
            decoded_parts = decode_header(subject)
            decoded_subject = ""
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    if encoding:
                        decoded_subject += part.decode(encoding)
                    else:
                        decoded_subject += part.decode('utf-8', errors='ignore')
                else:
                    decoded_subject += part
            return decoded_subject
        except Exception:
            return subject
    
    def _detect_urgency_indicators(self, text: str) -> List[str]:
        """Detect urgency indicators in text"""
        urgency_keywords = self.entity_patterns["content_patterns"]["urgency_keywords"]
        found_indicators = []
        text_lower = text.lower()
        
        for keyword in urgency_keywords:
            if keyword in text_lower:
                found_indicators.append(keyword)
        
        return found_indicators
    
    def _detect_suspicious_keywords(self, text: str) -> List[str]:
        """Detect suspicious keywords in text"""
        suspicious_keywords = self.entity_patterns["content_patterns"]["suspicious_keywords"]
        found_keywords = []
        text_lower = text.lower()
        
        for keyword in suspicious_keywords:
            if keyword in text_lower:
                found_keywords.append(keyword)
        
        return found_keywords
    
    def _analyze_subject_encoding(self, subject: str) -> Dict[str, Any]:
        """Analyze subject line encoding"""
        return {
            "has_encoding": "=?" in subject,
            "encoding_type": "quoted-printable" if "=?" in subject else "none",
            "base64_detected": "B?" in subject,
            "suspicious_encoding": len(subject) > 100 and "=?" in subject
        }
    
    def _detect_subject_language(self, subject: str) -> str:
        """Basic language detection for subject line"""
        # Simple heuristic - in production, use proper language detection library
        if re.search(r'[а-яё]', subject.lower()):
            return "russian"
        elif re.search(r'[一-龯]', subject):
            return "chinese"
        elif re.search(r'[ا-ي]', subject):
            return "arabic"
        else:
            return "latin"
    
    def _is_suspicious_attachment(self, attachment_info: Dict[str, Any]) -> bool:
        """Check if attachment has suspicious characteristics"""
        suspicious_extensions = [
            'exe', 'scr', 'bat', 'cmd', 'com', 'pif', 'vbs', 'js', 'jar',
            'zip', 'rar', '7z', 'docm', 'xlsm', 'pptm', 'dotm'
        ]
        
        extension = attachment_info.get("extension", "").lower()
        name = attachment_info.get("name", "").lower()
        
        # Check suspicious extension
        if extension in suspicious_extensions:
            return True
        
        # Check double extensions
        if name.count('.') > 1:
            return True
        
        # Check for misleading names
        misleading_patterns = ['invoice', 'receipt', 'document', 'photo', 'image']
        if any(pattern in name for pattern in misleading_patterns) and extension in suspicious_extensions:
            return True
        
        return False
    
    def _extract_urls_from_content(self, content: str) -> List[str]:
        """Extract URLs from email content"""
        url_pattern = self.entity_patterns["email_patterns"]["url"]
        return re.findall(url_pattern, content)
    
    def _analyze_content_characteristics(self, content: str) -> Dict[str, Any]:
        """Analyze characteristics of email content"""
        return {
            "character_count": len(content),
            "word_count": len(content.split()),
            "line_count": content.count('\n'),
            "has_html": '<' in content and '>' in content,
            "has_links": 'http' in content.lower(),
            "urgency_score": len(self._detect_urgency_indicators(content)),
            "suspicious_score": len(self._detect_suspicious_keywords(content))
        }
    
    def _parse_email_headers(self, raw_headers: str) -> Dict[str, str]:
        """Parse raw email headers into dictionary"""
        headers = {}
        current_header = ""
        current_value = ""
        
        lines = raw_headers.split('\n')
        for line in lines:
            if line.startswith(' ') or line.startswith('\t'):
                # Continuation of previous header
                current_value += " " + line.strip()
            else:
                # Save previous header
                if current_header:
                    headers[current_header] = current_value
                
                # Start new header
                if ':' in line:
                    parts = line.split(':', 1)
                    current_header = parts[0].strip()
                    current_value = parts[1].strip()
                else:
                    current_header = ""
                    current_value = ""
        
        # Save last header
        if current_header:
            headers[current_header] = current_value
        
        return headers
    
    def _extract_authentication_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Extract authentication-related headers"""
        auth_headers = {}
        
        auth_header_names = [
            'Authentication-Results', 'Received-SPF', 'DKIM-Signature',
            'ARC-Authentication-Results', 'ARC-Message-Signature'
        ]
        
        for header_name in auth_header_names:
            for key, value in headers.items():
                if header_name.lower() in key.lower():
                    auth_headers[header_name] = value
        
        return auth_headers
    
    def _extract_routing_headers(self, headers: Dict[str, str]) -> List[Dict[str, str]]:
        """Extract routing headers (Received headers)"""
        routing_headers = []
        
        for key, value in headers.items():
            if key.lower() == 'received':
                routing_headers.append({
                    "header": key,
                    "value": value,
                    "timestamp": self._extract_timestamp_from_received(value)
                })
        
        return routing_headers
    
    def _extract_timestamp_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Extract timestamp-related headers"""
        timestamp_headers = {}
        
        timestamp_header_names = ['Date', 'Received']
        
        for header_name in timestamp_header_names:
            for key, value in headers.items():
                if header_name.lower() in key.lower():
                    timestamp_headers[key] = value
        
        return timestamp_headers
    
    def _extract_timestamp_from_received(self, received_header: str) -> str:
        """Extract timestamp from Received header"""
        # Simple timestamp extraction - in production, use proper date parsing
        import re
        timestamp_pattern = r'\d{1,2}\s+\w{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}'
        match = re.search(timestamp_pattern, received_header)
        return match.group(0) if match else ""
    
    def _assess_header_completeness(self, headers: Dict[str, str]) -> float:
        """Assess completeness of email headers"""
        required_headers = ['From', 'To', 'Subject', 'Date', 'Message-ID']
        present_headers = sum(1 for header in required_headers if any(header.lower() in key.lower() for key in headers.keys()))
        return present_headers / len(required_headers)
    
    def _check_entity_consistency(self, extraction_results: Dict[str, Any]) -> Dict[str, Any]:
        """Check consistency between extracted entities"""
        consistency_checks = {
            "sender_recipient_consistency": True,
            "message_id_consistency": True,
            "timestamp_consistency": True,
            "consistency_score": 1.0,
            "consistency_issues": []
        }
        
        # Check if sender appears in recipient list (potential spoofing)
        sender_email = extraction_results["sender_information"].get("sender_email", "")
        recipients = extraction_results["recipient_information"].get("primary_recipients", [])
        
        if sender_email in recipients:
            consistency_checks["sender_recipient_consistency"] = False
            consistency_checks["consistency_issues"].append("sender_appears_in_recipients")
        
        # Additional consistency checks can be added here
        
        # Calculate overall consistency score
        failed_checks = len([check for check in [
            consistency_checks["sender_recipient_consistency"],
            consistency_checks["message_id_consistency"],
            consistency_checks["timestamp_consistency"]
        ] if not check])
        
        consistency_checks["consistency_score"] = 1.0 - (failed_checks / 3)
        
        return consistency_checks
    
    def _check_data_integrity(self, extraction_results: Dict[str, Any]) -> Dict[str, Any]:
        """Check data integrity of extracted entities"""
        integrity_checks = {
            "email_format_valid": True,
            "hash_format_valid": True,
            "encoding_valid": True,
            "integrity_score": 1.0,
            "integrity_issues": []
        }
        
        # Check email format validity
        sender_email = extraction_results["sender_information"].get("sender_email", "")
        if sender_email and not self._validate_email_format(sender_email):
            integrity_checks["email_format_valid"] = False
            integrity_checks["integrity_issues"].append("invalid_sender_email_format")
        
        # Check attachment hash formats
        attachment_hashes = extraction_results["attachment_metadata"].get("attachment_hashes", [])
        for hash_value in attachment_hashes:
            if not re.match(r'^[a-fA-F0-9]{32,64}$', hash_value):
                integrity_checks["hash_format_valid"] = False
                integrity_checks["integrity_issues"].append("invalid_hash_format")
                break
        
        # Calculate overall integrity score
        failed_checks = len([check for check in [
            integrity_checks["email_format_valid"],
            integrity_checks["hash_format_valid"],
            integrity_checks["encoding_valid"]
        ] if not check])
        
        integrity_checks["integrity_score"] = 1.0 - (failed_checks / 3)
        
        return integrity_checks
    
    # Confidence calculation methods
    def _calculate_identifier_confidence(self, identifiers: Dict[str, Any]) -> float:
        """Calculate confidence score for message identifiers"""
        score = 0.0
        if identifiers["message_id"]:
            score += 0.4
        if identifiers["network_message_id"]:
            score += 0.3
        if identifiers["correlation_id"]:
            score += 0.2
        if identifiers["identifier_sources"]:
            score += 0.1
        return min(score, 1.0)
    
    def _calculate_sender_confidence(self, sender_info: Dict[str, Any]) -> float:
        """Calculate confidence score for sender information"""
        score = 0.0
        if sender_info["sender_email"] and self._validate_email_format(sender_info["sender_email"]):
            score += 0.4
        if sender_info["sender_display_name"]:
            score += 0.2
        if sender_info["sender_domain"]:
            score += 0.2
        if sender_info["sender_ip"]:
            score += 0.2
        return min(score, 1.0)
    
    def _calculate_recipient_confidence(self, recipient_info: Dict[str, Any]) -> float:
        """Calculate confidence score for recipient information"""
        score = 0.0
        if recipient_info["primary_recipients"]:
            score += 0.5
        if recipient_info["total_recipient_count"] > 0:
            score += 0.2
        if recipient_info["recipient_domains"]:
            score += 0.2
        if recipient_info["internal_recipients"] or recipient_info["external_recipients"]:
            score += 0.1
        return min(score, 1.0)
    
    def _calculate_subject_confidence(self, subject_analysis: Dict[str, Any]) -> float:
        """Calculate confidence score for subject analysis"""
        score = 0.0
        if subject_analysis["subject_text"]:
            score += 0.5
        if subject_analysis["decoded_subject"]:
            score += 0.3
        if subject_analysis["subject_length"] > 0:
            score += 0.2
        return min(score, 1.0)
    
    def _calculate_attachment_confidence(self, attachment_metadata: Dict[str, Any]) -> float:
        """Calculate confidence score for attachment metadata"""
        score = 0.5  # Base score for having attachment data
        if attachment_metadata["attachment_count"] > 0:
            score += 0.2
        if attachment_metadata["attachment_hashes"]:
            score += 0.2
        if attachment_metadata["attachment_names"]:
            score += 0.1
        return min(score, 1.0)
    
    def _calculate_header_confidence(self, header_data: Dict[str, Any]) -> float:
        """Calculate confidence score for header data"""
        score = 0.0
        if header_data["raw_headers"]:
            score += 0.3
        if header_data["parsed_headers"]:
            score += 0.2
        if header_data["authentication_headers"]:
            score += 0.2
        if header_data["header_completeness"] > 0.5:
            score += 0.3
        return min(score, 1.0)
    
    def _calculate_content_confidence(self, content_metadata: Dict[str, Any]) -> float:
        """Calculate confidence score for content metadata"""
        score = 0.0
        if content_metadata["body_text"]:
            score += 0.4
        if content_metadata["content_length"] > 0:
            score += 0.2
        if content_metadata["extracted_urls"]:
            score += 0.2
        if content_metadata["content_analysis"]:
            score += 0.2
        return min(score, 1.0)
    
    def _analyze_scope_indicators(self, extracted_entities: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze scope indicators for investigation planning"""
        scope_indicators = {}
        
        # Attachment scope
        attachment_count = extracted_entities["attachment_metadata"]["attachment_count"]
        if attachment_count > 0:
            scope_indicators["attachment_analysis"] = {
                "required": True,
                "priority": "high" if attachment_count > 3 else "medium",
                "complexity": "complex" if attachment_count > 5 else "standard"
            }
        
        # URL scope
        url_count = extracted_entities["content_metadata"]["url_count"]
        if url_count > 0:
            scope_indicators["url_analysis"] = {
                "required": True,
                "priority": "high" if url_count > 5 else "medium",
                "complexity": "complex" if url_count > 10 else "standard"
            }
        
        # Sender reputation scope
        sender_email = extracted_entities["sender_information"]["sender_email"]
        if sender_email:
            scope_indicators["sender_reputation"] = {
                "required": True,
                "priority": "high",
                "complexity": "standard"
            }
        
        return scope_indicators
    
    def _identify_priority_factors(self, extracted_entities: Dict[str, Any]) -> Dict[str, Any]:
        """Identify priority factors for investigation"""
        priority_factors = {}
        
        # Urgency indicators
        urgency_indicators = extracted_entities["subject_analysis"]["urgency_indicators"]
        if urgency_indicators:
            priority_factors["urgency"] = {
                "level": "high" if len(urgency_indicators) > 2 else "medium",
                "indicators": urgency_indicators
            }
        
        # Suspicious attachments
        suspicious_attachments = extracted_entities["attachment_metadata"]["suspicious_attachments"]
        if suspicious_attachments:
            priority_factors["suspicious_attachments"] = {
                "level": "critical",
                "count": len(suspicious_attachments)
            }
        
        # External sender
        sender_domain = extracted_entities["sender_information"]["sender_domain"]
        if sender_domain and not self._is_internal_domain(sender_domain):
            priority_factors["external_sender"] = {
                "level": "medium",
                "domain": sender_domain
            }
        
        return priority_factors
    
    def _assess_investigation_complexity(self, scope_indicators: Dict[str, Any], 
                                       priority_factors: Dict[str, Any]) -> str:
        """Assess overall investigation complexity"""
        complexity_score = 0
        
        # Count high-priority scope indicators
        high_priority_count = sum(1 for indicator in scope_indicators.values() 
                                if indicator.get("priority") == "high")
        complexity_score += high_priority_count * 2
        
        # Count complex scope indicators
        complex_count = sum(1 for indicator in scope_indicators.values() 
                          if indicator.get("complexity") == "complex")
        complexity_score += complex_count * 3
        
        # Count critical priority factors
        critical_count = sum(1 for factor in priority_factors.values() 
                           if factor.get("level") == "critical")
        complexity_score += critical_count * 4
        
        if complexity_score >= 10:
            return "high"
        elif complexity_score >= 5:
            return "medium"
        else:
            return "low"
    
    def _determine_required_integrations(self, extracted_entities: Dict[str, Any]) -> List[str]:
        """Determine required integrations for investigation"""
        integrations = []
        
        # Always required
        integrations.extend(["Microsoft Defender for Office 365", "Azure AD"])
        
        # Conditional integrations
        if extracted_entities["attachment_metadata"]["attachment_count"] > 0:
            integrations.extend(["VirusTotal", "Microsoft Defender for Endpoint"])
        
        if extracted_entities["content_metadata"]["url_count"] > 0:
            integrations.extend(["URLhaus", "PhishTank"])
        
        if extracted_entities["sender_information"]["sender_email"]:
            integrations.extend(["MXToolbox", "Microsoft Graph API"])
        
        return list(set(integrations))  # Remove duplicates
    
    def _calculate_scope_confidence(self, scope_analysis: Dict[str, Any]) -> float:
        """Calculate confidence in scope determination"""
        confidence_factors = []
        
        # Scope indicator confidence
        scope_indicators = scope_analysis.get("scope_indicators", {})
        if len(scope_indicators) > 2:
            confidence_factors.append(0.8)
        elif len(scope_indicators) > 0:
            confidence_factors.append(0.6)
        else:
            confidence_factors.append(0.3)
        
        # Priority factor confidence
        priority_factors = scope_analysis.get("priority_factors", {})
        if len(priority_factors) > 1:
            confidence_factors.append(0.7)
        elif len(priority_factors) > 0:
            confidence_factors.append(0.5)
        else:
            confidence_factors.append(0.4)
        
        return sum(confidence_factors) / len(confidence_factors) if confidence_factors else 0.5
