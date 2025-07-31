"""
Email Security Analyzer Module - Enterprise Edition
State 2: Email Security Analysis
Uses Microsoft Defender for Office 365 to query email security verdicts, policy actions,
delivery status, message trace data, and Exchange Online Protection filtering results

Enterprise Features:
- Azure Key Vault integration for secure API credentials
- RBAC-based access control for security operations
- GDPR/HIPAA compliance logging and audit trails
- Enterprise-grade encryption for sensitive data
- High availability and auto-scaling support
- SLA monitoring and alerting
"""

import logging
import sys
import os
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import asyncio
import aiohttp
import json
from enum import Enum

# Add enterprise module to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from enterprise import (
    EnterpriseSecurityManager,
    EnterpriseComplianceManager,
    EnterpriseOperationsManager,
    SecurityRole,
    EncryptionLevel,
    ComplianceFramework,
    AlertSeverity
)

logger = logging.getLogger(__name__)

class SecurityVerdict(Enum):
    """Email security verdict enumeration"""
    CLEAN = "clean"
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    QUARANTINED = "quarantined"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"

class PolicyAction(Enum):
    """Email policy action enumeration"""
    ALLOW = "allow"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    DELETE = "delete"
    REDIRECT = "redirect"
    ENCRYPT = "encrypt"

class EmailSecurityAnalyzer:
    """
    Enterprise Email Security Analysis for phishing investigation
    Analyzes email security verdicts, policy actions, and delivery status
    
    Enterprise Features:
    - RBAC-based access control
    - GDPR/HIPAA compliance
    - Enterprise encryption
    - SLA monitoring
    """
    
    def __init__(self, security_manager: EnterpriseSecurityManager = None,
                 compliance_manager: EnterpriseComplianceManager = None,
                 operations_manager: EnterpriseOperationsManager = None):
        """Initialize enterprise email security analyzer"""
        self.security_manager = security_manager or EnterpriseSecurityManager()
        self.compliance_manager = compliance_manager or EnterpriseComplianceManager()
        self.operations_manager = operations_manager or EnterpriseOperationsManager()
        
        # Initialize enterprise features
        self.security_apis = self._initialize_security_apis()
        self.policy_cache = {}
        self.verdict_cache = {}
        
        # Enterprise metrics
        self.operations_manager.track_component_health(
            "email_security_analyzer",
            {"status": "initialized", "timestamp": datetime.now()}
        )
        
    async def analyze_email_security_verdicts(self, email_entities: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze email security verdicts from Microsoft Defender for Office 365
        
        Args:
            email_entities: Extracted email entities from State 1
            
        Returns:
            Security verdict analysis results
        """
        # Start SLA tracking
        sla_context = self.operations_manager.start_sla_tracking(
            "email_security_analysis",
            target_duration=30.0  # 30 seconds SLA
        )
        
        try:
            # RBAC check
            if not await self.security_manager.check_permission(
                SecurityRole.SOC_ANALYST, "email:analyze"
            ):
                raise PermissionError("Insufficient permissions for email security analysis")
            
            logger.info("Starting enterprise email security verdict analysis")
            
            # Compliance logging
            self.compliance_manager.log_data_access(
                "email_security_analysis",
                {"message_id": email_entities.get("message_identifiers", {}).get("message_id", "")},
                ComplianceFramework.GDPR
            )
            
            verdict_analysis = {
                "defender_verdicts": {},
                "policy_actions": {},
                "delivery_status": {},
                "threat_detection_details": {},
                "security_timeline": [],
                "verdict_confidence": 0.0,
                "security_metadata": {},
                "analysis_timestamp": datetime.now(),
                "enterprise_metadata": {
                    "analyst_id": await self.security_manager.get_current_user_id(),
                    "compliance_level": "enterprise",
                    "encryption_level": EncryptionLevel.HIGH.value
                }
            }
            
            # Extract key identifiers
            message_id = email_entities.get("message_identifiers", {}).get("message_id", "")
            sender_email = email_entities.get("sender_information", {}).get("sender_email", "")
            recipient_emails = email_entities.get("recipient_information", {}).get("primary_recipients", [])
            
            if not message_id and not sender_email:
                logger.warning("Insufficient identifiers for security verdict analysis")
                return verdict_analysis
                
            # Perform analysis with enterprise features
            try:
                # Microsoft Defender Analysis
                defender_results = await self._query_defender_verdicts(message_id, sender_email)
                verdict_analysis["defender_verdicts"] = defender_results
                
                # Policy Action Analysis
                policy_results = await self._analyze_policy_actions(message_id, recipient_emails)
                verdict_analysis["policy_actions"] = policy_results
                
                # Delivery Status Analysis
                delivery_results = await self._analyze_delivery_status(message_id)
                verdict_analysis["delivery_status"] = delivery_results
                
                # Threat Detection Details
                threat_details = await self._extract_threat_details(message_id)
                verdict_analysis["threat_detection_details"] = threat_details
                
                # Calculate verdict confidence
                verdict_analysis["verdict_confidence"] = self._calculate_verdict_confidence(verdict_analysis)
                
                # Encrypt sensitive data
                verdict_analysis = await self.security_manager.encrypt_sensitive_data(
                    verdict_analysis, EncryptionLevel.HIGH
                )
                
                # Complete SLA tracking
                self.operations_manager.complete_sla_tracking(sla_context, success=True)
                
                return verdict_analysis
                
            except Exception as e:
                logger.error(f"Error in email security analysis: {str(e)}")
                self.operations_manager.complete_sla_tracking(sla_context, success=False)
                raise
                
        except Exception as e:
            # Enterprise error handling
            await self.operations_manager.handle_error(
                "email_security_analysis_error",
                str(e),
                AlertSeverity.HIGH
            )
            raise
        
        # Query Microsoft Defender for Office 365 verdicts
        verdict_analysis["defender_verdicts"] = self._query_defender_verdicts(
            message_id, sender_email, recipient_emails
        )
        
        # Analyze policy actions
        verdict_analysis["policy_actions"] = self._analyze_policy_actions(
            verdict_analysis["defender_verdicts"], email_entities
        )
        
        # Check delivery status
        verdict_analysis["delivery_status"] = self._check_delivery_status(
            message_id, recipient_emails
        )
        
        # Get threat detection details
        verdict_analysis["threat_detection_details"] = self._get_threat_detection_details(
            verdict_analysis["defender_verdicts"], email_entities
        )
        
        # Build security timeline
        verdict_analysis["security_timeline"] = self._build_security_timeline(
            verdict_analysis["defender_verdicts"], verdict_analysis["policy_actions"]
        )
        
        # Calculate verdict confidence
        verdict_analysis["verdict_confidence"] = self._calculate_verdict_confidence(verdict_analysis)
        
        # Add security metadata
        verdict_analysis["security_metadata"] = {
            "analysis_timestamp": datetime.now(),
            "message_id_analyzed": bool(message_id),
            "sender_analyzed": bool(sender_email),
            "recipients_analyzed": len(recipient_emails),
            "verdicts_found": len(verdict_analysis["defender_verdicts"]),
            "policies_triggered": len(verdict_analysis["policy_actions"])
        }
        
        logger.info("Email security verdict analysis completed")
        return verdict_analysis
    
    def query_message_trace_data(self, email_entities: Dict[str, Any],
                               time_window_hours: int = 24) -> Dict[str, Any]:
        """
        Query message trace data to understand email flow and security interventions
        
        Args:
            email_entities: Extracted email entities
            time_window_hours: Time window for trace query
            
        Returns:
            Message trace analysis results
        """
        logger.info("Starting message trace data query")
        
        trace_analysis = {
            "message_trace_events": [],
            "email_flow_analysis": {},
            "security_interventions": [],
            "delivery_path": [],
            "trace_completeness": 0.0,
            "flow_anomalies": [],
            "trace_metadata": {},
            "analysis_timestamp": datetime.now()
        }
        
        # Extract trace query parameters
        message_id = email_entities.get("message_identifiers", {}).get("message_id", "")
        sender_email = email_entities.get("sender_information", {}).get("sender_email", "")
        recipient_emails = email_entities.get("recipient_information", {}).get("primary_recipients", [])
        
        # Define time window
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=time_window_hours)
        
        # Query message trace
        trace_analysis["message_trace_events"] = self._query_message_trace(
            message_id, sender_email, recipient_emails, start_time, end_time
        )
        
        # Analyze email flow
        trace_analysis["email_flow_analysis"] = self._analyze_email_flow(
            trace_analysis["message_trace_events"]
        )
        
        # Identify security interventions
        trace_analysis["security_interventions"] = self._identify_security_interventions(
            trace_analysis["message_trace_events"]
        )
        
        # Map delivery path
        trace_analysis["delivery_path"] = self._map_delivery_path(
            trace_analysis["message_trace_events"]
        )
        
        # Assess trace completeness
        trace_analysis["trace_completeness"] = self._assess_trace_completeness(
            trace_analysis["message_trace_events"], email_entities
        )
        
        # Detect flow anomalies
        trace_analysis["flow_anomalies"] = self._detect_flow_anomalies(
            trace_analysis["email_flow_analysis"], trace_analysis["delivery_path"]
        )
        
        # Add trace metadata
        trace_analysis["trace_metadata"] = {
            "query_timestamp": datetime.now(),
            "time_window_hours": time_window_hours,
            "trace_events_found": len(trace_analysis["message_trace_events"]),
            "security_interventions_found": len(trace_analysis["security_interventions"]),
            "delivery_hops": len(trace_analysis["delivery_path"])
        }
        
        logger.info("Message trace data query completed")
        return trace_analysis
    
    def analyze_exchange_protection_results(self, email_entities: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze Exchange Online Protection spam filtering and quarantine results
        
        Args:
            email_entities: Extracted email entities
            
        Returns:
            Exchange Online Protection analysis results
        """
        logger.info("Starting Exchange Online Protection analysis")
        
        eop_analysis = {
            "spam_filtering_results": {},
            "anti_malware_results": {},
            "quarantine_status": {},
            "transport_rules_triggered": [],
            "content_filtering_details": {},
            "connection_filtering_results": {},
            "eop_verdict_summary": {},
            "protection_effectiveness": 0.0,
            "eop_metadata": {},
            "analysis_timestamp": datetime.now()
        }
        
        # Extract key identifiers
        message_id = email_entities.get("message_identifiers", {}).get("message_id", "")
        sender_email = email_entities.get("sender_information", {}).get("sender_email", "")
        sender_ip = email_entities.get("sender_information", {}).get("sender_ip", "")
        
        # Query spam filtering results
        eop_analysis["spam_filtering_results"] = self._query_spam_filtering_results(
            message_id, sender_email
        )
        
        # Query anti-malware results
        eop_analysis["anti_malware_results"] = self._query_anti_malware_results(
            message_id, email_entities.get("attachment_metadata", {})
        )
        
        # Check quarantine status
        eop_analysis["quarantine_status"] = self._check_quarantine_status(
            message_id, sender_email
        )
        
        # Analyze transport rules
        eop_analysis["transport_rules_triggered"] = self._analyze_transport_rules(
            message_id, email_entities
        )
        
        # Analyze content filtering
        eop_analysis["content_filtering_details"] = self._analyze_content_filtering(
            email_entities.get("content_metadata", {}), email_entities.get("subject_analysis", {})
        )
        
        # Analyze connection filtering
        eop_analysis["connection_filtering_results"] = self._analyze_connection_filtering(
            sender_ip, sender_email
        )
        
        # Generate EOP verdict summary
        eop_analysis["eop_verdict_summary"] = self._generate_eop_verdict_summary(eop_analysis)
        
        # Calculate protection effectiveness
        eop_analysis["protection_effectiveness"] = self._calculate_protection_effectiveness(eop_analysis)
        
        # Add EOP metadata
        eop_analysis["eop_metadata"] = {
            "analysis_timestamp": datetime.now(),
            "message_id_queried": bool(message_id),
            "sender_analyzed": bool(sender_email),
            "sender_ip_analyzed": bool(sender_ip),
            "quarantine_checked": bool(eop_analysis["quarantine_status"]),
            "rules_evaluated": len(eop_analysis["transport_rules_triggered"])
        }
        
        logger.info("Exchange Online Protection analysis completed")
        return eop_analysis
    
    def correlate_security_findings(self, verdict_analysis: Dict[str, Any],
                                  trace_analysis: Dict[str, Any],
                                  eop_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Correlate findings from all security analysis components
        
        Args:
            verdict_analysis: Defender verdict analysis results
            trace_analysis: Message trace analysis results
            eop_analysis: EOP analysis results
            
        Returns:
            Correlated security findings
        """
        logger.info("Starting security findings correlation")
        
        correlation_results = {
            "overall_security_verdict": SecurityVerdict.UNKNOWN.value,
            "security_consensus": {},
            "conflicting_verdicts": [],
            "security_confidence_score": 0.0,
            "threat_indicators": [],
            "protection_gaps": [],
            "security_recommendations": [],
            "correlation_metadata": {},
            "analysis_timestamp": datetime.now()
        }
        
        # Collect all verdicts
        all_verdicts = self._collect_all_verdicts(verdict_analysis, trace_analysis, eop_analysis)
        
        # Determine security consensus
        correlation_results["security_consensus"] = self._determine_security_consensus(all_verdicts)
        
        # Identify conflicting verdicts
        correlation_results["conflicting_verdicts"] = self._identify_conflicting_verdicts(all_verdicts)
        
        # Calculate overall security verdict
        correlation_results["overall_security_verdict"] = self._calculate_overall_verdict(
            correlation_results["security_consensus"], correlation_results["conflicting_verdicts"]
        )
        
        # Calculate security confidence score
        correlation_results["security_confidence_score"] = self._calculate_security_confidence(
            correlation_results["security_consensus"], correlation_results["conflicting_verdicts"]
        )
        
        # Extract threat indicators
        correlation_results["threat_indicators"] = self._extract_threat_indicators(
            verdict_analysis, trace_analysis, eop_analysis
        )
        
        # Identify protection gaps
        correlation_results["protection_gaps"] = self._identify_protection_gaps(
            verdict_analysis, trace_analysis, eop_analysis
        )
        
        # Generate security recommendations
        correlation_results["security_recommendations"] = self._generate_security_recommendations(
            correlation_results["overall_security_verdict"],
            correlation_results["threat_indicators"],
            correlation_results["protection_gaps"]
        )
        
        # Add correlation metadata
        correlation_results["correlation_metadata"] = {
            "correlation_timestamp": datetime.now(),
            "verdicts_analyzed": len(all_verdicts),
            "consensus_strength": correlation_results["security_consensus"].get("consensus_strength", 0),
            "conflicts_detected": len(correlation_results["conflicting_verdicts"]),
            "threat_indicators_found": len(correlation_results["threat_indicators"]),
            "protection_gaps_identified": len(correlation_results["protection_gaps"])
        }
        
        logger.info("Security findings correlation completed")
        return correlation_results
    
    def _initialize_security_apis(self) -> Dict[str, Any]:
        """Initialize security API configurations"""
        return {
            "microsoft_defender_api": {
                "base_url": "https://api.securitycenter.microsoft.com",
                "version": "v1.0",
                "timeout": 30
            },
            "exchange_online_api": {
                "base_url": "https://outlook.office365.com",
                "version": "v2.0",
                "timeout": 30
            },
            "graph_api": {
                "base_url": "https://graph.microsoft.com",
                "version": "v1.0",
                "timeout": 30
            }
        }
    
    def _query_defender_verdicts(self, message_id: str, sender_email: str, 
                               recipient_emails: List[str]) -> Dict[str, Any]:
        """Query Microsoft Defender for Office 365 verdicts"""
        defender_verdicts = {
            "atp_safe_attachments": {},
            "atp_safe_links": {},
            "atp_anti_phishing": {},
            "threat_intelligence": {},
            "verdict_details": {},
            "confidence_scores": {}
        }
        
        # In production, this would make actual API calls to Microsoft Defender
        # For this implementation, we'll simulate the structure
        
        if message_id:
            # Simulate ATP Safe Attachments verdict
            defender_verdicts["atp_safe_attachments"] = {
                "verdict": SecurityVerdict.CLEAN.value,
                "scan_results": [],
                "detonation_results": {},
                "analysis_timestamp": datetime.now()
            }
            
            # Simulate ATP Safe Links verdict
            defender_verdicts["atp_safe_links"] = {
                "verdict": SecurityVerdict.SUSPICIOUS.value,
                "scanned_urls": [],
                "blocked_urls": [],
                "analysis_timestamp": datetime.now()
            }
            
            # Simulate ATP Anti-Phishing verdict
            defender_verdicts["atp_anti_phishing"] = {
                "verdict": SecurityVerdict.CLEAN.value,
                "impersonation_detection": {},
                "domain_reputation": {},
                "analysis_timestamp": datetime.now()
            }
        
        return defender_verdicts
    
    def _analyze_policy_actions(self, defender_verdicts: Dict[str, Any], 
                              email_entities: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze policy actions taken on the email"""
        policy_actions = {
            "executed_actions": [],
            "policy_matches": [],
            "action_effectiveness": {},
            "policy_coverage": 0.0
        }
        
        # Analyze executed actions based on verdicts
        for component, verdict_data in defender_verdicts.items():
            verdict = verdict_data.get("verdict")
            if verdict == SecurityVerdict.QUARANTINED.value:
                policy_actions["executed_actions"].append({
                    "action": PolicyAction.QUARANTINE.value,
                    "component": component,
                    "timestamp": verdict_data.get("analysis_timestamp")
                })
            elif verdict == SecurityVerdict.BLOCKED.value:
                policy_actions["executed_actions"].append({
                    "action": PolicyAction.BLOCK.value,
                    "component": component,
                    "timestamp": verdict_data.get("analysis_timestamp")
                })
        
        return policy_actions
    
    def _check_delivery_status(self, message_id: str, recipient_emails: List[str]) -> Dict[str, Any]:
        """Check email delivery status"""
        delivery_status = {
            "delivery_verdict": "unknown",
            "delivered_recipients": [],
            "failed_recipients": [],
            "delivery_attempts": [],
            "final_disposition": ""
        }
        
        # In production, query actual delivery status from Exchange
        # Simulate delivery status based on available data
        if recipient_emails:
            delivery_status["delivery_verdict"] = "delivered"
            delivery_status["delivered_recipients"] = recipient_emails[:1]  # Simulate partial delivery
            delivery_status["final_disposition"] = "inbox"
        
        return delivery_status
    
    def _get_threat_detection_details(self, defender_verdicts: Dict[str, Any], 
                                    email_entities: Dict[str, Any]) -> Dict[str, Any]:
        """Get detailed threat detection information"""
        threat_details = {
            "detected_threats": [],
            "threat_categories": [],
            "detection_methods": [],
            "threat_severity": "low",
            "iocs_identified": []
        }
        
        # Extract threat details from verdicts
        for component, verdict_data in defender_verdicts.items():
            verdict = verdict_data.get("verdict")
            if verdict in [SecurityVerdict.MALICIOUS.value, SecurityVerdict.SUSPICIOUS.value]:
                threat_details["detected_threats"].append({
                    "component": component,
                    "verdict": verdict,
                    "details": verdict_data
                })
        
        return threat_details
    
    def _build_security_timeline(self, defender_verdicts: Dict[str, Any], 
                               policy_actions: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Build chronological security timeline"""
        timeline_events = []
        
        # Add verdict events
        for component, verdict_data in defender_verdicts.items():
            if verdict_data.get("analysis_timestamp"):
                timeline_events.append({
                    "timestamp": verdict_data["analysis_timestamp"],
                    "event_type": "security_verdict",
                    "component": component,
                    "verdict": verdict_data.get("verdict"),
                    "details": verdict_data
                })
        
        # Add policy action events
        for action in policy_actions.get("executed_actions", []):
            if action.get("timestamp"):
                timeline_events.append({
                    "timestamp": action["timestamp"],
                    "event_type": "policy_action",
                    "action": action["action"],
                    "component": action["component"],
                    "details": action
                })
        
        # Sort by timestamp
        timeline_events.sort(key=lambda x: x["timestamp"])
        
        return timeline_events
    
    def _calculate_verdict_confidence(self, verdict_analysis: Dict[str, Any]) -> float:
        """Calculate confidence in security verdicts"""
        confidence_factors = []
        
        # Defender verdicts confidence
        defender_verdicts = verdict_analysis.get("defender_verdicts", {})
        if len(defender_verdicts) > 2:
            confidence_factors.append(0.8)
        elif len(defender_verdicts) > 0:
            confidence_factors.append(0.6)
        else:
            confidence_factors.append(0.2)
        
        # Policy actions confidence
        policy_actions = verdict_analysis.get("policy_actions", {})
        executed_actions = policy_actions.get("executed_actions", [])
        if len(executed_actions) > 0:
            confidence_factors.append(0.7)
        else:
            confidence_factors.append(0.5)
        
        # Delivery status confidence
        delivery_status = verdict_analysis.get("delivery_status", {})
        if delivery_status.get("delivery_verdict") != "unknown":
            confidence_factors.append(0.6)
        else:
            confidence_factors.append(0.3)
        
        return sum(confidence_factors) / len(confidence_factors) if confidence_factors else 0.5
    
    def _query_message_trace(self, message_id: str, sender_email: str, 
                           recipient_emails: List[str], start_time: datetime, 
                           end_time: datetime) -> List[Dict[str, Any]]:
        """Query message trace from Exchange Online"""
        trace_events = []
        
        # In production, this would query actual Exchange message trace
        # Simulate trace events
        if message_id or sender_email:
            # Simulate receive event
            trace_events.append({
                "timestamp": start_time + timedelta(minutes=5),
                "event_type": "RECEIVE",
                "message_id": message_id,
                "sender": sender_email,
                "recipients": recipient_emails,
                "source_ip": "192.168.1.100",
                "status": "SUCCESS"
            })
            
            # Simulate security scan event
            trace_events.append({
                "timestamp": start_time + timedelta(minutes=6),
                "event_type": "SECURITY_SCAN",
                "message_id": message_id,
                "scan_type": "ATP_SAFE_ATTACHMENTS",
                "result": "CLEAN",
                "status": "SUCCESS"
            })
            
            # Simulate deliver event
            trace_events.append({
                "timestamp": start_time + timedelta(minutes=7),
                "event_type": "DELIVER",
                "message_id": message_id,
                "recipients": recipient_emails,
                "destination": "INBOX",
                "status": "SUCCESS"
            })
        
        return trace_events
    
    def _analyze_email_flow(self, trace_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze email flow from trace events"""
        flow_analysis = {
            "total_hops": 0,
            "processing_time": 0,
            "flow_status": "unknown",
            "bottlenecks": [],
            "flow_anomalies": []
        }
        
        if not trace_events:
            return flow_analysis
        
        # Calculate processing time
        first_event = min(trace_events, key=lambda x: x["timestamp"])
        last_event = max(trace_events, key=lambda x: x["timestamp"])
        
        flow_analysis["total_hops"] = len(trace_events)
        flow_analysis["processing_time"] = (last_event["timestamp"] - first_event["timestamp"]).total_seconds()
        
        # Determine flow status
        failed_events = [event for event in trace_events if event.get("status") != "SUCCESS"]
        if failed_events:
            flow_analysis["flow_status"] = "failed"
        else:
            flow_analysis["flow_status"] = "success"
        
        # Identify bottlenecks (events taking unusually long)
        for i in range(1, len(trace_events)):
            time_diff = (trace_events[i]["timestamp"] - trace_events[i-1]["timestamp"]).total_seconds()
            if time_diff > 300:  # More than 5 minutes
                flow_analysis["bottlenecks"].append({
                    "between_events": f"{trace_events[i-1]['event_type']} -> {trace_events[i]['event_type']}",
                    "delay_seconds": time_diff
                })
        
        return flow_analysis
    
    def _identify_security_interventions(self, trace_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify security interventions from trace events"""
        security_interventions = []
        
        security_event_types = ["SECURITY_SCAN", "QUARANTINE", "BLOCK", "REDIRECT"]
        
        for event in trace_events:
            if event.get("event_type") in security_event_types:
                security_interventions.append({
                    "timestamp": event["timestamp"],
                    "intervention_type": event["event_type"],
                    "result": event.get("result", "unknown"),
                    "details": event
                })
        
        return security_interventions
    
    def _map_delivery_path(self, trace_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Map email delivery path from trace events"""
        delivery_path = []
        
        for event in trace_events:
            path_step = {
                "timestamp": event["timestamp"],
                "step_type": event["event_type"],
                "location": event.get("source_ip", "unknown"),
                "status": event.get("status", "unknown")
            }
            delivery_path.append(path_step)
        
        return delivery_path
    
    def _assess_trace_completeness(self, trace_events: List[Dict[str, Any]], 
                                 email_entities: Dict[str, Any]) -> float:
        """Assess completeness of message trace data"""
        expected_events = ["RECEIVE", "DELIVER"]
        found_events = [event["event_type"] for event in trace_events]
        
        # Check for expected events
        completeness_score = 0.0
        for expected_event in expected_events:
            if expected_event in found_events:
                completeness_score += 0.4
        
        # Additional completeness factors
        if any("SECURITY" in event_type for event_type in found_events):
            completeness_score += 0.2
        
        return min(completeness_score, 1.0)
    
    def _detect_flow_anomalies(self, flow_analysis: Dict[str, Any], 
                             delivery_path: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect anomalies in email flow"""
        anomalies = []
        
        # Check for unusual processing time
        processing_time = flow_analysis.get("processing_time", 0)
        if processing_time > 1800:  # More than 30 minutes
            anomalies.append({
                "anomaly_type": "excessive_processing_time",
                "severity": "medium",
                "details": f"Processing took {processing_time} seconds"
            })
        
        # Check for failed delivery attempts
        failed_steps = [step for step in delivery_path if step["status"] != "SUCCESS"]
        if failed_steps:
            anomalies.append({
                "anomaly_type": "delivery_failures",
                "severity": "high",
                "details": f"{len(failed_steps)} failed delivery attempts"
            })
        
        return anomalies
    
    def _query_spam_filtering_results(self, message_id: str, sender_email: str) -> Dict[str, Any]:
        """Query spam filtering results from Exchange Online Protection"""
        spam_results = {
            "spam_verdict": "not_spam",
            "spam_confidence_level": 0.0,
            "spam_filtering_rules": [],
            "content_filter_result": "pass"
        }
        
        # In production, query actual EOP spam filtering results
        # Simulate based on sender characteristics
        if sender_email:
            # Basic heuristic for demo
            if any(keyword in sender_email.lower() for keyword in ["noreply", "donotreply"]):
                spam_results["spam_verdict"] = "bulk"
                spam_results["spam_confidence_level"] = 0.3
            else:
                spam_results["spam_confidence_level"] = 0.1
        
        return spam_results
    
    def _query_anti_malware_results(self, message_id: str, 
                                  attachment_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Query anti-malware scan results"""
        malware_results = {
            "malware_verdict": "clean",
            "scanned_attachments": [],
            "malware_signatures": [],
            "quarantine_actions": []
        }
        
        # Analyze attachments if present
        attachments = attachment_metadata.get("attachment_list", [])
        for attachment in attachments:
            scan_result = {
                "attachment_name": attachment.get("name", ""),
                "scan_verdict": "clean",
                "scan_engine": "Microsoft Defender",
                "scan_timestamp": datetime.now()
            }
            
            # Check for suspicious attachment characteristics
            if attachment.get("is_suspicious", False):
                scan_result["scan_verdict"] = "suspicious"
            
            malware_results["scanned_attachments"].append(scan_result)
        
        return malware_results
    
    def _check_quarantine_status(self, message_id: str, sender_email: str) -> Dict[str, Any]:
        """Check if message is in quarantine"""
        quarantine_status = {
            "is_quarantined": False,
            "quarantine_reason": "",
            "quarantine_timestamp": None,
            "release_status": "not_applicable"
        }
        
        # In production, query actual quarantine status
        # For demo, assume not quarantined unless specific indicators
        
        return quarantine_status
    
    def _analyze_transport_rules(self, message_id: str, email_entities: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze transport rules triggered by the email"""
        triggered_rules = []
        
        # Simulate transport rule analysis based on email characteristics
        subject_text = email_entities.get("subject_analysis", {}).get("decoded_subject", "")
        sender_email = email_entities.get("sender_information", {}).get("sender_email", "")
        
        # Check for common transport rule triggers
        if any(keyword in subject_text.lower() for keyword in ["urgent", "immediate", "expires"]):
            triggered_rules.append({
                "rule_name": "Urgency Keyword Detection",
                "rule_action": "add_header",
                "severity": "medium",
                "trigger_reason": "urgency_keywords_detected"
            })
        
        # Check external sender rules
        if sender_email and not self._is_internal_domain(sender_email.split("@")[-1]):
            triggered_rules.append({
                "rule_name": "External Sender Marking",
                "rule_action": "add_disclaimer",
                "severity": "low",
                "trigger_reason": "external_sender"
            })
        
        return triggered_rules
    
    def _analyze_content_filtering(self, content_metadata: Dict[str, Any], 
                                 subject_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze content filtering results"""
        content_filtering = {
            "content_filter_verdict": "pass",
            "blocked_content": [],
            "suspicious_patterns": [],
            "content_risk_score": 0.0
        }
        
        # Analyze suspicious keywords
        suspicious_keywords = subject_analysis.get("suspicious_keywords", [])
        urgency_indicators = subject_analysis.get("urgency_indicators", [])
        
        content_risk_score = len(suspicious_keywords) * 0.1 + len(urgency_indicators) * 0.15
        
        content_filtering["content_risk_score"] = min(content_risk_score, 1.0)
        content_filtering["suspicious_patterns"] = suspicious_keywords + urgency_indicators
        
        if content_risk_score > 0.5:
            content_filtering["content_filter_verdict"] = "suspicious"
        
        return content_filtering
    
    def _analyze_connection_filtering(self, sender_ip: str, sender_email: str) -> Dict[str, Any]:
        """Analyze connection filtering results"""
        connection_filtering = {
            "ip_reputation": "unknown",
            "connection_verdict": "allow",
            "reputation_sources": [],
            "connection_risk_score": 0.0
        }
        
        # In production, query actual IP reputation services
        if sender_ip:
            # Simulate IP reputation check
            if sender_ip.startswith("192.168.") or sender_ip.startswith("10."):
                connection_filtering["ip_reputation"] = "internal"
                connection_filtering["connection_risk_score"] = 0.1
            else:
                connection_filtering["ip_reputation"] = "external"
                connection_filtering["connection_risk_score"] = 0.3
        
        return connection_filtering
    
    def _generate_eop_verdict_summary(self, eop_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of EOP analysis results"""
        verdict_summary = {
            "overall_eop_verdict": "clean",
            "protection_layers_triggered": [],
            "risk_indicators": [],
            "eop_confidence": 0.0
        }
        
        # Collect verdicts from different components
        spam_verdict = eop_analysis.get("spam_filtering_results", {}).get("spam_verdict", "not_spam")
        malware_verdict = eop_analysis.get("anti_malware_results", {}).get("malware_verdict", "clean")
        content_verdict = eop_analysis.get("content_filtering_details", {}).get("content_filter_verdict", "pass")
        
        # Determine overall verdict
        if malware_verdict != "clean":
            verdict_summary["overall_eop_verdict"] = "malicious"
        elif spam_verdict in ["spam", "high_confidence_spam"]:
            verdict_summary["overall_eop_verdict"] = "spam"
        elif content_verdict == "suspicious":
            verdict_summary["overall_eop_verdict"] = "suspicious"
        
        # Identify triggered protection layers
        if spam_verdict != "not_spam":
            verdict_summary["protection_layers_triggered"].append("spam_filtering")
        if malware_verdict != "clean":
            verdict_summary["protection_layers_triggered"].append("anti_malware")
        if eop_analysis.get("transport_rules_triggered"):
            verdict_summary["protection_layers_triggered"].append("transport_rules")
        
        return verdict_summary
    
    def _calculate_protection_effectiveness(self, eop_analysis: Dict[str, Any]) -> float:
        """Calculate effectiveness of protection mechanisms"""
        effectiveness_score = 0.0
        
        # Base effectiveness for having protection mechanisms
        if eop_analysis.get("spam_filtering_results"):
            effectiveness_score += 0.3
        if eop_analysis.get("anti_malware_results"):
            effectiveness_score += 0.3
        if eop_analysis.get("content_filtering_details"):
            effectiveness_score += 0.2
        if eop_analysis.get("transport_rules_triggered"):
            effectiveness_score += 0.2
        
        return min(effectiveness_score, 1.0)
    
    def _collect_all_verdicts(self, verdict_analysis: Dict[str, Any],
                            trace_analysis: Dict[str, Any],
                            eop_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Collect all security verdicts from different sources"""
        all_verdicts = []
        
        # Defender verdicts
        defender_verdicts = verdict_analysis.get("defender_verdicts", {})
        for component, verdict_data in defender_verdicts.items():
            all_verdicts.append({
                "source": f"defender_{component}",
                "verdict": verdict_data.get("verdict", SecurityVerdict.UNKNOWN.value),
                "confidence": 0.8,  # High confidence for Defender
                "timestamp": verdict_data.get("analysis_timestamp")
            })
        
        # EOP verdicts
        eop_verdict_summary = eop_analysis.get("eop_verdict_summary", {})
        if eop_verdict_summary:
            all_verdicts.append({
                "source": "eop_overall",
                "verdict": eop_verdict_summary.get("overall_eop_verdict", SecurityVerdict.UNKNOWN.value),
                "confidence": 0.7,  # Medium-high confidence for EOP
                "timestamp": datetime.now()
            })
        
        # Message trace verdicts (if any security events found)
        security_interventions = trace_analysis.get("security_interventions", [])
        for intervention in security_interventions:
            verdict_mapping = {
                "QUARANTINE": SecurityVerdict.QUARANTINED.value,
                "BLOCK": SecurityVerdict.BLOCKED.value,
                "SECURITY_SCAN": SecurityVerdict.CLEAN.value if intervention.get("result") == "CLEAN" else SecurityVerdict.SUSPICIOUS.value
            }
            
            verdict = verdict_mapping.get(intervention["intervention_type"], SecurityVerdict.UNKNOWN.value)
            all_verdicts.append({
                "source": f"trace_{intervention['intervention_type']}",
                "verdict": verdict,
                "confidence": 0.6,  # Medium confidence for trace data
                "timestamp": intervention["timestamp"]
            })
        
        return all_verdicts
    
    def _determine_security_consensus(self, all_verdicts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Determine consensus among security verdicts"""
        if not all_verdicts:
            return {"consensus_verdict": SecurityVerdict.UNKNOWN.value, "consensus_strength": 0.0}
        
        # Count verdicts weighted by confidence
        verdict_weights = {}
        total_weight = 0.0
        
        for verdict_data in all_verdicts:
            verdict = verdict_data["verdict"]
            confidence = verdict_data["confidence"]
            
            if verdict not in verdict_weights:
                verdict_weights[verdict] = 0.0
            
            verdict_weights[verdict] += confidence
            total_weight += confidence
        
        # Find consensus verdict
        if verdict_weights:
            consensus_verdict = max(verdict_weights.keys(), key=lambda k: verdict_weights[k])
            consensus_strength = verdict_weights[consensus_verdict] / total_weight
        else:
            consensus_verdict = SecurityVerdict.UNKNOWN.value
            consensus_strength = 0.0
        
        return {
            "consensus_verdict": consensus_verdict,
            "consensus_strength": consensus_strength,
            "verdict_distribution": verdict_weights
        }
    
    def _identify_conflicting_verdicts(self, all_verdicts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify conflicting verdicts between security sources"""
        conflicts = []
        
        # Group verdicts by source type
        defender_verdicts = [v for v in all_verdicts if v["source"].startswith("defender")]
        eop_verdicts = [v for v in all_verdicts if v["source"].startswith("eop")]
        trace_verdicts = [v for v in all_verdicts if v["source"].startswith("trace")]
        
        # Check for conflicts between major categories
        verdict_groups = [
            ("defender", defender_verdicts),
            ("eop", eop_verdicts),
            ("trace", trace_verdicts)
        ]
        
        for i, (source1, verdicts1) in enumerate(verdict_groups):
            for j, (source2, verdicts2) in enumerate(verdict_groups):
                if i < j and verdicts1 and verdicts2:
                    # Compare primary verdicts
                    primary_verdict1 = verdicts1[0]["verdict"]
                    primary_verdict2 = verdicts2[0]["verdict"]
                    
                    if self._are_verdicts_conflicting(primary_verdict1, primary_verdict2):
                        conflicts.append({
                            "source1": source1,
                            "verdict1": primary_verdict1,
                            "source2": source2,
                            "verdict2": primary_verdict2,
                            "conflict_severity": self._assess_conflict_severity(primary_verdict1, primary_verdict2)
                        })
        
        return conflicts
    
    def _are_verdicts_conflicting(self, verdict1: str, verdict2: str) -> bool:
        """Check if two verdicts are conflicting"""
        # Define conflicting verdict pairs
        conflicting_pairs = [
            (SecurityVerdict.CLEAN.value, SecurityVerdict.MALICIOUS.value),
            (SecurityVerdict.CLEAN.value, SecurityVerdict.QUARANTINED.value),
            (SecurityVerdict.CLEAN.value, SecurityVerdict.BLOCKED.value),
            (SecurityVerdict.SUSPICIOUS.value, SecurityVerdict.MALICIOUS.value)
        ]
        
        return (verdict1, verdict2) in conflicting_pairs or (verdict2, verdict1) in conflicting_pairs
    
    def _assess_conflict_severity(self, verdict1: str, verdict2: str) -> str:
        """Assess severity of verdict conflict"""
        high_severity_verdicts = [SecurityVerdict.MALICIOUS.value, SecurityVerdict.BLOCKED.value]
        
        if verdict1 in high_severity_verdicts or verdict2 in high_severity_verdicts:
            return "high"
        elif SecurityVerdict.SUSPICIOUS.value in [verdict1, verdict2]:
            return "medium"
        else:
            return "low"
    
    def _calculate_overall_verdict(self, security_consensus: Dict[str, Any], 
                                 conflicting_verdicts: List[Dict[str, Any]]) -> str:
        """Calculate overall security verdict"""
        consensus_verdict = security_consensus.get("consensus_verdict", SecurityVerdict.UNKNOWN.value)
        consensus_strength = security_consensus.get("consensus_strength", 0.0)
        
        # If strong consensus, use consensus verdict
        if consensus_strength >= 0.7:
            return consensus_verdict
        
        # If conflicts, lean toward more severe verdict
        if conflicting_verdicts:
            high_severity_conflicts = [c for c in conflicting_verdicts if c["conflict_severity"] == "high"]
            if high_severity_conflicts:
                return SecurityVerdict.SUSPICIOUS.value  # Conservative approach
        
        # Default to consensus verdict or unknown
        return consensus_verdict if consensus_verdict != SecurityVerdict.UNKNOWN.value else SecurityVerdict.UNKNOWN.value
    
    def _calculate_security_confidence(self, security_consensus: Dict[str, Any], 
                                     conflicting_verdicts: List[Dict[str, Any]]) -> float:
        """Calculate overall security confidence score"""
        base_confidence = security_consensus.get("consensus_strength", 0.0)
        
        # Reduce confidence for conflicts
        conflict_penalty = len(conflicting_verdicts) * 0.1
        
        # Reduce confidence for high-severity conflicts
        high_severity_conflicts = [c for c in conflicting_verdicts if c["conflict_severity"] == "high"]
        high_severity_penalty = len(high_severity_conflicts) * 0.2
        
        final_confidence = base_confidence - conflict_penalty - high_severity_penalty
        
        return max(final_confidence, 0.0)
    
    def _extract_threat_indicators(self, verdict_analysis: Dict[str, Any],
                                 trace_analysis: Dict[str, Any],
                                 eop_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract threat indicators from all security analyses"""
        threat_indicators = []
        
        # Extract from defender verdicts
        defender_verdicts = verdict_analysis.get("defender_verdicts", {})
        for component, verdict_data in defender_verdicts.items():
            verdict = verdict_data.get("verdict")
            if verdict in [SecurityVerdict.MALICIOUS.value, SecurityVerdict.SUSPICIOUS.value]:
                threat_indicators.append({
                    "indicator_type": "security_verdict",
                    "source": component,
                    "indicator": verdict,
                    "severity": "high" if verdict == SecurityVerdict.MALICIOUS.value else "medium"
                })
        
        # Extract from security interventions
        security_interventions = trace_analysis.get("security_interventions", [])
        for intervention in security_interventions:
            if intervention["intervention_type"] in ["QUARANTINE", "BLOCK"]:
                threat_indicators.append({
                    "indicator_type": "security_intervention",
                    "source": "message_trace",
                    "indicator": intervention["intervention_type"],
                    "severity": "high"
                })
        
        return threat_indicators
    
    def _identify_protection_gaps(self, verdict_analysis: Dict[str, Any],
                                trace_analysis: Dict[str, Any],
                                eop_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify gaps in protection mechanisms"""
        protection_gaps = []
        
        # Check if threat was detected but not blocked
        threat_indicators = self._extract_threat_indicators(verdict_analysis, trace_analysis, eop_analysis)
        security_interventions = trace_analysis.get("security_interventions", [])
        
        if threat_indicators and not security_interventions:
            protection_gaps.append({
                "gap_type": "detection_without_action",
                "description": "Threats detected but no protective actions taken",
                "severity": "high"
            })
        
        # Check for incomplete scanning
        defender_verdicts = verdict_analysis.get("defender_verdicts", {})
        if len(defender_verdicts) < 2:  # Expected multiple Defender components
            protection_gaps.append({
                "gap_type": "incomplete_scanning",
                "description": "Not all Defender protection components engaged",
                "severity": "medium"
            })
        
        return protection_gaps
    
    def _generate_security_recommendations(self, overall_verdict: str,
                                         threat_indicators: List[Dict[str, Any]],
                                         protection_gaps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        # Verdict-based recommendations
        if overall_verdict == SecurityVerdict.MALICIOUS.value:
            recommendations.append({
                "recommendation_type": "immediate_action",
                "action": "quarantine_message",
                "priority": "critical",
                "description": "Immediately quarantine malicious message and investigate"
            })
        elif overall_verdict == SecurityVerdict.SUSPICIOUS.value:
            recommendations.append({
                "recommendation_type": "enhanced_monitoring",
                "action": "monitor_recipients",
                "priority": "high", 
                "description": "Monitor recipient activities for suspicious behavior"
            })
        
        # Threat indicator recommendations
        if threat_indicators:
            recommendations.append({
                "recommendation_type": "threat_hunting",
                "action": "search_similar_threats",
                "priority": "high",
                "description": "Hunt for similar threats using identified indicators"
            })
        
        # Protection gap recommendations
        for gap in protection_gaps:
            if gap["gap_type"] == "detection_without_action":
                recommendations.append({
                    "recommendation_type": "policy_review",
                    "action": "review_protection_policies",
                    "priority": "medium",
                    "description": "Review and strengthen protection policies"
                })
        
        return recommendations
    
    def _is_internal_domain(self, domain: str) -> bool:
        """Check if domain is internal"""
        internal_indicators = ['.local', '.internal', '.corp', '.company']
        return any(indicator in domain.lower() for indicator in internal_indicators)
                                                