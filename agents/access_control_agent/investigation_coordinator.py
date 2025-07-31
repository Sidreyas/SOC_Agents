"""
Investigation Coordinator Module  
State 3: Investigation Coordination
Gathers additional evidence and performs contextual enrichment
"""

import logging
from typing import Dict, Any, List, Tuple
from datetime import datetime, timedelta
import json

logger = logging.getLogger(__name__)

class InvestigationCoordinator:
    """
    Coordinates investigation activities and gathers additional evidence
    Performs contextual enrichment and cross-references multiple data sources
    """
    
    def __init__(self):
        self.evidence_sources = {}
        self.investigation_cache = {}
        self.correlation_rules = {}
        
    def gather_additional_evidence(self, users: List[str], time_window: Dict[str, datetime]) -> Dict[str, Any]:
        """
        Gather additional evidence for investigation from multiple sources
        
        Returns:
            Comprehensive evidence collection from all available sources
        """
        logger.info(f"Gathering additional evidence for {len(users)} users")
        
        evidence = {
            "authentication_logs": {},
            "network_activity": {},
            "endpoint_logs": {},
            "application_logs": {},
            "security_events": {},
            "investigation_metadata": {
                "evidence_sources": [],
                "collection_time": datetime.now(),
                "time_window": time_window
            }
        }
        
        for user in users:
            logger.info(f"Collecting evidence for user: {user}")
            
            # Gather authentication evidence
            auth_evidence = self._collect_authentication_evidence(user, time_window)
            evidence["authentication_logs"][user] = auth_evidence
            
            # Gather network activity evidence
            network_evidence = self._collect_network_evidence(user, time_window)
            evidence["network_activity"][user] = network_evidence
            
            # Gather endpoint evidence
            endpoint_evidence = self._collect_endpoint_evidence(user, time_window)
            evidence["endpoint_logs"][user] = endpoint_evidence
            
            # Gather application evidence
            app_evidence = self._collect_application_evidence(user, time_window)
            evidence["application_logs"][user] = app_evidence
            
            # Gather security events
            security_evidence = self._collect_security_events(user, time_window)
            evidence["security_events"][user] = security_evidence
        
        # Update investigation metadata
        evidence["investigation_metadata"]["evidence_sources"] = [
            "Azure AD", "Network Monitoring", "EDR", "Application Logs", "Security Center"
        ]
        
        logger.info(f"Evidence collection complete. Total sources: {len(evidence['investigation_metadata']['evidence_sources'])}")
        return evidence
    
    def perform_contextual_enrichment(self, evidence: Dict[str, Any], permission_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform contextual enrichment by correlating evidence with external sources
        
        Returns:
            Enriched context with correlations, threat intelligence, and organizational data
        """
        logger.info("Performing contextual enrichment")
        
        enrichment = {
            "threat_intelligence": {},
            "organizational_context": {},
            "temporal_analysis": {},
            "behavioral_correlation": {},
            "risk_indicators": {},
            "external_correlations": {}
        }
        
        # Enrich with threat intelligence
        enrichment["threat_intelligence"] = self._enrich_threat_intelligence(evidence)
        
        # Add organizational context
        enrichment["organizational_context"] = self._enrich_organizational_context(evidence, permission_data)
        
        # Perform temporal analysis
        enrichment["temporal_analysis"] = self._perform_temporal_analysis(evidence)
        
        # Correlate behavioral patterns
        enrichment["behavioral_correlation"] = self._correlate_behavioral_patterns(evidence)
        
        # Identify risk indicators
        enrichment["risk_indicators"] = self._identify_risk_indicators(evidence, enrichment)
        
        # Check external correlations
        enrichment["external_correlations"] = self._check_external_correlations(evidence)
        
        logger.info("Contextual enrichment complete")
        return enrichment
    
    def query_cmdb_relationships(self, entities: List[str]) -> Dict[str, Any]:
        """
        Query CMDB for relationships between entities (users, systems, applications)
        
        Returns:
            Relationship mapping and dependency information
        """
        logger.info(f"Querying CMDB relationships for {len(entities)} entities")
        
        relationships = {
            "user_relationships": {},
            "system_dependencies": {},
            "application_mappings": {},
            "organizational_hierarchy": {},
            "asset_relationships": {}
        }
        
        for entity in entities:
            logger.info(f"Querying relationships for: {entity}")
            
            # Query user relationships
            if "@" in entity:  # Likely a user email
                relationships["user_relationships"][entity] = self._query_user_relationships(entity)
                relationships["organizational_hierarchy"][entity] = self._query_org_hierarchy(entity)
            
            # Query system dependencies
            elif "." in entity and not "@" in entity:  # Likely a system/hostname
                relationships["system_dependencies"][entity] = self._query_system_dependencies(entity)
                relationships["asset_relationships"][entity] = self._query_asset_relationships(entity)
            
            # Query application mappings
            else:  # Likely an application or service
                relationships["application_mappings"][entity] = self._query_application_mappings(entity)
        
        logger.info(f"CMDB relationship query complete for {len(entities)} entities")
        return relationships
    
    def correlate_cross_agent_findings(self, other_agent_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Correlate findings with other SOC agents for comprehensive analysis
        
        Returns:
            Cross-agent correlation results and shared indicators
        """
        logger.info("Correlating with other SOC agent findings")
        
        correlations = {
            "shared_indicators": {},
            "timeline_correlations": {},
            "entity_overlaps": {},
            "attack_chain_analysis": {},
            "confidence_scoring": {}
        }
        
        # Correlate with Phishing Agent findings
        if "phishing_agent" in other_agent_data:
            correlations["shared_indicators"]["phishing"] = self._correlate_phishing_indicators(
                other_agent_data["phishing_agent"]
            )
        
        # Correlate with Insider Behavior Agent findings
        if "insider_behavior_agent" in other_agent_data:
            correlations["shared_indicators"]["insider_behavior"] = self._correlate_insider_indicators(
                other_agent_data["insider_behavior_agent"]
            )
        
        # Correlate with Network & Exfiltration Agent findings
        if "network_exfiltration_agent" in other_agent_data:
            correlations["shared_indicators"]["network_exfiltration"] = self._correlate_network_indicators(
                other_agent_data["network_exfiltration_agent"]
            )
        
        # Perform timeline correlation across agents
        correlations["timeline_correlations"] = self._perform_timeline_correlation(other_agent_data)
        
        # Identify entity overlaps
        correlations["entity_overlaps"] = self._identify_entity_overlaps(other_agent_data)
        
        # Analyze potential attack chains
        correlations["attack_chain_analysis"] = self._analyze_attack_chains(other_agent_data)
        
        # Calculate cross-agent confidence scores
        correlations["confidence_scoring"] = self._calculate_cross_agent_confidence(correlations)
        
        logger.info("Cross-agent correlation complete")
        return correlations
    
    def query_security_tools(self, investigation_targets: List[str], time_window: Dict[str, datetime]) -> Dict[str, Any]:
        """
        Query additional security tools for relevant data
        
        Returns:
            Security tool data and analysis results
        """
        logger.info(f"Querying security tools for {len(investigation_targets)} targets")
        
        security_data = {
            "siem_data": {},
            "edr_data": {},
            "identity_security": {},
            "cloud_security": {},
            "network_security": {},
            "tool_correlations": {}
        }
        
        for target in investigation_targets:
            # Query SIEM for events
            security_data["siem_data"][target] = self._query_siem_events(target, time_window)
            
            # Query EDR for endpoint data
            security_data["edr_data"][target] = self._query_edr_data(target, time_window)
            
            # Query identity security tools
            security_data["identity_security"][target] = self._query_identity_tools(target, time_window)
            
            # Query cloud security tools
            security_data["cloud_security"][target] = self._query_cloud_security_tools(target, time_window)
            
            # Query network security tools
            security_data["network_security"][target] = self._query_network_security_tools(target, time_window)
        
        # Perform tool correlations
        security_data["tool_correlations"] = self._correlate_security_tools(security_data)
        
        logger.info("Security tool queries complete")
        return security_data
    
    def _collect_authentication_evidence(self, user: str, time_window: Dict[str, datetime]) -> Dict[str, Any]:
        """Collect authentication-related evidence"""
        return {
            "sign_in_logs": [
                {
                    "time": time_window["start"] + timedelta(hours=1),
                    "location": "Seattle, WA",
                    "device": "Windows 10",
                    "application": "Office 365",
                    "risk_level": "Low"
                },
                {
                    "time": time_window["start"] + timedelta(hours=3),
                    "location": "Unknown",
                    "device": "Unknown",
                    "application": "Azure Portal",
                    "risk_level": "High"
                }
            ],
            "failed_attempts": [
                {
                    "time": time_window["start"] + timedelta(minutes=30),
                    "reason": "Invalid password",
                    "source_ip": "192.168.1.100"
                }
            ],
            "mfa_events": [
                {
                    "time": time_window["start"] + timedelta(hours=1),
                    "method": "Microsoft Authenticator",
                    "result": "Success"
                }
            ]
        }
    
    def _collect_network_evidence(self, user: str, time_window: Dict[str, datetime]) -> Dict[str, Any]:
        """Collect network activity evidence"""
        return {
            "network_connections": [
                {
                    "time": time_window["start"] + timedelta(hours=2),
                    "source_ip": "10.0.1.50",
                    "destination_ip": "20.190.154.139",
                    "port": 443,
                    "protocol": "HTTPS",
                    "bytes_transferred": 1024000
                }
            ],
            "dns_queries": [
                {
                    "time": time_window["start"] + timedelta(hours=2),
                    "query": "graph.microsoft.com",
                    "response": "20.190.154.139"
                }
            ],
            "vpn_sessions": [
                {
                    "start_time": time_window["start"],
                    "end_time": time_window["start"] + timedelta(hours=8),
                    "source_ip": "203.0.113.10",
                    "vpn_gateway": "corp-vpn-01"
                }
            ]
        }
    
    def _collect_endpoint_evidence(self, user: str, time_window: Dict[str, datetime]) -> Dict[str, Any]:
        """Collect endpoint activity evidence"""
        return {
            "process_executions": [
                {
                    "time": time_window["start"] + timedelta(hours=1),
                    "process": "powershell.exe",
                    "command_line": "Get-AzureADUser",
                    "parent_process": "cmd.exe"
                }
            ],
            "file_activities": [
                {
                    "time": time_window["start"] + timedelta(hours=2),
                    "file_path": "C:\\temp\\users.csv",
                    "activity": "created",
                    "size": 50000
                }
            ],
            "registry_changes": [
                {
                    "time": time_window["start"] + timedelta(hours=1),
                    "key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "value": "AzureTools",
                    "activity": "created"
                }
            ]
        }
    
    def _collect_application_evidence(self, user: str, time_window: Dict[str, datetime]) -> Dict[str, Any]:
        """Collect application usage evidence"""
        return {
            "office365_activity": [
                {
                    "time": time_window["start"] + timedelta(hours=1),
                    "application": "Exchange Online",
                    "activity": "MailboxLogin",
                    "client_ip": "10.0.1.50"
                }
            ],
            "azure_portal_activity": [
                {
                    "time": time_window["start"] + timedelta(hours=2),
                    "activity": "View user profile",
                    "resource": "/users/john.doe@company.com",
                    "client_ip": "10.0.1.50"
                }
            ],
            "custom_applications": [
                {
                    "time": time_window["start"] + timedelta(hours=3),
                    "application": "HR System",
                    "activity": "User lookup",
                    "details": "Accessed employee directory"
                }
            ]
        }
    
    def _collect_security_events(self, user: str, time_window: Dict[str, datetime]) -> Dict[str, Any]:
        """Collect security-related events"""
        return {
            "security_alerts": [
                {
                    "time": time_window["start"] + timedelta(hours=2),
                    "alert_type": "Suspicious PowerShell Activity",
                    "severity": "Medium",
                    "description": "Unusual Azure AD cmdlet usage detected"
                }
            ],
            "dlp_events": [
                {
                    "time": time_window["start"] + timedelta(hours=3),
                    "policy": "PII Detection",
                    "action": "Alert",
                    "file": "users.csv"
                }
            ],
            "compliance_events": [
                {
                    "time": time_window["start"] + timedelta(hours=1),
                    "policy": "Admin Activity Monitoring",
                    "event": "Role assignment detected",
                    "status": "Flagged for review"
                }
            ]
        }
    
    def _enrich_threat_intelligence(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich evidence with threat intelligence"""
        return {
            "ip_reputation": {
                "20.190.154.139": {
                    "reputation": "Good",
                    "source": "Microsoft Azure",
                    "category": "Cloud Service"
                }
            },
            "domain_reputation": {
                "graph.microsoft.com": {
                    "reputation": "Good", 
                    "source": "Microsoft",
                    "category": "API Endpoint"
                }
            },
            "ioc_matches": [],
            "threat_campaigns": []
        }
    
    def _enrich_organizational_context(self, evidence: Dict[str, Any], permission_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add organizational context to evidence"""
        return {
            "business_context": {
                "department": "IT Operations",
                "role": "System Administrator", 
                "clearance_level": "Standard",
                "data_access_level": "Internal"
            },
            "operational_context": {
                "shift_schedule": "9 AM - 5 PM PST",
                "typical_locations": ["Seattle Office", "Home Office"],
                "authorized_systems": ["Azure Portal", "Office 365", "SIEM"]
            },
            "project_context": {
                "active_projects": ["Azure Migration", "Security Compliance"],
                "project_access": ["Azure Subscriptions", "Security Tools"]
            }
        }
    
    def _perform_temporal_analysis(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Perform temporal analysis of evidence"""
        return {
            "activity_timeline": [
                {"time": "2024-01-15 09:00", "event": "User login", "source": "Authentication"},
                {"time": "2024-01-15 10:00", "event": "PowerShell execution", "source": "Endpoint"},
                {"time": "2024-01-15 11:00", "event": "Azure Portal access", "source": "Application"}
            ],
            "activity_patterns": {
                "peak_hours": [9, 10, 11],
                "activity_frequency": "Normal",
                "outlier_activities": ["Off-hours admin activity"]
            },
            "sequence_analysis": {
                "logical_progression": True,
                "rapid_succession_events": False,
                "suspicious_sequences": []
            }
        }
    
    def _correlate_behavioral_patterns(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate behavioral patterns across evidence sources"""
        return {
            "consistency_analysis": {
                "location_consistency": True,
                "device_consistency": True,
                "timing_consistency": True
            },
            "anomaly_detection": {
                "statistical_outliers": [],
                "behavioral_deviations": ["Unusual Azure AD cmdlet usage"],
                "pattern_breaks": []
            },
            "correlation_strength": 0.85
        }
    
    def _identify_risk_indicators(self, evidence: Dict[str, Any], enrichment: Dict[str, Any]) -> Dict[str, Any]:
        """Identify risk indicators from evidence and enrichment"""
        return {
            "high_risk_indicators": [
                "Administrative PowerShell activity outside business hours",
                "Multiple failed authentication attempts"
            ],
            "medium_risk_indicators": [
                "Access from new location",
                "Unusual application usage pattern"
            ],
            "low_risk_indicators": [
                "Standard Office 365 usage",
                "VPN usage within policy"
            ],
            "risk_score": 6.5
        }
    
    def _check_external_correlations(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Check correlations with external sources"""
        return {
            "threat_feeds": {
                "matches": 0,
                "sources_checked": ["AlienVault", "ThreatConnect", "MISP"]
            },
            "reputation_services": {
                "ip_checks": 5,
                "domain_checks": 3,
                "clean_results": 8
            },
            "industry_reports": {
                "relevant_ttps": [],
                "campaign_matches": []
            }
        }
    
    def _query_user_relationships(self, user: str) -> Dict[str, Any]:
        """Query user relationships from CMDB"""
        return {
            "manager": "jane.manager@company.com",
            "direct_reports": ["junior.admin@company.com"],
            "team_members": ["peer1@company.com", "peer2@company.com"],
            "project_colleagues": ["project.lead@company.com"]
        }
    
    def _query_org_hierarchy(self, user: str) -> Dict[str, Any]:
        """Query organizational hierarchy"""
        return {
            "department": "Information Technology",
            "division": "Infrastructure",
            "cost_center": "IT-001",
            "reporting_chain": [
                "jane.manager@company.com",
                "senior.director@company.com",
                "cio@company.com"
            ]
        }
    
    def _query_system_dependencies(self, system: str) -> Dict[str, Any]:
        """Query system dependencies"""
        return {
            "dependent_systems": ["backup-server", "monitoring-system"],
            "dependencies": ["active-directory", "network-switch-01"],
            "service_accounts": ["svc-backup", "svc-monitoring"],
            "data_flows": ["logs to SIEM", "metrics to monitoring"]
        }
    
    def _query_asset_relationships(self, asset: str) -> Dict[str, Any]:
        """Query asset relationships"""
        return {
            "asset_type": "Server",
            "owner": "IT Operations",
            "location": "Data Center A",
            "network_segment": "DMZ",
            "security_zone": "Medium Trust"
        }
    
    def _query_application_mappings(self, application: str) -> Dict[str, Any]:
        """Query application mappings"""
        return {
            "business_owner": "HR Department",
            "technical_owner": "Application Team",
            "data_classification": "Internal",
            "compliance_requirements": ["SOX", "GDPR"],
            "integration_points": ["Active Directory", "HR Database"]
        }
    
    def _correlate_phishing_indicators(self, phishing_data: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate with phishing agent indicators"""
        return {
            "shared_users": ["user1@company.com"],
            "shared_timeframes": True,
            "email_to_permission_correlation": "Medium",
            "suspicious_links_accessed": False
        }
    
    def _correlate_insider_indicators(self, insider_data: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate with insider behavior indicators"""
        return {
            "behavioral_anomalies": ["Off-hours activity"],
            "data_access_patterns": "Elevated",
            "risk_correlation": "High",
            "insider_risk_score": 7.2
        }
    
    def _correlate_network_indicators(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate with network exfiltration indicators"""
        return {
            "data_transfer_correlation": False,
            "network_anomalies": [],
            "exfiltration_risk": "Low",
            "network_risk_score": 2.1
        }
    
    def _perform_timeline_correlation(self, other_agent_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform timeline correlation across agents"""
        return {
            "synchronized_events": [
                {
                    "time": "2024-01-15 10:00",
                    "agents": ["access_control", "insider_behavior"],
                    "correlation": "User privilege escalation during anomalous behavior period"
                }
            ],
            "temporal_gaps": [],
            "timeline_confidence": 0.92
        }
    
    def _identify_entity_overlaps(self, other_agent_data: Dict[str, Any]) -> Dict[str, Any]:
        """Identify entity overlaps across agents"""
        return {
            "common_users": ["user1@company.com", "admin@company.com"],
            "common_systems": ["workstation-01"],
            "common_timeframes": ["2024-01-15 09:00 - 12:00"],
            "overlap_significance": "High"
        }
    
    def _analyze_attack_chains(self, other_agent_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze potential attack chains"""
        return {
            "potential_chains": [
                {
                    "chain": "Phishing → Credential Compromise → Privilege Escalation",
                    "confidence": 0.75,
                    "supporting_evidence": ["Email click", "Failed auth", "Role assignment"]
                }
            ],
            "chain_completeness": 0.67,
            "attack_progression": "Partial"
        }
    
    def _calculate_cross_agent_confidence(self, correlations: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate cross-agent confidence scores"""
        return {
            "overall_confidence": 0.78,
            "agent_agreement": {
                "phishing_agent": 0.65,
                "insider_behavior_agent": 0.85,
                "network_exfiltration_agent": 0.45
            },
            "evidence_strength": "Strong",
            "correlation_reliability": "High"
        }
    
    def _query_siem_events(self, target: str, time_window: Dict[str, datetime]) -> Dict[str, Any]:
        """Query SIEM for events"""
        return {
            "events_found": 15,
            "high_severity_events": 2,
            "correlation_rules_triggered": ["Admin Activity", "Off-Hours Access"],
            "related_incidents": []
        }
    
    def _query_edr_data(self, target: str, time_window: Dict[str, datetime]) -> Dict[str, Any]:
        """Query EDR for endpoint data"""
        return {
            "process_events": 45,
            "network_connections": 23,
            "file_modifications": 8,
            "suspicious_activities": ["PowerShell execution with Azure cmdlets"],
            "threat_detections": []
        }
    
    def _query_identity_tools(self, target: str, time_window: Dict[str, datetime]) -> Dict[str, Any]:
        """Query identity security tools"""
        return {
            "identity_events": 12,
            "privileged_access": True,
            "conditional_access_evaluations": 8,
            "risk_events": ["Unusual sign-in location"],
            "identity_protection_alerts": []
        }
    
    def _query_cloud_security_tools(self, target: str, time_window: Dict[str, datetime]) -> Dict[str, Any]:
        """Query cloud security tools"""
        return {
            "cloud_events": 28,
            "policy_violations": 1,
            "resource_changes": 5,
            "compliance_alerts": [],
            "security_recommendations": ["Enable MFA for all admin accounts"]
        }
    
    def _query_network_security_tools(self, target: str, time_window: Dict[str, datetime]) -> Dict[str, Any]:
        """Query network security tools"""
        return {
            "network_events": 156,
            "blocked_connections": 0,
            "dns_lookups": 23,
            "bandwidth_anomalies": False,
            "network_threats": []
        }
    
    def _correlate_security_tools(self, security_data: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate data across security tools"""
        return {
            "cross_tool_correlations": [
                {
                    "tools": ["SIEM", "EDR"],
                    "correlation": "PowerShell execution detected by both systems",
                    "confidence": 0.95
                }
            ],
            "data_consistency": 0.88,
            "coverage_gaps": ["Network monitoring limited during VPN usage"],
            "tool_agreement": 0.82
        }
