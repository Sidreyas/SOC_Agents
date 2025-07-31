"""
Sentinel Integration Module
State 7: Microsoft Sentinel Integration and Synchronization
Integrates with Microsoft Sentinel for incident lifecycle management
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Union
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
import json
import aiohttp
import hashlib
import base64
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

class SentinelStatus(Enum):
    """Sentinel incident status values"""
    NEW = "New"
    ACTIVE = "Active"
    CLOSED = "Closed"

class SentinelClassification(Enum):
    """Sentinel incident classification"""
    UNDETERMINED = "Undetermined"
    TRUE_POSITIVE = "TruePositive"
    BENIGN_POSITIVE = "BenignPositive"
    FALSE_POSITIVE = "FalsePositive"

class SentinelSeverity(Enum):
    """Sentinel severity levels"""
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"

class SentinelLabel(Enum):
    """Sentinel incident labels"""
    AUTOMATED_INVESTIGATION = "AutomatedInvestigation"
    MANUAL_INVESTIGATION = "ManualInvestigation"
    ESCALATED = "Escalated"
    SOC_RESPONSE = "SOCResponse"

@dataclass
class SentinelComment:
    """Sentinel incident comment structure"""
    message: str
    author: str
    created_time: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "message": self.message,
            "author": self.author,
            "createdTimeUtc": self.created_time.isoformat() + "Z"
        }

@dataclass
class SentinelBookmark:
    """Sentinel investigation bookmark"""
    display_name: str
    query: str
    query_result: Optional[str]
    notes: Optional[str]
    labels: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "displayName": self.display_name,
            "query": self.query,
            "queryResult": self.query_result,
            "notes": self.notes,
            "labels": self.labels
        }

class SentinelIntegrator:
    """
    Microsoft Sentinel integration for incident lifecycle management
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.base_url = config.get("sentinel_base_url", "https://management.azure.com")
        self.subscription_id = config.get("subscription_id")
        self.resource_group = config.get("resource_group")
        self.workspace_name = config.get("workspace_name")
        self.tenant_id = config.get("tenant_id")
        self.client_id = config.get("client_id")
        self.client_secret = config.get("client_secret")
        
        self.api_version = "2023-02-01"
        self.access_token = None
        self.token_expires = None
        
        self.integration_stats = {
            "incidents_created": 0,
            "incidents_updated": 0,
            "incidents_closed": 0,
            "comments_added": 0,
            "bookmarks_created": 0,
            "api_calls_made": 0,
            "errors_encountered": 0
        }
        
        # Mapping between internal and Sentinel values
        self.severity_mapping = {
            "critical": SentinelSeverity.HIGH.value,
            "high": SentinelSeverity.HIGH.value,
            "medium": SentinelSeverity.MEDIUM.value,
            "low": SentinelSeverity.LOW.value,
            "informational": SentinelSeverity.INFORMATIONAL.value
        }
        
        self.status_mapping = {
            "new": SentinelStatus.NEW.value,
            "in_progress": SentinelStatus.ACTIVE.value,
            "active": SentinelStatus.ACTIVE.value,
            "investigating": SentinelStatus.ACTIVE.value,
            "resolved": SentinelStatus.CLOSED.value,
            "closed": SentinelStatus.CLOSED.value
        }
    
    async def authenticate(self) -> bool:
        """Authenticate with Microsoft Sentinel API"""
        try:
            auth_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
            
            auth_data = {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "https://management.azure.com/.default"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(auth_url, data=auth_data) as response:
                    if response.status == 200:
                        token_data = await response.json()
                        self.access_token = token_data["access_token"]
                        expires_in = token_data.get("expires_in", 3600)
                        self.token_expires = datetime.now() + timedelta(seconds=expires_in - 300)  # 5 min buffer
                        
                        logger.info("Successfully authenticated with Microsoft Sentinel")
                        return True
                    else:
                        error_text = await response.text()
                        logger.error(f"Authentication failed: {response.status} - {error_text}")
                        return False
        
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return False
    
    async def _ensure_authenticated(self) -> bool:
        """Ensure we have a valid authentication token"""
        if not self.access_token or (self.token_expires and datetime.now() >= self.token_expires):
            return await self.authenticate()
        return True
    
    def _get_headers(self) -> Dict[str, str]:
        """Get headers for API requests"""
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
    
    def _build_api_url(self, endpoint: str) -> str:
        """Build full API URL for Sentinel endpoints"""
        base_path = f"/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}/providers/Microsoft.SecurityInsights"
        return urljoin(self.base_url, f"{base_path}{endpoint}?api-version={self.api_version}")
    
    async def sync_incident_to_sentinel(self, 
                                      incident_data: Dict[str, Any],
                                      investigation_results: Dict[str, Any],
                                      validation_results: Dict[str, Any],
                                      documentation_package: Dict[str, Any]) -> Dict[str, Any]:
        """
        Synchronize incident with Microsoft Sentinel
        
        Args:
            incident_data: Core incident information
            investigation_results: Investigation findings and analysis
            validation_results: Validation results and status
            documentation_package: Generated documentation
            
        Returns:
            Synchronization results and Sentinel incident details
        """
        try:
            sync_start_time = datetime.now()
            
            if not await self._ensure_authenticated():
                raise Exception("Failed to authenticate with Microsoft Sentinel")
            
            incident_id = incident_data.get("incident_id", "unknown")
            logger.info(f"Starting Sentinel synchronization for incident {incident_id}")
            
            # Check if incident already exists in Sentinel
            existing_incident = await self._find_existing_incident(incident_id)
            
            if existing_incident:
                # Update existing incident
                sentinel_result = await self._update_sentinel_incident(
                    existing_incident, incident_data, investigation_results, 
                    validation_results, documentation_package
                )
            else:
                # Create new incident
                sentinel_result = await self._create_sentinel_incident(
                    incident_data, investigation_results, validation_results, documentation_package
                )
            
            # Add investigation comments
            await self._add_investigation_comments(
                sentinel_result["incident_id"], investigation_results
            )
            
            # Create investigation bookmarks
            await self._create_investigation_bookmarks(
                sentinel_result["incident_id"], investigation_results
            )
            
            # Update incident with final status
            if validation_results.get("validation_summary", {}).get("overall_status") == "passed":
                await self._close_sentinel_incident(
                    sentinel_result["incident_id"], validation_results, documentation_package
                )
            
            sync_duration = (datetime.now() - sync_start_time).total_seconds()
            
            logger.info(f"Sentinel synchronization completed for incident {incident_id}")
            
            return {
                "status": "completed",
                "incident_id": incident_id,
                "sentinel_incident_id": sentinel_result["incident_id"],
                "sync_summary": {
                    "operation": sentinel_result["operation"],
                    "sync_duration": sync_duration,
                    "comments_added": sentinel_result.get("comments_added", 0),
                    "bookmarks_created": sentinel_result.get("bookmarks_created", 0),
                    "final_status": sentinel_result.get("final_status", "active")
                },
                "sentinel_details": sentinel_result["incident_details"],
                "sync_metadata": {
                    "sync_timestamp": sync_start_time.isoformat(),
                    "api_version": self.api_version,
                    "workspace": self.workspace_name
                }
            }
            
        except Exception as e:
            self.integration_stats["errors_encountered"] += 1
            logger.error(f"Error synchronizing with Sentinel: {str(e)}")
            return {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    async def _find_existing_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Find existing incident in Sentinel by external reference"""
        try:
            # Search for incident with matching external reference
            search_url = self._build_api_url("/incidents")
            
            headers = self._get_headers()
            
            async with aiohttp.ClientSession() as session:
                async with session.get(search_url, headers=headers) as response:
                    self.integration_stats["api_calls_made"] += 1
                    
                    if response.status == 200:
                        incidents_data = await response.json()
                        incidents = incidents_data.get("value", [])
                        
                        # Look for incident with matching external reference
                        for incident in incidents:
                            properties = incident.get("properties", {})
                            additional_data = properties.get("additionalData", {})
                            if additional_data.get("externalIncidentId") == incident_id:
                                return incident
                        
                        return None
                    else:
                        logger.warning(f"Failed to search incidents: {response.status}")
                        return None
        
        except Exception as e:
            logger.error(f"Error searching for existing incident: {str(e)}")
            return None
    
    async def _create_sentinel_incident(self, 
                                      incident_data: Dict[str, Any],
                                      investigation_results: Dict[str, Any],
                                      validation_results: Dict[str, Any],
                                      documentation_package: Dict[str, Any]) -> Dict[str, Any]:
        """Create new incident in Microsoft Sentinel"""
        
        incident_id = incident_data.get("incident_id", "unknown")
        classification = incident_data.get("classification", {})
        
        # Build incident properties
        incident_properties = {
            "title": f"SOC Investigation: {incident_data.get('description', 'Security Incident')}",
            "description": self._build_incident_description(incident_data, investigation_results),
            "severity": self._map_severity(classification.get("severity", "medium")),
            "status": SentinelStatus.ACTIVE.value,
            "classification": SentinelClassification.UNDETERMINED.value,
            "classificationComment": "Automated investigation in progress",
            "owner": {
                "objectId": None,
                "email": "soc-team@company.com",
                "assignedTo": "SOC Automation",
                "userPrincipalName": "soc-automation@company.com"
            },
            "labels": [
                SentinelLabel.AUTOMATED_INVESTIGATION.value,
                SentinelLabel.SOC_RESPONSE.value
            ],
            "firstActivityTimeUtc": incident_data.get("timestamp", datetime.now().isoformat()) + "Z",
            "lastActivityTimeUtc": datetime.now().isoformat() + "Z",
            "additionalData": {
                "externalIncidentId": incident_id,
                "alertsCount": 1,
                "bookmarksCount": 0,
                "commentsCount": 0,
                "tactics": self._extract_tactics(investigation_results),
                "techniques": self._extract_techniques(investigation_results)
            }
        }
        
        incident_payload = {
            "properties": incident_properties
        }
        
        # Create incident
        create_url = self._build_api_url(f"/incidents/{incident_id}")
        headers = self._get_headers()
        
        async with aiohttp.ClientSession() as session:
            async with session.put(create_url, headers=headers, json=incident_payload) as response:
                self.integration_stats["api_calls_made"] += 1
                
                if response.status in [200, 201]:
                    incident_response = await response.json()
                    self.integration_stats["incidents_created"] += 1
                    
                    logger.info(f"Created Sentinel incident for {incident_id}")
                    
                    return {
                        "operation": "created",
                        "incident_id": incident_id,
                        "incident_details": incident_response,
                        "comments_added": 0,
                        "bookmarks_created": 0
                    }
                else:
                    error_text = await response.text()
                    raise Exception(f"Failed to create incident: {response.status} - {error_text}")
    
    async def _update_sentinel_incident(self, 
                                      existing_incident: Dict[str, Any],
                                      incident_data: Dict[str, Any],
                                      investigation_results: Dict[str, Any],
                                      validation_results: Dict[str, Any],
                                      documentation_package: Dict[str, Any]) -> Dict[str, Any]:
        """Update existing incident in Microsoft Sentinel"""
        
        incident_id = incident_data.get("incident_id", "unknown")
        sentinel_incident_id = existing_incident["name"]
        
        # Build update properties
        properties = existing_incident.get("properties", {})
        
        # Update description with investigation findings
        properties["description"] = self._build_incident_description(incident_data, investigation_results)
        
        # Update classification if validation completed
        validation_status = validation_results.get("validation_summary", {}).get("overall_status")
        if validation_status == "passed":
            properties["classification"] = SentinelClassification.TRUE_POSITIVE.value
            properties["classificationComment"] = "Investigation completed - confirmed security incident"
        elif validation_status == "failed":
            properties["classification"] = SentinelClassification.BENIGN_POSITIVE.value
            properties["classificationComment"] = "Investigation completed - no threat confirmed"
        
        # Update additional data
        additional_data = properties.get("additionalData", {})
        additional_data.update({
            "lastUpdated": datetime.now().isoformat() + "Z",
            "investigationComplete": validation_status == "passed",
            "tactics": self._extract_tactics(investigation_results),
            "techniques": self._extract_techniques(investigation_results)
        })
        
        properties["additionalData"] = additional_data
        properties["lastActivityTimeUtc"] = datetime.now().isoformat() + "Z"
        
        update_payload = {"properties": properties}
        
        # Update incident
        update_url = self._build_api_url(f"/incidents/{sentinel_incident_id}")
        headers = self._get_headers()
        
        async with aiohttp.ClientSession() as session:
            async with session.put(update_url, headers=headers, json=update_payload) as response:
                self.integration_stats["api_calls_made"] += 1
                
                if response.status == 200:
                    incident_response = await response.json()
                    self.integration_stats["incidents_updated"] += 1
                    
                    logger.info(f"Updated Sentinel incident {sentinel_incident_id}")
                    
                    return {
                        "operation": "updated",
                        "incident_id": incident_id,
                        "incident_details": incident_response,
                        "comments_added": 0,
                        "bookmarks_created": 0
                    }
                else:
                    error_text = await response.text()
                    raise Exception(f"Failed to update incident: {response.status} - {error_text}")
    
    async def _close_sentinel_incident(self, 
                                     incident_id: str,
                                     validation_results: Dict[str, Any],
                                     documentation_package: Dict[str, Any]) -> Dict[str, Any]:
        """Close incident in Microsoft Sentinel"""
        
        validation_summary = validation_results.get("validation_summary", {})
        
        # Determine classification based on validation
        if validation_summary.get("overall_status") == "passed":
            classification = SentinelClassification.TRUE_POSITIVE.value
            classification_comment = "Investigation completed successfully - threat confirmed and resolved"
        else:
            classification = SentinelClassification.BENIGN_POSITIVE.value
            classification_comment = "Investigation completed - no significant threat identified"
        
        # Build closure properties
        closure_properties = {
            "status": SentinelStatus.CLOSED.value,
            "classification": classification,
            "classificationComment": classification_comment,
            "classificationReason": "InvestigationCompleted",
            "lastActivityTimeUtc": datetime.now().isoformat() + "Z",
            "additionalData": {
                "closedTime": datetime.now().isoformat() + "Z",
                "validationScore": validation_summary.get("success_score", 0),
                "documentationPackageId": documentation_package.get("package_id"),
                "investigationDuration": self._calculate_investigation_duration(validation_results)
            }
        }
        
        update_payload = {"properties": closure_properties}
        
        # Close incident
        close_url = self._build_api_url(f"/incidents/{incident_id}")
        headers = self._get_headers()
        
        async with aiohttp.ClientSession() as session:
            async with session.patch(close_url, headers=headers, json=update_payload) as response:
                self.integration_stats["api_calls_made"] += 1
                
                if response.status == 200:
                    self.integration_stats["incidents_closed"] += 1
                    logger.info(f"Closed Sentinel incident {incident_id}")
                    return {"status": "closed", "classification": classification}
                else:
                    logger.warning(f"Failed to close incident: {response.status}")
                    return {"status": "error", "error": f"Failed to close: {response.status}"}
    
    async def _add_investigation_comments(self, 
                                        incident_id: str,
                                        investigation_results: Dict[str, Any]) -> int:
        """Add investigation comments to Sentinel incident"""
        
        comments_added = 0
        
        try:
            # Create timeline comment
            timeline_comment = self._build_timeline_comment(investigation_results)
            if timeline_comment:
                await self._add_comment(incident_id, timeline_comment)
                comments_added += 1
            
            # Create findings comment
            findings_comment = self._build_findings_comment(investigation_results)
            if findings_comment:
                await self._add_comment(incident_id, findings_comment)
                comments_added += 1
            
            # Create summary comment
            summary_comment = self._build_summary_comment(investigation_results)
            if summary_comment:
                await self._add_comment(incident_id, summary_comment)
                comments_added += 1
            
        except Exception as e:
            logger.error(f"Error adding comments: {str(e)}")
        
        return comments_added
    
    async def _add_comment(self, incident_id: str, comment: SentinelComment) -> bool:
        """Add a single comment to Sentinel incident"""
        
        comment_id = f"comment_{int(datetime.now().timestamp())}"
        comment_url = self._build_api_url(f"/incidents/{incident_id}/comments/{comment_id}")
        headers = self._get_headers()
        
        comment_payload = {
            "properties": comment.to_dict()
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.put(comment_url, headers=headers, json=comment_payload) as response:
                self.integration_stats["api_calls_made"] += 1
                
                if response.status in [200, 201]:
                    self.integration_stats["comments_added"] += 1
                    return True
                else:
                    logger.warning(f"Failed to add comment: {response.status}")
                    return False
    
    async def _create_investigation_bookmarks(self, 
                                            incident_id: str,
                                            investigation_results: Dict[str, Any]) -> int:
        """Create investigation bookmarks in Sentinel"""
        
        bookmarks_created = 0
        
        try:
            # Create evidence bookmark
            evidence_bookmark = self._build_evidence_bookmark(investigation_results)
            if evidence_bookmark:
                await self._add_bookmark(incident_id, evidence_bookmark)
                bookmarks_created += 1
            
            # Create IoC bookmark
            ioc_bookmark = self._build_ioc_bookmark(investigation_results)
            if ioc_bookmark:
                await self._add_bookmark(incident_id, ioc_bookmark)
                bookmarks_created += 1
            
            # Create timeline bookmark
            timeline_bookmark = self._build_timeline_bookmark(investigation_results)
            if timeline_bookmark:
                await self._add_bookmark(incident_id, timeline_bookmark)
                bookmarks_created += 1
            
        except Exception as e:
            logger.error(f"Error creating bookmarks: {str(e)}")
        
        return bookmarks_created
    
    async def _add_bookmark(self, incident_id: str, bookmark: SentinelBookmark) -> bool:
        """Add a single bookmark to Sentinel"""
        
        bookmark_id = f"bookmark_{int(datetime.now().timestamp())}"
        bookmark_url = self._build_api_url(f"/bookmarks/{bookmark_id}")
        headers = self._get_headers()
        
        bookmark_payload = {
            "properties": {
                **bookmark.to_dict(),
                "incidentInfo": {
                    "incidentId": incident_id,
                    "relationName": "investigation_evidence"
                }
            }
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.put(bookmark_url, headers=headers, json=bookmark_payload) as response:
                self.integration_stats["api_calls_made"] += 1
                
                if response.status in [200, 201]:
                    self.integration_stats["bookmarks_created"] += 1
                    return True
                else:
                    logger.warning(f"Failed to add bookmark: {response.status}")
                    return False
    
    def _build_incident_description(self, 
                                  incident_data: Dict[str, Any],
                                  investigation_results: Dict[str, Any]) -> str:
        """Build comprehensive incident description"""
        
        description_parts = []
        
        # Basic incident info
        description_parts.append(f"Incident ID: {incident_data.get('incident_id', 'Unknown')}")
        description_parts.append(f"Detection Time: {incident_data.get('timestamp', 'Unknown')}")
        description_parts.append(f"Source: {incident_data.get('source', 'Unknown')}")
        description_parts.append("")
        
        # Incident description
        description_parts.append("Incident Description:")
        description_parts.append(incident_data.get("description", "No description available"))
        description_parts.append("")
        
        # Investigation summary
        analysis_summary = investigation_results.get("analysis_results", {}).get("summary", {})
        if analysis_summary:
            description_parts.append("Investigation Summary:")
            description_parts.append(f"Threat Level: {analysis_summary.get('threat_level', 'Unknown')}")
            description_parts.append(f"Scope: {analysis_summary.get('incident_scope', 'Unknown')}")
            
            findings = analysis_summary.get("key_findings", [])
            if findings:
                description_parts.append("Key Findings:")
                for finding in findings[:3]:  # Top 3 findings
                    description_parts.append(f"- {finding}")
        
        return "\n".join(description_parts)
    
    def _build_timeline_comment(self, investigation_results: Dict[str, Any]) -> Optional[SentinelComment]:
        """Build timeline comment for investigation"""
        
        workflow_history = investigation_results.get("workflow_history", [])
        if not workflow_history:
            return None
        
        timeline_parts = ["Investigation Timeline:", ""]
        
        for entry in workflow_history[:10]:  # Last 10 entries
            timestamp = entry.get("timestamp", "Unknown")
            state = entry.get("state", "Unknown")
            timeline_parts.append(f"{timestamp}: {state}")
        
        return SentinelComment(
            message="\n".join(timeline_parts),
            author="SOC Automation",
            created_time=datetime.now()
        )
    
    def _build_findings_comment(self, investigation_results: Dict[str, Any]) -> Optional[SentinelComment]:
        """Build findings comment for investigation"""
        
        analysis_results = investigation_results.get("analysis_results", {})
        executed_tasks = analysis_results.get("executed_tasks", [])
        
        if not executed_tasks:
            return None
        
        findings_parts = ["Investigation Findings:", ""]
        
        for task in executed_tasks[:5]:  # Top 5 tasks
            task_name = task.get("task_name", "Unknown Task")
            findings = task.get("findings", [])
            
            findings_parts.append(f"{task_name}:")
            for finding in findings[:3]:  # Top 3 findings per task
                findings_parts.append(f"- {finding}")
            findings_parts.append("")
        
        return SentinelComment(
            message="\n".join(findings_parts),
            author="SOC Automation", 
            created_time=datetime.now()
        )
    
    def _build_summary_comment(self, investigation_results: Dict[str, Any]) -> Optional[SentinelComment]:
        """Build summary comment for investigation"""
        
        analysis_summary = investigation_results.get("analysis_results", {}).get("summary", {})
        if not analysis_summary:
            return None
        
        summary_parts = ["Investigation Summary:", ""]
        
        summary_parts.append(f"Threat Level: {analysis_summary.get('threat_level', 'Unknown')}")
        summary_parts.append(f"Incident Scope: {analysis_summary.get('incident_scope', 'Unknown')}")
        summary_parts.append(f"Containment Status: {analysis_summary.get('containment_status', 'Unknown')}")
        summary_parts.append("")
        
        recommendations = analysis_summary.get("recommendations", [])
        if recommendations:
            summary_parts.append("Recommendations:")
            for rec in recommendations[:3]:
                summary_parts.append(f"- {rec}")
        
        return SentinelComment(
            message="\n".join(summary_parts),
            author="SOC Automation",
            created_time=datetime.now()
        )
    
    def _build_evidence_bookmark(self, investigation_results: Dict[str, Any]) -> Optional[SentinelBookmark]:
        """Build evidence bookmark for investigation"""
        
        evidence_data = investigation_results.get("evidence_data", {})
        if not evidence_data:
            return None
        
        query = "SecurityAlert | where TimeGenerated > ago(24h) | summarize count() by AlertName"
        
        return SentinelBookmark(
            display_name="Investigation Evidence",
            query=query,
            query_result=json.dumps(evidence_data.get("correlation_report", {})),
            notes="Evidence collected during automated investigation",
            labels=["investigation", "evidence", "soc-automation"]
        )
    
    def _build_ioc_bookmark(self, investigation_results: Dict[str, Any]) -> Optional[SentinelBookmark]:
        """Build IoC bookmark for investigation"""
        
        evidence_data = investigation_results.get("evidence_data", {})
        key_indicators = evidence_data.get("correlation_report", {}).get("key_indicators", {})
        
        if not key_indicators:
            return None
        
        query = "CommonSecurityLog | where TimeGenerated > ago(7d) | where DeviceVendor == 'Investigation' | project TimeGenerated, SourceIP, DestinationIP"
        
        return SentinelBookmark(
            display_name="Investigation IoCs",
            query=query,
            query_result=json.dumps(key_indicators),
            notes="Indicators of Compromise identified during investigation",
            labels=["ioc", "investigation", "threat-intel"]
        )
    
    def _build_timeline_bookmark(self, investigation_results: Dict[str, Any]) -> Optional[SentinelBookmark]:
        """Build timeline bookmark for investigation"""
        
        timeline = investigation_results.get("evidence_data", {}).get("correlation_report", {}).get("timeline", [])
        
        if not timeline:
            return None
        
        query = "SecurityEvent | where TimeGenerated > ago(24h) | order by TimeGenerated asc | project TimeGenerated, EventID, Computer, Account"
        
        return SentinelBookmark(
            display_name="Investigation Timeline",
            query=query,
            query_result=json.dumps(timeline[:20]),  # First 20 events
            notes="Timeline of events during incident investigation",
            labels=["timeline", "investigation", "chronology"]
        )
    
    def _map_severity(self, severity: str) -> str:
        """Map internal severity to Sentinel severity"""
        return self.severity_mapping.get(severity.lower(), SentinelSeverity.MEDIUM.value)
    
    def _extract_tactics(self, investigation_results: Dict[str, Any]) -> List[str]:
        """Extract MITRE ATT&CK tactics from investigation"""
        tactics = []
        
        executed_tasks = investigation_results.get("analysis_results", {}).get("executed_tasks", [])
        for task in executed_tasks:
            findings = task.get("findings", [])
            for finding in findings:
                if "initial access" in finding.lower():
                    tactics.append("InitialAccess")
                if "execution" in finding.lower():
                    tactics.append("Execution")
                if "persistence" in finding.lower():
                    tactics.append("Persistence")
                if "lateral movement" in finding.lower():
                    tactics.append("LateralMovement")
        
        return list(set(tactics))  # Remove duplicates
    
    def _extract_techniques(self, investigation_results: Dict[str, Any]) -> List[str]:
        """Extract MITRE ATT&CK techniques from investigation"""
        techniques = []
        
        executed_tasks = investigation_results.get("analysis_results", {}).get("executed_tasks", [])
        for task in executed_tasks:
            findings = task.get("findings", [])
            for finding in findings:
                if "phishing" in finding.lower():
                    techniques.append("T1566")
                if "malware" in finding.lower():
                    techniques.append("T1204")
                if "powershell" in finding.lower():
                    techniques.append("T1059.001")
        
        return list(set(techniques))  # Remove duplicates
    
    def _calculate_investigation_duration(self, validation_results: Dict[str, Any]) -> str:
        """Calculate investigation duration"""
        validation_summary = validation_results.get("validation_summary", {})
        validation_date = validation_summary.get("validation_date")
        
        if validation_date:
            # Assuming investigation started 24 hours ago (simplified)
            duration = timedelta(hours=24)
            return str(duration)
        
        return "Unknown"
    
    async def get_integration_statistics(self) -> Dict[str, Any]:
        """Get Sentinel integration statistics"""
        return {
            "integration_stats": self.integration_stats,
            "configuration": {
                "workspace": self.workspace_name,
                "resource_group": self.resource_group,
                "api_version": self.api_version
            },
            "mappings": {
                "severity_mapping": self.severity_mapping,
                "status_mapping": self.status_mapping
            }
        }

def create_sentinel_integrator(config: Dict[str, Any]) -> SentinelIntegrator:
    """Factory function to create Sentinel integrator"""
    return SentinelIntegrator(config)

# Example usage
async def main():
    config = {
        "sentinel_base_url": "https://management.azure.com",
        "subscription_id": "your-subscription-id",
        "resource_group": "your-resource-group",
        "workspace_name": "your-sentinel-workspace",
        "tenant_id": "your-tenant-id",
        "client_id": "your-client-id",
        "client_secret": "your-client-secret"
    }
    
    integrator = create_sentinel_integrator(config)
    
    # Example sync
    sample_incident = {
        "incident_id": "inc_001",
        "description": "Critical malware detected",
        "timestamp": datetime.now().isoformat(),
        "classification": {"severity": "high"}
    }
    
    sample_investigation = {
        "analysis_results": {
            "executed_tasks": [{"task_name": "malware analysis", "findings": ["Trojan detected"]}],
            "summary": {"threat_level": "high"}
        },
        "workflow_history": [{"timestamp": datetime.now().isoformat(), "state": "completed"}]
    }
    
    sample_validation = {
        "validation_summary": {"overall_status": "passed", "success_score": 0.85}
    }
    
    sample_documentation = {
        "package_id": "doc_001",
        "package_summary": {"total_documents": 3}
    }
    
    result = await integrator.sync_incident_to_sentinel(
        sample_incident, sample_investigation, sample_validation, sample_documentation
    )
    
    print(f"Sentinel sync result: {json.dumps(result, indent=2)}")

if __name__ == "__main__":
    asyncio.run(main())
