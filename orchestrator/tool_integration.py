"""
Tool Integration Layer Module
Manages access to Microsoft security tools and external services
Implements graceful fallbacks when tools are unavailable
"""

import logging
import asyncio
import json
from typing import Dict, Any, Optional, List, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import uuid

logger = logging.getLogger(__name__)

class ToolStatus(Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    DEGRADED = "degraded"
    AUTHENTICATION_FAILED = "auth_failed"
    RATE_LIMITED = "rate_limited"
    MAINTENANCE = "maintenance"

class ToolCategory(Enum):
    MICROSOFT_SECURITY = "microsoft_security"
    THREAT_INTELLIGENCE = "threat_intelligence"
    EXTERNAL_API = "external_api"
    INTERNAL_TOOL = "internal_tool"

@dataclass
class ToolCapability:
    """Represents a tool capability with availability tracking"""
    tool_name: str
    category: ToolCategory
    description: str
    status: ToolStatus = ToolStatus.UNAVAILABLE
    last_check: datetime = field(default_factory=datetime.now)
    response_time: float = 0.0
    error_count: int = 0
    success_rate: float = 0.0
    rate_limit_reset: Optional[datetime] = None
    fallback_tools: List[str] = field(default_factory=list)

@dataclass
class ToolRequest:
    """Request to execute a tool operation"""
    tool_name: str
    operation: str
    parameters: Dict[str, Any]
    timeout: float = 30.0
    retry_count: int = 0
    max_retries: int = 2
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))

@dataclass
class ToolResponse:
    """Response from tool execution"""
    request_id: str
    tool_name: str
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    response_time: float = 0.0
    used_fallback: bool = False
    fallback_tool: Optional[str] = None

class ToolIntegrationLayer:
    """
    Manages integration with Microsoft security tools and external services
    Provides graceful fallbacks and mock responses when tools are unavailable
    """
    
    def __init__(self):
        self.tool_capabilities: Dict[str, ToolCapability] = {}
        self.mock_mode = True  # Start in mock mode since real tools not available
        self.check_interval = timedelta(minutes=5)
        self.last_availability_check = datetime.now()
        
        # Initialize tool definitions
        self._initialize_tools()
        
        # Start availability monitoring
        asyncio.create_task(self._monitor_tool_availability())
    
    async def execute_tool(self, request: ToolRequest) -> ToolResponse:
        """
        Execute tool operation with fallback handling
        
        Args:
            request: Tool request with operation details
            
        Returns:
            Tool response with data or error information
        """
        start_time = datetime.now()
        
        try:
            # Check if tool is available
            if not self._is_tool_available(request.tool_name):
                logger.warning(f"Tool {request.tool_name} not available, trying fallback")
                return await self._try_fallback_tools(request, start_time)
            
            # Execute the tool operation
            if self.mock_mode:
                response_data = await self._mock_tool_execution(request)
            else:
                response_data = await self._real_tool_execution(request)
            
            # Calculate response time
            response_time = (datetime.now() - start_time).total_seconds()
            
            # Update tool statistics
            self._update_tool_stats(request.tool_name, True, response_time)
            
            return ToolResponse(
                request_id=request.request_id,
                tool_name=request.tool_name,
                success=True,
                data=response_data,
                response_time=response_time
            )
            
        except Exception as e:
            response_time = (datetime.now() - start_time).total_seconds()
            error_msg = str(e)
            
            logger.error(f"Tool {request.tool_name} execution failed: {error_msg}")
            
            # Update error statistics
            self._update_tool_stats(request.tool_name, False, response_time)
            
            # Try fallback if available and retries remain
            if request.retry_count < request.max_retries:
                logger.info(f"Retrying tool {request.tool_name} (attempt {request.retry_count + 1})")
                request.retry_count += 1
                await asyncio.sleep(1)  # Brief delay before retry
                return await self.execute_tool(request)
            
            # Try fallback tools
            return await self._try_fallback_tools(request, start_time, error_msg)
    
    async def execute_batch_tools(self, requests: List[ToolRequest]) -> List[ToolResponse]:
        """Execute multiple tool requests concurrently"""
        logger.info(f"Executing batch of {len(requests)} tool requests")
        
        # Limit concurrent tool executions to prevent overwhelming systems
        semaphore = asyncio.Semaphore(5)
        
        async def execute_with_semaphore(request):
            async with semaphore:
                return await self.execute_tool(request)
        
        tasks = [execute_with_semaphore(request) for request in requests]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle exceptions
        processed_responses = []
        for i, response in enumerate(responses):
            if isinstance(response, Exception):
                logger.error(f"Batch execution error for request {i}: {response}")
                processed_responses.append(ToolResponse(
                    request_id=requests[i].request_id,
                    tool_name=requests[i].tool_name,
                    success=False,
                    error=str(response)
                ))
            else:
                processed_responses.append(response)
        
        return processed_responses
    
    def get_tool_status(self) -> Dict[str, Dict[str, Any]]:
        """Get current status of all tools"""
        status = {}
        for tool_name, capability in self.tool_capabilities.items():
            status[tool_name] = {
                "status": capability.status.value,
                "category": capability.category.value,
                "last_check": capability.last_check,
                "response_time": capability.response_time,
                "success_rate": capability.success_rate,
                "error_count": capability.error_count,
                "fallback_tools": capability.fallback_tools
            }
        return status
    
    def set_mock_mode(self, enabled: bool):
        """Enable or disable mock mode for testing"""
        self.mock_mode = enabled
        logger.info(f"Mock mode {'enabled' if enabled else 'disabled'}")
    
    async def check_tool_availability(self, tool_name: str) -> bool:
        """Check if specific tool is available"""
        if tool_name not in self.tool_capabilities:
            return False
        
        capability = self.tool_capabilities[tool_name]
        
        try:
            if self.mock_mode:
                # In mock mode, simulate availability
                capability.status = ToolStatus.AVAILABLE
                capability.last_check = datetime.now()
                return True
            else:
                # Real availability check would go here
                # For now, assume unavailable since we don't have real integrations
                capability.status = ToolStatus.UNAVAILABLE
                capability.last_check = datetime.now()
                return False
                
        except Exception as e:
            logger.error(f"Availability check failed for {tool_name}: {e}")
            capability.status = ToolStatus.UNAVAILABLE
            return False
    
    async def _try_fallback_tools(self, request: ToolRequest, start_time: datetime, 
                                error: Optional[str] = None) -> ToolResponse:
        """Try fallback tools if primary tool fails"""
        
        if request.tool_name not in self.tool_capabilities:
            return ToolResponse(
                request_id=request.request_id,
                tool_name=request.tool_name,
                success=False,
                error="Tool not found",
                response_time=(datetime.now() - start_time).total_seconds()
            )
        
        fallback_tools = self.tool_capabilities[request.tool_name].fallback_tools
        
        for fallback_tool in fallback_tools:
            if self._is_tool_available(fallback_tool):
                logger.info(f"Trying fallback tool {fallback_tool} for {request.tool_name}")
                
                # Create fallback request
                fallback_request = ToolRequest(
                    tool_name=fallback_tool,
                    operation=request.operation,
                    parameters=request.parameters,
                    timeout=request.timeout
                )
                
                try:
                    if self.mock_mode:
                        response_data = await self._mock_tool_execution(fallback_request)
                    else:
                        response_data = await self._real_tool_execution(fallback_request)
                    
                    response_time = (datetime.now() - start_time).total_seconds()
                    
                    return ToolResponse(
                        request_id=request.request_id,
                        tool_name=request.tool_name,
                        success=True,
                        data=response_data,
                        response_time=response_time,
                        used_fallback=True,
                        fallback_tool=fallback_tool
                    )
                    
                except Exception as fallback_error:
                    logger.error(f"Fallback tool {fallback_tool} also failed: {fallback_error}")
                    continue
        
        # No fallbacks worked, return error
        return ToolResponse(
            request_id=request.request_id,
            tool_name=request.tool_name,
            success=False,
            error=error or "All tools and fallbacks failed",
            response_time=(datetime.now() - start_time).total_seconds()
        )
    
    async def _mock_tool_execution(self, request: ToolRequest) -> Dict[str, Any]:
        """Mock tool execution for testing and development"""
        
        # Simulate processing delay
        await asyncio.sleep(0.1 + (hash(request.request_id) % 10) / 10)
        
        # Generate mock responses based on tool type
        mock_responses = {
            # Microsoft Defender tools
            "defender_atp_query": {
                "results": [
                    {
                        "timestamp": datetime.now().isoformat(),
                        "device_name": "WORKSTATION-01",
                        "process_name": "powershell.exe",
                        "command_line": "powershell.exe -encodedCommand <base64>",
                        "threat_score": 85
                    }
                ],
                "result_count": 1
            },
            
            "defender_threat_intel": {
                "file_reputation": "malicious",
                "confidence": 0.92,
                "threat_family": "Trojan.Generic",
                "first_seen": "2024-01-15T10:30:00Z",
                "last_seen": "2024-01-20T15:45:00Z"
            },
            
            # Sentinel tools
            "sentinel_kql_query": {
                "tables": [
                    {
                        "table_name": "SecurityEvent",
                        "rows": [
                            {
                                "TimeGenerated": datetime.now().isoformat(),
                                "EventID": 4624,
                                "Account": "john.doe@company.com",
                                "Computer": "DC-01"
                            }
                        ]
                    }
                ],
                "summary": {"total_rows": 1}
            },
            
            "sentinel_incident_update": {
                "incident_id": request.parameters.get("incident_id"),
                "status": "updated",
                "severity": request.parameters.get("severity", "Medium")
            },
            
            # Azure AD tools
            "azure_ad_user_lookup": {
                "user_id": request.parameters.get("user_id"),
                "display_name": "John Doe",
                "user_principal_name": "john.doe@company.com",
                "account_enabled": True,
                "last_sign_in": "2024-01-20T14:30:00Z",
                "risk_level": "medium"
            },
            
            "azure_ad_sign_in_logs": {
                "sign_ins": [
                    {
                        "timestamp": "2024-01-20T14:30:00Z",
                        "user": "john.doe@company.com",
                        "application": "Office 365",
                        "ip_address": "192.168.1.100",
                        "location": "New York, US",
                        "risk_level": "low"
                    }
                ]
            },
            
            # Threat Intelligence tools
            "virustotal_lookup": {
                "scan_id": "12345",
                "positives": 15,
                "total": 70,
                "scan_date": datetime.now().isoformat(),
                "permalink": "https://virustotal.com/file/scan/12345"
            },
            
            "urlvoid_lookup": {
                "domain": request.parameters.get("domain"),
                "reputation": "malicious",
                "blacklists": 3,
                "analysis_date": datetime.now().isoformat()
            }
        }
        
        # Return appropriate mock response
        response = mock_responses.get(request.tool_name, {
            "mock_response": True,
            "tool": request.tool_name,
            "operation": request.operation,
            "parameters": request.parameters,
            "timestamp": datetime.now().isoformat()
        })
        
        return response
    
    async def _real_tool_execution(self, request: ToolRequest) -> Dict[str, Any]:
        """Real tool execution (would implement actual API calls)"""
        
        # This would contain real implementations when tools are available
        # For now, raise an exception to indicate real tools not implemented
        raise NotImplementedError(f"Real implementation for {request.tool_name} not available")
    
    def _is_tool_available(self, tool_name: str) -> bool:
        """Check if tool is currently available"""
        if tool_name not in self.tool_capabilities:
            return False
        
        capability = self.tool_capabilities[tool_name]
        
        # Check if tool is in a usable state
        if capability.status in [ToolStatus.AVAILABLE, ToolStatus.DEGRADED]:
            # Check if rate limit has expired
            if capability.rate_limit_reset and datetime.now() < capability.rate_limit_reset:
                return False
            return True
        
        return False
    
    def _update_tool_stats(self, tool_name: str, success: bool, response_time: float):
        """Update tool performance statistics"""
        if tool_name in self.tool_capabilities:
            capability = self.tool_capabilities[tool_name]
            
            # Update response time (exponential moving average)
            if capability.response_time == 0:
                capability.response_time = response_time
            else:
                capability.response_time = 0.8 * capability.response_time + 0.2 * response_time
            
            # Update success rate (exponential moving average)
            success_value = 1.0 if success else 0.0
            if capability.success_rate == 0:
                capability.success_rate = success_value
            else:
                capability.success_rate = 0.9 * capability.success_rate + 0.1 * success_value
            
            # Update error count
            if not success:
                capability.error_count += 1
            
            # Update status based on performance
            if capability.success_rate >= 0.95:
                capability.status = ToolStatus.AVAILABLE
            elif capability.success_rate >= 0.80:
                capability.status = ToolStatus.DEGRADED
            else:
                capability.status = ToolStatus.UNAVAILABLE
    
    async def _monitor_tool_availability(self):
        """Background task to monitor tool availability"""
        while True:
            try:
                if datetime.now() - self.last_availability_check > self.check_interval:
                    logger.info("Checking tool availability")
                    
                    # Check availability for all tools
                    for tool_name in self.tool_capabilities.keys():
                        await self.check_tool_availability(tool_name)
                    
                    self.last_availability_check = datetime.now()
                
                # Wait before next check
                await asyncio.sleep(60)  # Check every minute for status updates
                
            except Exception as e:
                logger.error(f"Error in availability monitoring: {e}")
                await asyncio.sleep(60)
    
    def _initialize_tools(self):
        """Initialize tool capability definitions"""
        
        # Microsoft Security Tools (32 total as per requirements)
        microsoft_tools = [
            # Microsoft Defender ATP/MDR
            ("defender_atp_query", "Execute KQL queries in Microsoft Defender ATP"),
            ("defender_threat_intel", "Query Microsoft Defender threat intelligence"),
            ("defender_device_actions", "Execute device actions in Defender"),
            ("defender_file_analysis", "Analyze files using Defender sandboxing"),
            ("defender_hunt_queries", "Execute advanced hunting queries"),
            ("defender_indicators", "Manage threat indicators"),
            ("defender_machine_isolation", "Isolate machines using Defender"),
            ("defender_evidence_collection", "Collect forensic evidence"),
            
            # Microsoft Sentinel
            ("sentinel_kql_query", "Execute KQL queries in Sentinel"),
            ("sentinel_incident_management", "Manage Sentinel incidents"),
            ("sentinel_incident_update", "Update incident status and details"),
            ("sentinel_playbook_trigger", "Trigger automated playbooks"),
            ("sentinel_watchlist_management", "Manage Sentinel watchlists"),
            ("sentinel_analytics_rules", "Manage analytics rules"),
            ("sentinel_data_connectors", "Manage data connector status"),
            ("sentinel_workbook_queries", "Execute workbook queries"),
            
            # Azure Active Directory
            ("azure_ad_user_lookup", "Look up user information"),
            ("azure_ad_sign_in_logs", "Query sign-in logs"),
            ("azure_ad_audit_logs", "Query audit logs"),
            ("azure_ad_risk_events", "Query identity risk events"),
            ("azure_ad_conditional_access", "Manage conditional access policies"),
            ("azure_ad_identity_protection", "Query identity protection data"),
            ("azure_ad_privileged_accounts", "Manage privileged accounts"),
            ("azure_ad_group_management", "Manage security groups"),
            
            # Microsoft 365 Security
            ("m365_security_alerts", "Query M365 security alerts"),
            ("m365_threat_policies", "Manage threat protection policies"),
            ("m365_dlp_policies", "Manage data loss prevention"),
            ("m365_compliance_search", "Execute compliance searches"),
            ("m365_safe_links", "Manage safe links policies"),
            ("m365_safe_attachments", "Manage safe attachments"),
            ("m365_threat_explorer", "Query threat explorer data"),
            ("m365_incident_response", "M365 incident response actions")
        ]
        
        # External Tools (10 total as per requirements)
        external_tools = [
            ("virustotal_lookup", "VirusTotal file and URL analysis"),
            ("urlvoid_lookup", "URLVoid domain reputation check"),
            ("shodan_lookup", "Shodan IP and service information"),
            ("abuse_ipdb_lookup", "AbuseIPDB IP reputation check"),
            ("hybrid_analysis", "Hybrid Analysis sandbox execution"),
            ("joe_sandbox", "Joe Sandbox malware analysis"),
            ("recorded_future", "Recorded Future threat intelligence"),
            ("crowdstrike_falcon", "CrowdStrike Falcon intelligence"),
            ("carbon_black", "VMware Carbon Black queries"),
            ("splunk_enterprise", "Splunk enterprise security queries")
        ]
        
        # Initialize Microsoft tools
        for tool_name, description in microsoft_tools:
            self.tool_capabilities[tool_name] = ToolCapability(
                tool_name=tool_name,
                category=ToolCategory.MICROSOFT_SECURITY,
                description=description,
                fallback_tools=[]  # Will be set based on tool relationships
            )
        
        # Initialize external tools  
        for tool_name, description in external_tools:
            self.tool_capabilities[tool_name] = ToolCapability(
                tool_name=tool_name,
                category=ToolCategory.EXTERNAL_API,
                description=description,
                fallback_tools=[]
            )
        
        # Set up fallback relationships
        self._setup_tool_fallbacks()
    
    def _setup_tool_fallbacks(self):
        """Set up fallback tool relationships"""
        
        fallback_mappings = {
            # Threat intelligence fallbacks
            "defender_threat_intel": ["virustotal_lookup", "recorded_future"],
            "virustotal_lookup": ["urlvoid_lookup", "abuse_ipdb_lookup"],
            "urlvoid_lookup": ["abuse_ipdb_lookup", "shodan_lookup"],
            
            # Query fallbacks
            "defender_atp_query": ["sentinel_kql_query", "splunk_enterprise"],
            "sentinel_kql_query": ["defender_atp_query", "splunk_enterprise"],
            
            # Sandbox analysis fallbacks
            "defender_file_analysis": ["hybrid_analysis", "joe_sandbox"],
            "hybrid_analysis": ["joe_sandbox", "defender_file_analysis"],
            
            # User/identity fallbacks
            "azure_ad_user_lookup": ["azure_ad_sign_in_logs", "m365_security_alerts"],
            "azure_ad_sign_in_logs": ["azure_ad_audit_logs", "azure_ad_user_lookup"],
            
            # Incident management fallbacks
            "sentinel_incident_management": ["sentinel_incident_update", "m365_incident_response"],
            "m365_incident_response": ["sentinel_incident_management", "defender_device_actions"]
        }
        
        for tool_name, fallbacks in fallback_mappings.items():
            if tool_name in self.tool_capabilities:
                self.tool_capabilities[tool_name].fallback_tools = fallbacks
