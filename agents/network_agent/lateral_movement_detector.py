"""
Lateral Movement Detector Module
State 3: Lateral Movement Detection for Network & Exfiltration Agent
Detects lateral movement patterns and techniques across the network
"""

import logging
import asyncio
import ipaddress
from typing import Dict, Any, List, Optional, Set, Tuple
from datetime import datetime, timedelta
import json
from collections import defaultdict, Counter
import networkx as nx

logger = logging.getLogger(__name__)

class LateralMovementDetector:
    """
    Lateral Movement Detection System
    Detects lateral movement techniques including credential attacks,
    service exploitation, and network propagation patterns
    """
    
    def __init__(self):
        self.attack_patterns = self._load_attack_patterns()
        self.credential_patterns = self._load_credential_patterns()
        self.service_patterns = self._load_service_patterns()
        self.network_graph = nx.DiGraph()
        
    async def detect_lateral_movement(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect lateral movement activities
        
        Args:
            network_data: Network activity and authentication data
            
        Returns:
            Lateral movement detection results
        """
        logger.info("Starting lateral movement detection")
        
        detection_results = {
            "credential_attacks": {},
            "service_exploitation": {},
            "network_propagation": {},
            "admin_tool_abuse": {},
            "remote_access": {},
            "privilege_escalation": {},
            "persistence_mechanisms": {},
            "movement_graph": {},
            "timeline_analysis": {},
            "detection_timestamp": datetime.now()
        }
        
        try:
            # Build network activity graph
            await self._build_network_graph(network_data)
            
            # Credential-based attacks
            detection_results["credential_attacks"] = await self._detect_credential_attacks(network_data)
            
            # Service exploitation
            detection_results["service_exploitation"] = await self._detect_service_exploitation(network_data)
            
            # Network propagation patterns
            detection_results["network_propagation"] = await self._detect_network_propagation(network_data)
            
            # Administrative tool abuse
            detection_results["admin_tool_abuse"] = await self._detect_admin_tool_abuse(network_data)
            
            # Remote access techniques
            detection_results["remote_access"] = await self._detect_remote_access(network_data)
            
            # Privilege escalation
            detection_results["privilege_escalation"] = await self._detect_privilege_escalation(network_data)
            
            # Persistence mechanisms
            detection_results["persistence_mechanisms"] = await self._detect_persistence_mechanisms(network_data)
            
            # Movement graph analysis
            detection_results["movement_graph"] = await self._analyze_movement_graph()
            
            # Timeline analysis
            detection_results["timeline_analysis"] = await self._analyze_movement_timeline(network_data)
            
            logger.info("Lateral movement detection completed")
            
        except Exception as e:
            logger.error(f"Error in lateral movement detection: {str(e)}")
            detection_results["error"] = str(e)
            
        return detection_results
    
    async def _detect_credential_attacks(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect credential-based lateral movement attacks"""
        credential_attacks = {
            "pass_the_hash": [],
            "pass_the_ticket": [],
            "golden_ticket": [],
            "silver_ticket": [],
            "credential_stuffing": [],
            "password_spraying": [],
            "kerberoasting": [],
            "asrep_roasting": []
        }
        
        auth_logs = network_data.get("authentication_logs", [])
        kerberos_logs = network_data.get("kerberos_logs", [])
        ntlm_logs = network_data.get("ntlm_logs", [])
        
        # Pass-the-Hash detection
        credential_attacks["pass_the_hash"] = await self._detect_pass_the_hash(ntlm_logs, auth_logs)
        
        # Pass-the-Ticket detection
        credential_attacks["pass_the_ticket"] = await self._detect_pass_the_ticket(kerberos_logs)
        
        # Golden Ticket detection
        credential_attacks["golden_ticket"] = await self._detect_golden_ticket(kerberos_logs)
        
        # Silver Ticket detection
        credential_attacks["silver_ticket"] = await self._detect_silver_ticket(kerberos_logs)
        
        # Credential stuffing
        credential_attacks["credential_stuffing"] = await self._detect_credential_stuffing(auth_logs)
        
        # Password spraying
        credential_attacks["password_spraying"] = await self._detect_password_spraying(auth_logs)
        
        # Kerberoasting
        credential_attacks["kerberoasting"] = await self._detect_kerberoasting(kerberos_logs)
        
        # ASREPRoasting
        credential_attacks["asrep_roasting"] = await self._detect_asrep_roasting(kerberos_logs)
        
        return credential_attacks
    
    async def _detect_service_exploitation(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect service exploitation for lateral movement"""
        service_exploitation = {
            "smb_exploitation": [],
            "wmi_abuse": [],
            "psexec_usage": [],
            "winrm_abuse": [],
            "rpc_exploitation": [],
            "service_creation": [],
            "scheduled_tasks": [],
            "remote_registry": []
        }
        
        smb_logs = network_data.get("smb_logs", [])
        wmi_logs = network_data.get("wmi_logs", [])
        service_logs = network_data.get("service_logs", [])
        process_logs = network_data.get("process_logs", [])
        
        # SMB exploitation
        service_exploitation["smb_exploitation"] = await self._detect_smb_exploitation(smb_logs)
        
        # WMI abuse
        service_exploitation["wmi_abuse"] = await self._detect_wmi_abuse(wmi_logs)
        
        # PsExec usage
        service_exploitation["psexec_usage"] = await self._detect_psexec_usage(process_logs, service_logs)
        
        # WinRM abuse
        service_exploitation["winrm_abuse"] = await self._detect_winrm_abuse(network_data.get("winrm_logs", []))
        
        # RPC exploitation
        service_exploitation["rpc_exploitation"] = await self._detect_rpc_exploitation(network_data.get("rpc_logs", []))
        
        # Service creation
        service_exploitation["service_creation"] = await self._detect_suspicious_service_creation(service_logs)
        
        # Scheduled task abuse
        service_exploitation["scheduled_tasks"] = await self._detect_scheduled_task_abuse(network_data.get("task_logs", []))
        
        # Remote registry access
        service_exploitation["remote_registry"] = await self._detect_remote_registry_access(network_data.get("registry_logs", []))
        
        return service_exploitation
    
    async def _detect_network_propagation(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect network propagation patterns"""
        network_propagation = {
            "port_scanning": [],
            "service_enumeration": [],
            "network_discovery": [],
            "share_enumeration": [],
            "vulnerability_scanning": [],
            "beacon_activity": [],
            "pivot_points": [],
            "propagation_paths": []
        }
        
        flows = network_data.get("flows", [])
        dns_queries = network_data.get("dns_queries", [])
        
        # Port scanning detection
        network_propagation["port_scanning"] = await self._detect_port_scanning(flows)
        
        # Service enumeration
        network_propagation["service_enumeration"] = await self._detect_service_enumeration(flows)
        
        # Network discovery
        network_propagation["network_discovery"] = await self._detect_network_discovery(dns_queries, flows)
        
        # Share enumeration
        network_propagation["share_enumeration"] = await self._detect_share_enumeration(network_data.get("smb_logs", []))
        
        # Vulnerability scanning
        network_propagation["vulnerability_scanning"] = await self._detect_vulnerability_scanning(flows)
        
        # Beacon activity
        network_propagation["beacon_activity"] = await self._detect_beacon_activity(flows)
        
        # Pivot point identification
        network_propagation["pivot_points"] = await self._identify_pivot_points(flows)
        
        # Propagation path analysis
        network_propagation["propagation_paths"] = await self._analyze_propagation_paths()
        
        return network_propagation
    
    async def _detect_admin_tool_abuse(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect abuse of administrative tools"""
        admin_tool_abuse = {
            "powershell_remoting": [],
            "rdp_abuse": [],
            "ssh_tunneling": [],
            "remote_desktop": [],
            "admin_shares": [],
            "script_execution": [],
            "command_execution": [],
            "tool_transfer": []
        }
        
        process_logs = network_data.get("process_logs", [])
        rdp_logs = network_data.get("rdp_logs", [])
        ssh_logs = network_data.get("ssh_logs", [])
        
        # PowerShell remoting
        admin_tool_abuse["powershell_remoting"] = await self._detect_powershell_remoting(process_logs)
        
        # RDP abuse
        admin_tool_abuse["rdp_abuse"] = await self._detect_rdp_abuse(rdp_logs)
        
        # SSH tunneling
        admin_tool_abuse["ssh_tunneling"] = await self._detect_ssh_tunneling(ssh_logs)
        
        # Remote desktop connections
        admin_tool_abuse["remote_desktop"] = await self._detect_remote_desktop_abuse(rdp_logs)
        
        # Administrative share access
        admin_tool_abuse["admin_shares"] = await self._detect_admin_share_access(network_data.get("smb_logs", []))
        
        # Script execution
        admin_tool_abuse["script_execution"] = await self._detect_remote_script_execution(process_logs)
        
        # Command execution
        admin_tool_abuse["command_execution"] = await self._detect_remote_command_execution(process_logs)
        
        # Tool transfer
        admin_tool_abuse["tool_transfer"] = await self._detect_tool_transfer(network_data.get("file_transfer_logs", []))
        
        return admin_tool_abuse
    
    async def _detect_remote_access(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect remote access techniques"""
        remote_access = {
            "reverse_shells": [],
            "backdoors": [],
            "tunneling": [],
            "port_forwarding": [],
            "proxy_usage": [],
            "covert_channels": [],
            "c2_communication": [],
            "remote_file_access": []
        }
        
        flows = network_data.get("flows", [])
        process_logs = network_data.get("process_logs", [])
        
        # Reverse shell detection
        remote_access["reverse_shells"] = await self._detect_reverse_shells(flows, process_logs)
        
        # Backdoor detection
        remote_access["backdoors"] = await self._detect_backdoors(flows, process_logs)
        
        # Tunneling detection
        remote_access["tunneling"] = await self._detect_tunneling(flows)
        
        # Port forwarding
        remote_access["port_forwarding"] = await self._detect_port_forwarding(flows)
        
        # Proxy usage
        remote_access["proxy_usage"] = await self._detect_proxy_usage(flows)
        
        # Covert channels
        remote_access["covert_channels"] = await self._detect_covert_channels(flows)
        
        # C2 communication
        remote_access["c2_communication"] = await self._detect_c2_communication(flows)
        
        # Remote file access
        remote_access["remote_file_access"] = await self._detect_remote_file_access(network_data.get("file_access_logs", []))
        
        return remote_access
    
    async def _detect_privilege_escalation(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect privilege escalation activities"""
        privilege_escalation = {
            "token_manipulation": [],
            "service_escalation": [],
            "dll_hijacking": [],
            "uac_bypass": [],
            "kernel_exploits": [],
            "process_injection": [],
            "access_token_abuse": [],
            "credential_dumping": []
        }
        
        process_logs = network_data.get("process_logs", [])
        security_logs = network_data.get("security_logs", [])
        
        # Token manipulation
        privilege_escalation["token_manipulation"] = await self._detect_token_manipulation(process_logs)
        
        # Service escalation
        privilege_escalation["service_escalation"] = await self._detect_service_escalation(network_data.get("service_logs", []))
        
        # DLL hijacking
        privilege_escalation["dll_hijacking"] = await self._detect_dll_hijacking(process_logs)
        
        # UAC bypass
        privilege_escalation["uac_bypass"] = await self._detect_uac_bypass(process_logs)
        
        # Kernel exploits
        privilege_escalation["kernel_exploits"] = await self._detect_kernel_exploits(security_logs)
        
        # Process injection
        privilege_escalation["process_injection"] = await self._detect_process_injection(process_logs)
        
        # Access token abuse
        privilege_escalation["access_token_abuse"] = await self._detect_access_token_abuse(security_logs)
        
        # Credential dumping
        privilege_escalation["credential_dumping"] = await self._detect_credential_dumping(process_logs)
        
        return privilege_escalation
    
    async def _detect_persistence_mechanisms(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect persistence mechanisms"""
        persistence_mechanisms = {
            "registry_persistence": [],
            "scheduled_tasks": [],
            "service_persistence": [],
            "startup_persistence": [],
            "wmi_persistence": [],
            "dll_persistence": [],
            "account_creation": [],
            "group_modifications": []
        }
        
        registry_logs = network_data.get("registry_logs", [])
        task_logs = network_data.get("task_logs", [])
        service_logs = network_data.get("service_logs", [])
        
        # Registry persistence
        persistence_mechanisms["registry_persistence"] = await self._detect_registry_persistence(registry_logs)
        
        # Scheduled task persistence
        persistence_mechanisms["scheduled_tasks"] = await self._detect_task_persistence(task_logs)
        
        # Service persistence
        persistence_mechanisms["service_persistence"] = await self._detect_service_persistence(service_logs)
        
        # Startup persistence
        persistence_mechanisms["startup_persistence"] = await self._detect_startup_persistence(registry_logs)
        
        # WMI persistence
        persistence_mechanisms["wmi_persistence"] = await self._detect_wmi_persistence(network_data.get("wmi_logs", []))
        
        # DLL persistence
        persistence_mechanisms["dll_persistence"] = await self._detect_dll_persistence(registry_logs)
        
        # Account creation
        persistence_mechanisms["account_creation"] = await self._detect_account_creation(network_data.get("security_logs", []))
        
        # Group modifications
        persistence_mechanisms["group_modifications"] = await self._detect_group_modifications(network_data.get("security_logs", []))
        
        return persistence_mechanisms
    
    async def _build_network_graph(self, network_data: Dict[str, Any]):
        """Build network activity graph"""
        flows = network_data.get("flows", [])
        
        for flow in flows:
            source_ip = flow.get("source_ip")
            dest_ip = flow.get("destination_ip")
            
            if source_ip and dest_ip:
                # Add nodes
                self.network_graph.add_node(source_ip)
                self.network_graph.add_node(dest_ip)
                
                # Add edge with flow data
                self.network_graph.add_edge(
                    source_ip, 
                    dest_ip,
                    timestamp=flow.get("timestamp"),
                    protocol=flow.get("protocol"),
                    destination_port=flow.get("destination_port"),
                    bytes_transferred=flow.get("bytes_sent", 0) + flow.get("bytes_received", 0)
                )
    
    async def _analyze_movement_graph(self) -> Dict[str, Any]:
        """Analyze the movement graph for lateral movement patterns"""
        movement_analysis = {
            "network_topology": {},
            "central_nodes": [],
            "movement_paths": [],
            "suspicious_patterns": [],
            "pivot_candidates": [],
            "isolated_clusters": []
        }
        
        if self.network_graph.number_of_nodes() == 0:
            return movement_analysis
        
        # Network topology analysis
        movement_analysis["network_topology"] = {
            "node_count": self.network_graph.number_of_nodes(),
            "edge_count": self.network_graph.number_of_edges(),
            "density": nx.density(self.network_graph),
            "is_connected": nx.is_weakly_connected(self.network_graph)
        }
        
        # Central nodes (potential pivot points)
        centrality = nx.degree_centrality(self.network_graph)
        movement_analysis["central_nodes"] = sorted(
            centrality.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:10]
        
        # Movement paths
        movement_analysis["movement_paths"] = await self._identify_movement_paths()
        
        # Suspicious patterns
        movement_analysis["suspicious_patterns"] = await self._identify_suspicious_patterns()
        
        # Pivot candidates
        movement_analysis["pivot_candidates"] = await self._identify_pivot_candidates()
        
        # Isolated clusters
        if not nx.is_weakly_connected(self.network_graph):
            components = list(nx.weakly_connected_components(self.network_graph))
            movement_analysis["isolated_clusters"] = [list(component) for component in components]
        
        return movement_analysis
    
    # Helper methods for specific detection techniques
    async def _detect_pass_the_hash(self, ntlm_logs: List[Dict[str, Any]], auth_logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect Pass-the-Hash attacks"""
        pth_indicators = []
        
        # Look for NTLM authentication without password validation
        for log in ntlm_logs:
            if log.get("authentication_type") == "NTLM" and not log.get("password_validated"):
                # Check for authentication from unexpected sources
                source_ip = log.get("source_ip")
                target_ip = log.get("target_ip")
                username = log.get("username")
                
                # Look for rapid authentication attempts across multiple systems
                similar_auths = [
                    l for l in ntlm_logs 
                    if l.get("username") == username and 
                    l.get("timestamp", datetime.min) > log.get("timestamp", datetime.min) - timedelta(minutes=5)
                ]
                
                if len(similar_auths) > 3:  # Multiple rapid authentications
                    pth_indicators.append({
                        "log": log,
                        "similar_authentications": len(similar_auths),
                        "technique": "Pass-the-Hash",
                        "confidence": "high"
                    })
        
        return pth_indicators
    
    async def _detect_port_scanning(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect port scanning activities"""
        port_scanning = []
        
        # Group flows by source IP
        source_flows = defaultdict(list)
        for flow in flows:
            source_ip = flow.get("source_ip")
            if source_ip:
                source_flows[source_ip].append(flow)
        
        # Analyze each source for scanning behavior
        for source_ip, ip_flows in source_flows.items():
            # Count unique destination ports
            dest_ports = set()
            dest_ips = set()
            
            for flow in ip_flows:
                dest_port = flow.get("destination_port")
                dest_ip = flow.get("destination_ip")
                
                if dest_port:
                    dest_ports.add(dest_port)
                if dest_ip:
                    dest_ips.add(dest_ip)
            
            # Port scan indicators
            if len(dest_ports) > 20 and len(dest_ips) > 5:  # Many ports, multiple targets
                port_scanning.append({
                    "source_ip": source_ip,
                    "unique_ports": len(dest_ports),
                    "unique_targets": len(dest_ips),
                    "total_connections": len(ip_flows),
                    "scan_type": "horizontal_port_scan",
                    "confidence": "high"
                })
            elif len(dest_ports) > 50:  # Many ports, single/few targets
                port_scanning.append({
                    "source_ip": source_ip,
                    "unique_ports": len(dest_ports),
                    "unique_targets": len(dest_ips),
                    "total_connections": len(ip_flows),
                    "scan_type": "vertical_port_scan",
                    "confidence": "high"
                })
        
        return port_scanning
    
    def _load_attack_patterns(self) -> Dict[str, Any]:
        """Load lateral movement attack patterns"""
        return {
            "credential_attacks": {
                "pass_the_hash": {
                    "indicators": ["NTLM_without_password", "rapid_multi_host_auth"],
                    "confidence_threshold": 0.8
                },
                "pass_the_ticket": {
                    "indicators": ["kerberos_ticket_reuse", "golden_ticket_usage"],
                    "confidence_threshold": 0.9
                }
            },
            "service_exploitation": {
                "psexec": {
                    "indicators": ["psexecsvc_service", "admin_share_access"],
                    "confidence_threshold": 0.85
                },
                "wmi": {
                    "indicators": ["wmi_process_create", "wmi_remote_execution"],
                    "confidence_threshold": 0.8
                }
            },
            "network_patterns": {
                "port_scanning": {
                    "port_threshold": 20,
                    "target_threshold": 5,
                    "time_window": 300  # seconds
                },
                "service_enumeration": {
                    "service_ports": [135, 139, 445, 3389, 5985, 5986],
                    "enumeration_threshold": 10
                }
            }
        }
    
    def _load_credential_patterns(self) -> Dict[str, Any]:
        """Load credential attack patterns"""
        return {
            "ntlm_patterns": {
                "type1_message": "NTLMSSP_NEGOTIATE",
                "type2_message": "NTLMSSP_CHALLENGE", 
                "type3_message": "NTLMSSP_AUTH"
            },
            "kerberos_patterns": {
                "as_req": "AS-REQ",
                "as_rep": "AS-REP",
                "tgs_req": "TGS-REQ",
                "tgs_rep": "TGS-REP"
            },
            "suspicious_usernames": [
                "administrator", "admin", "root", "service_account",
                "backup", "guest", "test", "default"
            ]
        }
    
    def _load_service_patterns(self) -> Dict[str, Any]:
        """Load service exploitation patterns"""
        return {
            "smb_patterns": {
                "admin_shares": ["ADMIN$", "C$", "IPC$"],
                "suspicious_commands": ["cmd.exe", "powershell.exe", "wmic.exe"]
            },
            "wmi_patterns": {
                "suspicious_classes": [
                    "Win32_Process", "Win32_Service", "Win32_ScheduledJob"
                ],
                "creation_methods": ["Create", "CallMethod"]
            },
            "rpc_patterns": {
                "endpoints": [
                    "atsvc", "srvsvc", "winreg", "wkssvc", "samr"
                ],
                "operations": ["CreateService", "StartService", "OpenSCManager"]
            }
        }

# Factory function
def create_lateral_movement_detector() -> LateralMovementDetector:
    """Create and return LateralMovementDetector instance"""
    return LateralMovementDetector()
