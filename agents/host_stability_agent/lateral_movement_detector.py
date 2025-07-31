"""
Lateral Movement Detector Module
State 1: Lateral Movement Detection
Detects and analyzes lateral movement patterns across network hosts
"""

import logging
from typing import Dict, Any, List, Tuple, Set
from datetime import datetime, timedelta
import json
from collections import defaultdict
import ipaddress
import statistics
from enum import Enum

logger = logging.getLogger(__name__)

class MovementTechnique(Enum):
    """Enumeration for lateral movement techniques"""
    RDP_BRUTE_FORCE = "rdp_brute_force"
    SMB_EXPLOITATION = "smb_exploitation"
    WMI_EXECUTION = "wmi_execution"
    PSEXEC = "psexec"
    CREDENTIAL_DUMPING = "credential_dumping"
    KERBEROS_ATTACKS = "kerberos_attacks"
    POWERSHELL_REMOTING = "powershell_remoting"
    SSH_TUNNELING = "ssh_tunneling"
    TOKEN_MANIPULATION = "token_manipulation"

class MovementPattern(Enum):
    """Enumeration for movement patterns"""
    BEACON_PATTERN = "beacon_pattern"
    PIVOT_PATTERN = "pivot_pattern"
    SPRAY_PATTERN = "spray_pattern"
    STEALTH_PATTERN = "stealth_pattern"
    ESCALATION_PATTERN = "escalation_pattern"

class LateralMovementDetector:
    """
    Detects and analyzes lateral movement patterns across network hosts
    Provides comprehensive lateral movement detection and analysis
    """
    
    def __init__(self):
        self.movement_signatures = self._load_movement_signatures()
        self.network_topology = {}
        self.host_profiles = {}
        self.movement_cache = {}
        
    def detect_lateral_movement(self, host_logs: List[Dict[str, Any]], network_data: Dict[str, Any], authentication_logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Detect lateral movement patterns across hosts
        
        Args:
            host_logs: Host-based security logs
            network_data: Network topology and connection data
            authentication_logs: Authentication and login logs
            
        Returns:
            Lateral movement detection results
        """
        logger.info("Detecting lateral movement patterns")
        
        movement_analysis = {
            "movement_chains": {},
            "suspicious_hosts": {},
            "attack_vectors": {},
            "movement_timeline": [],
            "network_propagation": {},
            "credential_reuse": {},
            "pivot_points": {},
            "analysis_metadata": {}
        }
        
        # Analyze host connections and authentication patterns
        movement_analysis["movement_chains"] = self._analyze_movement_chains(
            host_logs, network_data, authentication_logs
        )
        
        # Identify suspicious hosts
        movement_analysis["suspicious_hosts"] = self._identify_suspicious_hosts(
            host_logs, movement_analysis["movement_chains"]
        )
        
        # Detect attack vectors
        movement_analysis["attack_vectors"] = self._detect_attack_vectors(
            host_logs, authentication_logs
        )
        
        # Build movement timeline
        movement_analysis["movement_timeline"] = self._build_movement_timeline(
            movement_analysis["movement_chains"], 
            movement_analysis["attack_vectors"]
        )
        
        # Analyze network propagation
        movement_analysis["network_propagation"] = self._analyze_network_propagation(
            network_data, movement_analysis["movement_chains"]
        )
        
        # Detect credential reuse patterns
        movement_analysis["credential_reuse"] = self._detect_credential_reuse(
            authentication_logs, movement_analysis["movement_chains"]
        )
        
        # Identify pivot points
        movement_analysis["pivot_points"] = self._identify_pivot_points(
            movement_analysis["movement_chains"], 
            movement_analysis["network_propagation"]
        )
        
        # Add analysis metadata
        movement_analysis["analysis_metadata"] = {
            "analysis_timestamp": datetime.now(),
            "hosts_analyzed": len(set([log.get("hostname", "") for log in host_logs])),
            "movement_chains_detected": len(movement_analysis["movement_chains"]),
            "suspicious_hosts_identified": len(movement_analysis["suspicious_hosts"]),
            "attack_vectors_detected": len(movement_analysis["attack_vectors"]),
            "detection_confidence": self._calculate_detection_confidence(movement_analysis)
        }
        
        logger.info("Lateral movement detection complete")
        return movement_analysis
    
    def analyze_host_compromise_indicators(self, host_logs: List[Dict[str, Any]], system_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze indicators of host compromise
        
        Args:
            host_logs: Host security logs
            system_events: System event logs
            
        Returns:
            Host compromise analysis
        """
        logger.info("Analyzing host compromise indicators")
        
        compromise_analysis = {
            "compromise_indicators": {},
            "persistence_mechanisms": {},
            "privilege_escalation": {},
            "defense_evasion": {},
            "discovery_activities": {},
            "collection_activities": {},
            "host_risk_scores": {},
            "analysis_metadata": {}
        }
        
        # Detect compromise indicators
        compromise_analysis["compromise_indicators"] = self._detect_compromise_indicators(
            host_logs, system_events
        )
        
        # Identify persistence mechanisms
        compromise_analysis["persistence_mechanisms"] = self._identify_persistence_mechanisms(
            host_logs, system_events
        )
        
        # Detect privilege escalation
        compromise_analysis["privilege_escalation"] = self._detect_privilege_escalation(
            host_logs, system_events
        )
        
        # Identify defense evasion techniques
        compromise_analysis["defense_evasion"] = self._identify_defense_evasion(
            host_logs, system_events
        )
        
        # Detect discovery activities
        compromise_analysis["discovery_activities"] = self._detect_discovery_activities(
            host_logs, system_events
        )
        
        # Identify collection activities
        compromise_analysis["collection_activities"] = self._identify_collection_activities(
            host_logs, system_events
        )
        
        # Calculate host risk scores
        compromise_analysis["host_risk_scores"] = self._calculate_host_risk_scores(
            compromise_analysis
        )
        
        # Add analysis metadata
        compromise_analysis["analysis_metadata"] = {
            "analysis_timestamp": datetime.now(),
            "hosts_analyzed": len(set([log.get("hostname", "") for log in host_logs])),
            "indicators_detected": sum([
                len(compromise_analysis["compromise_indicators"]),
                len(compromise_analysis["persistence_mechanisms"]),
                len(compromise_analysis["privilege_escalation"])
            ]),
            "high_risk_hosts": len([
                host for host, score in compromise_analysis["host_risk_scores"].items()
                if score >= 7.0
            ])
        }
        
        logger.info("Host compromise analysis complete")
        return compromise_analysis
    
    def track_attack_progression(self, movement_analysis: Dict[str, Any], compromise_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Track attack progression across the network
        
        Args:
            movement_analysis: Lateral movement analysis results
            compromise_analysis: Host compromise analysis results
            
        Returns:
            Attack progression tracking results
        """
        logger.info("Tracking attack progression")
        
        progression_analysis = {
            "attack_stages": {},
            "progression_timeline": [],
            "attack_paths": {},
            "target_identification": {},
            "impact_assessment": {},
            "containment_recommendations": {},
            "analysis_metadata": {}
        }
        
        # Identify attack stages
        progression_analysis["attack_stages"] = self._identify_attack_stages(
            movement_analysis, compromise_analysis
        )
        
        # Build progression timeline
        progression_analysis["progression_timeline"] = self._build_progression_timeline(
            movement_analysis, compromise_analysis
        )
        
        # Map attack paths
        progression_analysis["attack_paths"] = self._map_attack_paths(
            movement_analysis["movement_chains"],
            progression_analysis["attack_stages"]
        )
        
        # Identify likely targets
        progression_analysis["target_identification"] = self._identify_attack_targets(
            progression_analysis["attack_paths"],
            movement_analysis["network_propagation"]
        )
        
        # Assess impact
        progression_analysis["impact_assessment"] = self._assess_attack_impact(
            progression_analysis["attack_stages"],
            compromise_analysis["host_risk_scores"]
        )
        
        # Generate containment recommendations
        progression_analysis["containment_recommendations"] = self._generate_containment_recommendations(
            progression_analysis["attack_paths"],
            progression_analysis["impact_assessment"]
        )
        
        # Add analysis metadata
        progression_analysis["analysis_metadata"] = {
            "analysis_timestamp": datetime.now(),
            "attack_stages_identified": len(progression_analysis["attack_stages"]),
            "attack_paths_mapped": len(progression_analysis["attack_paths"]),
            "high_value_targets": len([
                target for target in progression_analysis["target_identification"].values()
                if target.get("risk_level") == "high"
            ]),
            "progression_confidence": self._calculate_progression_confidence(progression_analysis)
        }
        
        logger.info("Attack progression tracking complete")
        return progression_analysis
    
    def _load_movement_signatures(self) -> Dict[str, Any]:
        """Load lateral movement signatures and patterns"""
        return {
            "rdp_signatures": [
                {"event_id": 4624, "logon_type": 10, "pattern": "remote_desktop"},
                {"event_id": 4625, "logon_type": 10, "pattern": "failed_rdp"}
            ],
            "smb_signatures": [
                {"event_id": 5140, "pattern": "smb_share_access"},
                {"event_id": 5145, "pattern": "smb_detailed_access"}
            ],
            "wmi_signatures": [
                {"event_id": 4688, "process": "wmiprvse.exe", "pattern": "wmi_execution"},
                {"event_id": 4648, "pattern": "explicit_credential_use"}
            ],
            "powershell_signatures": [
                {"event_id": 4103, "pattern": "powershell_execution"},
                {"event_id": 4104, "pattern": "powershell_script_block"}
            ]
        }
    
    def _analyze_movement_chains(self, host_logs: List[Dict[str, Any]], network_data: Dict[str, Any], authentication_logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze lateral movement chains"""
        movement_chains = {}
        
        # Group events by source and destination hosts
        host_connections = defaultdict(list)
        
        for log in host_logs:
            source_host = log.get("source_host", log.get("hostname", ""))
            destination_host = log.get("destination_host", "")
            
            if source_host and destination_host and source_host != destination_host:
                connection = {
                    "timestamp": log.get("timestamp", datetime.now()),
                    "source": source_host,
                    "destination": destination_host,
                    "event_type": log.get("event_type", ""),
                    "event_id": log.get("event_id", ""),
                    "user": log.get("user", ""),
                    "process": log.get("process", ""),
                    "details": log.get("details", {})
                }
                host_connections[f"{source_host}->{destination_host}"].append(connection)
        
        # Analyze each connection pattern
        for connection_key, connections in host_connections.items():
            if len(connections) >= 2:  # Multiple connections indicate potential movement
                movement_chains[connection_key] = {
                    "source_host": connections[0]["source"],
                    "destination_host": connections[0]["destination"],
                    "connection_count": len(connections),
                    "first_seen": min([conn["timestamp"] for conn in connections]),
                    "last_seen": max([conn["timestamp"] for conn in connections]),
                    "movement_techniques": self._identify_movement_techniques(connections),
                    "suspicious_indicators": self._identify_suspicious_connection_indicators(connections),
                    "risk_score": self._calculate_movement_risk_score(connections)
                }
        
        return movement_chains
    
    def _identify_suspicious_hosts(self, host_logs: List[Dict[str, Any]], movement_chains: Dict[str, Any]) -> Dict[str, Any]:
        """Identify hosts showing suspicious behavior"""
        suspicious_hosts = {}
        
        # Analyze hosts by connection patterns
        host_activity = defaultdict(lambda: {
            "outbound_connections": 0,
            "inbound_connections": 0,
            "unique_destinations": set(),
            "unique_sources": set(),
            "movement_techniques": set(),
            "suspicious_events": []
        })
        
        # Process movement chains
        for chain_key, chain_data in movement_chains.items():
            source = chain_data["source_host"]
            destination = chain_data["destination_host"]
            
            host_activity[source]["outbound_connections"] += chain_data["connection_count"]
            host_activity[source]["unique_destinations"].add(destination)
            host_activity[source]["movement_techniques"].update(chain_data["movement_techniques"])
            
            host_activity[destination]["inbound_connections"] += chain_data["connection_count"]
            host_activity[destination]["unique_sources"].add(source)
        
        # Identify suspicious patterns
        for host, activity in host_activity.items():
            suspicion_score = 0.0
            suspicion_reasons = []
            
            # High outbound connection count
            if activity["outbound_connections"] > 10:
                suspicion_score += 2.0
                suspicion_reasons.append("high_outbound_connections")
            
            # Many unique destinations
            if len(activity["unique_destinations"]) > 5:
                suspicion_score += 1.5
                suspicion_reasons.append("many_unique_destinations")
            
            # Multiple movement techniques
            if len(activity["movement_techniques"]) > 2:
                suspicion_score += 2.5
                suspicion_reasons.append("multiple_movement_techniques")
            
            # Determine suspicion level
            if suspicion_score >= 4.0:
                suspicion_level = "high"
            elif suspicion_score >= 2.0:
                suspicion_level = "medium"
            elif suspicion_score >= 1.0:
                suspicion_level = "low"
            else:
                continue  # Not suspicious
            
            suspicious_hosts[host] = {
                "suspicion_level": suspicion_level,
                "suspicion_score": suspicion_score,
                "suspicion_reasons": suspicion_reasons,
                "activity_summary": {
                    "outbound_connections": activity["outbound_connections"],
                    "inbound_connections": activity["inbound_connections"],
                    "unique_destinations": len(activity["unique_destinations"]),
                    "unique_sources": len(activity["unique_sources"]),
                    "movement_techniques": list(activity["movement_techniques"])
                }
            }
        
        return suspicious_hosts
    
    def _detect_attack_vectors(self, host_logs: List[Dict[str, Any]], authentication_logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect lateral movement attack vectors"""
        attack_vectors = {}
        
        # Analyze different attack vectors
        vector_analysis = {
            "rdp_attacks": self._detect_rdp_attacks(host_logs, authentication_logs),
            "smb_attacks": self._detect_smb_attacks(host_logs),
            "wmi_attacks": self._detect_wmi_attacks(host_logs),
            "powershell_attacks": self._detect_powershell_attacks(host_logs),
            "credential_attacks": self._detect_credential_attacks(authentication_logs)
        }
        
        # Consolidate and prioritize attack vectors
        for vector_type, attacks in vector_analysis.items():
            if attacks:
                attack_vectors[vector_type] = {
                    "attack_count": len(attacks),
                    "affected_hosts": list(set([attack.get("hostname", "") for attack in attacks])),
                    "first_detected": min([attack.get("timestamp", datetime.now()) for attack in attacks]),
                    "last_detected": max([attack.get("timestamp", datetime.now()) for attack in attacks]),
                    "attack_details": attacks,
                    "severity": self._assess_vector_severity(vector_type, attacks)
                }
        
        return attack_vectors
    
    def _detect_rdp_attacks(self, host_logs: List[Dict[str, Any]], authentication_logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect RDP-based attacks"""
        rdp_attacks = []
        
        # Look for RDP brute force patterns
        rdp_events = [log for log in authentication_logs if log.get("logon_type") == 10]
        
        # Group by source IP and username
        rdp_attempts = defaultdict(list)
        
        for event in rdp_events:
            source_ip = event.get("source_ip", "")
            username = event.get("username", "")
            key = f"{source_ip}_{username}"
            rdp_attempts[key].append(event)
        
        # Identify brute force patterns
        for key, attempts in rdp_attempts.items():
            failed_attempts = [attempt for attempt in attempts if attempt.get("event_id") == 4625]
            successful_attempts = [attempt for attempt in attempts if attempt.get("event_id") == 4624]
            
            if len(failed_attempts) >= 5 and successful_attempts:
                rdp_attacks.append({
                    "attack_type": "rdp_brute_force_success",
                    "source_ip": attempts[0].get("source_ip"),
                    "username": attempts[0].get("username"),
                    "failed_attempts": len(failed_attempts),
                    "successful_attempts": len(successful_attempts),
                    "timestamp": successful_attempts[0].get("timestamp"),
                    "hostname": successful_attempts[0].get("hostname")
                })
        
        return rdp_attacks
    
    def _detect_smb_attacks(self, host_logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect SMB-based attacks"""
        smb_attacks = []
        
        # Look for SMB-related events
        smb_events = [log for log in host_logs if log.get("event_id") in [5140, 5145]]
        
        # Analyze SMB access patterns
        smb_access = defaultdict(list)
        
        for event in smb_events:
            source_host = event.get("source_host", event.get("hostname", ""))
            share_name = event.get("share_name", "")
            key = f"{source_host}_{share_name}"
            smb_access[key].append(event)
        
        # Identify suspicious SMB activity
        for key, accesses in smb_access.items():
            if len(accesses) > 10:  # High volume SMB access
                smb_attacks.append({
                    "attack_type": "smb_enumeration",
                    "source_host": accesses[0].get("source_host"),
                    "share_name": accesses[0].get("share_name"),
                    "access_count": len(accesses),
                    "timestamp": accesses[0].get("timestamp"),
                    "hostname": accesses[0].get("hostname")
                })
        
        return smb_attacks
    
    def _detect_wmi_attacks(self, host_logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect WMI-based attacks"""
        wmi_attacks = []
        
        # Look for WMI-related events
        wmi_events = [log for log in host_logs if 
                     log.get("process", "").lower() == "wmiprvse.exe" or
                     log.get("event_id") == 4648]  # Explicit credential use
        
        # Analyze WMI execution patterns
        for event in wmi_events:
            if event.get("event_id") == 4648:  # Explicit credential use
                wmi_attacks.append({
                    "attack_type": "wmi_credential_use",
                    "username": event.get("username"),
                    "target_host": event.get("target_host"),
                    "timestamp": event.get("timestamp"),
                    "hostname": event.get("hostname")
                })
        
        return wmi_attacks
    
    def _detect_powershell_attacks(self, host_logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect PowerShell-based attacks"""
        powershell_attacks = []
        
        # Look for PowerShell events
        ps_events = [log for log in host_logs if log.get("event_id") in [4103, 4104]]
        
        # Analyze PowerShell execution patterns
        for event in ps_events:
            script_content = event.get("script_content", "")
            if any(suspicious in script_content.lower() for suspicious in 
                   ["invoke-command", "enter-pssession", "new-pssession"]):
                powershell_attacks.append({
                    "attack_type": "powershell_remoting",
                    "script_content": script_content[:200],  # Truncate for safety
                    "username": event.get("username"),
                    "timestamp": event.get("timestamp"),
                    "hostname": event.get("hostname")
                })
        
        return powershell_attacks
    
    def _detect_credential_attacks(self, authentication_logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect credential-based attacks"""
        credential_attacks = []
        
        # Look for credential dumping indicators
        credential_events = [log for log in authentication_logs if 
                           log.get("event_id") in [4648, 4672]]  # Explicit creds, special privileges
        
        # Group by user and analyze patterns
        user_activity = defaultdict(list)
        for event in credential_events:
            username = event.get("username", "")
            user_activity[username].append(event)
        
        # Identify suspicious credential usage
        for username, events in user_activity.items():
            if len(events) > 5:  # High credential usage
                credential_attacks.append({
                    "attack_type": "excessive_credential_use",
                    "username": username,
                    "event_count": len(events),
                    "first_seen": min([e.get("timestamp", datetime.now()) for e in events]),
                    "last_seen": max([e.get("timestamp", datetime.now()) for e in events])
                })
        
        return credential_attacks
    
    def _identify_movement_techniques(self, connections: List[Dict[str, Any]]) -> List[str]:
        """Identify lateral movement techniques used"""
        techniques = set()
        
        for connection in connections:
            event_id = connection.get("event_id")
            process = connection.get("process", "").lower()
            
            if event_id == 4624 and connection.get("details", {}).get("logon_type") == 10:
                techniques.add(MovementTechnique.RDP_BRUTE_FORCE.value)
            elif event_id in [5140, 5145]:
                techniques.add(MovementTechnique.SMB_EXPLOITATION.value)
            elif "wmiprvse.exe" in process:
                techniques.add(MovementTechnique.WMI_EXECUTION.value)
            elif "powershell" in process:
                techniques.add(MovementTechnique.POWERSHELL_REMOTING.value)
        
        return list(techniques)
    
    def _identify_suspicious_connection_indicators(self, connections: List[Dict[str, Any]]) -> List[str]:
        """Identify suspicious indicators in connections"""
        indicators = []
        
        # Check for rapid successive connections
        timestamps = [conn.get("timestamp", datetime.now()) for conn in connections]
        timestamps.sort()
        
        rapid_connections = 0
        for i in range(1, len(timestamps)):
            if (timestamps[i] - timestamps[i-1]).total_seconds() < 60:  # Within 1 minute
                rapid_connections += 1
        
        if rapid_connections >= 3:
            indicators.append("rapid_successive_connections")
        
        # Check for multiple users
        users = set([conn.get("user", "") for conn in connections])
        if len(users) > 2:
            indicators.append("multiple_users")
        
        # Check for off-hours activity
        off_hours_count = 0
        for conn in connections:
            timestamp = conn.get("timestamp", datetime.now())
            if timestamp.hour < 6 or timestamp.hour > 22:  # Outside business hours
                off_hours_count += 1
        
        if off_hours_count / len(connections) > 0.5:  # More than 50% off-hours
            indicators.append("off_hours_activity")
        
        return indicators
    
    def _calculate_movement_risk_score(self, connections: List[Dict[str, Any]]) -> float:
        """Calculate risk score for movement pattern"""
        risk_score = 0.0
        
        # Base score from connection count
        risk_score += min(len(connections) * 0.5, 5.0)
        
        # Add risk for suspicious indicators
        indicators = self._identify_suspicious_connection_indicators(connections)
        risk_score += len(indicators) * 1.5
        
        # Add risk for movement techniques
        techniques = self._identify_movement_techniques(connections)
        risk_score += len(techniques) * 2.0
        
        return min(risk_score, 10.0)
    
    def _build_movement_timeline(self, movement_chains: Dict[str, Any], attack_vectors: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Build chronological timeline of movement activities"""
        timeline_events = []
        
        # Add movement chain events
        for chain_key, chain_data in movement_chains.items():
            timeline_events.append({
                "timestamp": chain_data["first_seen"],
                "event_type": "movement_chain_start",
                "source": chain_data["source_host"],
                "destination": chain_data["destination_host"],
                "details": chain_data
            })
            
            timeline_events.append({
                "timestamp": chain_data["last_seen"],
                "event_type": "movement_chain_end",
                "source": chain_data["source_host"],
                "destination": chain_data["destination_host"],
                "details": chain_data
            })
        
        # Add attack vector events
        for vector_type, vector_data in attack_vectors.items():
            timeline_events.append({
                "timestamp": vector_data["first_detected"],
                "event_type": f"attack_vector_{vector_type}",
                "affected_hosts": vector_data["affected_hosts"],
                "details": vector_data
            })
        
        # Sort by timestamp
        timeline_events.sort(key=lambda x: x["timestamp"])
        
        return timeline_events
    
    def _analyze_network_propagation(self, network_data: Dict[str, Any], movement_chains: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze how attacks propagate through the network"""
        propagation_analysis = {
            "propagation_paths": [],
            "network_segments": {},
            "critical_nodes": {},
            "propagation_speed": {}
        }
        
        # Build network graph from movement chains
        network_graph = defaultdict(set)
        for chain_key, chain_data in movement_chains.items():
            source = chain_data["source_host"]
            destination = chain_data["destination_host"]
            network_graph[source].add(destination)
        
        # Identify propagation paths
        for source, destinations in network_graph.items():
            if len(destinations) > 1:  # Host connecting to multiple destinations
                propagation_analysis["propagation_paths"].append({
                    "source_host": source,
                    "destination_count": len(destinations),
                    "destinations": list(destinations),
                    "propagation_risk": "high" if len(destinations) > 3 else "medium"
                })
        
        # Identify critical nodes (high connectivity)
        for host, connections in network_graph.items():
            if len(connections) >= 3:
                propagation_analysis["critical_nodes"][host] = {
                    "connection_count": len(connections),
                    "criticality": "high" if len(connections) > 5 else "medium",
                    "connected_hosts": list(connections)
                }
        
        return propagation_analysis
    
    def _detect_credential_reuse(self, authentication_logs: List[Dict[str, Any]], movement_chains: Dict[str, Any]) -> Dict[str, Any]:
        """Detect credential reuse patterns"""
        credential_analysis = {
            "reused_credentials": {},
            "credential_timeline": [],
            "suspicious_accounts": {}
        }
        
        # Group authentication events by username
        user_auth_events = defaultdict(list)
        for log in authentication_logs:
            username = log.get("username", "")
            if username:
                user_auth_events[username].append(log)
        
        # Analyze credential usage patterns
        for username, auth_events in user_auth_events.items():
            unique_hosts = set([event.get("hostname", "") for event in auth_events])
            
            if len(unique_hosts) > 3:  # Same credentials used on multiple hosts
                credential_analysis["reused_credentials"][username] = {
                    "host_count": len(unique_hosts),
                    "hosts": list(unique_hosts),
                    "authentication_count": len(auth_events),
                    "first_seen": min([e.get("timestamp", datetime.now()) for e in auth_events]),
                    "last_seen": max([e.get("timestamp", datetime.now()) for e in auth_events]),
                    "risk_level": "high" if len(unique_hosts) > 5 else "medium"
                }
        
        return credential_analysis
    
    def _identify_pivot_points(self, movement_chains: Dict[str, Any], network_propagation: Dict[str, Any]) -> Dict[str, Any]:
        """Identify potential pivot points in the attack"""
        pivot_points = {}
        
        # Identify hosts that are both sources and destinations
        source_hosts = set()
        destination_hosts = set()
        
        for chain_data in movement_chains.values():
            source_hosts.add(chain_data["source_host"])
            destination_hosts.add(chain_data["destination_host"])
        
        # Find intersection (potential pivot points)
        potential_pivots = source_hosts.intersection(destination_hosts)
        
        for pivot_host in potential_pivots:
            # Count inbound and outbound connections
            inbound_count = sum(1 for chain in movement_chains.values() 
                              if chain["destination_host"] == pivot_host)
            outbound_count = sum(1 for chain in movement_chains.values() 
                               if chain["source_host"] == pivot_host)
            
            pivot_points[pivot_host] = {
                "inbound_connections": inbound_count,
                "outbound_connections": outbound_count,
                "total_connections": inbound_count + outbound_count,
                "pivot_likelihood": "high" if (inbound_count + outbound_count) > 3 else "medium",
                "strategic_value": self._assess_pivot_strategic_value(pivot_host, network_propagation)
            }
        
        return pivot_points
    
    def _assess_pivot_strategic_value(self, pivot_host: str, network_propagation: Dict[str, Any]) -> str:
        """Assess strategic value of a pivot point"""
        # Check if pivot is a critical node
        critical_nodes = network_propagation.get("critical_nodes", {})
        if pivot_host in critical_nodes:
            return "critical"
        
        # Check propagation paths
        propagation_paths = network_propagation.get("propagation_paths", [])
        for path in propagation_paths:
            if path["source_host"] == pivot_host and path["propagation_risk"] == "high":
                return "high"
        
        return "medium"
    
    def _calculate_detection_confidence(self, movement_analysis: Dict[str, Any]) -> float:
        """Calculate overall detection confidence"""
        confidence_factors = []
        
        # Factor 1: Number of movement chains detected
        chain_count = len(movement_analysis.get("movement_chains", {}))
        if chain_count > 0:
            confidence_factors.append(min(chain_count * 0.2, 1.0))
        
        # Factor 2: Number of attack vectors identified
        vector_count = len(movement_analysis.get("attack_vectors", {}))
        if vector_count > 0:
            confidence_factors.append(min(vector_count * 0.3, 1.0))
        
        # Factor 3: Presence of pivot points
        pivot_count = len(movement_analysis.get("pivot_points", {}))
        if pivot_count > 0:
            confidence_factors.append(min(pivot_count * 0.4, 1.0))
        
        # Factor 4: Timeline consistency
        timeline_events = movement_analysis.get("movement_timeline", [])
        if len(timeline_events) > 2:
            confidence_factors.append(0.8)
        
        return sum(confidence_factors) / len(confidence_factors) if confidence_factors else 0.0
    
    def _assess_vector_severity(self, vector_type: str, attacks: List[Dict[str, Any]]) -> str:
        """Assess severity of attack vector"""
        attack_count = len(attacks)
        
        # High-risk vectors
        if vector_type in ["credential_attacks", "wmi_attacks"]:
            if attack_count >= 3:
                return "critical"
            elif attack_count >= 2:
                return "high"
            else:
                return "medium"
        
        # Medium-risk vectors
        elif vector_type in ["powershell_attacks", "smb_attacks"]:
            if attack_count >= 5:
                return "high"
            elif attack_count >= 3:
                return "medium"
            else:
                return "low"
        
        # Lower-risk vectors
        else:
            if attack_count >= 10:
                return "medium"
            else:
                return "low"
    
    # Additional helper methods for compromise and progression analysis
    
    def _detect_compromise_indicators(self, host_logs: List[Dict[str, Any]], system_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect indicators of compromise on hosts"""
        compromise_indicators = {}
        
        # Group events by hostname
        host_events = defaultdict(list)
        for log in host_logs + system_events:
            hostname = log.get("hostname", "")
            if hostname:
                host_events[hostname].append(log)
        
        # Analyze each host for compromise indicators
        for hostname, events in host_events.items():
            indicators = []
            
            # Check for suspicious process execution
            suspicious_processes = ["mimikatz", "procdump", "pwdump", "lsass"]
            for event in events:
                process = event.get("process", "").lower()
                if any(sus_proc in process for sus_proc in suspicious_processes):
                    indicators.append(f"suspicious_process_{process}")
            
            # Check for unusual network connections
            network_events = [e for e in events if e.get("event_type") == "network_connection"]
            if len(network_events) > 50:  # High network activity
                indicators.append("high_network_activity")
            
            # Check for file system modifications
            file_events = [e for e in events if e.get("event_type") == "file_creation"]
            suspicious_locations = ["\\temp\\", "\\windows\\temp\\", "\\appdata\\"]
            for event in file_events:
                file_path = event.get("file_path", "").lower()
                if any(sus_loc in file_path for sus_loc in suspicious_locations):
                    indicators.append("suspicious_file_creation")
            
            if indicators:
                compromise_indicators[hostname] = {
                    "indicators": indicators,
                    "indicator_count": len(indicators),
                    "compromise_likelihood": "high" if len(indicators) > 3 else "medium",
                    "first_detected": min([e.get("timestamp", datetime.now()) for e in events])
                }
        
        return compromise_indicators
    
    def _identify_persistence_mechanisms(self, host_logs: List[Dict[str, Any]], system_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Identify persistence mechanisms"""
        persistence_mechanisms = {}
        
        # Look for common persistence techniques
        persistence_indicators = {
            "registry_modification": [4657],  # Registry value modified
            "scheduled_task": [4698, 4702],   # Scheduled task created/enabled
            "service_creation": [7045],       # Service installed
            "startup_modification": [4656]    # Object handle requested
        }
        
        for mechanism, event_ids in persistence_indicators.items():
            relevant_events = [log for log in host_logs + system_events 
                             if log.get("event_id") in event_ids]
            
            if relevant_events:
                persistence_mechanisms[mechanism] = {
                    "event_count": len(relevant_events),
                    "affected_hosts": list(set([e.get("hostname", "") for e in relevant_events])),
                    "first_detected": min([e.get("timestamp", datetime.now()) for e in relevant_events]),
                    "persistence_risk": "high" if len(relevant_events) > 5 else "medium"
                }
        
        return persistence_mechanisms
    
    def _detect_privilege_escalation(self, host_logs: List[Dict[str, Any]], system_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect privilege escalation attempts"""
        privilege_escalation = {}
        
        # Look for privilege escalation indicators
        escalation_events = [log for log in host_logs + system_events 
                           if log.get("event_id") in [4672, 4673, 4674]]  # Special privileges assigned/used
        
        # Group by user and analyze patterns
        user_escalation = defaultdict(list)
        for event in escalation_events:
            username = event.get("username", "")
            user_escalation[username].append(event)
        
        for username, events in user_escalation.items():
            if len(events) > 3:  # Multiple privilege escalation attempts
                privilege_escalation[username] = {
                    "escalation_attempts": len(events),
                    "affected_hosts": list(set([e.get("hostname", "") for e in events])),
                    "privileges_gained": list(set([e.get("privilege", "") for e in events])),
                    "escalation_risk": "critical" if len(events) > 10 else "high",
                    "timeline": {
                        "first_attempt": min([e.get("timestamp", datetime.now()) for e in events]),
                        "last_attempt": max([e.get("timestamp", datetime.now()) for e in events])
                    }
                }
        
        return privilege_escalation
