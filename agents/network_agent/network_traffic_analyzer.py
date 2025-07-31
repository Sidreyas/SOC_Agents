"""
Network Traffic Analyzer Module
State 1: Network Traffic Analysis for Network & Exfiltration Agent
Analyzes network traffic patterns, flows, and anomalies
"""

import logging
import asyncio
import ipaddress
from typing import Dict, Any, List, Optional, Set, Tuple
from datetime import datetime, timedelta
import json
import re
from collections import defaultdict
import statistics

logger = logging.getLogger(__name__)

class NetworkTrafficAnalyzer:
    """
    Network Traffic Analysis for exfiltration detection
    Analyzes traffic patterns, flows, and communication behaviors
    """
    
    def __init__(self):
        self.baseline_patterns = self._load_baseline_patterns()
        self.suspicious_ports = self._load_suspicious_ports()
        self.protocol_analysis = self._load_protocol_patterns()
        
    async def analyze_network_traffic(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze network traffic for exfiltration indicators
        
        Args:
            network_data: Network traffic data from various sources
            
        Returns:
            Network traffic analysis results
        """
        logger.info("Starting network traffic analysis")
        
        analysis_results = {
            "traffic_patterns": {},
            "flow_analysis": {},
            "protocol_analysis": {},
            "anomaly_detection": {},
            "bandwidth_analysis": {},
            "connection_analysis": {},
            "geographic_analysis": {},
            "temporal_analysis": {},
            "analysis_timestamp": datetime.now()
        }
        
        try:
            # Extract and normalize traffic data
            normalized_traffic = await self._normalize_traffic_data(network_data)
            
            # Traffic pattern analysis
            analysis_results["traffic_patterns"] = await self._analyze_traffic_patterns(normalized_traffic)
            
            # Flow analysis
            analysis_results["flow_analysis"] = await self._analyze_network_flows(normalized_traffic)
            
            # Protocol analysis
            analysis_results["protocol_analysis"] = await self._analyze_protocols(normalized_traffic)
            
            # Anomaly detection
            analysis_results["anomaly_detection"] = await self._detect_traffic_anomalies(normalized_traffic)
            
            # Bandwidth analysis
            analysis_results["bandwidth_analysis"] = await self._analyze_bandwidth_usage(normalized_traffic)
            
            # Connection analysis
            analysis_results["connection_analysis"] = await self._analyze_connections(normalized_traffic)
            
            # Geographic analysis
            analysis_results["geographic_analysis"] = await self._analyze_geographic_patterns(normalized_traffic)
            
            # Temporal analysis
            analysis_results["temporal_analysis"] = await self._analyze_temporal_patterns(normalized_traffic)
            
            logger.info("Network traffic analysis completed")
            
        except Exception as e:
            logger.error(f"Error in network traffic analysis: {str(e)}")
            analysis_results["error"] = str(e)
            
        return analysis_results
    
    async def _normalize_traffic_data(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize traffic data from various sources"""
        normalized = {
            "flows": [],
            "connections": [],
            "dns_queries": [],
            "http_requests": [],
            "metadata": {}
        }
        
        # Extract from firewall logs
        firewall_logs = network_data.get("firewall_logs", [])
        for log in firewall_logs:
            flow = {
                "timestamp": log.get("timestamp"),
                "source_ip": log.get("source_ip"),
                "destination_ip": log.get("destination_ip"),
                "source_port": log.get("source_port"),
                "destination_port": log.get("destination_port"),
                "protocol": log.get("protocol"),
                "bytes_sent": log.get("bytes_sent", 0),
                "bytes_received": log.get("bytes_received", 0),
                "action": log.get("action"),
                "source": "firewall"
            }
            normalized["flows"].append(flow)
        
        # Extract from network monitoring
        netflow_data = network_data.get("netflow_data", [])
        for flow in netflow_data:
            normalized_flow = {
                "timestamp": flow.get("timestamp"),
                "source_ip": flow.get("srcaddr"),
                "destination_ip": flow.get("dstaddr"),
                "source_port": flow.get("srcport"),
                "destination_port": flow.get("dstport"),
                "protocol": flow.get("protocol"),
                "bytes_sent": flow.get("bytes", 0),
                "packets": flow.get("packets", 0),
                "duration": flow.get("duration", 0),
                "source": "netflow"
            }
            normalized["flows"].append(normalized_flow)
        
        # Extract DNS queries
        dns_logs = network_data.get("dns_logs", [])
        for query in dns_logs:
            dns_query = {
                "timestamp": query.get("timestamp"),
                "source_ip": query.get("source_ip"),
                "query_name": query.get("query_name"),
                "query_type": query.get("query_type"),
                "response_code": query.get("response_code"),
                "resolved_ips": query.get("resolved_ips", [])
            }
            normalized["dns_queries"].append(dns_query)
        
        # Extract HTTP requests
        http_logs = network_data.get("http_logs", [])
        for request in http_logs:
            http_request = {
                "timestamp": request.get("timestamp"),
                "source_ip": request.get("source_ip"),
                "destination_ip": request.get("destination_ip"),
                "url": request.get("url"),
                "method": request.get("method"),
                "user_agent": request.get("user_agent"),
                "response_code": request.get("response_code"),
                "bytes_transferred": request.get("bytes_transferred", 0)
            }
            normalized["http_requests"].append(http_request)
        
        return normalized
    
    async def _analyze_traffic_patterns(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze overall traffic patterns"""
        traffic_patterns = {
            "volume_patterns": {},
            "directional_patterns": {},
            "protocol_distribution": {},
            "port_usage": {},
            "top_talkers": {},
            "communication_pairs": {}
        }
        
        flows = traffic_data.get("flows", [])
        
        # Volume patterns
        traffic_patterns["volume_patterns"] = await self._analyze_volume_patterns(flows)
        
        # Directional patterns (inbound vs outbound)
        traffic_patterns["directional_patterns"] = await self._analyze_directional_patterns(flows)
        
        # Protocol distribution
        traffic_patterns["protocol_distribution"] = await self._analyze_protocol_distribution(flows)
        
        # Port usage analysis
        traffic_patterns["port_usage"] = await self._analyze_port_usage(flows)
        
        # Top talkers (most active hosts)
        traffic_patterns["top_talkers"] = await self._identify_top_talkers(flows)
        
        # Communication pairs
        traffic_patterns["communication_pairs"] = await self._analyze_communication_pairs(flows)
        
        return traffic_patterns
    
    async def _analyze_network_flows(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze individual network flows"""
        flow_analysis = {
            "long_duration_flows": [],
            "high_volume_flows": [],
            "unusual_protocols": [],
            "encrypted_flows": [],
            "tunnel_indicators": [],
            "flow_statistics": {}
        }
        
        flows = traffic_data.get("flows", [])
        
        # Long duration flows
        flow_analysis["long_duration_flows"] = await self._identify_long_duration_flows(flows)
        
        # High volume flows
        flow_analysis["high_volume_flows"] = await self._identify_high_volume_flows(flows)
        
        # Unusual protocols
        flow_analysis["unusual_protocols"] = await self._identify_unusual_protocols(flows)
        
        # Encrypted flows
        flow_analysis["encrypted_flows"] = await self._identify_encrypted_flows(flows)
        
        # Tunnel indicators
        flow_analysis["tunnel_indicators"] = await self._detect_tunnel_indicators(flows)
        
        # Flow statistics
        flow_analysis["flow_statistics"] = await self._calculate_flow_statistics(flows)
        
        return flow_analysis
    
    async def _analyze_protocols(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze protocol usage and behaviors"""
        protocol_analysis = {
            "http_analysis": {},
            "https_analysis": {},
            "dns_analysis": {},
            "ftp_analysis": {},
            "smtp_analysis": {},
            "ssh_analysis": {},
            "custom_protocols": {}
        }
        
        flows = traffic_data.get("flows", [])
        dns_queries = traffic_data.get("dns_queries", [])
        http_requests = traffic_data.get("http_requests", [])
        
        # HTTP analysis
        protocol_analysis["http_analysis"] = await self._analyze_http_traffic(http_requests, flows)
        
        # HTTPS analysis
        protocol_analysis["https_analysis"] = await self._analyze_https_traffic(flows)
        
        # DNS analysis
        protocol_analysis["dns_analysis"] = await self._analyze_dns_traffic(dns_queries)
        
        # FTP analysis
        protocol_analysis["ftp_analysis"] = await self._analyze_ftp_traffic(flows)
        
        # SMTP analysis
        protocol_analysis["smtp_analysis"] = await self._analyze_smtp_traffic(flows)
        
        # SSH analysis
        protocol_analysis["ssh_analysis"] = await self._analyze_ssh_traffic(flows)
        
        # Custom protocols
        protocol_analysis["custom_protocols"] = await self._analyze_custom_protocols(flows)
        
        return protocol_analysis
    
    async def _detect_traffic_anomalies(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect traffic anomalies"""
        anomaly_detection = {
            "volume_anomalies": [],
            "timing_anomalies": [],
            "protocol_anomalies": [],
            "geographic_anomalies": [],
            "behavioral_anomalies": [],
            "statistical_anomalies": {}
        }
        
        flows = traffic_data.get("flows", [])
        
        # Volume anomalies
        anomaly_detection["volume_anomalies"] = await self._detect_volume_anomalies(flows)
        
        # Timing anomalies
        anomaly_detection["timing_anomalies"] = await self._detect_timing_anomalies(flows)
        
        # Protocol anomalies
        anomaly_detection["protocol_anomalies"] = await self._detect_protocol_anomalies(flows)
        
        # Geographic anomalies
        anomaly_detection["geographic_anomalies"] = await self._detect_geographic_anomalies(flows)
        
        # Behavioral anomalies
        anomaly_detection["behavioral_anomalies"] = await self._detect_behavioral_anomalies(flows)
        
        # Statistical anomalies
        anomaly_detection["statistical_anomalies"] = await self._detect_statistical_anomalies(flows)
        
        return anomaly_detection
    
    async def _analyze_bandwidth_usage(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze bandwidth usage patterns"""
        bandwidth_analysis = {
            "total_bandwidth": 0,
            "peak_usage": {},
            "baseline_deviation": {},
            "per_host_usage": {},
            "per_protocol_usage": {},
            "usage_trends": {}
        }
        
        flows = traffic_data.get("flows", [])
        
        # Calculate total bandwidth
        total_bytes = sum(flow.get("bytes_sent", 0) + flow.get("bytes_received", 0) for flow in flows)
        bandwidth_analysis["total_bandwidth"] = total_bytes
        
        # Peak usage analysis
        bandwidth_analysis["peak_usage"] = await self._analyze_peak_usage(flows)
        
        # Baseline deviation
        bandwidth_analysis["baseline_deviation"] = await self._calculate_baseline_deviation(flows)
        
        # Per-host usage
        bandwidth_analysis["per_host_usage"] = await self._calculate_per_host_usage(flows)
        
        # Per-protocol usage
        bandwidth_analysis["per_protocol_usage"] = await self._calculate_per_protocol_usage(flows)
        
        # Usage trends
        bandwidth_analysis["usage_trends"] = await self._analyze_usage_trends(flows)
        
        return bandwidth_analysis
    
    async def _analyze_connections(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze connection patterns"""
        connection_analysis = {
            "connection_count": 0,
            "unique_destinations": 0,
            "connection_duration": {},
            "failed_connections": [],
            "suspicious_connections": [],
            "connection_patterns": {}
        }
        
        flows = traffic_data.get("flows", [])
        
        # Connection count
        connection_analysis["connection_count"] = len(flows)
        
        # Unique destinations
        unique_destinations = set()
        for flow in flows:
            dest_ip = flow.get("destination_ip")
            if dest_ip:
                unique_destinations.add(dest_ip)
        connection_analysis["unique_destinations"] = len(unique_destinations)
        
        # Connection duration analysis
        connection_analysis["connection_duration"] = await self._analyze_connection_duration(flows)
        
        # Failed connections
        connection_analysis["failed_connections"] = await self._identify_failed_connections(flows)
        
        # Suspicious connections
        connection_analysis["suspicious_connections"] = await self._identify_suspicious_connections(flows)
        
        # Connection patterns
        connection_analysis["connection_patterns"] = await self._analyze_connection_patterns(flows)
        
        return connection_analysis
    
    async def _analyze_geographic_patterns(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze geographic traffic patterns"""
        geographic_analysis = {
            "country_distribution": {},
            "unusual_locations": [],
            "geo_anomalies": [],
            "travel_impossible": [],
            "risk_regions": []
        }
        
        flows = traffic_data.get("flows", [])
        
        # Country distribution
        geographic_analysis["country_distribution"] = await self._analyze_country_distribution(flows)
        
        # Unusual locations
        geographic_analysis["unusual_locations"] = await self._identify_unusual_locations(flows)
        
        # Geographic anomalies
        geographic_analysis["geo_anomalies"] = await self._detect_geographic_anomalies(flows)
        
        # Impossible travel scenarios
        geographic_analysis["travel_impossible"] = await self._detect_impossible_travel(flows)
        
        # High-risk regions
        geographic_analysis["risk_regions"] = await self._identify_risk_regions(flows)
        
        return geographic_analysis
    
    async def _analyze_temporal_patterns(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze temporal traffic patterns"""
        temporal_analysis = {
            "hourly_patterns": {},
            "daily_patterns": {},
            "weekly_patterns": {},
            "seasonal_patterns": {},
            "off_hours_activity": [],
            "periodic_activity": []
        }
        
        flows = traffic_data.get("flows", [])
        
        # Hourly patterns
        temporal_analysis["hourly_patterns"] = await self._analyze_hourly_patterns(flows)
        
        # Daily patterns
        temporal_analysis["daily_patterns"] = await self._analyze_daily_patterns(flows)
        
        # Weekly patterns
        temporal_analysis["weekly_patterns"] = await self._analyze_weekly_patterns(flows)
        
        # Off-hours activity
        temporal_analysis["off_hours_activity"] = await self._detect_off_hours_activity(flows)
        
        # Periodic activity
        temporal_analysis["periodic_activity"] = await self._detect_periodic_activity(flows)
        
        return temporal_analysis
    
    # Helper methods for pattern analysis
    async def _identify_top_talkers(self, flows: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Identify top talking hosts"""
        host_stats = defaultdict(lambda: {"bytes_sent": 0, "bytes_received": 0, "connections": 0})
        
        for flow in flows:
            source_ip = flow.get("source_ip")
            if source_ip:
                host_stats[source_ip]["bytes_sent"] += flow.get("bytes_sent", 0)
                host_stats[source_ip]["connections"] += 1
            
            dest_ip = flow.get("destination_ip")
            if dest_ip:
                host_stats[dest_ip]["bytes_received"] += flow.get("bytes_received", 0)
        
        # Sort by total bytes
        sorted_hosts = sorted(
            host_stats.items(),
            key=lambda x: x[1]["bytes_sent"] + x[1]["bytes_received"],
            reverse=True
        )
        
        return {
            "top_senders": sorted_hosts[:10],
            "top_receivers": sorted(host_stats.items(), key=lambda x: x[1]["bytes_received"], reverse=True)[:10],
            "most_connections": sorted(host_stats.items(), key=lambda x: x[1]["connections"], reverse=True)[:10]
        }
    
    async def _detect_volume_anomalies(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect volume-based anomalies"""
        volume_anomalies = []
        
        # Calculate baseline statistics
        volumes = [flow.get("bytes_sent", 0) + flow.get("bytes_received", 0) for flow in flows]
        if volumes:
            mean_volume = statistics.mean(volumes)
            std_volume = statistics.stdev(volumes) if len(volumes) > 1 else 0
            threshold = mean_volume + (3 * std_volume)  # 3-sigma rule
            
            for flow in flows:
                flow_volume = flow.get("bytes_sent", 0) + flow.get("bytes_received", 0)
                if flow_volume > threshold:
                    volume_anomalies.append({
                        "flow": flow,
                        "volume": flow_volume,
                        "threshold": threshold,
                        "deviation": flow_volume - mean_volume,
                        "anomaly_type": "high_volume"
                    })
        
        return volume_anomalies
    
    def _load_baseline_patterns(self) -> Dict[str, Any]:
        """Load baseline traffic patterns"""
        return {
            "normal_protocols": ["http", "https", "dns", "smtp", "ssh"],
            "business_hours": {"start": 8, "end": 18},
            "typical_bandwidth": {"hourly": 1000000, "daily": 24000000},
            "common_ports": [80, 443, 53, 25, 22, 993, 995]
        }
    
    def _load_suspicious_ports(self) -> List[int]:
        """Load suspicious port numbers"""
        return [
            4444, 5555, 6666, 7777, 8080, 8443, 9999,  # Common backdoor ports
            1234, 31337, 12345, 54321,  # Known malware ports
            6667, 6668, 6669,  # IRC ports
            1080, 3128, 8080  # Proxy ports
        ]
    
    def _load_protocol_patterns(self) -> Dict[str, Any]:
        """Load protocol analysis patterns"""
        return {
            "encrypted_ports": [443, 993, 995, 22, 990],
            "file_transfer_ports": [21, 22, 990, 989],
            "email_ports": [25, 110, 143, 993, 995],
            "web_ports": [80, 443, 8080, 8443]
        }

# Factory function
def create_network_traffic_analyzer() -> NetworkTrafficAnalyzer:
    """Create and return NetworkTrafficAnalyzer instance"""
    return NetworkTrafficAnalyzer()
