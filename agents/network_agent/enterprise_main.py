"""
Network & Exfiltration Agent - Enterprise Main Module
Orchestrates network monitoring, exfiltration detection, and threat analysis
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import json

# Import enterprise managers
from common.config import get_config
from common.utils import setup_logging

# Import workflow modules
from .network_traffic_analyzer import create_network_traffic_analyzer
from .data_exfiltration_detector import create_data_exfiltration_detector
from .lateral_movement_detector import create_lateral_movement_detector
from .command_control_analyzer import create_command_control_analyzer
from .threat_intelligence_correlator import create_threat_intelligence_correlator
from .final_assessment import create_final_assessment

logger = logging.getLogger(__name__)

class NetworkExfiltrationAgent:
    """
    Enterprise Network & Exfiltration Detection Agent
    
    6-State Workflow:
    1. Network Traffic Analysis - Analyze traffic patterns and flows
    2. Data Exfiltration Detection - Detect various exfiltration methods
    3. Lateral Movement Detection - Identify lateral movement techniques
    4. Command & Control Analysis - Analyze C2 communication patterns
    5. Threat Intelligence Correlation - Correlate with threat feeds
    6. Final Assessment - Comprehensive assessment and recommendations
    """
    
    def __init__(self):
        self.config = get_config()
        self.agent_id = "network_exfiltration_agent"
        self.version = "2.0.0"
        
        # Initialize workflow modules
        self.traffic_analyzer = None
        self.exfiltration_detector = None
        self.lateral_movement_detector = None
        self.c2_analyzer = None
        self.threat_intel_correlator = None
        self.final_assessor = None
        
    async def initialize(self):
        """Initialize the Network & Exfiltration Agent"""
        logger.info(f"Initializing {self.agent_id} v{self.version}")
        
        # Initialize enterprise components
        await self._setup_enterprise_infrastructure()
        
        # Initialize workflow modules
        await self._initialize_workflow_modules()
        
        logger.info("Network & Exfiltration Agent initialized successfully")
    
    async def _setup_enterprise_infrastructure(self):
        """Setup enterprise infrastructure components"""
        # Enterprise infrastructure setup would go here
        pass
    
    async def _initialize_workflow_modules(self):
        """Initialize all workflow analysis modules"""
        try:
            self.traffic_analyzer = create_network_traffic_analyzer()
            self.exfiltration_detector = create_data_exfiltration_detector()
            self.lateral_movement_detector = create_lateral_movement_detector()
            self.c2_analyzer = create_command_control_analyzer()
            self.threat_intel_correlator = create_threat_intelligence_correlator()
            self.final_assessor = create_final_assessment()
            
            logger.info("All workflow modules initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing workflow modules: {str(e)}")
            raise
    
    async def analyze_network_threat(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze network threat with 6-state comprehensive assessment
        
        Args:
            alert_data: Network alert or incident data
            
        Returns:
            Comprehensive threat analysis results
        """
        try:
            analysis_start = datetime.now()
            logger.info(f"Starting network threat analysis for alert: {alert_data.get('alert_id', 'unknown')}")
            
            # Extract and prepare network data
            network_data = await self._extract_network_data(alert_data)
            
            # State 1: Network Traffic Analysis
            logger.info("State 1: Analyzing network traffic patterns")
            traffic_analysis = await self.traffic_analyzer.analyze_network_traffic(network_data)
            
            # State 2: Data Exfiltration Detection
            logger.info("State 2: Detecting data exfiltration activities")
            exfiltration_analysis = await self.exfiltration_detector.detect_data_exfiltration(network_data)
            
            # State 3: Lateral Movement Detection
            logger.info("State 3: Detecting lateral movement patterns")
            lateral_movement_analysis = await self.lateral_movement_detector.detect_lateral_movement(network_data)
            
            # State 4: Command & Control Analysis
            logger.info("State 4: Analyzing command & control communications")
            c2_analysis = await self.c2_analyzer.analyze_command_control(network_data)
            
            # State 5: Threat Intelligence Correlation
            logger.info("State 5: Correlating with threat intelligence")
            network_indicators = await self._extract_network_indicators(
                traffic_analysis, exfiltration_analysis, lateral_movement_analysis, c2_analysis
            )
            threat_intelligence = await self.threat_intel_correlator.correlate_threat_intelligence(network_indicators)
            
            # State 6: Final Assessment
            logger.info("State 6: Performing final assessment")
            combined_results = {
                "traffic_analysis": traffic_analysis,
                "exfiltration_detection": exfiltration_analysis,
                "lateral_movement": lateral_movement_analysis,
                "c2_analysis": c2_analysis,
                "threat_intelligence": threat_intelligence
            }
            final_assessment = await self.final_assessor.perform_final_assessment(combined_results)
            
            # Compile comprehensive results
            analysis_results = {
                "agent_id": self.agent_id,
                "agent_version": self.version,
                "analysis_timestamp": analysis_start,
                "analysis_duration": (datetime.now() - analysis_start).total_seconds(),
                "alert_data": alert_data,
                
                # State results
                "state_1_traffic_analysis": traffic_analysis,
                "state_2_exfiltration_detection": exfiltration_analysis,
                "state_3_lateral_movement": lateral_movement_analysis,
                "state_4_c2_analysis": c2_analysis,
                "state_5_threat_intelligence": threat_intelligence,
                "state_6_final_assessment": final_assessment,
                
                # Summary
                "executive_summary": final_assessment.get("executive_summary", {}),
                "severity": final_assessment.get("severity_assessment", {}).get("overall_severity", "low"),
                "confidence": final_assessment.get("confidence_analysis", {}).get("confidence_level", "low"),
                "recommendations": final_assessment.get("response_recommendations", {}),
                "iocs": final_assessment.get("ioc_summary", {}),
                
                # Metadata
                "workflow_status": "completed",
                "states_completed": 6,
                "enterprise_ready": True
            }
            
            logger.info(f"Network threat analysis completed in {analysis_results['analysis_duration']:.2f} seconds")
            return analysis_results
            
        except Exception as e:
            logger.error(f"Error in network threat analysis: {str(e)}")
            return {
                "agent_id": self.agent_id,
                "error": str(e),
                "workflow_status": "failed",
                "analysis_timestamp": datetime.now()
            }
    
    async def _extract_network_data(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract and normalize network data from alert"""
        network_data = {
            "flows": alert_data.get("network_flows", []),
            "dns_queries": alert_data.get("dns_logs", []),
            "http_requests": alert_data.get("http_logs", []),
            "firewall_logs": alert_data.get("firewall_logs", []),
            "netflow_data": alert_data.get("netflow_data", []),
            "authentication_logs": alert_data.get("auth_logs", []),
            "process_logs": alert_data.get("process_logs", []),
            "file_logs": alert_data.get("file_logs", []),
            "email_logs": alert_data.get("email_logs", []),
            "smb_logs": alert_data.get("smb_logs", []),
            "metadata": {
                "source": alert_data.get("source", "unknown"),
                "timestamp": alert_data.get("timestamp", datetime.now()),
                "alert_id": alert_data.get("alert_id", "unknown")
            }
        }
        
        return network_data
    
    async def _extract_network_indicators(self, traffic_analysis: Dict[str, Any], 
                                        exfiltration_analysis: Dict[str, Any],
                                        lateral_movement_analysis: Dict[str, Any],
                                        c2_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Extract network indicators from analysis results"""
        indicators = {
            "ip_addresses": [],
            "domains": [],
            "urls": [],
            "file_hashes": [],
            "network_signatures": [],
            "behavioral_indicators": []
        }
        
        # Extract IPs from various analyses
        try:
            # From traffic analysis
            top_talkers = traffic_analysis.get("traffic_patterns", {}).get("top_talkers", {})
            if "top_senders" in top_talkers:
                indicators["ip_addresses"].extend([item[0] for item in top_talkers["top_senders"][:10]])
            
            # From C2 analysis
            c2_infrastructure = c2_analysis.get("c2_infrastructure", {})
            if "ip_addresses" in c2_infrastructure:
                indicators["ip_addresses"].extend([ip["ip"] for ip in c2_infrastructure["ip_addresses"]])
            
            # From lateral movement
            movement_graph = lateral_movement_analysis.get("movement_graph", {})
            if "central_nodes" in movement_graph:
                indicators["ip_addresses"].extend([node[0] for node in movement_graph["central_nodes"][:5]])
        
        except Exception as e:
            logger.warning(f"Error extracting IP indicators: {str(e)}")
        
        # Extract domains from analyses
        try:
            # From C2 analysis
            c2_domains = c2_analysis.get("c2_infrastructure", {}).get("domains", [])
            indicators["domains"].extend([domain["domain"] for domain in c2_domains])
            
            # From DGA detection
            dga_domains = c2_analysis.get("dga_detection", {}).get("dga_domains", [])
            indicators["domains"].extend([domain["domain"] for domain in dga_domains])
        
        except Exception as e:
            logger.warning(f"Error extracting domain indicators: {str(e)}")
        
        # Remove duplicates
        indicators["ip_addresses"] = list(set(indicators["ip_addresses"]))
        indicators["domains"] = list(set(indicators["domains"]))
        
        return indicators
    
    async def run_continuous_monitoring(self):
        """Run continuous network monitoring"""
        logger.info("Starting continuous network monitoring")
        
        while True:
            try:
                # Monitor for network alerts
                # This would integrate with actual monitoring systems
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Error in continuous monitoring: {str(e)}")
                await asyncio.sleep(30)
    
    async def process_alert_queue(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process multiple alerts concurrently"""
        logger.info(f"Processing {len(alerts)} network alerts")
        
        tasks = []
        for alert in alerts:
            task = self.analyze_network_threat(alert)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append({
                    "alert_id": alerts[i].get("alert_id", f"alert_{i}"),
                    "error": str(result),
                    "status": "failed"
                })
            else:
                processed_results.append(result)
        
        logger.info(f"Processed {len(processed_results)} alerts")
        return processed_results

async def main():
    """Main function for Network & Exfiltration Agent"""
    setup_logging()
    
    agent = NetworkExfiltrationAgent()
    await agent.initialize()
    
    # Example usage with comprehensive network alert
    sample_alert = {
        "alert_id": "NET_001",
        "timestamp": datetime.now(),
        "source": "network_monitor",
        "description": "Suspicious network activity detected - potential data exfiltration",
        "severity": "high",
        "network_flows": [
            {
                "timestamp": datetime.now(),
                "source_ip": "192.168.1.100",
                "destination_ip": "203.0.113.42",
                "source_port": 12345,
                "destination_port": 443,
                "protocol": "tcp",
                "bytes_sent": 1048576,
                "bytes_received": 2048
            }
        ],
        "dns_logs": [
            {
                "timestamp": datetime.now(),
                "source_ip": "192.168.1.100",
                "query_name": "suspicious-domain.example.com",
                "query_type": "A",
                "response_code": "NOERROR"
            }
        ],
        "http_logs": [
            {
                "timestamp": datetime.now(),
                "source_ip": "192.168.1.100",
                "destination_ip": "203.0.113.42",
                "url": "https://suspicious-domain.example.com/upload",
                "method": "POST",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "response_code": 200,
                "bytes_transferred": 1048576
            }
        ]
    }
    
    results = await agent.analyze_network_threat(sample_alert)
    logger.info(f"Analysis completed - Severity: {results.get('severity', 'unknown')}")
    logger.info(f"Confidence: {results.get('confidence', 'unknown')}")
    logger.info(f"States completed: {results.get('states_completed', 0)}/6")

if __name__ == "__main__":
    asyncio.run(main())
