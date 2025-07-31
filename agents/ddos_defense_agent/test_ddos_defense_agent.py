"""
DDoS Defense Agent - Comprehensive Testing Module
Testing framework for all DDoS defense analysis states and integration
"""

import unittest
import asyncio
import logging
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta
from typing import Dict, Any, List
import json

# Import all modules for testing
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ddos_defense_agent import (
    DDoSDefenseAgent, 
    DDoSAnalysisRequest, 
    DDoSAnalysisResult,
    DDoSDefenseAgentStatus
)
from traffic_pattern_analyzer import TrafficPatternAnalyzer, TrafficAnalysisResult
from source_ip_intelligence import SourceIPIntelligenceAnalyzer, SourceIntelligenceResult
from attack_vector_classifier import AttackVectorClassifier, AttackClassificationResult
from impact_assessment import ImpactAssessmentAnalyzer, ImpactAssessmentResult
from mitigation_effectiveness import MitigationEffectivenessAnalyzer, MitigationEffectivenessResult
from threat_attribution import ThreatAttributionAnalyzer, ThreatAttributionResult

# Configure test logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TestDDoSDefenseAgent(unittest.TestCase):
    """Test suite for DDoS Defense Agent main functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.agent = DDoSDefenseAgent()
        self.sample_request = DDoSAnalysisRequest(
            request_id="test-request-001",
            request_timestamp=datetime.now(),
            traffic_data=self._get_sample_traffic_data(),
            azure_monitor_data=self._get_sample_azure_data(),
            network_security_logs=self._get_sample_network_logs(),
            application_logs=self._get_sample_app_logs(),
            priority="high"
        )
    
    def test_agent_initialization(self):
        """Test agent initialization"""
        self.assertEqual(self.agent.status, DDoSDefenseAgentStatus.IDLE)
        self.assertIsInstance(self.agent.traffic_analyzer, TrafficPatternAnalyzer)
        self.assertIsInstance(self.agent.source_intelligence_analyzer, SourceIPIntelligenceAnalyzer)
        self.assertIsInstance(self.agent.attack_classifier, AttackVectorClassifier)
        self.assertIsInstance(self.agent.impact_assessor, ImpactAssessmentAnalyzer)
        self.assertIsInstance(self.agent.mitigation_analyzer, MitigationEffectivenessAnalyzer)
        self.assertIsInstance(self.agent.attribution_analyzer, ThreatAttributionAnalyzer)
    
    @patch('ddos_defense_agent.TrafficPatternAnalyzer.analyze_traffic_patterns')
    @patch('ddos_defense_agent.SourceIPIntelligenceAnalyzer.analyze_source_intelligence')
    @patch('ddos_defense_agent.AttackVectorClassifier.classify_attack_vectors')
    @patch('ddos_defense_agent.ImpactAssessmentAnalyzer.assess_ddos_impact')
    @patch('ddos_defense_agent.MitigationEffectivenessAnalyzer.analyze_mitigation_effectiveness')
    @patch('ddos_defense_agent.ThreatAttributionAnalyzer.perform_threat_attribution')
    def test_complete_analysis_workflow(self, mock_attribution, mock_mitigation, 
                                      mock_impact, mock_classification, 
                                      mock_source_intel, mock_traffic):
        """Test complete DDoS analysis workflow"""
        # Setup mocks
        mock_traffic.return_value = self._get_mock_traffic_result()
        mock_source_intel.return_value = self._get_mock_source_intelligence_result()
        mock_classification.return_value = self._get_mock_classification_result()
        mock_impact.return_value = self._get_mock_impact_result()
        mock_mitigation.return_value = self._get_mock_mitigation_result()
        mock_attribution.return_value = self._get_mock_attribution_result()
        
        # Run analysis
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(self.agent.analyze_ddos_threat(self.sample_request))
        
        # Verify results
        self.assertIsInstance(result, DDoSAnalysisResult)
        self.assertEqual(result.request_id, self.sample_request.request_id)
        self.assertEqual(result.overall_status, "completed")
        self.assertIn(result.threat_level, ["critical", "high", "medium", "low"])
        self.assertGreaterEqual(result.confidence_score, 0.0)
        self.assertLessEqual(result.confidence_score, 1.0)
        
        # Verify all analyzers were called
        mock_traffic.assert_called_once()
        mock_source_intel.assert_called_once()
        mock_classification.assert_called_once()
        mock_impact.assert_called_once()
        mock_mitigation.assert_called_once()
        mock_attribution.assert_called_once()
    
    def test_get_agent_metrics(self):
        """Test agent metrics retrieval"""
        # Add some mock analysis history
        self.agent.analysis_history = [
            self._get_mock_analysis_result("analysis-1"),
            self._get_mock_analysis_result("analysis-2")
        ]
        
        metrics = self.agent.get_agent_metrics()
        
        self.assertEqual(metrics["total_analyses"], 2)
        self.assertIn("success_rate", metrics)
        self.assertIn("current_status", metrics)
        self.assertEqual(metrics["current_status"], "idle")
    
    def test_get_analysis_history(self):
        """Test analysis history retrieval"""
        # Add mock history
        self.agent.analysis_history = [
            self._get_mock_analysis_result("analysis-1"),
            self._get_mock_analysis_result("analysis-2"),
            self._get_mock_analysis_result("analysis-3")
        ]
        
        history = self.agent.get_analysis_history(limit=2)
        self.assertEqual(len(history), 2)
        
        history_all = self.agent.get_analysis_history()
        self.assertEqual(len(history_all), 3)
    
    def _get_sample_traffic_data(self) -> Dict[str, Any]:
        """Get sample traffic data for testing"""
        return {
            "baseline_data": {
                "average_requests_per_second": 1000,
                "average_bytes_per_second": 10000000,
                "typical_source_countries": ["US", "UK", "DE"]
            },
            "current_metrics": {
                "requests_per_second": 50000,
                "bytes_per_second": 500000000,
                "unique_source_ips": 10000
            }
        }
    
    def _get_sample_azure_data(self) -> Dict[str, Any]:
        """Get sample Azure Monitor data for testing"""
        return {
            "ddos_protection_metrics": {
                "mitigation_triggered": True,
                "packets_dropped": 1000000,
                "mitigation_start_time": datetime.now() - timedelta(minutes=30)
            },
            "network_analytics": {
                "flow_logs": [],
                "security_center_alerts": []
            },
            "protection_logs": {
                "waf_blocks": 5000,
                "firewall_drops": 2000
            }
        }
    
    def _get_sample_network_logs(self) -> Dict[str, Any]:
        """Get sample network security logs for testing"""
        return {
            "firewall_logs": [
                {
                    "timestamp": datetime.now(),
                    "source_ip": "192.168.1.100",
                    "action": "drop",
                    "protocol": "UDP"
                }
            ],
            "flow_logs": [
                {
                    "timestamp": datetime.now(),
                    "source_ip": "10.0.0.1",
                    "destination_port": 80,
                    "bytes": 1500
                }
            ]
        }
    
    def _get_sample_app_logs(self) -> Dict[str, Any]:
        """Get sample application logs for testing"""
        return {
            "service_metrics": {
                "response_time_ms": 5000,
                "error_rate_percent": 15,
                "availability_percent": 85
            },
            "business_metrics": {
                "transactions_per_minute": 500,
                "revenue_impact": 10000
            }
        }
    
    def _get_mock_traffic_result(self) -> TrafficAnalysisResult:
        """Get mock traffic analysis result"""
        return TrafficAnalysisResult(
            analysis_id="traffic-001",
            analysis_timestamp=datetime.now(),
            attack_detected=True,
            baseline_deviation={"requests_per_second": 50.0},
            anomaly_indicators=["volume_spike"],
            threat_indicators={"volumetric_attack": 0.9},
            azure_ddos_metrics={"protection_active": True},
            confidence_score=0.85
        )
    
    def _get_mock_source_intelligence_result(self) -> SourceIntelligenceResult:
        """Get mock source intelligence result"""
        return SourceIntelligenceResult(
            analysis_id="source-001",
            analysis_timestamp=datetime.now(),
            geographic_analysis={"top_countries": ["CN", "RU"]},
            reputation_analysis={"malicious_ips": 500},
            threat_correlation={"botnet_indicators": ["mirai"]},
            attack_infrastructure={"c2_servers": []},
            confidence_score=0.80
        )
    
    def _get_mock_classification_result(self) -> AttackClassificationResult:
        """Get mock attack classification result"""
        from attack_vector_classifier import AttackType, AttackSeverity, AttackVector
        
        return AttackClassificationResult(
            analysis_id="class-001",
            analysis_timestamp=datetime.now(),
            primary_attack_vectors=[
                AttackVector(
                    vector_type=AttackType.VOLUMETRIC_UDP,
                    confidence_score=0.9,
                    volume_metrics={"pps": 500000},
                    protocol_analysis={"udp_dominant": True},
                    application_impact={"service_degradation": 0.8},
                    severity=AttackSeverity.HIGH
                )
            ],
            attack_characteristics={"coordinated": True},
            protocol_analysis={"dominant_protocol": "UDP"},
            application_analysis={"affected_services": ["web"]},
            volumetric_analysis={"peak_pps": 500000},
            attack_sophistication="medium",
            overall_severity=AttackSeverity.HIGH,
            confidence_score=0.85
        )
    
    def _get_mock_impact_result(self) -> ImpactAssessmentResult:
        """Get mock impact assessment result"""
        from impact_assessment import BusinessImpact, ServiceMetrics, ServiceType, BusinessMetrics
        
        return ImpactAssessmentResult(
            assessment_id="impact-001",
            assessment_timestamp=datetime.now(),
            overall_impact=BusinessImpact.HIGH,
            service_impacts=[
                ServiceMetrics(
                    service_name="web_service",
                    service_type=ServiceType.WEB_APPLICATION,
                    availability_percentage=85.0,
                    response_time_ms=5000,
                    error_rate_percentage=15.0,
                    throughput_requests_per_second=500,
                    concurrent_users=1000,
                    resource_utilization={"cpu": 90.0}
                )
            ],
            business_metrics=BusinessMetrics(
                revenue_impact_per_hour=25000,
                customer_impact_count=5000,
                transaction_loss_count=100,
                sla_violations=["availability"],
                reputation_risk_score=7.0,
                recovery_cost_estimate=15000
            ),
            availability_analysis={"overall_availability": 85.0},
            performance_analysis={"degradation": 50.0},
            customer_impact_analysis={"affected_users": 5000},
            financial_impact_analysis={"total_cost": 75000},
            recovery_analysis={"estimated_time": timedelta(hours=4)},
            sla_compliance_analysis={"violations": 1},
            confidence_score=0.82
        )
    
    def _get_mock_mitigation_result(self) -> MitigationEffectivenessResult:
        """Get mock mitigation effectiveness result"""
        from mitigation_effectiveness import MitigationStatus, MitigationResult, MitigationType, ProtectionLayer, MitigationMetrics
        
        return MitigationEffectivenessResult(
            analysis_id="mitigation-001",
            analysis_timestamp=datetime.now(),
            overall_effectiveness=MitigationStatus.EFFECTIVE,
            mitigation_results=[
                MitigationResult(
                    mitigation_id="ddos-std-001",
                    mitigation_type=MitigationType.AZURE_DDOS_STANDARD,
                    status=MitigationStatus.EFFECTIVE,
                    metrics=MitigationMetrics(
                        mitigation_type=MitigationType.AZURE_DDOS_STANDARD,
                        protection_layer=ProtectionLayer.NETWORK_LAYER,
                        effectiveness_percentage=85.0,
                        traffic_blocked_percentage=80.0,
                        false_positive_rate=2.0,
                        response_time_ms=45000,
                        activation_delay_seconds=30,
                        resource_utilization={"cpu": 20.0}
                    ),
                    performance_impact={"latency_increase": 5.0},
                    configuration_effectiveness={"optimal": True},
                    recommendations=["Optimize thresholds"]
                )
            ],
            protection_coverage={"network_layer": 90.0},
            azure_ddos_analysis={"effectiveness": 85.0},
            waf_effectiveness={"blocking_rate": 95.0},
            cdn_performance={"cache_hit_ratio": 85.0},
            optimization_recommendations=[],
            cost_effectiveness_analysis={"roi": 8.0},
            confidence_score=0.88
        )
    
    def _get_mock_attribution_result(self) -> ThreatAttributionResult:
        """Get mock threat attribution result"""
        return ThreatAttributionResult(
            analysis_id="attribution-001",
            analysis_timestamp=datetime.now(),
            attack_fingerprint={"hash": "abc123"},
            pattern_analysis={"patterns_identified": 3},
            historical_correlation={"similar_attacks": 2},
            threat_intelligence_matches={"actor_matches": ["apt29"]},
            attribution_results=[],
            campaign_analysis={"campaign_detected": False},
            infrastructure_analysis={"infrastructure_type": "botnet"},
            confidence_assessment={"overall_confidence": "medium"}
        )
    
    def _get_mock_analysis_result(self, analysis_id: str) -> DDoSAnalysisResult:
        """Get mock complete analysis result"""
        return DDoSAnalysisResult(
            analysis_id=analysis_id,
            request_id="test-request",
            analysis_timestamp=datetime.now() - timedelta(hours=1),
            completion_timestamp=datetime.now(),
            overall_status="completed",
            threat_level="high",
            confidence_score=0.85,
            traffic_analysis=self._get_mock_traffic_result(),
            source_intelligence=self._get_mock_source_intelligence_result(),
            attack_classification=self._get_mock_classification_result(),
            impact_assessment=self._get_mock_impact_result(),
            mitigation_effectiveness=self._get_mock_mitigation_result(),
            threat_attribution=self._get_mock_attribution_result(),
            executive_summary={"attack_detected": True},
            recommendations=[{"action": "enhance_protection"}],
            next_actions=["monitor_situation"]
        )


class TestTrafficPatternAnalyzer(unittest.TestCase):
    """Test suite for Traffic Pattern Analyzer (State 1)"""
    
    def setUp(self):
        """Set up test environment"""
        self.analyzer = TrafficPatternAnalyzer()
    
    def test_analyzer_initialization(self):
        """Test analyzer initialization"""
        self.assertIsNotNone(self.analyzer.analysis_config)
        self.assertIsNotNone(self.analyzer.azure_ddos_client)
        self.assertIsNotNone(self.analyzer.baseline_calculator)
    
    def test_analyze_traffic_patterns(self):
        """Test traffic pattern analysis"""
        ddos_metrics = {
            "packets_per_second": 100000,
            "bytes_per_second": 1000000000,
            "unique_sources": 10000
        }
        
        baseline_data = {
            "average_pps": 1000,
            "average_bps": 10000000,
            "typical_sources": 100
        }
        
        network_analytics = {
            "flow_logs": [],
            "security_alerts": []
        }
        
        result = self.analyzer.analyze_traffic_patterns(
            ddos_metrics, baseline_data, network_analytics
        )
        
        self.assertIsInstance(result, TrafficAnalysisResult)
        self.assertIsNotNone(result.analysis_id)
        self.assertIsInstance(result.attack_detected, bool)
        self.assertIsInstance(result.confidence_score, float)
    
    def test_detect_volumetric_attacks(self):
        """Test volumetric attack detection"""
        traffic_metrics = {
            "packets_per_second": 500000,
            "bytes_per_second": 5000000000
        }
        
        baseline_data = {
            "average_pps": 1000,
            "average_bps": 10000000
        }
        
        result = self.analyzer.detect_volumetric_attacks(traffic_metrics, baseline_data)
        
        self.assertIn("analysis_metadata", result)
        self.assertIn("attack_detected", result["analysis_metadata"])
        self.assertIsInstance(result["analysis_metadata"]["attack_detected"], bool)


class TestSourceIPIntelligenceAnalyzer(unittest.TestCase):
    """Test suite for Source IP Intelligence Analyzer (State 2)"""
    
    def setUp(self):
        """Set up test environment"""
        self.analyzer = SourceIPIntelligenceAnalyzer()
    
    def test_analyzer_initialization(self):
        """Test analyzer initialization"""
        self.assertIsNotNone(self.analyzer.intelligence_config)
        self.assertIsNotNone(self.analyzer.reputation_services)
        self.assertIsNotNone(self.analyzer.geographic_db)
    
    def test_analyze_source_intelligence(self):
        """Test source IP intelligence analysis"""
        traffic_data = {
            "source_ips": ["192.168.1.1", "10.0.0.1", "172.16.0.1"],
            "request_counts": {"192.168.1.1": 10000}
        }
        
        firewall_logs = [
            {"source_ip": "192.168.1.1", "action": "drop"},
            {"source_ip": "10.0.0.1", "action": "allow"}
        ]
        
        flow_logs = [
            {"source_ip": "192.168.1.1", "bytes": 1500}
        ]
        
        result = self.analyzer.analyze_source_intelligence(
            traffic_data, firewall_logs, flow_logs
        )
        
        self.assertIsInstance(result, SourceIntelligenceResult)
        self.assertIsNotNone(result.analysis_id)
        self.assertIsInstance(result.confidence_score, float)
    
    def test_analyze_geographic_distribution(self):
        """Test geographic distribution analysis"""
        source_ips = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
        
        result = self.analyzer.analyze_geographic_distribution(source_ips)
        
        self.assertIn("analysis_metadata", result)
        self.assertIn("countries_detected", result["analysis_metadata"])
        self.assertIsInstance(result["analysis_metadata"]["countries_detected"], int)


class TestAttackVectorClassifier(unittest.TestCase):
    """Test suite for Attack Vector Classifier (State 3)"""
    
    def setUp(self):
        """Set up test environment"""
        self.classifier = AttackVectorClassifier()
    
    def test_classifier_initialization(self):
        """Test classifier initialization"""
        self.assertIsNotNone(self.classifier.classification_config)
        self.assertIsNotNone(self.classifier.azure_monitor_client)
        self.assertIsNotNone(self.classifier.attack_signatures)
    
    def test_classify_attack_vectors(self):
        """Test attack vector classification"""
        traffic_data = {
            "volume_metrics": {"pps": 100000, "bps": 1000000000},
            "protocol_distribution": {"UDP": 0.8, "TCP": 0.2}
        }
        
        source_intelligence = {
            "geographic_spread": "global",
            "reputation_analysis": {"malicious_ratio": 0.7}
        }
        
        azure_monitor_data = {
            "ddos_protection_active": True,
            "mitigation_triggered": True
        }
        
        result = self.classifier.classify_attack_vectors(
            traffic_data, source_intelligence, azure_monitor_data
        )
        
        self.assertIsInstance(result, AttackClassificationResult)
        self.assertIsNotNone(result.analysis_id)
        self.assertIsInstance(result.primary_attack_vectors, list)
        self.assertIsInstance(result.confidence_score, float)


class TestImpactAssessmentAnalyzer(unittest.TestCase):
    """Test suite for Impact Assessment Analyzer (State 4)"""
    
    def setUp(self):
        """Set up test environment"""
        self.assessor = ImpactAssessmentAnalyzer()
    
    def test_assessor_initialization(self):
        """Test assessor initialization"""
        self.assertIsNotNone(self.assessor.assessment_config)
        self.assertIsNotNone(self.assessor.service_monitors)
        self.assertIsNotNone(self.assessor.sla_definitions)
    
    def test_assess_ddos_impact(self):
        """Test DDoS impact assessment"""
        attack_classification = {
            "primary_vectors": ["volumetric"],
            "severity": "high"
        }
        
        service_metrics = {
            "web_service": {
                "availability": 85.0,
                "response_time": 5000,
                "error_rate": 15.0
            }
        }
        
        business_metrics = {
            "revenue_per_hour": 10000,
            "customer_count": 50000
        }
        
        result = self.assessor.assess_ddos_impact(
            attack_classification, service_metrics, business_metrics
        )
        
        self.assertIsInstance(result, ImpactAssessmentResult)
        self.assertIsNotNone(result.assessment_id)
        self.assertIsInstance(result.service_impacts, list)
        self.assertIsInstance(result.confidence_score, float)


class TestMitigationEffectivenessAnalyzer(unittest.TestCase):
    """Test suite for Mitigation Effectiveness Analyzer (State 5)"""
    
    def setUp(self):
        """Set up test environment"""
        self.analyzer = MitigationEffectivenessAnalyzer()
    
    def test_analyzer_initialization(self):
        """Test analyzer initialization"""
        self.assertIsNotNone(self.analyzer.mitigation_config)
        self.assertIsNotNone(self.analyzer.azure_ddos_client)
        self.assertIsNotNone(self.analyzer.waf_analyzer)
    
    def test_analyze_mitigation_effectiveness(self):
        """Test mitigation effectiveness analysis"""
        attack_data = {
            "attack_type": "volumetric",
            "severity": "high"
        }
        
        impact_assessment = {
            "service_degradation": 50.0,
            "business_impact": "high"
        }
        
        azure_protection_logs = {
            "ddos_mitigation_active": True,
            "packets_dropped": 1000000,
            "waf_blocks": 5000
        }
        
        result = self.analyzer.analyze_mitigation_effectiveness(
            attack_data, impact_assessment, azure_protection_logs
        )
        
        self.assertIsInstance(result, MitigationEffectivenessResult)
        self.assertIsNotNone(result.analysis_id)
        self.assertIsInstance(result.mitigation_results, list)
        self.assertIsInstance(result.confidence_score, float)


class TestThreatAttributionAnalyzer(unittest.TestCase):
    """Test suite for Threat Attribution Analyzer (State 6)"""
    
    def setUp(self):
        """Set up test environment"""
        self.analyzer = ThreatAttributionAnalyzer()
    
    def test_analyzer_initialization(self):
        """Test analyzer initialization"""
        self.assertIsNotNone(self.analyzer.attribution_config)
        self.assertIsNotNone(self.analyzer.threat_intelligence_db)
        self.assertIsNotNone(self.analyzer.pattern_matching_engine)
    
    def test_perform_threat_attribution(self):
        """Test threat attribution analysis"""
        attack_data = {
            "attack_vectors": ["volumetric"],
            "infrastructure": "botnet"
        }
        
        source_intelligence = {
            "geographic_origins": ["CN", "RU"],
            "infrastructure_analysis": {"hosting_providers": ["provider_a"]}
        }
        
        attack_classification = {
            "sophistication": "medium",
            "coordination": "high"
        }
        
        mitigation_analysis = {
            "evasion_attempts": 3,
            "adaptation_observed": True
        }
        
        result = self.analyzer.perform_threat_attribution(
            attack_data, source_intelligence, attack_classification, mitigation_analysis
        )
        
        self.assertIsInstance(result, ThreatAttributionResult)
        self.assertIsNotNone(result.analysis_id)
        self.assertIsInstance(result.attribution_results, list)


class TestDDoSDefenseIntegration(unittest.TestCase):
    """Integration tests for complete DDoS Defense Agent workflow"""
    
    def setUp(self):
        """Set up integration test environment"""
        self.agent = DDoSDefenseAgent()
    
    @patch('ddos_defense_agent.DDoSDefenseAgent._check_azure_ddos_status')
    @patch('ddos_defense_agent.DDoSDefenseAgent._check_waf_status')
    @patch('ddos_defense_agent.DDoSDefenseAgent._check_cdn_status')
    @patch('ddos_defense_agent.DDoSDefenseAgent._check_firewall_status')
    def test_real_time_status_integration(self, mock_firewall, mock_cdn, mock_waf, mock_ddos):
        """Test real-time status integration"""
        # Setup mocks
        mock_ddos.return_value = {"status": "active"}
        mock_waf.return_value = {"status": "active"}
        mock_cdn.return_value = {"status": "active"}
        mock_firewall.return_value = {"status": "active"}
        
        # Run test
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        status = loop.run_until_complete(self.agent.get_real_time_status())
        
        # Verify results
        self.assertIn("agent_status", status)
        self.assertIn("protection_status", status)
        self.assertIn("current_metrics", status)
        self.assertEqual(status["agent_status"], "idle")
    
    def test_configuration_optimization_workflow(self):
        """Test configuration optimization workflow"""
        historical_data = {
            "past_attacks": [
                {"type": "volumetric", "effectiveness": 0.8},
                {"type": "application", "effectiveness": 0.6}
            ],
            "mitigation_performance": {
                "ddos_protection": 0.85,
                "waf": 0.90
            }
        }
        
        # Run optimization
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        optimization = loop.run_until_complete(
            self.agent.optimize_defense_configuration(historical_data)
        )
        
        # Verify results
        self.assertIn("optimization_id", optimization)
        self.assertIn("optimization_recommendations", optimization)
        self.assertIn("expected_improvements", optimization)
        self.assertIn("implementation_plan", optimization)


def run_comprehensive_tests():
    """Run all comprehensive tests for DDoS Defense Agent"""
    logger.info("Starting comprehensive DDoS Defense Agent tests")
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [
        TestDDoSDefenseAgent,
        TestTrafficPatternAnalyzer,
        TestSourceIPIntelligenceAnalyzer,
        TestAttackVectorClassifier,
        TestImpactAssessmentAnalyzer,
        TestMitigationEffectivenessAnalyzer,
        TestThreatAttributionAnalyzer,
        TestDDoSDefenseIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Report results
    logger.info(f"Tests run: {result.testsRun}")
    logger.info(f"Failures: {len(result.failures)}")
    logger.info(f"Errors: {len(result.errors)}")
    
    if result.failures:
        logger.error("Test failures:")
        for test, failure in result.failures:
            logger.error(f"  {test}: {failure}")
    
    if result.errors:
        logger.error("Test errors:")
        for test, error in result.errors:
            logger.error(f"  {test}: {error}")
    
    success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun) * 100
    logger.info(f"Success rate: {success_rate:.1f}%")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    # Run comprehensive tests
    success = run_comprehensive_tests()
    
    if success:
        logger.info("✅ All DDoS Defense Agent tests passed successfully!")
        print("\n🛡️ DDoS Defense Agent - All Tests Passed! 🛡️")
        print("=" * 60)
        print("✅ State 1: Traffic Pattern Analysis - PASSED")
        print("✅ State 2: Source IP Intelligence - PASSED")
        print("✅ State 3: Attack Vector Classification - PASSED")
        print("✅ State 4: Impact Assessment - PASSED")
        print("✅ State 5: Mitigation Effectiveness - PASSED")
        print("✅ State 6: Threat Attribution - PASSED")
        print("✅ Integration Testing - PASSED")
        print("=" * 60)
        print("🚀 DDoS Defense Agent ready for deployment!")
    else:
        logger.error("❌ Some DDoS Defense Agent tests failed!")
        print("\n⚠️ DDoS Defense Agent - Test Failures Detected ⚠️")
        exit(1)
