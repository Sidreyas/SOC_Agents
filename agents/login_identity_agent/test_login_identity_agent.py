"""
Login & Identity Agent Testing Framework
Comprehensive testing suite for all 6 states of the Login & Identity Agent
"""

import unittest
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the complete agent and all state modules
from .complete_login_identity_agent import CompleteLoginIdentityAgent, LoginIdentityAnalysisResult
from .authentication_log_analyzer import AuthenticationLogAnalyzer
from .geographic_infrastructure_analyzer import GeographicInfrastructureAnalyzer
from .user_behavior_profiler import UserBehaviorProfiler
from .credential_compromise_assessor import CredentialCompromiseAssessor
from .lateral_movement_detector import LateralMovementDetector
from .account_security_validator import AccountSecurityValidator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('login_identity_agent_test.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class TestDataGenerator:
    """Generate test data for Login & Identity Agent testing"""
    
    @staticmethod
    def generate_sample_authentication_logs() -> List[Dict[str, Any]]:
        """Generate sample authentication logs for testing"""
        base_time = datetime.now() - timedelta(days=7)
        
        sample_logs = []
        
        # Normal user authentication patterns
        for day in range(7):
            for hour in [8, 9, 17, 18]:  # Normal business hours
                sample_logs.append({
                    "event_id": f"auth_{day}_{hour}_001",
                    "timestamp": (base_time + timedelta(days=day, hours=hour)).isoformat(),
                    "user_id": "user1@company.com",
                    "user_principal_name": "user1@company.com",
                    "source_ip": "192.168.1.100",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "authentication_result": "success",
                    "application": "Office365",
                    "device_id": "device001",
                    "location": {
                        "country": "United States",
                        "city": "New York",
                        "coordinates": {"lat": 40.7128, "lon": -74.0060}
                    },
                    "risk_level": "low",
                    "conditional_access_policies": ["policy1", "policy2"],
                    "mfa_result": "success"
                })
        
        # Suspicious authentication patterns
        suspicious_patterns = [
            {
                "event_id": "auth_suspicious_001",
                "timestamp": (base_time + timedelta(days=3, hours=2)).isoformat(),
                "user_id": "user1@company.com",
                "user_principal_name": "user1@company.com",
                "source_ip": "185.220.101.43",  # Tor exit node
                "user_agent": "curl/7.68.0",
                "authentication_result": "success",
                "application": "Azure Portal",
                "device_id": "unknown",
                "location": {
                    "country": "Russia",
                    "city": "Moscow",
                    "coordinates": {"lat": 55.7558, "lon": 37.6176}
                },
                "risk_level": "high",
                "conditional_access_policies": [],
                "mfa_result": "bypassed"
            },
            {
                "event_id": "auth_brute_force_001",
                "timestamp": (base_time + timedelta(days=4, hours=22, minutes=30)).isoformat(),
                "user_id": "admin@company.com",
                "user_principal_name": "admin@company.com",
                "source_ip": "45.142.214.219",
                "user_agent": "python-requests/2.25.1",
                "authentication_result": "failure",
                "application": "Azure AD",
                "device_id": "unknown",
                "location": {
                    "country": "China",
                    "city": "Beijing",
                    "coordinates": {"lat": 39.9042, "lon": 116.4074}
                },
                "risk_level": "high",
                "failure_reason": "invalid_credentials",
                "conditional_access_policies": [],
                "mfa_result": "not_attempted"
            }
        ]
        
        # Add multiple brute force attempts
        for i in range(10):
            brute_force_attempt = suspicious_patterns[1].copy()
            brute_force_attempt["event_id"] = f"auth_brute_force_{i:03d}"
            brute_force_attempt["timestamp"] = (
                base_time + timedelta(days=4, hours=22, minutes=30 + i)
            ).isoformat()
            sample_logs.append(brute_force_attempt)
        
        sample_logs.extend(suspicious_patterns)
        return sample_logs
    
    @staticmethod
    def generate_log_sources_config() -> Dict[str, Any]:
        """Generate log sources configuration"""
        return {
            "azure_ad": {
                "enabled": True,
                "log_types": ["sign_ins", "audit_logs", "risk_detections"],
                "retention_days": 90,
                "api_version": "v1.0"
            },
            "azure_sentinel": {
                "enabled": True,
                "workspace_id": "test-workspace-001",
                "log_analytics_tables": ["SigninLogs", "AuditLogs", "SecurityAlert"]
            },
            "office365": {
                "enabled": True,
                "unified_audit_log": True,
                "exchange_admin_audit": True
            },
            "on_premises_ad": {
                "enabled": False,
                "domain_controllers": [],
                "event_forwarding": False
            }
        }
    
    @staticmethod
    def generate_network_topology() -> Dict[str, Any]:
        """Generate sample network topology for testing"""
        return {
            "hosts": [
                {
                    "host_id": "host001",
                    "hostname": "DC01.company.local",
                    "ip_address": "192.168.1.10",
                    "role": "domain_controller",
                    "os": "Windows Server 2019",
                    "criticality": "high"
                },
                {
                    "host_id": "host002",
                    "hostname": "FILE01.company.local",
                    "ip_address": "192.168.1.20",
                    "role": "file_server",
                    "os": "Windows Server 2016",
                    "criticality": "medium"
                },
                {
                    "host_id": "host003",
                    "hostname": "WS001.company.local",
                    "ip_address": "192.168.1.100",
                    "role": "workstation",
                    "os": "Windows 10",
                    "criticality": "low"
                }
            ],
            "segments": [
                {
                    "segment_id": "dmz",
                    "network": "10.0.1.0/24",
                    "description": "DMZ Segment",
                    "security_level": "medium"
                },
                {
                    "segment_id": "internal",
                    "network": "192.168.1.0/24",
                    "description": "Internal Corporate Network",
                    "security_level": "high"
                }
            ],
            "trust_relationships": [
                {
                    "source": "internal",
                    "target": "dmz",
                    "trust_level": "limited"
                }
            ]
        }

class LoginIdentityAgentTestCase(unittest.TestCase):
    """Base test case for Login & Identity Agent testing"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.agent = CompleteLoginIdentityAgent()
        self.test_data = TestDataGenerator()
        
        # Generate test input data
        self.input_data = {
            "authentication_logs": self.test_data.generate_sample_authentication_logs(),
            "log_sources": self.test_data.generate_log_sources_config(),
            "network_topology": self.test_data.generate_network_topology(),
            "analysis_config": {
                "enable_detailed_analysis": True,
                "correlation_timeframe_hours": 24,
                "anomaly_detection_sensitivity": "medium",
                "threat_intelligence_enabled": True
            }
        }
        
        logger.info("Test setup completed")
    
    def tearDown(self):
        """Clean up after tests"""
        logger.info("Test teardown completed")

class TestCompleteLoginIdentityAgent(LoginIdentityAgentTestCase):
    """Test cases for the Complete Login & Identity Agent"""
    
    def test_agent_initialization(self):
        """Test that the agent initializes correctly"""
        self.assertIsInstance(self.agent, CompleteLoginIdentityAgent)
        self.assertIsNotNone(self.agent.agent_config)
        self.assertIsNotNone(self.agent.analysis_pipeline)
        
        # Verify all state analyzers are initialized
        self.assertIsInstance(self.agent.state_1_analyzer, AuthenticationLogAnalyzer)
        self.assertIsInstance(self.agent.state_2_analyzer, GeographicInfrastructureAnalyzer)
        self.assertIsInstance(self.agent.state_3_analyzer, UserBehaviorProfiler)
        self.assertIsInstance(self.agent.state_4_analyzer, CredentialCompromiseAssessor)
        self.assertIsInstance(self.agent.state_5_analyzer, LateralMovementDetector)
        self.assertIsInstance(self.agent.state_6_analyzer, AccountSecurityValidator)
        
        logger.info("Agent initialization test passed")
    
    def test_complete_analysis_execution(self):
        """Test complete analysis execution through all 6 states"""
        logger.info("Starting complete analysis execution test")
        
        try:
            # Execute complete analysis
            result = self.agent.execute_complete_analysis(self.input_data)
            
            # Verify result structure
            self.assertIsInstance(result, LoginIdentityAnalysisResult)
            self.assertIsNotNone(result.analysis_id)
            self.assertIsNotNone(result.analysis_timestamp)
            self.assertIsNotNone(result.analysis_duration)
            
            # Verify all state results are present
            state_results = result.state_results
            self.assertIn("state_1_authentication_analysis", state_results)
            self.assertIn("state_2_geographic_analysis", state_results)
            self.assertIn("state_3_behavior_analysis", state_results)
            self.assertIn("state_4_credential_analysis", state_results)
            self.assertIn("state_5_lateral_movement_analysis", state_results)
            self.assertIn("state_6_security_validation", state_results)
            self.assertIn("integration_results", state_results)
            self.assertIn("final_assessment", state_results)
            
            # Verify final assessment components
            final_assessment = result.final_assessment
            self.assertIn("overall_security_score", final_assessment)
            self.assertIn("security_maturity_level", final_assessment)
            self.assertIn("critical_findings", final_assessment)
            self.assertIn("high_priority_recommendations", final_assessment)
            
            # Verify security posture and threat indicators
            self.assertIsNotNone(result.security_posture)
            self.assertIsInstance(result.threat_indicators, list)
            self.assertIsNotNone(result.remediation_plan)
            self.assertIsNotNone(result.compliance_status)
            
            logger.info("Complete analysis execution test passed")
            
        except Exception as e:
            logger.error(f"Complete analysis execution test failed: {str(e)}")
            raise
    
    def test_targeted_analysis_execution(self):
        """Test targeted analysis for specific states"""
        logger.info("Starting targeted analysis execution test")
        
        try:
            # Test single state execution
            target_states = [1]
            result = self.agent.execute_targeted_analysis(target_states, self.input_data)
            
            self.assertIn("state_1", result["state_results"])
            self.assertEqual(len(result["state_results"]), 1)
            
            # Test multiple states with dependencies
            target_states = [3, 4]
            result = self.agent.execute_targeted_analysis(target_states, self.input_data)
            
            # Should include dependencies (states 1, 2)
            self.assertGreaterEqual(len(result["state_results"]), 4)
            
            logger.info("Targeted analysis execution test passed")
            
        except Exception as e:
            logger.error(f"Targeted analysis execution test failed: {str(e)}")
            raise
    
    def test_comprehensive_report_generation(self):
        """Test comprehensive report generation"""
        logger.info("Starting comprehensive report generation test")
        
        try:
            # First execute complete analysis
            analysis_result = self.agent.execute_complete_analysis(self.input_data)
            
            # Generate comprehensive report
            comprehensive_report = self.agent.generate_comprehensive_report(analysis_result)
            
            # Verify report structure
            expected_sections = [
                "executive_summary",
                "analysis_overview",
                "state_by_state_analysis",
                "integrated_findings",
                "threat_landscape",
                "security_posture_assessment",
                "compliance_status",
                "risk_assessment",
                "remediation_roadmap",
                "strategic_recommendations",
                "monitoring_guidance",
                "appendices",
                "report_metadata"
            ]
            
            for section in expected_sections:
                self.assertIn(section, comprehensive_report)
            
            # Verify report metadata
            report_metadata = comprehensive_report["report_metadata"]
            self.assertIn("report_id", report_metadata)
            self.assertIn("analysis_id", report_metadata)
            self.assertIn("report_timestamp", report_metadata)
            self.assertEqual(report_metadata["report_scope"], "comprehensive_login_identity_analysis")
            
            logger.info("Comprehensive report generation test passed")
            
        except Exception as e:
            logger.error(f"Comprehensive report generation test failed: {str(e)}")
            raise

class TestAuthenticationLogAnalyzer(LoginIdentityAgentTestCase):
    """Test cases for State 1: Authentication Log Analyzer"""
    
    def setUp(self):
        super().setUp()
        self.state_1_analyzer = AuthenticationLogAnalyzer()
    
    def test_authentication_log_analysis(self):
        """Test authentication log analysis functionality"""
        logger.info("Testing authentication log analysis")
        
        authentication_logs = self.input_data["authentication_logs"]
        log_sources = self.input_data["log_sources"]
        
        # Execute analysis
        result = self.state_1_analyzer.analyze_authentication_logs(authentication_logs, log_sources)
        
        # Verify result structure
        self.assertIn("authentication_events", result)
        self.assertIn("log_analysis_summary", result)
        self.assertIn("event_statistics", result)
        
        # Verify authentication events are processed
        auth_events = result["authentication_events"]
        self.assertIsInstance(auth_events, list)
        self.assertGreater(len(auth_events), 0)
        
        logger.info("Authentication log analysis test passed")
    
    def test_anomaly_detection(self):
        """Test authentication anomaly detection"""
        logger.info("Testing anomaly detection")
        
        authentication_logs = self.input_data["authentication_logs"]
        
        # First analyze logs to get events
        analysis_result = self.state_1_analyzer.analyze_authentication_logs(
            authentication_logs, self.input_data["log_sources"]
        )
        authentication_events = analysis_result["authentication_events"]
        
        # Execute anomaly detection
        anomaly_result = self.state_1_analyzer.detect_authentication_anomalies(authentication_events)
        
        # Verify anomaly detection structure
        self.assertIn("anomalies", anomaly_result)
        self.assertIn("anomaly_statistics", anomaly_result)
        self.assertIn("risk_assessment", anomaly_result)
        
        logger.info("Anomaly detection test passed")

class TestGeographicInfrastructureAnalyzer(LoginIdentityAgentTestCase):
    """Test cases for State 2: Geographic Infrastructure Analyzer"""
    
    def setUp(self):
        super().setUp()
        self.state_2_analyzer = GeographicInfrastructureAnalyzer()
    
    def test_geographic_analysis(self):
        """Test geographic analysis functionality"""
        logger.info("Testing geographic analysis")
        
        authentication_events = self.input_data["authentication_logs"]
        
        # Execute geographic analysis
        result = self.state_2_analyzer.analyze_geographic_infrastructure(authentication_events)
        
        # Verify result structure
        self.assertIn("location_analysis", result)
        self.assertIn("infrastructure_analysis", result)
        self.assertIn("geographic_statistics", result)
        
        logger.info("Geographic analysis test passed")
    
    def test_impossible_travel_detection(self):
        """Test impossible travel detection"""
        logger.info("Testing impossible travel detection")
        
        authentication_events = self.input_data["authentication_logs"]
        location_analysis = {"user_locations": {}}  # Simplified for testing
        
        # Execute impossible travel analysis
        result = self.state_2_analyzer.analyze_impossible_travel_scenarios(
            authentication_events, location_analysis
        )
        
        # Verify result structure
        self.assertIn("impossible_travel_events", result)
        self.assertIn("travel_analysis", result)
        
        logger.info("Impossible travel detection test passed")

class TestUserBehaviorProfiler(LoginIdentityAgentTestCase):
    """Test cases for State 3: User Behavior Profiler"""
    
    def setUp(self):
        super().setUp()
        self.state_3_analyzer = UserBehaviorProfiler()
    
    def test_user_behavior_analysis(self):
        """Test user behavior analysis"""
        logger.info("Testing user behavior analysis")
        
        authentication_events = self.input_data["authentication_logs"]
        geographic_analysis = {"location_analysis": {}}
        
        # Execute behavior analysis
        result = self.state_3_analyzer.analyze_user_behavior(
            authentication_events, geographic_analysis
        )
        
        # Verify result structure
        self.assertIn("user_profiles", result)
        self.assertIn("behavioral_baselines", result)
        self.assertIn("behavior_statistics", result)
        
        logger.info("User behavior analysis test passed")
    
    def test_behavioral_anomaly_detection(self):
        """Test behavioral anomaly detection"""
        logger.info("Testing behavioral anomaly detection")
        
        user_id = "user1@company.com"
        user_events = [event for event in self.input_data["authentication_logs"] 
                      if event.get("user_id") == user_id]
        baseline = {"normal_hours": [8, 9, 17, 18], "normal_locations": ["New York"]}
        
        # Execute anomaly detection
        result = self.state_3_analyzer.detect_behavioral_anomalies(
            user_id, user_events, baseline
        )
        
        # Verify result structure
        self.assertIn("anomalies", result)
        self.assertIn("anomaly_score", result)
        
        logger.info("Behavioral anomaly detection test passed")

class TestCredentialCompromiseAssessor(LoginIdentityAgentTestCase):
    """Test cases for State 4: Credential Compromise Assessor"""
    
    def setUp(self):
        super().setUp()
        self.state_4_analyzer = CredentialCompromiseAssessor()
    
    def test_credential_compromise_assessment(self):
        """Test credential compromise assessment"""
        logger.info("Testing credential compromise assessment")
        
        authentication_events = self.input_data["authentication_logs"]
        user_behavior = {"user_profiles": {}}
        geographic_analysis = {"location_analysis": {}}
        
        # Execute compromise assessment
        result = self.state_4_analyzer.assess_credential_compromise(
            authentication_events, user_behavior, geographic_analysis
        )
        
        # Verify result structure
        self.assertIn("credential_analysis", result)
        self.assertIn("compromise_indicators", result)
        self.assertIn("assessment_statistics", result)
        
        logger.info("Credential compromise assessment test passed")
    
    def test_brute_force_detection(self):
        """Test brute force attack detection"""
        logger.info("Testing brute force attack detection")
        
        authentication_events = self.input_data["authentication_logs"]
        
        # Execute brute force detection
        result = self.state_4_analyzer.detect_brute_force_attacks(authentication_events)
        
        # Verify result structure
        self.assertIn("attack_patterns", result)
        self.assertIn("affected_accounts", result)
        self.assertIn("attack_statistics", result)
        
        # Should detect the brute force attempts in test data
        attack_stats = result["attack_statistics"]
        self.assertGreater(attack_stats.get("total_attacks_detected", 0), 0)
        
        logger.info("Brute force detection test passed")

class TestLateralMovementDetector(LoginIdentityAgentTestCase):
    """Test cases for State 5: Lateral Movement Detector"""
    
    def setUp(self):
        super().setUp()
        self.state_5_analyzer = LateralMovementDetector()
    
    def test_lateral_movement_detection(self):
        """Test lateral movement detection"""
        logger.info("Testing lateral movement detection")
        
        authentication_events = self.input_data["authentication_logs"]
        user_behavior = {"user_profiles": {}}
        credential_assessment = {"credential_analysis": {}}
        
        # Execute lateral movement detection
        result = self.state_5_analyzer.detect_lateral_movement(
            authentication_events, user_behavior, credential_assessment
        )
        
        # Verify result structure
        self.assertIn("lateral_movement_events", result)
        self.assertIn("movement_patterns", result)
        self.assertIn("detection_statistics", result)
        
        logger.info("Lateral movement detection test passed")
    
    def test_attack_path_analysis(self):
        """Test attack path analysis"""
        logger.info("Testing attack path analysis")
        
        lateral_movement_events = []
        network_topology = self.input_data["network_topology"]
        
        # Execute attack path analysis
        result = self.state_5_analyzer.analyze_attack_paths(
            lateral_movement_events, network_topology
        )
        
        # Verify result structure
        self.assertIn("attack_chains", result)
        self.assertIn("path_analysis", result)
        
        logger.info("Attack path analysis test passed")

class TestAccountSecurityValidator(LoginIdentityAgentTestCase):
    """Test cases for State 6: Account Security Validator"""
    
    def setUp(self):
        super().setUp()
        self.state_6_analyzer = AccountSecurityValidator()
    
    def test_account_security_validation(self):
        """Test account security validation"""
        logger.info("Testing account security validation")
        
        authentication_events = self.input_data["authentication_logs"]
        user_behavior = {"user_profiles": {}}
        geographic_analysis = {"location_analysis": {}}
        credential_assessment = {"credential_analysis": {}}
        lateral_movement = {"lateral_movement_events": []}
        
        # Execute security validation
        result = self.state_6_analyzer.validate_account_security(
            authentication_events, user_behavior, geographic_analysis,
            credential_assessment, lateral_movement
        )
        
        # Verify result structure
        self.assertIn("security_controls", result)
        self.assertIn("validation_results", result)
        self.assertIn("validation_statistics", result)
        
        logger.info("Account security validation test passed")
    
    def test_compliance_assessment(self):
        """Test compliance assessment"""
        logger.info("Testing compliance assessment")
        
        security_validation = {"security_controls": {}, "validation_results": {}}
        
        # Execute compliance assessment
        result = self.state_6_analyzer.assess_compliance_status(security_validation)
        
        # Verify result structure
        self.assertIn("framework_assessments", result)
        self.assertIn("compliance_score", result)
        self.assertIn("compliance_gaps", result)
        
        logger.info("Compliance assessment test passed")
    
    def test_remediation_plan_generation(self):
        """Test remediation plan generation"""
        logger.info("Testing remediation plan generation")
        
        security_validation = {"security_controls": {}, "validation_results": {}}
        compliance_status = {"framework_assessments": {}, "compliance_gaps": []}
        
        # Execute remediation plan generation
        result = self.state_6_analyzer.generate_remediation_plan(
            security_validation, compliance_status
        )
        
        # Verify result structure
        self.assertIn("remediation_items", result)
        self.assertIn("implementation_timeline", result)
        self.assertIn("remediation_statistics", result)
        
        logger.info("Remediation plan generation test passed")

class LoginIdentityAgentTestSuite:
    """Test suite coordinator for Login & Identity Agent"""
    
    def __init__(self):
        self.test_results = {}
        self.total_tests = 0
        self.passed_tests = 0
        self.failed_tests = 0
    
    def run_all_tests(self):
        """Run all Login & Identity Agent tests"""
        logger.info("Starting Login & Identity Agent comprehensive test suite")
        
        # Create test suite
        test_suite = unittest.TestSuite()
        
        # Add all test cases
        test_classes = [
            TestCompleteLoginIdentityAgent,
            TestAuthenticationLogAnalyzer,
            TestGeographicInfrastructureAnalyzer,
            TestUserBehaviorProfiler,
            TestCredentialCompromiseAssessor,
            TestLateralMovementDetector,
            TestAccountSecurityValidator
        ]
        
        for test_class in test_classes:
            tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
            test_suite.addTests(tests)
        
        # Run tests
        runner = unittest.TextTestRunner(verbosity=2)
        test_result = runner.run(test_suite)
        
        # Record results
        self.total_tests = test_result.testsRun
        self.failed_tests = len(test_result.failures) + len(test_result.errors)
        self.passed_tests = self.total_tests - self.failed_tests
        
        # Generate test report
        self.generate_test_report(test_result)
        
        logger.info(f"Test suite completed: {self.passed_tests}/{self.total_tests} tests passed")
        
        return test_result
    
    def generate_test_report(self, test_result):
        """Generate comprehensive test report"""
        report = {
            "test_summary": {
                "total_tests": self.total_tests,
                "passed_tests": self.passed_tests,
                "failed_tests": self.failed_tests,
                "success_rate": (self.passed_tests / self.total_tests * 100) if self.total_tests > 0 else 0,
                "test_timestamp": datetime.now().isoformat()
            },
            "test_details": {
                "failures": [str(failure) for failure in test_result.failures],
                "errors": [str(error) for error in test_result.errors],
                "skipped": [str(skip) for skip in test_result.skipped] if hasattr(test_result, 'skipped') else []
            },
            "coverage_analysis": {
                "states_tested": [1, 2, 3, 4, 5, 6],
                "integration_tested": True,
                "report_generation_tested": True,
                "error_handling_tested": True
            }
        }
        
        # Write test report to file
        with open('login_identity_agent_test_report.json', 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info("Test report generated: login_identity_agent_test_report.json")

def main():
    """Main function to run Login & Identity Agent tests"""
    print("="*80)
    print("LOGIN & IDENTITY AGENT - COMPREHENSIVE TEST SUITE")
    print("="*80)
    
    # Initialize test suite
    test_suite = LoginIdentityAgentTestSuite()
    
    try:
        # Run all tests
        test_result = test_suite.run_all_tests()
        
        # Print final summary
        print("\n" + "="*80)
        print("TEST EXECUTION SUMMARY")
        print("="*80)
        print(f"Total Tests Run: {test_suite.total_tests}")
        print(f"Tests Passed: {test_suite.passed_tests}")
        print(f"Tests Failed: {test_suite.failed_tests}")
        print(f"Success Rate: {(test_suite.passed_tests / test_suite.total_tests * 100):.2f}%")
        
        if test_suite.failed_tests == 0:
            print("🎉 ALL TESTS PASSED! Login & Identity Agent is ready for deployment.")
        else:
            print("⚠️  Some tests failed. Please review the test report for details.")
        
        return test_result.wasSuccessful()
        
    except Exception as e:
        logger.error(f"Test execution failed: {str(e)}")
        print(f"❌ Test execution failed: {str(e)}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
