"""
Risk Assessment and Classification Module
State 6: Risk Assessment and Final Classification
Final analysis state that synthesizes all previous analysis results to provide
comprehensive risk scoring, threat classification, and actionable recommendations
"""

import logging
import json
import statistics
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

# Configure logger
logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    """Threat level classifications"""
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    CRITICAL = "critical"

class RiskCategory(Enum):
    """Risk category classifications"""
    CREDENTIAL_THEFT = "credential_theft"
    MALWARE_DELIVERY = "malware_delivery"
    BUSINESS_EMAIL_COMPROMISE = "business_email_compromise"
    PHISHING = "phishing"
    SOCIAL_ENGINEERING = "social_engineering"
    DATA_EXFILTRATION = "data_exfiltration"
    FINANCIAL_FRAUD = "financial_fraud"
    RECONNAISSANCE = "reconnaissance"

@dataclass
class RiskScore:
    """Risk score container"""
    overall_score: float
    confidence: float
    threat_level: ThreatLevel
    risk_category: RiskCategory
    contributing_factors: List[str]
    score_breakdown: Dict[str, float]

@dataclass
class ActionableRecommendation:
    """Actionable recommendation container"""
    priority: str  # high, medium, low
    action_type: str  # immediate, short_term, long_term
    category: str  # technical, procedural, awareness
    description: str
    implementation_details: List[str]
    success_metrics: List[str]

class RiskAssessmentClassifier:
    """
    Risk Assessment and Classification Engine
    Synthesizes all previous analysis results to provide final threat assessment
    """
    
    def __init__(self):
        """Initialize the Risk Assessment Classifier"""
        self.risk_weights = self._initialize_risk_weights()
        self.classification_thresholds = self._initialize_classification_thresholds()
        self.baseline_scores = self._initialize_baseline_scores()
        
    def assess_overall_risk(self, entity_analysis: Dict[str, Any],
                          security_analysis: Dict[str, Any],
                          reputation_analysis: Dict[str, Any],
                          url_attachment_analysis: Dict[str, Any],
                          threat_intelligence: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform comprehensive risk assessment across all analysis dimensions
        
        Args:
            entity_analysis: Results from State 1 (Email Entity Extraction)
            security_analysis: Results from State 2 (Email Security Analysis)
            reputation_analysis: Results from State 3 (Sender Reputation Assessment)
            url_attachment_analysis: Results from State 4 (URL and Attachment Analysis)
            threat_intelligence: Results from State 5 (Threat Intelligence Correlation)
            
        Returns:
            Comprehensive risk assessment results
        """
        logger.info("Starting comprehensive risk assessment")
        
        risk_assessment = {
            "overall_risk_score": 0.0,
            "risk_breakdown": {},
            "threat_classification": None,
            "risk_category": None,
            "confidence_assessment": {},
            "contributing_factors": [],
            "risk_timeline": {},
            "assessment_metadata": {
                "assessment_timestamp": datetime.now(),
                "assessment_version": "1.0",
                "data_completeness": 0.0
            }
        }
        
        # Calculate individual risk component scores
        risk_assessment["risk_breakdown"] = self._calculate_risk_breakdown(
            entity_analysis, security_analysis, reputation_analysis,
            url_attachment_analysis, threat_intelligence
        )
        
        # Calculate overall weighted risk score
        risk_assessment["overall_risk_score"] = self._calculate_overall_risk_score(
            risk_assessment["risk_breakdown"]
        )
        
        # Classify threat level
        risk_assessment["threat_classification"] = self._classify_threat_level(
            risk_assessment["overall_risk_score"]
        )
        
        # Determine risk category
        risk_assessment["risk_category"] = self._determine_risk_category(
            entity_analysis, security_analysis, reputation_analysis,
            url_attachment_analysis, threat_intelligence
        )
        
        # Assess confidence in the assessment
        risk_assessment["confidence_assessment"] = self._assess_confidence(
            entity_analysis, security_analysis, reputation_analysis,
            url_attachment_analysis, threat_intelligence
        )
        
        # Identify contributing factors
        risk_assessment["contributing_factors"] = self._identify_contributing_factors(
            risk_assessment["risk_breakdown"],
            risk_assessment["threat_classification"]
        )
        
        # Build risk timeline
        risk_assessment["risk_timeline"] = self._build_risk_timeline(
            entity_analysis, security_analysis, reputation_analysis,
            url_attachment_analysis, threat_intelligence
        )
        
        # Calculate data completeness
        risk_assessment["assessment_metadata"]["data_completeness"] = self._calculate_data_completeness(
            entity_analysis, security_analysis, reputation_analysis,
            url_attachment_analysis, threat_intelligence
        )
        
        logger.info(f"Risk assessment completed - Overall Score: {risk_assessment['overall_risk_score']:.2f}")
        return risk_assessment
    
    def generate_actionable_recommendations(self, risk_assessment: Dict[str, Any],
                                          entity_analysis: Dict[str, Any],
                                          security_analysis: Dict[str, Any],
                                          reputation_analysis: Dict[str, Any],
                                          url_attachment_analysis: Dict[str, Any],
                                          threat_intelligence: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate actionable recommendations based on risk assessment
        
        Args:
            risk_assessment: Overall risk assessment results
            entity_analysis: Results from State 1
            security_analysis: Results from State 2
            reputation_analysis: Results from State 3
            url_attachment_analysis: Results from State 4
            threat_intelligence: Results from State 5
            
        Returns:
            Comprehensive actionable recommendations
        """
        logger.info("Generating actionable recommendations")
        
        recommendations = {
            "immediate_actions": [],
            "short_term_actions": [],
            "long_term_actions": [],
            "technical_recommendations": [],
            "procedural_recommendations": [],
            "awareness_recommendations": [],
            "monitoring_recommendations": [],
            "remediation_priority": "",
            "implementation_timeline": {},
            "resource_requirements": {},
            "recommendation_metadata": {
                "generation_timestamp": datetime.now(),
                "recommendation_version": "1.0",
                "assessment_basis": risk_assessment.get("threat_classification", "unknown")
            }
        }
        
        # Generate immediate actions based on threat level
        recommendations["immediate_actions"] = self._generate_immediate_actions(
            risk_assessment, threat_intelligence
        )
        
        # Generate short-term actions
        recommendations["short_term_actions"] = self._generate_short_term_actions(
            risk_assessment, security_analysis, reputation_analysis
        )
        
        # Generate long-term actions
        recommendations["long_term_actions"] = self._generate_long_term_actions(
            risk_assessment, entity_analysis, threat_intelligence
        )
        
        # Generate technical recommendations
        recommendations["technical_recommendations"] = self._generate_technical_recommendations(
            security_analysis, url_attachment_analysis, threat_intelligence
        )
        
        # Generate procedural recommendations
        recommendations["procedural_recommendations"] = self._generate_procedural_recommendations(
            risk_assessment, entity_analysis, reputation_analysis
        )
        
        # Generate awareness recommendations
        recommendations["awareness_recommendations"] = self._generate_awareness_recommendations(
            risk_assessment, entity_analysis, security_analysis
        )
        
        # Generate monitoring recommendations
        recommendations["monitoring_recommendations"] = self._generate_monitoring_recommendations(
            risk_assessment, threat_intelligence, url_attachment_analysis
        )
        
        # Determine remediation priority
        recommendations["remediation_priority"] = self._determine_remediation_priority(
            risk_assessment
        )
        
        # Build implementation timeline
        recommendations["implementation_timeline"] = self._build_implementation_timeline(
            recommendations["immediate_actions"],
            recommendations["short_term_actions"],
            recommendations["long_term_actions"]
        )
        
        # Assess resource requirements
        recommendations["resource_requirements"] = self._assess_resource_requirements(
            recommendations, risk_assessment
        )
        
        logger.info("Actionable recommendations generation completed")
        return recommendations
    
    def generate_executive_summary(self, risk_assessment: Dict[str, Any],
                                 recommendations: Dict[str, Any],
                                 entity_analysis: Dict[str, Any],
                                 security_analysis: Dict[str, Any],
                                 reputation_analysis: Dict[str, Any],
                                 url_attachment_analysis: Dict[str, Any],
                                 threat_intelligence: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate executive summary for stakeholders
        
        Args:
            risk_assessment: Overall risk assessment results
            recommendations: Actionable recommendations
            All state analysis results for context
            
        Returns:
            Executive summary with key findings and recommendations
        """
        logger.info("Generating executive summary")
        
        executive_summary = {
            "summary_overview": {},
            "key_findings": [],
            "risk_highlights": {},
            "critical_actions": [],
            "business_impact": {},
            "stakeholder_communications": {},
            "next_steps": [],
            "appendices": {},
            "summary_metadata": {
                "summary_timestamp": datetime.now(),
                "summary_version": "1.0",
                "intended_audience": ["CISO", "Security Operations", "IT Management"],
                "classification": "TLP:AMBER"
            }
        }
        
        # Create summary overview
        executive_summary["summary_overview"] = self._create_summary_overview(
            risk_assessment, entity_analysis
        )
        
        # Extract key findings
        executive_summary["key_findings"] = self._extract_key_findings(
            risk_assessment, security_analysis, reputation_analysis,
            url_attachment_analysis, threat_intelligence
        )
        
        # Highlight critical risks
        executive_summary["risk_highlights"] = self._highlight_critical_risks(
            risk_assessment, threat_intelligence
        )
        
        # Identify critical actions
        executive_summary["critical_actions"] = self._identify_critical_actions(
            recommendations, risk_assessment
        )
        
        # Assess business impact
        executive_summary["business_impact"] = self._assess_business_impact(
            risk_assessment, entity_analysis, threat_intelligence
        )
        
        # Prepare stakeholder communications
        executive_summary["stakeholder_communications"] = self._prepare_stakeholder_communications(
            risk_assessment, recommendations
        )
        
        # Define next steps
        executive_summary["next_steps"] = self._define_next_steps(
            recommendations, risk_assessment
        )
        
        # Compile appendices
        executive_summary["appendices"] = self._compile_executive_appendices(
            risk_assessment, recommendations, threat_intelligence
        )
        
        logger.info("Executive summary generation completed")
        return executive_summary
    
    def generate_detailed_analysis_report(self, risk_assessment: Dict[str, Any],
                                        recommendations: Dict[str, Any],
                                        executive_summary: Dict[str, Any],
                                        entity_analysis: Dict[str, Any],
                                        security_analysis: Dict[str, Any],
                                        reputation_analysis: Dict[str, Any],
                                        url_attachment_analysis: Dict[str, Any],
                                        threat_intelligence: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive detailed analysis report
        
        Args:
            All analysis results and assessments
            
        Returns:
            Comprehensive detailed analysis report
        """
        logger.info("Generating detailed analysis report")
        
        detailed_report = {
            "report_header": {},
            "executive_summary": executive_summary,
            "methodology": {},
            "detailed_findings": {},
            "risk_analysis": risk_assessment,
            "threat_intelligence_analysis": {},
            "recommendations": recommendations,
            "technical_appendices": {},
            "glossary": {},
            "references": {},
            "report_metadata": {
                "report_id": f"PHI-RPT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                "report_timestamp": datetime.now(),
                "report_version": "1.0",
                "generated_by": "SOC Phishing Agent - Risk Assessment Classifier",
                "classification": "TLP:AMBER",
                "distribution": ["SOC Team", "CISO", "IT Security Management"]
            }
        }
        
        # Create report header
        detailed_report["report_header"] = self._create_report_header(
            risk_assessment, entity_analysis
        )
        
        # Document methodology
        detailed_report["methodology"] = self._document_methodology()
        
        # Compile detailed findings
        detailed_report["detailed_findings"] = self._compile_detailed_findings(
            entity_analysis, security_analysis, reputation_analysis,
            url_attachment_analysis, threat_intelligence
        )
        
        # Create threat intelligence analysis section
        detailed_report["threat_intelligence_analysis"] = self._create_threat_intelligence_section(
            threat_intelligence
        )
        
        # Compile technical appendices
        detailed_report["technical_appendices"] = self._compile_technical_appendices(
            entity_analysis, security_analysis, reputation_analysis,
            url_attachment_analysis, threat_intelligence
        )
        
        # Create glossary
        detailed_report["glossary"] = self._create_glossary()
        
        # Add references
        detailed_report["references"] = self._add_references()
        
        logger.info("Detailed analysis report generation completed")
        return detailed_report
    
    def _initialize_risk_weights(self) -> Dict[str, float]:
        """Initialize risk component weights"""
        return {
            "entity_extraction": 0.15,      # Email entity analysis weight
            "security_analysis": 0.25,      # Email security analysis weight
            "reputation_analysis": 0.20,    # Sender reputation weight
            "url_attachment": 0.25,         # URL/attachment analysis weight
            "threat_intelligence": 0.15     # Threat intelligence correlation weight
        }
    
    def _initialize_classification_thresholds(self) -> Dict[str, Tuple[float, float]]:
        """Initialize threat classification thresholds"""
        return {
            "benign": (0.0, 0.3),
            "suspicious": (0.3, 0.6),
            "malicious": (0.6, 0.85),
            "critical": (0.85, 1.0)
        }
    
    def _initialize_baseline_scores(self) -> Dict[str, float]:
        """Initialize baseline risk scores for different categories"""
        return {
            "credential_theft": 0.7,
            "malware_delivery": 0.8,
            "business_email_compromise": 0.75,
            "phishing": 0.65,
            "social_engineering": 0.6,
            "data_exfiltration": 0.85,
            "financial_fraud": 0.8,
            "reconnaissance": 0.4
        }
    
    def _calculate_risk_breakdown(self, entity_analysis: Dict[str, Any],
                                security_analysis: Dict[str, Any],
                                reputation_analysis: Dict[str, Any],
                                url_attachment_analysis: Dict[str, Any],
                                threat_intelligence: Dict[str, Any]) -> Dict[str, float]:
        """Calculate risk scores for each analysis component"""
        breakdown = {}
        
        # Entity extraction risk score
        breakdown["entity_extraction"] = self._calculate_entity_risk_score(entity_analysis)
        
        # Security analysis risk score
        breakdown["security_analysis"] = self._calculate_security_risk_score(security_analysis)
        
        # Reputation analysis risk score
        breakdown["reputation_analysis"] = self._calculate_reputation_risk_score(reputation_analysis)
        
        # URL/Attachment analysis risk score
        breakdown["url_attachment"] = self._calculate_url_attachment_risk_score(url_attachment_analysis)
        
        # Threat intelligence risk score
        breakdown["threat_intelligence"] = self._calculate_threat_intelligence_risk_score(threat_intelligence)
        
        return breakdown
    
    def _calculate_overall_risk_score(self, risk_breakdown: Dict[str, float]) -> float:
        """Calculate weighted overall risk score"""
        total_score = 0.0
        
        for component, score in risk_breakdown.items():
            weight = self.risk_weights.get(component, 0.0)
            total_score += score * weight
        
        return min(total_score, 1.0)  # Cap at 1.0
    
    def _classify_threat_level(self, overall_score: float) -> str:
        """Classify threat level based on overall score"""
        for level, (min_threshold, max_threshold) in self.classification_thresholds.items():
            if min_threshold <= overall_score < max_threshold:
                return level
        
        return "critical" if overall_score >= 0.85 else "benign"
    
    def _determine_risk_category(self, entity_analysis: Dict[str, Any],
                               security_analysis: Dict[str, Any],
                               reputation_analysis: Dict[str, Any],
                               url_attachment_analysis: Dict[str, Any],
                               threat_intelligence: Dict[str, Any]) -> str:
        """Determine primary risk category"""
        category_scores = {}
        
        # Analyze patterns to determine category
        if self._indicates_credential_theft(entity_analysis, url_attachment_analysis):
            category_scores["credential_theft"] = 0.8
        
        if self._indicates_malware_delivery(url_attachment_analysis, security_analysis):
            category_scores["malware_delivery"] = 0.9
        
        if self._indicates_bec(entity_analysis, reputation_analysis):
            category_scores["business_email_compromise"] = 0.85
        
        if self._indicates_phishing(entity_analysis, security_analysis, url_attachment_analysis):
            category_scores["phishing"] = 0.7
        
        if self._indicates_social_engineering(entity_analysis, security_analysis):
            category_scores["social_engineering"] = 0.6
        
        # Return category with highest score
        if category_scores:
            return max(category_scores.items(), key=lambda x: x[1])[0]
        
        return "phishing"  # Default category
    
    def _calculate_entity_risk_score(self, entity_analysis: Dict[str, Any]) -> float:
        """Calculate risk score from entity analysis"""
        score = 0.0
        
        # Check for suspicious entities
        entities = entity_analysis.get("extracted_entities", {})
        
        # URLs risk
        urls = entities.get("urls", [])
        if urls:
            suspicious_urls = sum(1 for url in urls if url.get("risk_level", "low") in ["high", "critical"])
            score += min(suspicious_urls * 0.2, 0.4)
        
        # Email addresses risk
        emails = entities.get("email_addresses", [])
        if emails:
            external_emails = sum(1 for email in emails if not email.get("is_internal", True))
            score += min(external_emails * 0.1, 0.2)
        
        # Phone numbers risk
        phones = entities.get("phone_numbers", [])
        if phones:
            score += min(len(phones) * 0.05, 0.1)
        
        # Suspicious patterns
        patterns = entity_analysis.get("pattern_analysis", {})
        urgency_score = patterns.get("urgency_indicators", {}).get("urgency_score", 0.0)
        score += urgency_score * 0.3
        
        return min(score, 1.0)
    
    def _calculate_security_risk_score(self, security_analysis: Dict[str, Any]) -> float:
        """Calculate risk score from security analysis"""
        score = 0.0
        
        # Authentication failures
        auth_analysis = security_analysis.get("authentication_analysis", {})
        if not auth_analysis.get("spf_valid", True):
            score += 0.2
        if not auth_analysis.get("dkim_valid", True):
            score += 0.2
        if not auth_analysis.get("dmarc_valid", True):
            score += 0.3
        
        # Content analysis
        content_analysis = security_analysis.get("content_analysis", {})
        suspicious_patterns = content_analysis.get("suspicious_patterns", [])
        score += min(len(suspicious_patterns) * 0.1, 0.3)
        
        # Social engineering indicators
        social_eng = content_analysis.get("social_engineering_indicators", {})
        se_score = social_eng.get("overall_score", 0.0)
        score += se_score * 0.4
        
        return min(score, 1.0)
    
    def _calculate_reputation_risk_score(self, reputation_analysis: Dict[str, Any]) -> float:
        """Calculate risk score from reputation analysis"""
        score = 0.0
        
        # Sender reputation
        sender_rep = reputation_analysis.get("sender_reputation", {})
        rep_score = sender_rep.get("reputation_score", 0.5)
        score += (1.0 - rep_score) * 0.4  # Higher risk for lower reputation
        
        # Domain reputation
        domain_rep = reputation_analysis.get("domain_reputation", {})
        domain_score = domain_rep.get("overall_score", 0.5)
        score += (1.0 - domain_score) * 0.3
        
        # Historical analysis
        historical = reputation_analysis.get("historical_analysis", {})
        risk_indicators = historical.get("risk_indicators", [])
        score += min(len(risk_indicators) * 0.1, 0.3)
        
        return min(score, 1.0)
    
    def _calculate_url_attachment_risk_score(self, url_attachment_analysis: Dict[str, Any]) -> float:
        """Calculate risk score from URL and attachment analysis"""
        score = 0.0
        
        # URL analysis
        url_analysis = url_attachment_analysis.get("url_analysis", {})
        malicious_urls = url_analysis.get("malicious_urls", [])
        suspicious_urls = url_analysis.get("suspicious_urls", [])
        score += len(malicious_urls) * 0.3 + len(suspicious_urls) * 0.15
        
        # Attachment analysis
        attachment_analysis = url_attachment_analysis.get("attachment_analysis", {})
        malicious_attachments = attachment_analysis.get("malicious_files", [])
        suspicious_attachments = attachment_analysis.get("suspicious_files", [])
        score += len(malicious_attachments) * 0.4 + len(suspicious_attachments) * 0.2
        
        # Sandbox analysis
        sandbox_results = url_attachment_analysis.get("sandbox_analysis", {})
        if sandbox_results.get("threat_detected", False):
            score += 0.5
        
        return min(score, 1.0)
    
    def _calculate_threat_intelligence_risk_score(self, threat_intelligence: Dict[str, Any]) -> float:
        """Calculate risk score from threat intelligence correlation"""
        score = 0.0
        
        # IOC matches
        ioc_correlation = threat_intelligence.get("correlation_results", {}).get("ioc_correlation", {})
        matched_iocs = ioc_correlation.get("matched_iocs", [])
        score += min(len(matched_iocs) * 0.2, 0.4)
        
        # Campaign correlation
        campaign_correlation = threat_intelligence.get("correlation_results", {}).get("campaign_correlation", {})
        matched_campaigns = campaign_correlation.get("matched_campaigns", [])
        score += min(len(matched_campaigns) * 0.25, 0.5)
        
        # Actor attribution
        actor_attribution = threat_intelligence.get("correlation_results", {}).get("actor_attribution", {})
        attributed_actors = actor_attribution.get("attributed_actors", [])
        score += min(len(attributed_actors) * 0.3, 0.6)
        
        return min(score, 1.0)
    
    def _indicates_credential_theft(self, entity_analysis: Dict[str, Any],
                                  url_attachment_analysis: Dict[str, Any]) -> bool:
        """Check if indicators suggest credential theft"""
        # Check for login pages in URLs
        urls = entity_analysis.get("extracted_entities", {}).get("urls", [])
        login_keywords = ["login", "signin", "portal", "account", "secure"]
        
        for url in urls:
            url_text = url.get("url", "").lower()
            if any(keyword in url_text for keyword in login_keywords):
                return True
        
        # Check URL analysis for credential theft indicators
        url_analysis = url_attachment_analysis.get("url_analysis", {})
        for url_result in url_analysis.get("analyzed_urls", []):
            if "credential" in url_result.get("threat_type", "").lower():
                return True
        
        return False
    
    def _indicates_malware_delivery(self, url_attachment_analysis: Dict[str, Any],
                                  security_analysis: Dict[str, Any]) -> bool:
        """Check if indicators suggest malware delivery"""
        # Check for malicious attachments
        attachment_analysis = url_attachment_analysis.get("attachment_analysis", {})
        if attachment_analysis.get("malicious_files", []):
            return True
        
        # Check for executable file types
        for attachment in attachment_analysis.get("analyzed_files", []):
            file_type = attachment.get("file_type", "").lower()
            if file_type in ["exe", "scr", "bat", "cmd", "pif", "com"]:
                return True
        
        return False
    
    def _indicates_bec(self, entity_analysis: Dict[str, Any],
                      reputation_analysis: Dict[str, Any]) -> bool:
        """Check if indicators suggest Business Email Compromise"""
        # Check for executive impersonation
        entities = entity_analysis.get("extracted_entities", {})
        pattern_analysis = entity_analysis.get("pattern_analysis", {})
        
        # Look for authority/urgency indicators
        urgency_indicators = pattern_analysis.get("urgency_indicators", {})
        if urgency_indicators.get("urgency_score", 0.0) > 0.7:
            return True
        
        # Check for financial request patterns
        financial_keywords = ["wire", "transfer", "payment", "invoice", "urgent"]
        content = entity_analysis.get("email_content", {}).get("content", "").lower()
        if sum(1 for keyword in financial_keywords if keyword in content) >= 2:
            return True
        
        return False
    
    def _indicates_phishing(self, entity_analysis: Dict[str, Any],
                           security_analysis: Dict[str, Any],
                           url_attachment_analysis: Dict[str, Any]) -> bool:
        """Check if indicators suggest generic phishing"""
        # Check for suspicious URLs
        url_analysis = url_attachment_analysis.get("url_analysis", {})
        if url_analysis.get("suspicious_urls", []):
            return True
        
        # Check for social engineering patterns
        content_analysis = security_analysis.get("content_analysis", {})
        se_indicators = content_analysis.get("social_engineering_indicators", {})
        if se_indicators.get("overall_score", 0.0) > 0.6:
            return True
        
        return False
    
    def _indicates_social_engineering(self, entity_analysis: Dict[str, Any],
                                    security_analysis: Dict[str, Any]) -> bool:
        """Check if indicators suggest social engineering"""
        # Check social engineering indicators from content analysis
        content_analysis = security_analysis.get("content_analysis", {})
        se_indicators = content_analysis.get("social_engineering_indicators", {})
        
        # Check for psychological manipulation techniques
        techniques = se_indicators.get("identified_techniques", [])
        manipulation_techniques = ["urgency", "authority", "fear", "scarcity"]
        
        return any(tech in techniques for tech in manipulation_techniques)
    
    def _assess_confidence(self, entity_analysis: Dict[str, Any],
                          security_analysis: Dict[str, Any],
                          reputation_analysis: Dict[str, Any],
                          url_attachment_analysis: Dict[str, Any],
                          threat_intelligence: Dict[str, Any]) -> Dict[str, Any]:
        """Assess confidence in the risk assessment"""
        confidence_assessment = {
            "overall_confidence": 0.0,
            "component_confidence": {},
            "data_quality_factors": {},
            "confidence_factors": []
        }
        
        # Calculate confidence for each component
        confidence_assessment["component_confidence"]["entity_extraction"] = self._calculate_entity_confidence(entity_analysis)
        confidence_assessment["component_confidence"]["security_analysis"] = self._calculate_security_confidence(security_analysis)
        confidence_assessment["component_confidence"]["reputation_analysis"] = self._calculate_reputation_confidence(reputation_analysis)
        confidence_assessment["component_confidence"]["url_attachment"] = self._calculate_url_attachment_confidence(url_attachment_analysis)
        confidence_assessment["component_confidence"]["threat_intelligence"] = self._calculate_threat_intelligence_confidence(threat_intelligence)
        
        # Calculate overall confidence
        component_confidences = list(confidence_assessment["component_confidence"].values())
        confidence_assessment["overall_confidence"] = statistics.mean(component_confidences) if component_confidences else 0.0
        
        # Assess data quality factors
        confidence_assessment["data_quality_factors"] = self._assess_data_quality_factors(
            entity_analysis, security_analysis, reputation_analysis,
            url_attachment_analysis, threat_intelligence
        )
        
        # Identify confidence factors
        confidence_assessment["confidence_factors"] = self._identify_confidence_factors(
            confidence_assessment["component_confidence"],
            confidence_assessment["data_quality_factors"]
        )
        
        return confidence_assessment
    
    def _calculate_entity_confidence(self, entity_analysis: Dict[str, Any]) -> float:
        """Calculate confidence in entity extraction analysis"""
        confidence = 0.8  # Base confidence
        
        entities = entity_analysis.get("extracted_entities", {})
        
        # Reduce confidence if few entities extracted
        total_entities = sum(len(entity_list) for entity_list in entities.values())
        if total_entities < 3:
            confidence -= 0.2
        
        # Increase confidence if high-confidence extractions
        extraction_confidence = entity_analysis.get("extraction_confidence", {})
        avg_confidence = extraction_confidence.get("average_confidence", 0.5)
        confidence = (confidence + avg_confidence) / 2
        
        return min(confidence, 1.0)
    
    def _calculate_security_confidence(self, security_analysis: Dict[str, Any]) -> float:
        """Calculate confidence in security analysis"""
        confidence = 0.9  # Base confidence (security checks are reliable)
        
        # Check if all authentication mechanisms were analyzed
        auth_analysis = security_analysis.get("authentication_analysis", {})
        auth_checks = ["spf_valid", "dkim_valid", "dmarc_valid"]
        completed_checks = sum(1 for check in auth_checks if check in auth_analysis)
        
        if completed_checks < len(auth_checks):
            confidence -= 0.1 * (len(auth_checks) - completed_checks)
        
        return max(confidence, 0.5)
    
    def _calculate_reputation_confidence(self, reputation_analysis: Dict[str, Any]) -> float:
        """Calculate confidence in reputation analysis"""
        confidence = 0.7  # Base confidence
        
        # Check data sources availability
        sender_rep = reputation_analysis.get("sender_reputation", {})
        domain_rep = reputation_analysis.get("domain_reputation", {})
        
        if sender_rep.get("data_sources", []):
            confidence += 0.1
        if domain_rep.get("data_sources", []):
            confidence += 0.1
        
        # Check for historical data
        historical = reputation_analysis.get("historical_analysis", {})
        if historical.get("data_points", 0) > 10:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _calculate_url_attachment_confidence(self, url_attachment_analysis: Dict[str, Any]) -> float:
        """Calculate confidence in URL and attachment analysis"""
        confidence = 0.8  # Base confidence
        
        # Check if sandbox analysis was performed
        sandbox_analysis = url_attachment_analysis.get("sandbox_analysis", {})
        if sandbox_analysis.get("analysis_completed", False):
            confidence += 0.1
        
        # Check number of analysis engines used
        url_analysis = url_attachment_analysis.get("url_analysis", {})
        analysis_engines = url_analysis.get("analysis_engines", [])
        if len(analysis_engines) >= 3:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _calculate_threat_intelligence_confidence(self, threat_intelligence: Dict[str, Any]) -> float:
        """Calculate confidence in threat intelligence correlation"""
        confidence = 0.6  # Base confidence (external feeds can be variable)
        
        # Check number of active feeds
        enrichment_results = threat_intelligence.get("enrichment_results", {})
        active_feeds = enrichment_results.get("external_feeds", [])
        confidence += min(len(active_feeds) * 0.1, 0.3)
        
        # Check correlation strength
        correlation_results = threat_intelligence.get("correlation_results", {})
        ioc_matches = len(correlation_results.get("ioc_correlation", {}).get("matched_iocs", []))
        confidence += min(ioc_matches * 0.05, 0.2)
        
        return min(confidence, 1.0)
    
    def _identify_contributing_factors(self, risk_breakdown: Dict[str, float],
                                     threat_classification: str) -> List[str]:
        """Identify key factors contributing to the risk assessment"""
        factors = []
        
        # High-risk components
        for component, score in risk_breakdown.items():
            if score > 0.6:
                factors.append(f"High risk from {component.replace('_', ' ')}")
        
        # Threat level specific factors
        if threat_classification == "critical":
            factors.append("Multiple high-confidence threat indicators")
        elif threat_classification == "malicious":
            factors.append("Clear malicious intent detected")
        elif threat_classification == "suspicious":
            factors.append("Suspicious patterns requiring investigation")
        
        return factors
    
    def _build_risk_timeline(self, entity_analysis: Dict[str, Any],
                           security_analysis: Dict[str, Any],
                           reputation_analysis: Dict[str, Any],
                           url_attachment_analysis: Dict[str, Any],
                           threat_intelligence: Dict[str, Any]) -> Dict[str, Any]:
        """Build risk timeline showing progression"""
        timeline = {
            "risk_progression": [],
            "key_events": [],
            "escalation_points": [],
            "timeline_confidence": 0.0
        }
        
        current_time = datetime.now()
        
        # Add email arrival
        timeline["key_events"].append({
            "timestamp": current_time - timedelta(minutes=30),
            "event": "Email received",
            "risk_level": "unknown"
        })
        
        # Add analysis milestones
        timeline["key_events"].append({
            "timestamp": current_time - timedelta(minutes=25),
            "event": "Security analysis completed",
            "risk_level": "assessment"
        })
        
        timeline["key_events"].append({
            "timestamp": current_time - timedelta(minutes=20),
            "event": "Threat intelligence correlation",
            "risk_level": "correlation"
        })
        
        timeline["key_events"].append({
            "timestamp": current_time,
            "event": "Risk assessment completed",
            "risk_level": "final"
        })
        
        timeline["timeline_confidence"] = 0.8
        
        return timeline
    
    def _calculate_data_completeness(self, entity_analysis: Dict[str, Any],
                                   security_analysis: Dict[str, Any],
                                   reputation_analysis: Dict[str, Any],
                                   url_attachment_analysis: Dict[str, Any],
                                   threat_intelligence: Dict[str, Any]) -> float:
        """Calculate data completeness score"""
        completeness_scores = []
        
        # Entity analysis completeness
        entities = entity_analysis.get("extracted_entities", {})
        entity_completeness = min(len(entities.keys()) * 0.2, 1.0)
        completeness_scores.append(entity_completeness)
        
        # Security analysis completeness
        auth_analysis = security_analysis.get("authentication_analysis", {})
        security_completeness = min(len(auth_analysis.keys()) * 0.1, 1.0)
        completeness_scores.append(security_completeness)
        
        # Reputation analysis completeness
        rep_completeness = 1.0 if reputation_analysis.get("sender_reputation") else 0.5
        completeness_scores.append(rep_completeness)
        
        # URL/Attachment analysis completeness
        url_completeness = 1.0 if url_attachment_analysis.get("url_analysis") else 0.5
        completeness_scores.append(url_completeness)
        
        # Threat intelligence completeness
        ti_completeness = 1.0 if threat_intelligence.get("correlation_results") else 0.3
        completeness_scores.append(ti_completeness)
        
        return statistics.mean(completeness_scores)
    
    def _generate_immediate_actions(self, risk_assessment: Dict[str, Any],
                                  threat_intelligence: Dict[str, Any]) -> List[ActionableRecommendation]:
        """Generate immediate actions based on threat level"""
        actions = []
        threat_level = risk_assessment.get("threat_classification", "suspicious")
        
        if threat_level in ["critical", "malicious"]:
            actions.extend([
                ActionableRecommendation(
                    priority="critical",
                    action_type="immediate",
                    category="technical",
                    description="Block sender and quarantine email immediately",
                    implementation_details=[
                        "Add sender to email security gateway blacklist",
                        "Move email to quarantine folder",
                        "Block sender domain if confirmed malicious"
                    ],
                    success_metrics=["Email blocked", "Sender blacklisted", "No additional emails received"]
                ),
                ActionableRecommendation(
                    priority="critical",
                    action_type="immediate",
                    category="procedural",
                    description="Initiate incident response procedures",
                    implementation_details=[
                        "Create security incident ticket",
                        "Notify SOC lead and CISO",
                        "Begin threat hunting for similar emails"
                    ],
                    success_metrics=["Incident created", "Stakeholders notified", "Response team activated"]
                )
            ])
        
        if threat_level == "suspicious":
            actions.append(
                ActionableRecommendation(
                    priority="high",
                    action_type="immediate",
                    category="technical",
                    description="Place email in pending review queue",
                    implementation_details=[
                        "Move to security review folder",
                        "Flag for manual analysis",
                        "Monitor user interaction"
                    ],
                    success_metrics=["Email flagged", "Review initiated", "User protected"]
                )
            )
        
        return actions
    
    def _generate_short_term_actions(self, risk_assessment: Dict[str, Any],
                                   security_analysis: Dict[str, Any],
                                   reputation_analysis: Dict[str, Any]) -> List[ActionableRecommendation]:
        """Generate short-term actions (1-7 days)"""
        actions = []
        
        # Authentication issues
        auth_analysis = security_analysis.get("authentication_analysis", {})
        if not auth_analysis.get("spf_valid", True) or not auth_analysis.get("dkim_valid", True):
            actions.append(
                ActionableRecommendation(
                    priority="high",
                    action_type="short_term",
                    category="technical",
                    description="Review and update email authentication policies",
                    implementation_details=[
                        "Audit SPF, DKIM, and DMARC records",
                        "Update authentication failure handling",
                        "Implement stricter authentication policies"
                    ],
                    success_metrics=["Authentication updated", "Policy compliance improved", "False positives reduced"]
                )
            )
        
        # Reputation issues
        sender_rep = reputation_analysis.get("sender_reputation", {})
        if sender_rep.get("reputation_score", 0.5) < 0.3:
            actions.append(
                ActionableRecommendation(
                    priority="medium",
                    action_type="short_term",
                    category="procedural",
                    description="Investigate sender reputation patterns",
                    implementation_details=[
                        "Analyze sender email patterns",
                        "Review domain registration details",
                        "Check for similar suspicious senders"
                    ],
                    success_metrics=["Pattern analysis completed", "Threat intelligence updated", "Detection rules improved"]
                )
            )
        
        return actions
    
    def _generate_long_term_actions(self, risk_assessment: Dict[str, Any],
                                  entity_analysis: Dict[str, Any],
                                  threat_intelligence: Dict[str, Any]) -> List[ActionableRecommendation]:
        """Generate long-term actions (1+ weeks)"""
        actions = []
        
        # Security awareness
        pattern_analysis = entity_analysis.get("pattern_analysis", {})
        if pattern_analysis.get("urgency_indicators", {}).get("urgency_score", 0.0) > 0.5:
            actions.append(
                ActionableRecommendation(
                    priority="medium",
                    action_type="long_term",
                    category="awareness",
                    description="Enhance security awareness training on urgency tactics",
                    implementation_details=[
                        "Develop urgency-based phishing simulations",
                        "Create awareness materials on pressure tactics",
                        "Implement regular testing and training"
                    ],
                    success_metrics=["Training completion rates", "Simulated phishing resistance", "Incident reduction"]
                )
            )
        
        # Threat intelligence integration
        correlation_results = threat_intelligence.get("correlation_results", {})
        if correlation_results.get("ioc_correlation", {}).get("matched_iocs", []):
            actions.append(
                ActionableRecommendation(
                    priority="medium",
                    action_type="long_term",
                    category="technical",
                    description="Enhance threat intelligence integration",
                    implementation_details=[
                        "Expand threat feed sources",
                        "Improve IOC correlation algorithms",
                        "Implement automated threat hunting"
                    ],
                    success_metrics=["Feed coverage increased", "Detection accuracy improved", "Response time reduced"]
                )
            )
        
        return actions
    
    def _generate_technical_recommendations(self, security_analysis: Dict[str, Any],
                                          url_attachment_analysis: Dict[str, Any],
                                          threat_intelligence: Dict[str, Any]) -> List[ActionableRecommendation]:
        """Generate technical recommendations"""
        recommendations = []
        
        # Email security gateway enhancements
        recommendations.append(
            ActionableRecommendation(
                priority="high",
                action_type="short_term",
                category="technical",
                description="Enhance email security gateway rules",
                implementation_details=[
                    "Update attachment type filtering",
                    "Implement advanced URL scanning",
                    "Enable behavioral analysis features"
                ],
                success_metrics=["Detection rate improved", "False positives reduced", "Response time decreased"]
            )
        )
        
        # Sandbox analysis enhancement
        sandbox_analysis = url_attachment_analysis.get("sandbox_analysis", {})
        if not sandbox_analysis.get("analysis_completed", False):
            recommendations.append(
                ActionableRecommendation(
                    priority="medium",
                    action_type="short_term",
                    category="technical",
                    description="Implement advanced sandbox analysis",
                    implementation_details=[
                        "Deploy automated sandbox environment",
                        "Integrate with email security stack",
                        "Enable behavioral analysis"
                    ],
                    success_metrics=["Sandbox deployment completed", "Analysis automation achieved", "Threat detection improved"]
                )
            )
        
        return recommendations
    
    def _generate_procedural_recommendations(self, risk_assessment: Dict[str, Any],
                                           entity_analysis: Dict[str, Any],
                                           reputation_analysis: Dict[str, Any]) -> List[ActionableRecommendation]:
        """Generate procedural recommendations"""
        recommendations = []
        
        threat_level = risk_assessment.get("threat_classification", "suspicious")
        
        if threat_level in ["critical", "malicious"]:
            recommendations.append(
                ActionableRecommendation(
                    priority="high",
                    action_type="immediate",
                    category="procedural",
                    description="Update incident response playbooks",
                    implementation_details=[
                        "Review current response procedures",
                        "Update escalation criteria",
                        "Improve communication protocols"
                    ],
                    success_metrics=["Playbook updated", "Response time improved", "Escalation clarity achieved"]
                )
            )
        
        # User education
        recommendations.append(
            ActionableRecommendation(
                priority="medium",
                action_type="long_term",
                category="procedural",
                description="Enhance user reporting procedures",
                implementation_details=[
                    "Simplify phishing reporting process",
                    "Implement user feedback mechanisms",
                    "Create clear reporting guidelines"
                ],
                success_metrics=["Reporting rate increased", "User satisfaction improved", "Detection time reduced"]
            )
        )
        
        return recommendations
    
    def _generate_awareness_recommendations(self, risk_assessment: Dict[str, Any],
                                          entity_analysis: Dict[str, Any],
                                          security_analysis: Dict[str, Any]) -> List[ActionableRecommendation]:
        """Generate security awareness recommendations"""
        recommendations = []
        
        # Social engineering awareness
        content_analysis = security_analysis.get("content_analysis", {})
        se_indicators = content_analysis.get("social_engineering_indicators", {})
        
        if se_indicators.get("overall_score", 0.0) > 0.5:
            recommendations.append(
                ActionableRecommendation(
                    priority="medium",
                    action_type="long_term",
                    category="awareness",
                    description="Implement targeted social engineering awareness training",
                    implementation_details=[
                        "Create scenario-based training modules",
                        "Implement regular phishing simulations",
                        "Develop recognition skills training"
                    ],
                    success_metrics=["Training completion rates", "Simulation pass rates", "Incident reporting improvement"]
                )
            )
        
        # Authority impersonation awareness
        pattern_analysis = entity_analysis.get("pattern_analysis", {})
        urgency_score = pattern_analysis.get("urgency_indicators", {}).get("urgency_score", 0.0)
        
        if urgency_score > 0.6:
            recommendations.append(
                ActionableRecommendation(
                    priority="medium",
                    action_type="short_term",
                    category="awareness",
                    description="Focus on authority and urgency tactics in training",
                    implementation_details=[
                        "Develop authority impersonation scenarios",
                        "Train on urgency pressure recognition",
                        "Create verification procedure guidelines"
                    ],
                    success_metrics=["Authority recognition improved", "Verification procedures adopted", "Pressure tactic resistance increased"]
                )
            )
        
        return recommendations
    
    def _generate_monitoring_recommendations(self, risk_assessment: Dict[str, Any],
                                           threat_intelligence: Dict[str, Any],
                                           url_attachment_analysis: Dict[str, Any]) -> List[ActionableRecommendation]:
        """Generate monitoring and detection recommendations"""
        recommendations = []
        
        # Enhanced monitoring
        recommendations.append(
            ActionableRecommendation(
                priority="high",
                action_type="short_term",
                category="technical",
                description="Implement enhanced email monitoring",
                implementation_details=[
                    "Deploy behavioral email analysis",
                    "Implement real-time threat detection",
                    "Enable automated response capabilities"
                ],
                success_metrics=["Monitoring coverage increased", "Detection time reduced", "Automated responses enabled"]
            )
        )
        
        # Threat hunting
        correlation_results = threat_intelligence.get("correlation_results", {})
        if correlation_results.get("campaign_correlation", {}).get("matched_campaigns", []):
            recommendations.append(
                ActionableRecommendation(
                    priority="medium",
                    action_type="short_term",
                    category="technical",
                    description="Initiate proactive threat hunting",
                    implementation_details=[
                        "Hunt for campaign-related indicators",
                        "Search for similar attack patterns",
                        "Investigate related threat actors"
                    ],
                    success_metrics=["Hunting queries executed", "Additional threats discovered", "Prevention measures implemented"]
                )
            )
        
        return recommendations
    
    def _determine_remediation_priority(self, risk_assessment: Dict[str, Any]) -> str:
        """Determine overall remediation priority"""
        threat_level = risk_assessment.get("threat_classification", "suspicious")
        overall_score = risk_assessment.get("overall_risk_score", 0.0)
        
        if threat_level == "critical" or overall_score >= 0.85:
            return "critical"
        elif threat_level == "malicious" or overall_score >= 0.6:
            return "high"
        elif threat_level == "suspicious" or overall_score >= 0.3:
            return "medium"
        else:
            return "low"
    
    def _build_implementation_timeline(self, immediate_actions: List[ActionableRecommendation],
                                     short_term_actions: List[ActionableRecommendation],
                                     long_term_actions: List[ActionableRecommendation]) -> Dict[str, Any]:
        """Build implementation timeline for recommendations"""
        timeline = {
            "immediate": {
                "timeframe": "0-2 hours",
                "actions": len(immediate_actions),
                "priority": "critical"
            },
            "short_term": {
                "timeframe": "1-7 days", 
                "actions": len(short_term_actions),
                "priority": "high"
            },
            "long_term": {
                "timeframe": "1+ weeks",
                "actions": len(long_term_actions),
                "priority": "medium"
            }
        }
        
        return timeline
    
    def _assess_resource_requirements(self, recommendations: Dict[str, Any],
                                    risk_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Assess resource requirements for implementing recommendations"""
        resources = {
            "personnel": {
                "security_analysts": 2,
                "system_administrators": 1,
                "training_coordinators": 1
            },
            "technology": {
                "security_tools": ["Email gateway", "Sandbox", "SIEM"],
                "automation_platforms": ["SOAR", "Threat intelligence"],
                "monitoring_systems": ["Email security", "Network monitoring"]
            },
            "budget_estimate": {
                "immediate": "Low",
                "short_term": "Medium", 
                "long_term": "High"
            },
            "timeline": {
                "immediate_deployment": "2 hours",
                "short_term_deployment": "1 week",
                "long_term_deployment": "1 month"
            }
        }
        
        return resources
    
    def _assess_data_quality_factors(self, entity_analysis: Dict[str, Any],
                                   security_analysis: Dict[str, Any],
                                   reputation_analysis: Dict[str, Any],
                                   url_attachment_analysis: Dict[str, Any],
                                   threat_intelligence: Dict[str, Any]) -> Dict[str, Any]:
        """Assess data quality factors affecting confidence"""
        factors = {
            "completeness": {},
            "accuracy": {},
            "timeliness": {},
            "consistency": {}
        }
        
        # Completeness assessment
        factors["completeness"]["entity_data"] = "high" if entity_analysis.get("extracted_entities") else "low"
        factors["completeness"]["security_data"] = "high" if security_analysis.get("authentication_analysis") else "medium"
        factors["completeness"]["reputation_data"] = "medium" if reputation_analysis.get("sender_reputation") else "low"
        factors["completeness"]["url_data"] = "high" if url_attachment_analysis.get("url_analysis") else "low"
        factors["completeness"]["threat_intel"] = "medium" if threat_intelligence.get("correlation_results") else "low"
        
        # Accuracy assessment (simplified)
        factors["accuracy"]["overall"] = "high"
        
        # Timeliness assessment
        factors["timeliness"]["data_freshness"] = "current"
        factors["timeliness"]["feed_updates"] = "recent"
        
        # Consistency assessment
        factors["consistency"]["cross_validation"] = "consistent"
        
        return factors
    
    def _identify_confidence_factors(self, component_confidence: Dict[str, float],
                                   data_quality_factors: Dict[str, Any]) -> List[str]:
        """Identify factors affecting confidence assessment"""
        factors = []
        
        # High confidence components
        for component, confidence in component_confidence.items():
            if confidence > 0.8:
                factors.append(f"High confidence in {component.replace('_', ' ')}")
            elif confidence < 0.5:
                factors.append(f"Low confidence in {component.replace('_', ' ')}")
        
        # Data quality factors
        completeness = data_quality_factors.get("completeness", {})
        if any(level == "low" for level in completeness.values()):
            factors.append("Limited data completeness affecting confidence")
        
        return factors
    
    def _create_summary_overview(self, risk_assessment: Dict[str, Any],
                               entity_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Create executive summary overview"""
        overview = {
            "threat_level": risk_assessment.get("threat_classification", "unknown"),
            "risk_score": risk_assessment.get("overall_risk_score", 0.0),
            "risk_category": risk_assessment.get("risk_category", "unknown"),
            "email_subject": entity_analysis.get("email_content", {}).get("subject", "N/A"),
            "sender": entity_analysis.get("extracted_entities", {}).get("email_addresses", [{}])[0].get("address", "N/A"),
            "assessment_timestamp": datetime.now(),
            "key_verdict": self._generate_key_verdict(risk_assessment)
        }
        
        return overview
    
    def _generate_key_verdict(self, risk_assessment: Dict[str, Any]) -> str:
        """Generate key verdict statement"""
        threat_level = risk_assessment.get("threat_classification", "unknown")
        
        verdicts = {
            "critical": "CRITICAL THREAT - Immediate action required",
            "malicious": "MALICIOUS EMAIL - Block and investigate",
            "suspicious": "SUSPICIOUS ACTIVITY - Review and monitor",
            "benign": "BENIGN EMAIL - Low risk, continue monitoring"
        }
        
        return verdicts.get(threat_level, "UNKNOWN THREAT LEVEL - Manual review required")
    
    def _extract_key_findings(self, risk_assessment: Dict[str, Any],
                            security_analysis: Dict[str, Any],
                            reputation_analysis: Dict[str, Any],
                            url_attachment_analysis: Dict[str, Any],
                            threat_intelligence: Dict[str, Any]) -> List[str]:
        """Extract key findings for executive summary"""
        findings = []
        
        # Risk level finding
        threat_level = risk_assessment.get("threat_classification", "unknown")
        findings.append(f"Email classified as {threat_level.upper()} threat")
        
        # Authentication findings
        auth_analysis = security_analysis.get("authentication_analysis", {})
        failed_auth = []
        if not auth_analysis.get("spf_valid", True):
            failed_auth.append("SPF")
        if not auth_analysis.get("dkim_valid", True):
            failed_auth.append("DKIM")
        if not auth_analysis.get("dmarc_valid", True):
            failed_auth.append("DMARC")
        
        if failed_auth:
            findings.append(f"Authentication failures detected: {', '.join(failed_auth)}")
        
        # Threat intelligence findings
        correlation_results = threat_intelligence.get("correlation_results", {})
        ioc_matches = correlation_results.get("ioc_correlation", {}).get("matched_iocs", [])
        if ioc_matches:
            findings.append(f"Matched {len(ioc_matches)} threat intelligence indicators")
        
        # URL/Attachment findings
        url_analysis = url_attachment_analysis.get("url_analysis", {})
        malicious_urls = url_analysis.get("malicious_urls", [])
        if malicious_urls:
            findings.append(f"Detected {len(malicious_urls)} malicious URLs")
        
        return findings
    
    def _highlight_critical_risks(self, risk_assessment: Dict[str, Any],
                                threat_intelligence: Dict[str, Any]) -> Dict[str, Any]:
        """Highlight critical risks for executive attention"""
        highlights = {
            "immediate_risks": [],
            "potential_impact": [],
            "threat_actors": [],
            "attack_vectors": []
        }
        
        threat_level = risk_assessment.get("threat_classification", "unknown")
        
        if threat_level in ["critical", "malicious"]:
            highlights["immediate_risks"].extend([
                "Active malicious email in environment",
                "Potential for credential compromise",
                "Risk of lateral movement"
            ])
        
        # Potential impacts
        risk_category = risk_assessment.get("risk_category", "unknown")
        impact_mapping = {
            "credential_theft": "Compromised user credentials",
            "malware_delivery": "Malware infection and system compromise",
            "business_email_compromise": "Financial fraud and data theft",
            "phishing": "Credential theft and account takeover"
        }
        
        if risk_category in impact_mapping:
            highlights["potential_impact"].append(impact_mapping[risk_category])
        
        # Threat actors
        correlation_results = threat_intelligence.get("correlation_results", {})
        actor_attribution = correlation_results.get("actor_attribution", {})
        attributed_actors = actor_attribution.get("attributed_actors", [])
        highlights["threat_actors"] = attributed_actors
        
        return highlights
    
    def _identify_critical_actions(self, recommendations: Dict[str, Any],
                                 risk_assessment: Dict[str, Any]) -> List[str]:
        """Identify critical actions for executive summary"""
        actions = []
        
        immediate_actions = recommendations.get("immediate_actions", [])
        for action in immediate_actions:
            if action.priority == "critical":
                actions.append(action.description)
        
        # Add priority-based actions
        remediation_priority = recommendations.get("remediation_priority", "medium")
        if remediation_priority == "critical":
            actions.append("Initiate emergency incident response procedures")
        
        return actions
    
    def _assess_business_impact(self, risk_assessment: Dict[str, Any],
                              entity_analysis: Dict[str, Any],
                              threat_intelligence: Dict[str, Any]) -> Dict[str, Any]:
        """Assess potential business impact"""
        impact = {
            "financial_risk": "medium",
            "operational_risk": "medium",
            "reputational_risk": "low",
            "compliance_risk": "low",
            "estimated_cost": "medium"
        }
        
        threat_level = risk_assessment.get("threat_classification", "unknown")
        risk_category = risk_assessment.get("risk_category", "unknown")
        
        # Adjust based on threat level
        if threat_level == "critical":
            impact["financial_risk"] = "high"
            impact["operational_risk"] = "high"
            impact["reputational_risk"] = "medium"
        elif threat_level == "malicious":
            impact["financial_risk"] = "medium"
            impact["operational_risk"] = "medium"
        
        # Adjust based on category
        if risk_category in ["business_email_compromise", "financial_fraud"]:
            impact["financial_risk"] = "high"
            impact["compliance_risk"] = "medium"
        
        return impact
    
    def _prepare_stakeholder_communications(self, risk_assessment: Dict[str, Any],
                                          recommendations: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare stakeholder communications"""
        communications = {
            "ciso_briefing": {
                "priority": "high",
                "key_points": [
                    f"Threat level: {risk_assessment.get('threat_classification', 'unknown')}",
                    f"Risk score: {risk_assessment.get('overall_risk_score', 0.0):.2f}",
                    "Immediate actions required"
                ],
                "recommended_actions": recommendations.get("immediate_actions", [])[:3]
            },
            "soc_team_alert": {
                "priority": "immediate",
                "escalation_required": risk_assessment.get("threat_classification") in ["critical", "malicious"],
                "investigation_steps": [
                    "Review email headers and content",
                    "Check for similar emails",
                    "Monitor user activity"
                ]
            },
            "end_user_notification": {
                "required": True,
                "message_type": "security_awareness",
                "urgency": "medium"
            }
        }
        
        return communications
    
    def _define_next_steps(self, recommendations: Dict[str, Any],
                         risk_assessment: Dict[str, Any]) -> List[str]:
        """Define next steps for stakeholders"""
        next_steps = []
        
        threat_level = risk_assessment.get("threat_classification", "unknown")
        
        if threat_level in ["critical", "malicious"]:
            next_steps.extend([
                "Execute immediate containment procedures",
                "Initiate incident response team activation",
                "Begin forensic analysis and evidence collection"
            ])
        elif threat_level == "suspicious":
            next_steps.extend([
                "Continue monitoring and analysis",
                "Implement additional security controls",
                "Review security awareness training effectiveness"
            ])
        
        # Add recommendation-based steps
        immediate_actions = recommendations.get("immediate_actions", [])
        if immediate_actions:
            next_steps.append("Implement immediate technical controls")
        
        return next_steps
    
    def _compile_executive_appendices(self, risk_assessment: Dict[str, Any],
                                    recommendations: Dict[str, Any],
                                    threat_intelligence: Dict[str, Any]) -> Dict[str, Any]:
        """Compile appendices for executive summary"""
        appendices = {
            "risk_scoring_methodology": {
                "description": "Risk scoring based on weighted analysis of multiple security dimensions",
                "weight_distribution": self.risk_weights
            },
            "threat_intelligence_sources": {
                "external_feeds": threat_intelligence.get("enrichment_results", {}).get("external_feeds", []),
                "ioc_databases": ["MISP", "OTX", "VirusTotal"],
                "correlation_confidence": threat_intelligence.get("correlation_results", {}).get("correlation_confidence", 0.0)
            },
            "recommendation_prioritization": {
                "methodology": "Priority based on threat level, business impact, and implementation complexity",
                "timeline_framework": recommendations.get("implementation_timeline", {})
            }
        }
        
        return appendices
    
    def _create_report_header(self, risk_assessment: Dict[str, Any],
                            entity_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Create detailed report header"""
        header = {
            "report_title": "Phishing Email Risk Assessment Report",
            "threat_classification": risk_assessment.get("threat_classification", "unknown"),
            "overall_risk_score": risk_assessment.get("overall_risk_score", 0.0),
            "email_metadata": {
                "subject": entity_analysis.get("email_content", {}).get("subject", "N/A"),
                "sender": entity_analysis.get("extracted_entities", {}).get("email_addresses", [{}])[0].get("address", "N/A"),
                "received_timestamp": entity_analysis.get("email_content", {}).get("timestamp", datetime.now())
            },
            "analysis_scope": [
                "Entity extraction and pattern analysis",
                "Email security and authentication validation",
                "Sender and domain reputation assessment",
                "URL and attachment security analysis",
                "Threat intelligence correlation",
                "Risk assessment and classification"
            ]
        }
        
        return header
    
    def _document_methodology(self) -> Dict[str, Any]:
        """Document analysis methodology"""
        methodology = {
            "overview": "Comprehensive phishing email analysis using multi-stage security assessment",
            "analysis_stages": {
                "stage_1": "Email Entity Extraction and Pattern Analysis",
                "stage_2": "Email Security Analysis and Authentication Validation",
                "stage_3": "Sender Reputation Assessment", 
                "stage_4": "URL and Attachment Security Analysis",
                "stage_5": "Threat Intelligence Correlation",
                "stage_6": "Risk Assessment and Classification"
            },
            "risk_scoring": {
                "methodology": "Weighted risk scoring across all analysis dimensions",
                "weights": self.risk_weights,
                "thresholds": self.classification_thresholds
            },
            "confidence_assessment": {
                "factors": ["Data completeness", "Analysis accuracy", "Source reliability"],
                "scoring": "Statistical aggregation of component confidence scores"
            }
        }
        
        return methodology
    
    def _compile_detailed_findings(self, entity_analysis: Dict[str, Any],
                                 security_analysis: Dict[str, Any],
                                 reputation_analysis: Dict[str, Any],
                                 url_attachment_analysis: Dict[str, Any],
                                 threat_intelligence: Dict[str, Any]) -> Dict[str, Any]:
        """Compile detailed findings section"""
        findings = {
            "entity_analysis_findings": self._extract_entity_findings(entity_analysis),
            "security_analysis_findings": self._extract_security_findings(security_analysis),
            "reputation_analysis_findings": self._extract_reputation_findings(reputation_analysis),
            "url_attachment_findings": self._extract_url_attachment_findings(url_attachment_analysis),
            "threat_intelligence_findings": self._extract_threat_intelligence_findings(threat_intelligence)
        }
        
        return findings
    
    def _extract_entity_findings(self, entity_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Extract entity analysis findings"""
        return {
            "extracted_entities": entity_analysis.get("extracted_entities", {}),
            "pattern_analysis": entity_analysis.get("pattern_analysis", {}),
            "key_observations": [
                f"Extracted {len(entity_analysis.get('extracted_entities', {}).get('urls', []))} URLs",
                f"Identified {len(entity_analysis.get('extracted_entities', {}).get('email_addresses', []))} email addresses"
            ]
        }
    
    def _extract_security_findings(self, security_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Extract security analysis findings"""
        return {
            "authentication_results": security_analysis.get("authentication_analysis", {}),
            "content_analysis": security_analysis.get("content_analysis", {}),
            "key_observations": [
                "Authentication validation completed",
                "Content analysis performed",
                "Social engineering indicators assessed"
            ]
        }
    
    def _extract_reputation_findings(self, reputation_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Extract reputation analysis findings"""
        return {
            "sender_reputation": reputation_analysis.get("sender_reputation", {}),
            "domain_reputation": reputation_analysis.get("domain_reputation", {}),
            "historical_analysis": reputation_analysis.get("historical_analysis", {}),
            "key_observations": [
                "Sender reputation assessed",
                "Domain reputation evaluated",
                "Historical patterns analyzed"
            ]
        }
    
    def _extract_url_attachment_findings(self, url_attachment_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Extract URL and attachment analysis findings"""
        return {
            "url_analysis": url_attachment_analysis.get("url_analysis", {}),
            "attachment_analysis": url_attachment_analysis.get("attachment_analysis", {}),
            "sandbox_results": url_attachment_analysis.get("sandbox_analysis", {}),
            "key_observations": [
                "URL security analysis completed",
                "Attachment scanning performed",
                "Sandbox analysis executed"
            ]
        }
    
    def _extract_threat_intelligence_findings(self, threat_intelligence: Dict[str, Any]) -> Dict[str, Any]:
        """Extract threat intelligence findings"""
        return {
            "correlation_results": threat_intelligence.get("correlation_results", {}),
            "enrichment_results": threat_intelligence.get("enrichment_results", {}),
            "attribution_analysis": threat_intelligence.get("correlation_results", {}).get("actor_attribution", {}),
            "key_observations": [
                "Threat intelligence correlation performed",
                "External feed enrichment completed",
                "Actor attribution analysis conducted"
            ]
        }
    
    def _create_threat_intelligence_section(self, threat_intelligence: Dict[str, Any]) -> Dict[str, Any]:
        """Create threat intelligence analysis section"""
        return {
            "correlation_summary": threat_intelligence.get("correlation_results", {}),
            "ioc_analysis": threat_intelligence.get("correlation_results", {}).get("ioc_correlation", {}),
            "campaign_correlation": threat_intelligence.get("correlation_results", {}).get("campaign_correlation", {}),
            "actor_attribution": threat_intelligence.get("correlation_results", {}).get("actor_attribution", {}),
            "attack_lifecycle": threat_intelligence.get("lifecycle_analysis", {}),
            "historical_correlation": threat_intelligence.get("historical_correlation", {})
        }
    
    def _compile_technical_appendices(self, entity_analysis: Dict[str, Any],
                                    security_analysis: Dict[str, Any],
                                    reputation_analysis: Dict[str, Any],
                                    url_attachment_analysis: Dict[str, Any],
                                    threat_intelligence: Dict[str, Any]) -> Dict[str, Any]:
        """Compile technical appendices"""
        appendices = {
            "raw_analysis_data": {
                "entity_extraction": entity_analysis,
                "security_analysis": security_analysis,
                "reputation_analysis": reputation_analysis,
                "url_attachment_analysis": url_attachment_analysis,
                "threat_intelligence": threat_intelligence
            },
            "technical_indicators": {
                "iocs": threat_intelligence.get("correlation_results", {}).get("ioc_correlation", {}).get("matched_iocs", []),
                "ttps": threat_intelligence.get("correlation_results", {}).get("ttp_correlation", {}).get("identified_ttps", [])
            },
            "analysis_metadata": {
                "tools_used": ["Email parser", "Security scanner", "Reputation checker", "Sandbox", "TI correlator"],
                "data_sources": ["Internal logs", "External threat feeds", "Reputation databases"],
                "analysis_duration": "Automated - Real-time analysis"
            }
        }
        
        return appendices
    
    def _create_glossary(self) -> Dict[str, str]:
        """Create glossary of terms"""
        return {
            "IOC": "Indicator of Compromise - Observable artifacts that indicate potential intrusion",
            "TTP": "Tactics, Techniques, and Procedures - Methods used by threat actors",
            "MITRE ATT&CK": "Framework for describing adversary tactics and techniques",
            "SPF": "Sender Policy Framework - Email authentication method",
            "DKIM": "DomainKeys Identified Mail - Email authentication method",
            "DMARC": "Domain-based Message Authentication, Reporting, and Conformance",
            "BEC": "Business Email Compromise - Type of fraud targeting organizations",
            "Phishing": "Fraudulent attempt to obtain sensitive information",
            "Sandbox": "Isolated environment for analyzing suspicious files",
            "TLP": "Traffic Light Protocol - Information sharing classification"
        }
    
    def _add_references(self) -> List[str]:
        """Add references and sources"""
        return [
            "NIST Cybersecurity Framework",
            "MITRE ATT&CK Framework",
            "SANS Email Security Best Practices",
            "Anti-Phishing Working Group (APWG) Reports",
            "Threat Intelligence Platform Documentation",
            "Email Authentication Standards (RFC specifications)"
        ]
