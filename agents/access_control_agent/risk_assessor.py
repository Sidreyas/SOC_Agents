"""
Risk Assessor Module
State 4: Risk Assessment  
Calculates comprehensive risk scores and determines threat levels
"""

import logging
from typing import Dict, Any, List, Tuple
from datetime import datetime, timedelta
import json
import math

logger = logging.getLogger(__name__)

class RiskAssessor:
    """
    Calculates comprehensive risk scores and determines threat levels
    Combines multiple risk factors to produce actionable risk assessments
    """
    
    def __init__(self):
        self.risk_weights = self._initialize_risk_weights()
        self.threat_indicators = {}
        self.organizational_risk_tolerance = 0.7  # 0-1 scale
        
    def calculate_permission_risk_score(self, permission_analysis: Dict[str, Any], baseline_validation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate risk score based on permission analysis and baseline validation
        
        Returns:
            Comprehensive permission risk assessment with detailed scoring
        """
        logger.info("Calculating permission risk score")
        
        risk_assessment = {
            "overall_risk_score": 0.0,
            "risk_level": "low",
            "risk_factors": {},
            "scoring_breakdown": {},
            "mitigation_priority": "low",
            "confidence_level": 0.0
        }
        
        # Initialize risk factors
        risk_factors = {
            "privilege_escalation": 0.0,
            "administrative_access": 0.0,
            "policy_violations": 0.0,
            "baseline_deviations": 0.0,
            "temporal_anomalies": 0.0,
            "scope_expansion": 0.0
        }
        
        # Calculate privilege escalation risk
        risk_factors["privilege_escalation"] = self._calculate_privilege_escalation_risk(permission_analysis)
        
        # Calculate administrative access risk
        risk_factors["administrative_access"] = self._calculate_administrative_access_risk(permission_analysis)
        
        # Calculate policy violation risk
        risk_factors["policy_violations"] = self._calculate_policy_violation_risk(baseline_validation)
        
        # Calculate baseline deviation risk
        risk_factors["baseline_deviations"] = self._calculate_baseline_deviation_risk(baseline_validation)
        
        # Calculate temporal anomaly risk
        risk_factors["temporal_anomalies"] = self._calculate_temporal_anomaly_risk(permission_analysis)
        
        # Calculate scope expansion risk
        risk_factors["scope_expansion"] = self._calculate_scope_expansion_risk(permission_analysis)
        
        # Calculate weighted overall score
        overall_score = 0.0
        for factor, score in risk_factors.items():
            weighted_score = score * self.risk_weights.get(factor, 1.0)
            overall_score += weighted_score
            
        # Normalize score to 0-10 scale
        risk_assessment["overall_risk_score"] = min(overall_score, 10.0)
        risk_assessment["risk_factors"] = risk_factors
        
        # Determine risk level
        risk_assessment["risk_level"] = self._determine_risk_level(risk_assessment["overall_risk_score"])
        
        # Determine mitigation priority
        risk_assessment["mitigation_priority"] = self._determine_mitigation_priority(
            risk_assessment["overall_risk_score"], 
            risk_factors
        )
        
        # Calculate confidence level
        risk_assessment["confidence_level"] = self._calculate_confidence_level(permission_analysis, baseline_validation)
        
        # Provide detailed scoring breakdown
        risk_assessment["scoring_breakdown"] = self._create_scoring_breakdown(risk_factors, self.risk_weights)
        
        logger.info(f"Permission risk score calculated: {risk_assessment['overall_risk_score']:.2f} ({risk_assessment['risk_level']})")
        return risk_assessment
    
    def assess_threat_level(self, enrichment_data: Dict[str, Any], cross_agent_correlations: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess threat level based on enrichment data and cross-agent correlations
        
        Returns:
            Comprehensive threat level assessment
        """
        logger.info("Assessing threat level")
        
        threat_assessment = {
            "threat_level": "low",
            "threat_score": 0.0,
            "threat_indicators": {},
            "attack_likelihood": 0.0,
            "impact_potential": 0.0,
            "threat_actor_analysis": {},
            "recommended_actions": []
        }
        
        # Analyze threat indicators
        threat_assessment["threat_indicators"] = self._analyze_threat_indicators(enrichment_data)
        
        # Calculate attack likelihood
        threat_assessment["attack_likelihood"] = self._calculate_attack_likelihood(
            enrichment_data, 
            cross_agent_correlations
        )
        
        # Calculate impact potential
        threat_assessment["impact_potential"] = self._calculate_impact_potential(enrichment_data)
        
        # Perform threat actor analysis
        threat_assessment["threat_actor_analysis"] = self._analyze_threat_actors(enrichment_data)
        
        # Calculate overall threat score
        threat_assessment["threat_score"] = (
            threat_assessment["attack_likelihood"] * 0.6 + 
            threat_assessment["impact_potential"] * 0.4
        )
        
        # Determine threat level
        threat_assessment["threat_level"] = self._determine_threat_level(threat_assessment["threat_score"])
        
        # Generate recommended actions
        threat_assessment["recommended_actions"] = self._generate_threat_response_actions(threat_assessment)
        
        logger.info(f"Threat level assessed: {threat_assessment['threat_level']} (score: {threat_assessment['threat_score']:.2f})")
        return threat_assessment
    
    def calculate_business_impact(self, permission_data: Dict[str, Any], organizational_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate potential business impact of identified risks
        
        Returns:
            Business impact assessment with quantified risks
        """
        logger.info("Calculating business impact")
        
        impact_assessment = {
            "business_impact_score": 0.0,
            "impact_categories": {},
            "affected_systems": [],
            "data_exposure_risk": 0.0,
            "operational_impact": 0.0,
            "compliance_risk": 0.0,
            "financial_impact_estimate": {}
        }
        
        # Calculate impact across different categories
        impact_categories = {
            "data_confidentiality": self._calculate_data_confidentiality_impact(permission_data),
            "system_availability": self._calculate_system_availability_impact(permission_data),
            "operational_continuity": self._calculate_operational_continuity_impact(organizational_context),
            "regulatory_compliance": self._calculate_compliance_impact(permission_data),
            "reputation_damage": self._calculate_reputation_impact(permission_data, organizational_context)
        }
        
        impact_assessment["impact_categories"] = impact_categories
        
        # Calculate overall business impact score
        impact_assessment["business_impact_score"] = sum(impact_categories.values()) / len(impact_categories)
        
        # Identify affected systems
        impact_assessment["affected_systems"] = self._identify_affected_systems(permission_data)
        
        # Calculate specific risk metrics
        impact_assessment["data_exposure_risk"] = self._calculate_data_exposure_risk(permission_data)
        impact_assessment["operational_impact"] = self._calculate_operational_impact(permission_data)
        impact_assessment["compliance_risk"] = self._calculate_compliance_risk(permission_data)
        
        # Estimate financial impact
        impact_assessment["financial_impact_estimate"] = self._estimate_financial_impact(impact_assessment)
        
        logger.info(f"Business impact calculated: {impact_assessment['business_impact_score']:.2f}")
        return impact_assessment
    
    def prioritize_response_actions(self, risk_score: float, threat_level: str, business_impact: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prioritize response actions based on risk, threat, and business impact
        
        Returns:
            Prioritized list of response actions with timelines and owners
        """
        logger.info("Prioritizing response actions")
        
        response_prioritization = {
            "immediate_actions": [],
            "short_term_actions": [],
            "long_term_actions": [],
            "action_priorities": {},
            "resource_requirements": {},
            "timeline_recommendations": {}
        }
        
        # Determine action urgency based on risk and threat level
        urgency_score = self._calculate_urgency_score(risk_score, threat_level, business_impact)
        
        # Generate immediate actions (< 4 hours)
        if urgency_score >= 8.0:
            response_prioritization["immediate_actions"] = self._generate_immediate_actions(
                risk_score, threat_level, business_impact
            )
        
        # Generate short-term actions (< 24 hours)
        if urgency_score >= 5.0:
            response_prioritization["short_term_actions"] = self._generate_short_term_actions(
                risk_score, threat_level, business_impact
            )
        
        # Generate long-term actions (< 30 days)
        response_prioritization["long_term_actions"] = self._generate_long_term_actions(
            risk_score, threat_level, business_impact
        )
        
        # Prioritize all actions
        all_actions = (
            response_prioritization["immediate_actions"] + 
            response_prioritization["short_term_actions"] + 
            response_prioritization["long_term_actions"]
        )
        
        response_prioritization["action_priorities"] = self._prioritize_actions(all_actions, urgency_score)
        
        # Estimate resource requirements
        response_prioritization["resource_requirements"] = self._estimate_resource_requirements(all_actions)
        
        # Create timeline recommendations
        response_prioritization["timeline_recommendations"] = self._create_timeline_recommendations(
            response_prioritization
        )
        
        logger.info(f"Response actions prioritized. Urgency score: {urgency_score:.2f}")
        return response_prioritization
    
    def _initialize_risk_weights(self) -> Dict[str, float]:
        """Initialize risk factor weights"""
        return {
            "privilege_escalation": 2.5,
            "administrative_access": 2.0,
            "policy_violations": 1.8,
            "baseline_deviations": 1.5,
            "temporal_anomalies": 1.2,
            "scope_expansion": 1.0
        }
    
    def _calculate_privilege_escalation_risk(self, permission_analysis: Dict[str, Any]) -> float:
        """Calculate risk score for privilege escalation"""
        escalation_patterns = permission_analysis.get("escalation_patterns", [])
        
        if not escalation_patterns:
            return 0.0
        
        risk_score = 0.0
        
        for pattern in escalation_patterns:
            severity = pattern.get("severity", "Low")
            if severity == "High":
                risk_score += 3.0
            elif severity == "Medium":
                risk_score += 2.0
            else:
                risk_score += 1.0
        
        return min(risk_score, 10.0)
    
    def _calculate_administrative_access_risk(self, permission_analysis: Dict[str, Any]) -> float:
        """Calculate risk score for administrative access"""
        admin_roles = permission_analysis.get("admin_roles", [])
        
        risk_score = 0.0
        high_privilege_roles = ["Global Administrator", "User Administrator", "Security Administrator"]
        
        for role in admin_roles:
            if role in high_privilege_roles:
                risk_score += 2.5
            else:
                risk_score += 1.0
        
        return min(risk_score, 10.0)
    
    def _calculate_policy_violation_risk(self, baseline_validation: Dict[str, Any]) -> float:
        """Calculate risk score for policy violations"""
        violations = baseline_validation.get("policy_violations", [])
        
        if not violations:
            return 0.0
        
        risk_score = 0.0
        
        for violation in violations:
            severity = violation.get("severity", "Low")
            if severity == "High":
                risk_score += 2.0
            elif severity == "Medium":
                risk_score += 1.5
            else:
                risk_score += 1.0
        
        return min(risk_score, 10.0)
    
    def _calculate_baseline_deviation_risk(self, baseline_validation: Dict[str, Any]) -> float:
        """Calculate risk score for baseline deviations"""
        compliance_score = baseline_validation.get("compliance_score", 1.0)
        
        # Higher deviation = lower compliance score = higher risk
        deviation_risk = (1.0 - compliance_score) * 10.0
        
        return min(deviation_risk, 10.0)
    
    def _calculate_temporal_anomaly_risk(self, permission_analysis: Dict[str, Any]) -> float:
        """Calculate risk score for temporal anomalies"""
        time_analysis = permission_analysis.get("time_analysis", {})
        
        risk_score = 0.0
        
        # Off-hours activity
        if time_analysis.get("off_hours_activity", False):
            risk_score += 2.0
        
        # Rapid succession changes
        if time_analysis.get("rapid_changes", False):
            risk_score += 1.5
        
        # Weekend activity
        if time_analysis.get("weekend_activity", False):
            risk_score += 1.0
        
        return min(risk_score, 10.0)
    
    def _calculate_scope_expansion_risk(self, permission_analysis: Dict[str, Any]) -> float:
        """Calculate risk score for scope expansion"""
        scope_analysis = permission_analysis.get("scope_analysis", {})
        
        risk_score = 0.0
        
        # Cross-tenant permissions
        if scope_analysis.get("cross_tenant", False):
            risk_score += 2.5
        
        # Multiple subscription access
        subscription_count = scope_analysis.get("subscription_count", 0)
        if subscription_count > 5:
            risk_score += 2.0
        elif subscription_count > 2:
            risk_score += 1.0
        
        # Resource group sprawl
        rg_count = scope_analysis.get("resource_group_count", 0)
        if rg_count > 10:
            risk_score += 1.5
        
        return min(risk_score, 10.0)
    
    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level based on score"""
        if risk_score >= 8.0:
            return "critical"
        elif risk_score >= 6.0:
            return "high"
        elif risk_score >= 4.0:
            return "medium"
        else:
            return "low"
    
    def _determine_mitigation_priority(self, risk_score: float, risk_factors: Dict[str, float]) -> str:
        """Determine mitigation priority"""
        # Check for critical factors
        critical_factors = [k for k, v in risk_factors.items() if v >= 7.0]
        
        if critical_factors or risk_score >= 8.0:
            return "immediate"
        elif risk_score >= 6.0:
            return "high"
        elif risk_score >= 4.0:
            return "medium"
        else:
            return "low"
    
    def _calculate_confidence_level(self, permission_analysis: Dict[str, Any], baseline_validation: Dict[str, Any]) -> float:
        """Calculate confidence level in the assessment"""
        confidence_factors = []
        
        # Data quality factors
        if permission_analysis.get("data_completeness", 0) > 0.8:
            confidence_factors.append(0.2)
        
        if baseline_validation.get("baseline_coverage", 0) > 0.7:
            confidence_factors.append(0.2)
        
        # Evidence strength
        evidence_count = len(permission_analysis.get("supporting_evidence", []))
        if evidence_count >= 5:
            confidence_factors.append(0.3)
        elif evidence_count >= 3:
            confidence_factors.append(0.2)
        
        # Correlation strength
        correlation_strength = permission_analysis.get("correlation_strength", 0.5)
        confidence_factors.append(correlation_strength * 0.3)
        
        return sum(confidence_factors)
    
    def _create_scoring_breakdown(self, risk_factors: Dict[str, float], weights: Dict[str, float]) -> Dict[str, Any]:
        """Create detailed scoring breakdown"""
        breakdown = {}
        
        for factor, score in risk_factors.items():
            weight = weights.get(factor, 1.0)
            weighted_score = score * weight
            
            breakdown[factor] = {
                "raw_score": score,
                "weight": weight,
                "weighted_score": weighted_score,
                "contribution_percentage": (weighted_score / sum(risk_factors.values())) * 100
            }
        
        return breakdown
    
    def _analyze_threat_indicators(self, enrichment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze threat indicators from enrichment data"""
        indicators = {
            "ioc_matches": len(enrichment_data.get("threat_intelligence", {}).get("ioc_matches", [])),
            "suspicious_ips": self._count_suspicious_ips(enrichment_data),
            "malicious_domains": self._count_malicious_domains(enrichment_data),
            "behavioral_anomalies": len(enrichment_data.get("behavioral_correlation", {}).get("anomaly_detection", {}).get("behavioral_deviations", [])),
            "risk_indicators": len(enrichment_data.get("risk_indicators", {}).get("high_risk_indicators", []))
        }
        
        return indicators
    
    def _calculate_attack_likelihood(self, enrichment_data: Dict[str, Any], cross_agent_correlations: Dict[str, Any]) -> float:
        """Calculate likelihood of ongoing attack"""
        likelihood_factors = []
        
        # Threat intelligence matches
        ioc_matches = len(enrichment_data.get("threat_intelligence", {}).get("ioc_matches", []))
        if ioc_matches > 0:
            likelihood_factors.append(min(ioc_matches * 2.0, 10.0))
        
        # Cross-agent correlations
        correlation_strength = cross_agent_correlations.get("overall_confidence", 0.0)
        likelihood_factors.append(correlation_strength * 10.0)
        
        # Risk indicators
        high_risk_indicators = len(enrichment_data.get("risk_indicators", {}).get("high_risk_indicators", []))
        likelihood_factors.append(min(high_risk_indicators * 1.5, 10.0))
        
        # Attack chain analysis
        attack_chains = cross_agent_correlations.get("attack_chain_analysis", {}).get("potential_chains", [])
        if attack_chains:
            max_chain_confidence = max([chain.get("confidence", 0.0) for chain in attack_chains])
            likelihood_factors.append(max_chain_confidence * 10.0)
        
        return sum(likelihood_factors) / len(likelihood_factors) if likelihood_factors else 0.0
    
    def _calculate_impact_potential(self, enrichment_data: Dict[str, Any]) -> float:
        """Calculate potential impact of the threat"""
        impact_factors = []
        
        # Organizational context
        org_context = enrichment_data.get("organizational_context", {})
        clearance_level = org_context.get("business_context", {}).get("clearance_level", "Standard")
        
        if clearance_level == "High":
            impact_factors.append(8.0)
        elif clearance_level == "Medium":
            impact_factors.append(6.0)
        else:
            impact_factors.append(4.0)
        
        # Data access level
        data_access = org_context.get("business_context", {}).get("data_access_level", "Internal")
        if data_access == "Confidential":
            impact_factors.append(9.0)
        elif data_access == "Internal":
            impact_factors.append(6.0)
        else:
            impact_factors.append(3.0)
        
        # System criticality
        authorized_systems = org_context.get("operational_context", {}).get("authorized_systems", [])
        critical_systems = ["Azure Portal", "SIEM", "Domain Controllers"]
        critical_access = any(system in authorized_systems for system in critical_systems)
        
        if critical_access:
            impact_factors.append(8.0)
        else:
            impact_factors.append(4.0)
        
        return sum(impact_factors) / len(impact_factors) if impact_factors else 0.0
    
    def _analyze_threat_actors(self, enrichment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze potential threat actors"""
        return {
            "likely_actor_types": ["Insider Threat", "External Attacker"],
            "sophistication_level": "Medium",
            "attack_vectors": ["Credential Compromise", "Privilege Escalation"],
            "motivation_assessment": "Financial gain or Data theft",
            "attribution_confidence": 0.6
        }
    
    def _determine_threat_level(self, threat_score: float) -> str:
        """Determine overall threat level"""
        if threat_score >= 8.0:
            return "critical"
        elif threat_score >= 6.0:
            return "high"
        elif threat_score >= 4.0:
            return "medium"
        else:
            return "low"
    
    def _generate_threat_response_actions(self, threat_assessment: Dict[str, Any]) -> List[str]:
        """Generate recommended response actions based on threat assessment"""
        actions = []
        threat_level = threat_assessment["threat_level"]
        
        if threat_level in ["critical", "high"]:
            actions.extend([
                "Immediately disable suspicious user accounts",
                "Reset credentials for affected users",
                "Enable enhanced monitoring for related systems",
                "Initiate incident response procedure"
            ])
        
        if threat_level in ["medium"]:
            actions.extend([
                "Increase monitoring for suspicious activities",
                "Review and validate recent permission changes",
                "Notify security team for investigation"
            ])
        
        return actions
    
    def _calculate_data_confidentiality_impact(self, permission_data: Dict[str, Any]) -> float:
        """Calculate impact on data confidentiality"""
        # Mock calculation based on permission scope
        sensitive_permissions = permission_data.get("sensitive_permissions", [])
        return min(len(sensitive_permissions) * 2.0, 10.0)
    
    def _calculate_system_availability_impact(self, permission_data: Dict[str, Any]) -> float:
        """Calculate impact on system availability"""
        # Mock calculation based on administrative permissions
        admin_permissions = permission_data.get("admin_permissions", [])
        return min(len(admin_permissions) * 1.5, 10.0)
    
    def _calculate_operational_continuity_impact(self, organizational_context: Dict[str, Any]) -> float:
        """Calculate impact on operational continuity"""
        # Mock calculation based on role criticality
        business_context = organizational_context.get("business_context", {})
        role = business_context.get("role", "")
        
        if "Administrator" in role:
            return 8.0
        elif "Manager" in role:
            return 6.0
        else:
            return 4.0
    
    def _calculate_compliance_impact(self, permission_data: Dict[str, Any]) -> float:
        """Calculate impact on regulatory compliance"""
        # Mock calculation based on compliance-related permissions
        compliance_permissions = permission_data.get("compliance_permissions", [])
        return min(len(compliance_permissions) * 2.5, 10.0)
    
    def _calculate_reputation_impact(self, permission_data: Dict[str, Any], organizational_context: Dict[str, Any]) -> float:
        """Calculate impact on organizational reputation"""
        # Mock calculation based on external-facing permissions
        external_permissions = permission_data.get("external_permissions", [])
        return min(len(external_permissions) * 1.8, 10.0)
    
    def _identify_affected_systems(self, permission_data: Dict[str, Any]) -> List[str]:
        """Identify systems affected by the permission changes"""
        return [
            "Azure Active Directory",
            "Office 365",
            "Azure Subscriptions", 
            "SharePoint Online",
            "Exchange Online"
        ]
    
    def _calculate_data_exposure_risk(self, permission_data: Dict[str, Any]) -> float:
        """Calculate risk of data exposure"""
        data_permissions = permission_data.get("data_access_permissions", [])
        return min(len(data_permissions) * 1.5, 10.0)
    
    def _calculate_operational_impact(self, permission_data: Dict[str, Any]) -> float:
        """Calculate operational impact"""
        operational_permissions = permission_data.get("operational_permissions", [])
        return min(len(operational_permissions) * 1.2, 10.0)
    
    def _calculate_compliance_risk(self, permission_data: Dict[str, Any]) -> float:
        """Calculate compliance risk"""
        compliance_violations = permission_data.get("compliance_violations", [])
        return min(len(compliance_violations) * 2.0, 10.0)
    
    def _estimate_financial_impact(self, impact_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Estimate financial impact"""
        business_impact_score = impact_assessment["business_impact_score"]
        
        return {
            "estimated_cost_range": {
                "minimum": business_impact_score * 10000,
                "maximum": business_impact_score * 50000
            },
            "cost_categories": {
                "incident_response": business_impact_score * 5000,
                "business_disruption": business_impact_score * 15000,
                "regulatory_fines": business_impact_score * 20000,
                "reputation_damage": business_impact_score * 10000
            },
            "currency": "USD"
        }
    
    def _calculate_urgency_score(self, risk_score: float, threat_level: str, business_impact: Dict[str, Any]) -> float:
        """Calculate urgency score for response prioritization"""
        urgency_components = [
            risk_score,
            {"critical": 10.0, "high": 8.0, "medium": 6.0, "low": 4.0}.get(threat_level, 4.0),
            business_impact["business_impact_score"]
        ]
        
        return sum(urgency_components) / len(urgency_components)
    
    def _generate_immediate_actions(self, risk_score: float, threat_level: str, business_impact: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate immediate response actions"""
        return [
            {
                "action": "Disable suspicious user accounts",
                "priority": 1,
                "timeline": "< 1 hour",
                "owner": "Security Operations Center",
                "risk_reduction": 3.0
            },
            {
                "action": "Reset credentials for affected users",
                "priority": 2,
                "timeline": "< 2 hours", 
                "owner": "Identity Administration",
                "risk_reduction": 2.5
            }
        ]
    
    def _generate_short_term_actions(self, risk_score: float, threat_level: str, business_impact: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate short-term response actions"""
        return [
            {
                "action": "Review and audit all recent permission changes",
                "priority": 3,
                "timeline": "< 8 hours",
                "owner": "Security Team",
                "risk_reduction": 2.0
            },
            {
                "action": "Implement enhanced monitoring",
                "priority": 4,
                "timeline": "< 24 hours",
                "owner": "SOC Team",
                "risk_reduction": 1.5
            }
        ]
    
    def _generate_long_term_actions(self, risk_score: float, threat_level: str, business_impact: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate long-term response actions"""
        return [
            {
                "action": "Implement additional access controls",
                "priority": 5,
                "timeline": "< 7 days",
                "owner": "IT Security",
                "risk_reduction": 1.8
            },
            {
                "action": "Update security policies and procedures",
                "priority": 6,
                "timeline": "< 30 days",
                "owner": "Security Governance",
                "risk_reduction": 1.2
            }
        ]
    
    def _prioritize_actions(self, actions: List[Dict[str, Any]], urgency_score: float) -> Dict[str, Any]:
        """Prioritize actions based on risk reduction and urgency"""
        prioritized = sorted(actions, key=lambda x: x.get("risk_reduction", 0.0), reverse=True)
        
        return {
            "highest_priority": prioritized[:2],
            "medium_priority": prioritized[2:4],
            "lower_priority": prioritized[4:],
            "total_actions": len(actions)
        }
    
    def _estimate_resource_requirements(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Estimate resource requirements for actions"""
        return {
            "personnel_hours": len(actions) * 4,
            "required_teams": list(set([action["owner"] for action in actions])),
            "estimated_cost": len(actions) * 2000,
            "tools_required": ["SIEM", "Identity Management", "Monitoring Tools"]
        }
    
    def _create_timeline_recommendations(self, response_prioritization: Dict[str, Any]) -> Dict[str, Any]:
        """Create timeline recommendations"""
        return {
            "phase_1": {
                "timeframe": "0-4 hours",
                "actions": response_prioritization["immediate_actions"],
                "success_criteria": "Threat containment achieved"
            },
            "phase_2": {
                "timeframe": "4-24 hours", 
                "actions": response_prioritization["short_term_actions"],
                "success_criteria": "Full assessment completed"
            },
            "phase_3": {
                "timeframe": "1-30 days",
                "actions": response_prioritization["long_term_actions"],
                "success_criteria": "Preventive controls implemented"
            }
        }
    
    def _count_suspicious_ips(self, enrichment_data: Dict[str, Any]) -> int:
        """Count suspicious IP addresses"""
        threat_intel = enrichment_data.get("threat_intelligence", {})
        ip_reputation = threat_intel.get("ip_reputation", {})
        
        suspicious_count = 0
        for ip, data in ip_reputation.items():
            if data.get("reputation", "Good") in ["Bad", "Suspicious"]:
                suspicious_count += 1
        
        return suspicious_count
    
    def _count_malicious_domains(self, enrichment_data: Dict[str, Any]) -> int:
        """Count malicious domains"""
        threat_intel = enrichment_data.get("threat_intelligence", {})
        domain_reputation = threat_intel.get("domain_reputation", {})
        
        malicious_count = 0
        for domain, data in domain_reputation.items():
            if data.get("reputation", "Good") in ["Bad", "Malicious"]:
                malicious_count += 1
        
        return malicious_count
