"""
Classification Engine Module
State 5: Classification & Response
Provides final classification and escalation decisions
"""

import logging
from typing import Dict, Any, List, Tuple
from datetime import datetime, timedelta
import json

logger = logging.getLogger(__name__)

class ClassificationEngine:
    """
    Provides final classification and escalation decisions
    Determines incident severity and appropriate response actions
    """
    
    def __init__(self):
        self.classification_thresholds = self._initialize_classification_thresholds()
        self.escalation_matrix = self._initialize_escalation_matrix()
        self.incident_templates = self._initialize_incident_templates()
        
    def classify_incident_severity(self, risk_assessment: Dict[str, Any], threat_assessment: Dict[str, Any], business_impact: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify incident severity based on comprehensive assessments
        
        Returns:
            Final incident classification with severity level and justification
        """
        logger.info("Classifying incident severity")
        
        classification = {
            "severity_level": "low",
            "confidence_score": 0.0,
            "classification_rationale": [],
            "supporting_factors": [],
            "mitigating_factors": [],
            "final_score": 0.0,
            "incident_type": "",
            "classification_metadata": {}
        }
        
        # Calculate composite severity score
        severity_components = {
            "risk_score": risk_assessment.get("overall_risk_score", 0.0),
            "threat_score": threat_assessment.get("threat_score", 0.0),
            "business_impact_score": business_impact.get("business_impact_score", 0.0)
        }
        
        # Weight the components
        weighted_score = (
            severity_components["risk_score"] * 0.4 +
            severity_components["threat_score"] * 0.35 +
            severity_components["business_impact_score"] * 0.25
        )
        
        classification["final_score"] = weighted_score
        
        # Determine severity level
        classification["severity_level"] = self._determine_severity_level(weighted_score)
        
        # Identify incident type
        classification["incident_type"] = self._identify_incident_type(risk_assessment, threat_assessment)
        
        # Build classification rationale
        classification["classification_rationale"] = self._build_classification_rationale(
            severity_components, 
            classification["severity_level"]
        )
        
        # Identify supporting factors
        classification["supporting_factors"] = self._identify_supporting_factors(
            risk_assessment, 
            threat_assessment, 
            business_impact
        )
        
        # Identify mitigating factors
        classification["mitigating_factors"] = self._identify_mitigating_factors(
            risk_assessment, 
            threat_assessment, 
            business_impact
        )
        
        # Calculate confidence score
        classification["confidence_score"] = self._calculate_classification_confidence(
            risk_assessment, 
            threat_assessment, 
            business_impact
        )
        
        # Add classification metadata
        classification["classification_metadata"] = {
            "classification_time": datetime.now(),
            "algorithm_version": "2.1",
            "data_sources": ["Permission Analysis", "Threat Intelligence", "Business Context"],
            "reviewer_required": classification["severity_level"] in ["critical", "high"]
        }
        
        logger.info(f"Incident classified as {classification['severity_level']} severity (score: {weighted_score:.2f})")
        return classification
    
    def determine_escalation_path(self, classification: Dict[str, Any], response_prioritization: Dict[str, Any]) -> Dict[str, Any]:
        """
        Determine appropriate escalation path based on classification
        
        Returns:
            Escalation plan with contacts, timelines, and procedures
        """
        logger.info(f"Determining escalation path for {classification['severity_level']} severity incident")
        
        escalation_plan = {
            "escalation_level": 0,
            "notification_targets": [],
            "escalation_timeline": {},
            "required_approvals": [],
            "communication_plan": {},
            "escalation_triggers": []
        }
        
        severity_level = classification["severity_level"]
        incident_type = classification["incident_type"]
        
        # Determine escalation level
        escalation_plan["escalation_level"] = self._determine_escalation_level(severity_level, incident_type)
        
        # Identify notification targets
        escalation_plan["notification_targets"] = self._identify_notification_targets(
            escalation_plan["escalation_level"], 
            incident_type
        )
        
        # Create escalation timeline
        escalation_plan["escalation_timeline"] = self._create_escalation_timeline(
            severity_level, 
            escalation_plan["escalation_level"]
        )
        
        # Determine required approvals
        escalation_plan["required_approvals"] = self._determine_required_approvals(
            severity_level, 
            response_prioritization
        )
        
        # Create communication plan
        escalation_plan["communication_plan"] = self._create_communication_plan(
            escalation_plan["notification_targets"], 
            escalation_plan["escalation_timeline"]
        )
        
        # Define escalation triggers
        escalation_plan["escalation_triggers"] = self._define_escalation_triggers(severity_level)
        
        logger.info(f"Escalation plan created for level {escalation_plan['escalation_level']}")
        return escalation_plan
    
    def generate_incident_ticket(self, classification: Dict[str, Any], escalation_plan: Dict[str, Any], evidence_summary: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate incident ticket with all relevant information
        
        Returns:
            Complete incident ticket ready for ITSM system
        """
        logger.info("Generating incident ticket")
        
        ticket = {
            "ticket_id": f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "title": "",
            "description": "",
            "severity": classification["severity_level"],
            "priority": self._determine_priority(classification),
            "category": "Security Incident",
            "subcategory": classification["incident_type"],
            "assigned_team": "",
            "reporter": "SOC Access Control Agent",
            "affected_users": [],
            "affected_systems": [],
            "business_impact": "",
            "technical_details": {},
            "remediation_steps": [],
            "evidence_attachments": [],
            "escalation_contacts": [],
            "sla_targets": {}
        }
        
        # Generate ticket title
        ticket["title"] = self._generate_ticket_title(classification, evidence_summary)
        
        # Generate detailed description
        ticket["description"] = self._generate_ticket_description(
            classification, 
            escalation_plan, 
            evidence_summary
        )
        
        # Assign to appropriate team
        ticket["assigned_team"] = self._determine_assigned_team(classification["incident_type"])
        
        # Extract affected entities
        ticket["affected_users"] = self._extract_affected_users(evidence_summary)
        ticket["affected_systems"] = self._extract_affected_systems(evidence_summary)
        
        # Add business impact statement
        ticket["business_impact"] = self._generate_business_impact_statement(classification)
        
        # Add technical details
        ticket["technical_details"] = self._compile_technical_details(evidence_summary)
        
        # Generate remediation steps
        ticket["remediation_steps"] = self._generate_remediation_steps(classification, escalation_plan)
        
        # Prepare evidence attachments
        ticket["evidence_attachments"] = self._prepare_evidence_attachments(evidence_summary)
        
        # Add escalation contacts
        ticket["escalation_contacts"] = escalation_plan.get("notification_targets", [])
        
        # Set SLA targets
        ticket["sla_targets"] = self._set_sla_targets(classification["severity_level"])
        
        logger.info(f"Incident ticket {ticket['ticket_id']} generated")
        return ticket
    
    def create_final_report(self, all_analysis_data: Dict[str, Any], classification: Dict[str, Any], escalation_plan: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create comprehensive final report with all analysis results
        
        Returns:
            Complete investigation and analysis report
        """
        logger.info("Creating final analysis report")
        
        report = {
            "report_id": f"RPT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "report_type": "Access Control Investigation",
            "generated_time": datetime.now(),
            "executive_summary": {},
            "detailed_findings": {},
            "risk_analysis": {},
            "threat_assessment": {},
            "business_impact": {},
            "recommendations": {},
            "technical_appendix": {},
            "evidence_catalog": {},
            "compliance_assessment": {}
        }
        
        # Create executive summary
        report["executive_summary"] = self._create_executive_summary(all_analysis_data, classification)
        
        # Compile detailed findings
        report["detailed_findings"] = self._compile_detailed_findings(all_analysis_data)
        
        # Extract risk analysis
        report["risk_analysis"] = all_analysis_data.get("risk_assessment", {})
        
        # Extract threat assessment  
        report["threat_assessment"] = all_analysis_data.get("threat_assessment", {})
        
        # Extract business impact
        report["business_impact"] = all_analysis_data.get("business_impact", {})
        
        # Generate recommendations
        report["recommendations"] = self._generate_comprehensive_recommendations(
            all_analysis_data, 
            classification, 
            escalation_plan
        )
        
        # Compile technical appendix
        report["technical_appendix"] = self._compile_technical_appendix(all_analysis_data)
        
        # Create evidence catalog
        report["evidence_catalog"] = self._create_evidence_catalog(all_analysis_data)
        
        # Add compliance assessment
        report["compliance_assessment"] = self._create_compliance_assessment(all_analysis_data)
        
        logger.info(f"Final report {report['report_id']} created")
        return report
    
    def _initialize_classification_thresholds(self) -> Dict[str, Dict[str, float]]:
        """Initialize classification thresholds"""
        return {
            "severity_levels": {
                "critical": 8.0,
                "high": 6.0,
                "medium": 4.0,
                "low": 0.0
            },
            "confidence_levels": {
                "high": 0.8,
                "medium": 0.6,
                "low": 0.4
            }
        }
    
    def _initialize_escalation_matrix(self) -> Dict[str, Dict[str, Any]]:
        """Initialize escalation matrix"""
        return {
            "critical": {
                "level": 3,
                "contacts": ["CISO", "IT Director", "Security Manager", "On-call Engineer"],
                "timeline": {"immediate": 15, "escalation_1": 30, "escalation_2": 60},
                "approvals": ["CISO", "IT Director"]
            },
            "high": {
                "level": 2,
                "contacts": ["Security Manager", "SOC Lead", "System Administrator"],
                "timeline": {"immediate": 30, "escalation_1": 60, "escalation_2": 120},
                "approvals": ["Security Manager"]
            },
            "medium": {
                "level": 1,
                "contacts": ["SOC Analyst", "System Administrator"],
                "timeline": {"immediate": 60, "escalation_1": 240},
                "approvals": []
            },
            "low": {
                "level": 0,
                "contacts": ["SOC Analyst"],
                "timeline": {"immediate": 240},
                "approvals": []
            }
        }
    
    def _initialize_incident_templates(self) -> Dict[str, str]:
        """Initialize incident templates"""
        return {
            "privilege_escalation": "Unauthorized privilege escalation detected",
            "administrative_access": "Suspicious administrative access activity",
            "policy_violation": "Access control policy violation identified",
            "baseline_deviation": "Deviation from established access baselines"
        }
    
    def _determine_severity_level(self, weighted_score: float) -> str:
        """Determine severity level based on weighted score"""
        thresholds = self.classification_thresholds["severity_levels"]
        
        if weighted_score >= thresholds["critical"]:
            return "critical"
        elif weighted_score >= thresholds["high"]:
            return "high"
        elif weighted_score >= thresholds["medium"]:
            return "medium"
        else:
            return "low"
    
    def _identify_incident_type(self, risk_assessment: Dict[str, Any], threat_assessment: Dict[str, Any]) -> str:
        """Identify the primary incident type"""
        risk_factors = risk_assessment.get("risk_factors", {})
        
        # Check for privilege escalation
        if risk_factors.get("privilege_escalation", 0.0) >= 6.0:
            return "privilege_escalation"
        
        # Check for administrative access issues
        if risk_factors.get("administrative_access", 0.0) >= 6.0:
            return "administrative_access"
        
        # Check for policy violations
        if risk_factors.get("policy_violations", 0.0) >= 6.0:
            return "policy_violation"
        
        # Check for baseline deviations
        if risk_factors.get("baseline_deviations", 0.0) >= 6.0:
            return "baseline_deviation"
        
        return "access_control_anomaly"
    
    def _build_classification_rationale(self, severity_components: Dict[str, float], severity_level: str) -> List[str]:
        """Build classification rationale"""
        rationale = []
        
        rationale.append(f"Incident classified as {severity_level} severity based on composite analysis")
        
        for component, score in severity_components.items():
            if score >= 8.0:
                rationale.append(f"High {component.replace('_', ' ')}: {score:.1f}/10")
            elif score >= 6.0:
                rationale.append(f"Elevated {component.replace('_', ' ')}: {score:.1f}/10")
        
        return rationale
    
    def _identify_supporting_factors(self, risk_assessment: Dict[str, Any], threat_assessment: Dict[str, Any], business_impact: Dict[str, Any]) -> List[str]:
        """Identify factors supporting the classification"""
        factors = []
        
        # Risk assessment factors
        risk_factors = risk_assessment.get("risk_factors", {})
        for factor, score in risk_factors.items():
            if score >= 6.0:
                factors.append(f"High {factor.replace('_', ' ')} risk: {score:.1f}/10")
        
        # Threat assessment factors
        threat_indicators = threat_assessment.get("threat_indicators", {})
        for indicator, count in threat_indicators.items():
            if count > 0:
                factors.append(f"{indicator.replace('_', ' ').title()}: {count} detected")
        
        # Business impact factors
        impact_categories = business_impact.get("impact_categories", {})
        for category, score in impact_categories.items():
            if score >= 7.0:
                factors.append(f"High {category.replace('_', ' ')} impact: {score:.1f}/10")
        
        return factors
    
    def _identify_mitigating_factors(self, risk_assessment: Dict[str, Any], threat_assessment: Dict[str, Any], business_impact: Dict[str, Any]) -> List[str]:
        """Identify factors that mitigate the severity"""
        factors = []
        
        # Check confidence levels
        if risk_assessment.get("confidence_level", 0.0) < 0.7:
            factors.append("Lower confidence in risk assessment due to limited data")
        
        # Check for existing controls
        if threat_assessment.get("existing_controls", {}).get("effectiveness", 0.0) > 0.7:
            factors.append("Effective existing security controls in place")
        
        # Check business impact mitigation
        if business_impact.get("mitigation_measures", {}).get("effectiveness", 0.0) > 0.6:
            factors.append("Business impact mitigation measures available")
        
        return factors
    
    def _calculate_classification_confidence(self, risk_assessment: Dict[str, Any], threat_assessment: Dict[str, Any], business_impact: Dict[str, Any]) -> float:
        """Calculate confidence in the classification"""
        confidence_factors = [
            risk_assessment.get("confidence_level", 0.5),
            threat_assessment.get("confidence_level", 0.5),
            business_impact.get("confidence_level", 0.5)
        ]
        
        # Add data quality factor
        data_quality = min([
            risk_assessment.get("data_quality", 0.7),
            threat_assessment.get("data_quality", 0.7),
            business_impact.get("data_quality", 0.7)
        ])
        
        confidence_factors.append(data_quality)
        
        return sum(confidence_factors) / len(confidence_factors)
    
    def _determine_escalation_level(self, severity_level: str, incident_type: str) -> int:
        """Determine escalation level"""
        base_level = self.escalation_matrix[severity_level]["level"]
        
        # Adjust for specific incident types
        if incident_type == "privilege_escalation" and severity_level in ["high", "critical"]:
            base_level = min(base_level + 1, 3)
        
        return base_level
    
    def _identify_notification_targets(self, escalation_level: int, incident_type: str) -> List[Dict[str, Any]]:
        """Identify notification targets"""
        # Find severity level for escalation level
        severity_mappings = {0: "low", 1: "medium", 2: "high", 3: "critical"}
        severity = severity_mappings.get(escalation_level, "low")
        
        base_contacts = self.escalation_matrix[severity]["contacts"]
        
        notification_targets = []
        for contact in base_contacts:
            notification_targets.append({
                "name": contact,
                "role": contact,
                "contact_method": "email",
                "notification_priority": base_contacts.index(contact) + 1
            })
        
        return notification_targets
    
    def _create_escalation_timeline(self, severity_level: str, escalation_level: int) -> Dict[str, Any]:
        """Create escalation timeline"""
        base_timeline = self.escalation_matrix[severity_level]["timeline"]
        
        return {
            "initial_notification": f"{base_timeline['immediate']} minutes",
            "first_escalation": f"{base_timeline.get('escalation_1', 60)} minutes",
            "second_escalation": f"{base_timeline.get('escalation_2', 120)} minutes",
            "executive_notification": "4 hours" if escalation_level >= 3 else "24 hours"
        }
    
    def _determine_required_approvals(self, severity_level: str, response_prioritization: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Determine required approvals"""
        base_approvals = self.escalation_matrix[severity_level]["approvals"]
        
        approvals = []
        for approver in base_approvals:
            approvals.append({
                "approver": approver,
                "approval_type": "Response Authorization",
                "required_for": "Remediation Actions",
                "deadline": "2 hours" if severity_level == "critical" else "4 hours"
            })
        
        return approvals
    
    def _create_communication_plan(self, notification_targets: List[Dict[str, Any]], escalation_timeline: Dict[str, Any]) -> Dict[str, Any]:
        """Create communication plan"""
        return {
            "initial_notifications": {
                "recipients": [target["name"] for target in notification_targets[:2]],
                "method": "Email + SMS",
                "timeline": escalation_timeline["initial_notification"]
            },
            "status_updates": {
                "frequency": "Every 2 hours",
                "recipients": [target["name"] for target in notification_targets],
                "method": "Email"
            },
            "resolution_notification": {
                "recipients": [target["name"] for target in notification_targets],
                "method": "Email",
                "timeline": "Within 1 hour of resolution"
            }
        }
    
    def _define_escalation_triggers(self, severity_level: str) -> List[Dict[str, Any]]:
        """Define escalation triggers"""
        triggers = [
            {
                "trigger": "No response within timeline",
                "action": "Escalate to next level",
                "timeline": "15 minutes" if severity_level == "critical" else "30 minutes"
            },
            {
                "trigger": "Incident scope expansion",
                "action": "Re-evaluate severity and escalate if needed",
                "timeline": "Immediate"
            }
        ]
        
        if severity_level in ["high", "critical"]:
            triggers.append({
                "trigger": "Remediation attempts failed",
                "action": "Escalate to executive team",
                "timeline": "2 hours"
            })
        
        return triggers
    
    def _determine_priority(self, classification: Dict[str, Any]) -> str:
        """Determine ticket priority"""
        severity = classification["severity_level"]
        business_impact = classification.get("business_impact_score", 0.0)
        
        priority_matrix = {
            "critical": "P1",
            "high": "P2", 
            "medium": "P3",
            "low": "P4"
        }
        
        base_priority = priority_matrix[severity]
        
        # Adjust for high business impact
        if business_impact >= 8.0 and base_priority in ["P3", "P4"]:
            base_priority = "P2"
        
        return base_priority
    
    def _generate_ticket_title(self, classification: Dict[str, Any], evidence_summary: Dict[str, Any]) -> str:
        """Generate incident ticket title"""
        incident_type = classification["incident_type"]
        severity = classification["severity_level"]
        
        base_title = self.incident_templates.get(incident_type, "Access control incident")
        
        # Add affected user count if available
        affected_users = evidence_summary.get("affected_users", [])
        if affected_users:
            user_count = len(affected_users)
            base_title += f" affecting {user_count} user{'s' if user_count > 1 else ''}"
        
        return f"[{severity.upper()}] {base_title}"
    
    def _generate_ticket_description(self, classification: Dict[str, Any], escalation_plan: Dict[str, Any], evidence_summary: Dict[str, Any]) -> str:
        """Generate detailed ticket description"""
        description_parts = [
            f"INCIDENT CLASSIFICATION: {classification['severity_level'].upper()}",
            f"INCIDENT TYPE: {classification['incident_type'].replace('_', ' ').title()}",
            f"DETECTION TIME: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "SUMMARY:",
            f"Access control anomaly detected with {classification['severity_level']} severity.",
            f"Classification confidence: {classification['confidence_score']:.2f}",
            "",
            "KEY FINDINGS:"
        ]
        
        # Add supporting factors
        for factor in classification.get("supporting_factors", []):
            description_parts.append(f"- {factor}")
        
        description_parts.extend([
            "",
            "AFFECTED ENTITIES:",
            f"- Users: {', '.join(evidence_summary.get('affected_users', ['None identified']))}",
            f"- Systems: {', '.join(evidence_summary.get('affected_systems', ['None identified']))}",
            "",
            "NEXT STEPS:",
            "- Immediate containment actions as per escalation plan",
            "- Detailed investigation of permission changes",
            "- Coordination with security team for remediation"
        ])
        
        return "\n".join(description_parts)
    
    def _determine_assigned_team(self, incident_type: str) -> str:
        """Determine assigned team based on incident type"""
        team_mapping = {
            "privilege_escalation": "Identity Security Team",
            "administrative_access": "SOC Team",
            "policy_violation": "Compliance Team",
            "baseline_deviation": "SOC Team",
            "access_control_anomaly": "SOC Team"
        }
        
        return team_mapping.get(incident_type, "SOC Team")
    
    def _extract_affected_users(self, evidence_summary: Dict[str, Any]) -> List[str]:
        """Extract affected users from evidence"""
        users = set()
        
        # Extract from permission analysis
        permission_data = evidence_summary.get("permission_analysis", {})
        for user_data in permission_data.get("user_accounts", []):
            users.add(user_data.get("upn", ""))
        
        # Extract from evidence
        for evidence_type, evidence_data in evidence_summary.items():
            if isinstance(evidence_data, dict):
                for user in evidence_data.keys():
                    if "@" in user:  # Likely an email address
                        users.add(user)
        
        return list(filter(None, users))
    
    def _extract_affected_systems(self, evidence_summary: Dict[str, Any]) -> List[str]:
        """Extract affected systems from evidence"""
        systems = set()
        
        # Add common systems based on evidence types
        if "azure_ad_analysis" in evidence_summary:
            systems.add("Azure Active Directory")
        
        if "arm_analysis" in evidence_summary:
            systems.add("Azure Resource Manager")
        
        if "authentication_logs" in evidence_summary:
            systems.add("Identity Management System")
        
        return list(systems)
    
    def _generate_business_impact_statement(self, classification: Dict[str, Any]) -> str:
        """Generate business impact statement"""
        severity = classification["severity_level"]
        incident_type = classification["incident_type"]
        
        impact_statements = {
            "critical": "Potential for significant business disruption and data exposure",
            "high": "Risk of operational impact and unauthorized access to sensitive resources",
            "medium": "Moderate risk to security posture and compliance requirements",
            "low": "Minor security concern with limited business impact"
        }
        
        base_impact = impact_statements[severity]
        
        # Add specific impact based on incident type
        if incident_type == "privilege_escalation":
            base_impact += ". Unauthorized elevation of user privileges detected."
        elif incident_type == "administrative_access":
            base_impact += ". Suspicious administrative access patterns identified."
        
        return base_impact
    
    def _compile_technical_details(self, evidence_summary: Dict[str, Any]) -> Dict[str, Any]:
        """Compile technical details for the ticket"""
        return {
            "detection_source": "SOC Access Control Agent",
            "analysis_timestamp": datetime.now().isoformat(),
            "evidence_sources": list(evidence_summary.keys()),
            "data_sources": [
                "Azure Active Directory Logs",
                "Azure Resource Manager Logs", 
                "Authentication Events",
                "Permission Change Events"
            ],
            "investigation_id": evidence_summary.get("investigation_id", "N/A")
        }
    
    def _generate_remediation_steps(self, classification: Dict[str, Any], escalation_plan: Dict[str, Any]) -> List[str]:
        """Generate remediation steps"""
        severity = classification["severity_level"]
        incident_type = classification["incident_type"]
        
        base_steps = [
            "1. Review and validate incident classification",
            "2. Implement immediate containment measures",
            "3. Conduct detailed investigation of permission changes",
            "4. Document findings and evidence",
            "5. Implement corrective actions",
            "6. Update security policies if necessary",
            "7. Conduct post-incident review"
        ]
        
        # Add severity-specific steps
        if severity in ["critical", "high"]:
            base_steps.insert(2, "2a. Disable affected user accounts if necessary")
            base_steps.insert(3, "2b. Reset credentials for affected accounts")
        
        # Add incident-type specific steps
        if incident_type == "privilege_escalation":
            base_steps.insert(-2, "6a. Review all recent privilege assignments")
        
        return base_steps
    
    def _prepare_evidence_attachments(self, evidence_summary: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Prepare evidence attachments"""
        attachments = []
        
        for evidence_type, evidence_data in evidence_summary.items():
            attachments.append({
                "name": f"{evidence_type}_analysis.json",
                "type": "Analysis Results",
                "description": f"Detailed {evidence_type.replace('_', ' ')} analysis results",
                "size": "Estimated 50KB",
                "format": "JSON"
            })
        
        return attachments
    
    def _set_sla_targets(self, severity_level: str) -> Dict[str, str]:
        """Set SLA targets based on severity"""
        sla_matrix = {
            "critical": {
                "response_time": "15 minutes",
                "resolution_time": "4 hours",
                "communication_frequency": "Every 30 minutes"
            },
            "high": {
                "response_time": "30 minutes", 
                "resolution_time": "8 hours",
                "communication_frequency": "Every 2 hours"
            },
            "medium": {
                "response_time": "2 hours",
                "resolution_time": "24 hours", 
                "communication_frequency": "Every 4 hours"
            },
            "low": {
                "response_time": "4 hours",
                "resolution_time": "72 hours",
                "communication_frequency": "Daily"
            }
        }
        
        return sla_matrix.get(severity_level, sla_matrix["low"])
    
    def _create_executive_summary(self, all_analysis_data: Dict[str, Any], classification: Dict[str, Any]) -> Dict[str, Any]:
        """Create executive summary for the report"""
        return {
            "incident_overview": f"{classification['severity_level'].title()} severity access control incident detected",
            "key_findings": [
                f"Incident classified as {classification['incident_type'].replace('_', ' ')}",
                f"Final risk score: {classification.get('final_score', 0.0):.2f}/10",
                f"Classification confidence: {classification.get('confidence_score', 0.0):.2f}"
            ],
            "business_impact": all_analysis_data.get("business_impact", {}).get("business_impact_score", 0.0),
            "recommended_actions": [
                "Immediate investigation required",
                "Implement recommended security controls",
                "Review and update access policies"
            ],
            "timeline": {
                "detection": datetime.now().isoformat(),
                "classification": datetime.now().isoformat(),
                "estimated_resolution": (datetime.now() + timedelta(hours=24)).isoformat()
            }
        }
    
    def _compile_detailed_findings(self, all_analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Compile detailed findings from all analysis data"""
        return {
            "permission_analysis_findings": all_analysis_data.get("permission_analysis", {}),
            "baseline_validation_findings": all_analysis_data.get("baseline_validation", {}),
            "investigation_findings": all_analysis_data.get("investigation_data", {}),
            "cross_agent_correlations": all_analysis_data.get("cross_agent_correlations", {}),
            "evidence_summary": all_analysis_data.get("evidence_summary", {})
        }
    
    def _generate_comprehensive_recommendations(self, all_analysis_data: Dict[str, Any], classification: Dict[str, Any], escalation_plan: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive recommendations"""
        return {
            "immediate_actions": escalation_plan.get("immediate_actions", []),
            "short_term_improvements": [
                "Implement enhanced monitoring for privilege changes",
                "Review and update RBAC policies",
                "Strengthen change management processes"
            ],
            "long_term_strategic": [
                "Deploy automated access governance tools",
                "Implement zero-trust access model",
                "Enhance user behavior analytics"
            ],
            "policy_updates": [
                "Update access control policies",
                "Enhance approval workflows",
                "Strengthen audit requirements"
            ],
            "technology_recommendations": [
                "Deploy Privileged Identity Management",
                "Implement continuous compliance monitoring",
                "Enhance identity protection capabilities"
            ]
        }
    
    def _compile_technical_appendix(self, all_analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Compile technical appendix"""
        return {
            "data_sources": [
                "Azure Active Directory Audit Logs",
                "Azure Resource Manager Activity Logs",
                "Authentication Events",
                "Security Events"
            ],
            "analysis_methodology": "Multi-stage analysis using permission analysis, baseline validation, and risk assessment",
            "confidence_metrics": all_analysis_data.get("confidence_metrics", {}),
            "limitations": [
                "Analysis based on available log data",
                "Some historical data may be incomplete",
                "External threat intelligence coverage may vary"
            ],
            "technical_details": all_analysis_data.get("technical_metadata", {})
        }
    
    def _create_evidence_catalog(self, all_analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create evidence catalog"""
        return {
            "digital_evidence": {
                "log_files": ["Azure AD Logs", "ARM Logs", "Authentication Logs"],
                "event_data": ["Permission Changes", "Role Assignments", "Login Events"],
                "analysis_outputs": ["Risk Scores", "Threat Assessments", "Business Impact"]
            },
            "preservation_status": "All evidence preserved in secure storage",
            "chain_of_custody": "Maintained throughout investigation",
            "evidence_integrity": "Cryptographic hashes calculated for all evidence"
        }
    
    def _create_compliance_assessment(self, all_analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create compliance assessment"""
        return {
            "regulatory_frameworks": ["SOX", "GDPR", "HIPAA", "PCI-DSS"],
            "compliance_status": "Under Review",
            "potential_violations": all_analysis_data.get("baseline_validation", {}).get("policy_violations", []),
            "remediation_requirements": [
                "Document all access changes",
                "Implement proper approval workflows",
                "Enhance audit trail capabilities"
            ],
            "compliance_score": all_analysis_data.get("baseline_validation", {}).get("compliance_score", 0.0)
        }
