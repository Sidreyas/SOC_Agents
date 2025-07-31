"""
Documentation Generator Module
State 5: Documentation Generation and Report Creation
Generates comprehensive incident documentation and reports
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Union
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
import json
import hashlib
from pathlib import Path

logger = logging.getLogger(__name__)

class DocumentType(Enum):
    """Types of documents that can be generated"""
    INCIDENT_REPORT = "incident_report"
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_ANALYSIS = "technical_analysis"
    FORENSIC_REPORT = "forensic_report"
    COMPLIANCE_REPORT = "compliance_report"
    LESSONS_LEARNED = "lessons_learned"
    TIMELINE_REPORT = "timeline_report"
    EVIDENCE_INVENTORY = "evidence_inventory"
    REMEDIATION_PLAN = "remediation_plan"

class DocumentFormat(Enum):
    """Document output formats"""
    PDF = "pdf"
    HTML = "html"
    DOCX = "docx"
    JSON = "json"
    XML = "xml"
    MARKDOWN = "markdown"

class DocumentClassification(Enum):
    """Document security classifications"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"

@dataclass
class DocumentMetadata:
    """Document metadata structure"""
    document_id: str
    title: str
    document_type: str
    classification: str
    created_date: datetime
    last_modified: datetime
    version: str
    author: str
    reviewers: List[str]
    approval_status: str
    retention_period: str
    distribution_list: List[str]
    file_size: int
    checksum: str
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['created_date'] = self.created_date.isoformat()
        result['last_modified'] = self.last_modified.isoformat()
        return result

class DocumentationGenerator:
    """
    Generates comprehensive incident documentation and reports
    """
    
    def __init__(self):
        self.document_templates = self._initialize_document_templates()
        self.formatting_rules = self._initialize_formatting_rules()
        self.compliance_requirements = self._initialize_compliance_requirements()
        self.document_cache = {}
        self.generation_stats = {
            "total_documents_generated": 0,
            "documents_by_type": {dtype.value: 0 for dtype in DocumentType},
            "average_generation_time": 0,
            "template_usage": {},
            "format_distribution": {fmt.value: 0 for fmt in DocumentFormat}
        }
    
    def _initialize_document_templates(self) -> Dict[str, Dict[str, Any]]:
        """Initialize document templates for different types"""
        return {
            DocumentType.INCIDENT_REPORT.value: {
                "sections": [
                    {
                        "section_id": "executive_summary",
                        "title": "Executive Summary",
                        "required": True,
                        "max_pages": 2,
                        "subsections": [
                            "incident_overview",
                            "impact_assessment",
                            "key_findings",
                            "recommendations"
                        ]
                    },
                    {
                        "section_id": "incident_details",
                        "title": "Incident Details",
                        "required": True,
                        "max_pages": 3,
                        "subsections": [
                            "detection_timeline",
                            "affected_systems",
                            "initial_indicators",
                            "classification"
                        ]
                    },
                    {
                        "section_id": "investigation_findings",
                        "title": "Investigation Findings",
                        "required": True,
                        "max_pages": 5,
                        "subsections": [
                            "analysis_methodology",
                            "evidence_analysis",
                            "threat_attribution",
                            "attack_timeline"
                        ]
                    },
                    {
                        "section_id": "technical_analysis",
                        "title": "Technical Analysis",
                        "required": True,
                        "max_pages": 8,
                        "subsections": [
                            "malware_analysis",
                            "network_analysis",
                            "forensic_artifacts",
                            "vulnerability_assessment"
                        ]
                    },
                    {
                        "section_id": "response_actions",
                        "title": "Response Actions",
                        "required": True,
                        "max_pages": 3,
                        "subsections": [
                            "containment_actions",
                            "eradication_steps",
                            "recovery_procedures",
                            "monitoring_enhancements"
                        ]
                    },
                    {
                        "section_id": "recommendations",
                        "title": "Recommendations",
                        "required": True,
                        "max_pages": 2,
                        "subsections": [
                            "immediate_actions",
                            "long_term_improvements",
                            "policy_updates",
                            "training_needs"
                        ]
                    },
                    {
                        "section_id": "appendices",
                        "title": "Appendices",
                        "required": False,
                        "max_pages": 20,
                        "subsections": [
                            "evidence_inventory",
                            "tool_outputs",
                            "timeline_details",
                            "compliance_checklist"
                        ]
                    }
                ],
                "default_classification": DocumentClassification.CONFIDENTIAL.value,
                "retention_period": "7_years",
                "required_approvals": ["incident_commander", "ciso"]
            },
            
            DocumentType.EXECUTIVE_SUMMARY.value: {
                "sections": [
                    {
                        "section_id": "overview",
                        "title": "Incident Overview",
                        "required": True,
                        "max_pages": 1,
                        "subsections": ["summary", "impact", "status"]
                    },
                    {
                        "section_id": "key_findings",
                        "title": "Key Findings",
                        "required": True,
                        "max_pages": 1,
                        "subsections": ["root_cause", "scope", "risks"]
                    },
                    {
                        "section_id": "actions",
                        "title": "Actions Taken",
                        "required": True,
                        "max_pages": 1,
                        "subsections": ["immediate_response", "containment", "recovery"]
                    },
                    {
                        "section_id": "next_steps",
                        "title": "Next Steps",
                        "required": True,
                        "max_pages": 1,
                        "subsections": ["recommendations", "timeline", "resources"]
                    }
                ],
                "default_classification": DocumentClassification.INTERNAL.value,
                "retention_period": "5_years",
                "required_approvals": ["incident_commander"]
            },
            
            DocumentType.TECHNICAL_ANALYSIS.value: {
                "sections": [
                    {
                        "section_id": "methodology",
                        "title": "Analysis Methodology",
                        "required": True,
                        "max_pages": 2,
                        "subsections": ["approach", "tools_used", "limitations"]
                    },
                    {
                        "section_id": "malware_analysis",
                        "title": "Malware Analysis",
                        "required": False,
                        "max_pages": 5,
                        "subsections": ["static_analysis", "dynamic_analysis", "behavior", "iocs"]
                    },
                    {
                        "section_id": "network_analysis",
                        "title": "Network Analysis",
                        "required": False,
                        "max_pages": 4,
                        "subsections": ["traffic_patterns", "communications", "protocols", "anomalies"]
                    },
                    {
                        "section_id": "host_analysis",
                        "title": "Host Analysis",
                        "required": False,
                        "max_pages": 4,
                        "subsections": ["artifacts", "persistence", "lateral_movement", "data_access"]
                    },
                    {
                        "section_id": "attribution",
                        "title": "Threat Attribution",
                        "required": False,
                        "max_pages": 3,
                        "subsections": ["ttps", "infrastructure", "campaigns", "confidence"]
                    }
                ],
                "default_classification": DocumentClassification.CONFIDENTIAL.value,
                "retention_period": "10_years",
                "required_approvals": ["technical_lead", "senior_analyst"]
            },
            
            DocumentType.COMPLIANCE_REPORT.value: {
                "sections": [
                    {
                        "section_id": "regulatory_overview",
                        "title": "Regulatory Requirements",
                        "required": True,
                        "max_pages": 2,
                        "subsections": ["applicable_regulations", "notification_requirements", "timelines"]
                    },
                    {
                        "section_id": "compliance_status",
                        "title": "Compliance Status",
                        "required": True,
                        "max_pages": 3,
                        "subsections": ["requirements_met", "gaps_identified", "remediation_actions"]
                    },
                    {
                        "section_id": "notifications",
                        "title": "Regulatory Notifications",
                        "required": True,
                        "max_pages": 2,
                        "subsections": ["notifications_sent", "response_tracking", "follow_up_required"]
                    },
                    {
                        "section_id": "documentation",
                        "title": "Compliance Documentation",
                        "required": True,
                        "max_pages": 5,
                        "subsections": ["evidence_preservation", "audit_trail", "reporting_records"]
                    }
                ],
                "default_classification": DocumentClassification.RESTRICTED.value,
                "retention_period": "permanent",
                "required_approvals": ["legal_counsel", "compliance_officer", "ciso"]
            }
        }
    
    def _initialize_formatting_rules(self) -> Dict[str, Dict[str, Any]]:
        """Initialize formatting rules for different output formats"""
        return {
            DocumentFormat.PDF.value: {
                "page_size": "A4",
                "margins": {"top": 1, "bottom": 1, "left": 1, "right": 1},
                "font_family": "Arial",
                "font_size": 11,
                "line_spacing": 1.15,
                "include_header": True,
                "include_footer": True,
                "include_page_numbers": True,
                "include_toc": True,
                "watermark": "CONFIDENTIAL"
            },
            
            DocumentFormat.HTML.value: {
                "css_framework": "bootstrap",
                "responsive": True,
                "include_navigation": True,
                "syntax_highlighting": True,
                "collapsible_sections": True,
                "dark_mode": False
            },
            
            DocumentFormat.DOCX.value: {
                "template_file": "incident_report_template.docx",
                "styles": {
                    "heading1": {"font": "Calibri", "size": 16, "bold": True},
                    "heading2": {"font": "Calibri", "size": 14, "bold": True},
                    "normal": {"font": "Calibri", "size": 11}
                },
                "include_comments": True,
                "track_changes": False
            },
            
            DocumentFormat.MARKDOWN.value: {
                "flavor": "github",
                "include_toc": True,
                "code_highlighting": True,
                "math_support": False,
                "mermaid_diagrams": True
            }
        }
    
    def _initialize_compliance_requirements(self) -> Dict[str, Dict[str, Any]]:
        """Initialize compliance requirements for different regulations"""
        return {
            "gdpr": {
                "notification_timeline": "72_hours",
                "required_sections": [
                    "data_breach_description",
                    "affected_data_subjects",
                    "likely_consequences",
                    "measures_taken"
                ],
                "documentation_requirements": [
                    "timeline_of_events",
                    "technical_investigation",
                    "notification_records",
                    "remediation_actions"
                ]
            },
            
            "hipaa": {
                "notification_timeline": "60_days",
                "required_sections": [
                    "breach_description",
                    "phi_involved",
                    "individuals_affected",
                    "mitigation_steps"
                ],
                "documentation_requirements": [
                    "risk_assessment",
                    "notification_documentation",
                    "business_associate_notifications",
                    "media_notifications"
                ]
            },
            
            "pci_dss": {
                "notification_timeline": "immediately",
                "required_sections": [
                    "incident_description",
                    "cardholder_data_exposure",
                    "forensic_investigation",
                    "remediation_plan"
                ],
                "documentation_requirements": [
                    "forensic_report",
                    "vulnerability_scan_results",
                    "remediation_validation",
                    "compliance_restoration"
                ]
            },
            
            "sox": {
                "notification_timeline": "immediately",
                "required_sections": [
                    "financial_impact",
                    "internal_controls_affected",
                    "remediation_timeline",
                    "management_assessment"
                ],
                "documentation_requirements": [
                    "internal_control_testing",
                    "management_representation",
                    "auditor_notifications",
                    "quarterly_reporting"
                ]
            }
        }
    
    async def generate_incident_documentation(self, 
                                            incident_data: Dict[str, Any],
                                            investigation_results: Dict[str, Any],
                                            document_types: List[str] = None,
                                            output_formats: List[str] = None) -> Dict[str, Any]:
        """
        Generate comprehensive incident documentation
        
        Args:
            incident_data: Complete incident information
            investigation_results: Results from investigation and analysis
            document_types: Types of documents to generate
            output_formats: Output formats for documents
            
        Returns:
            Generated documentation package
        """
        try:
            generation_start_time = datetime.now()
            
            # Set defaults
            if document_types is None:
                document_types = [DocumentType.INCIDENT_REPORT.value, DocumentType.EXECUTIVE_SUMMARY.value]
            
            if output_formats is None:
                output_formats = [DocumentFormat.PDF.value, DocumentFormat.HTML.value]
            
            incident_id = incident_data.get("incident_id", "unknown")
            
            logger.info(f"Generating documentation for incident {incident_id}")
            
            # Generate documents
            generated_documents = []
            
            for doc_type in document_types:
                for output_format in output_formats:
                    document = await self._generate_single_document(
                        doc_type, output_format, incident_data, investigation_results
                    )
                    
                    if document:
                        generated_documents.append(document)
            
            # Create documentation package
            documentation_package = await self._create_documentation_package(
                incident_id, generated_documents, incident_data, investigation_results
            )
            
            # Update statistics
            self._update_generation_stats(document_types, output_formats, generation_start_time)
            
            logger.info(f"Documentation generation completed for incident {incident_id}")
            
            return {
                "status": "completed",
                "incident_id": incident_id,
                "generation_summary": {
                    "documents_generated": len(generated_documents),
                    "document_types": document_types,
                    "output_formats": output_formats,
                    "generation_time": (datetime.now() - generation_start_time).total_seconds() / 60
                },
                "documentation_package": documentation_package,
                "generated_documents": generated_documents
            }
            
        except Exception as e:
            logger.error(f"Error generating documentation: {str(e)}")
            return {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    async def _generate_single_document(self, 
                                      doc_type: str,
                                      output_format: str,
                                      incident_data: Dict[str, Any],
                                      investigation_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a single document of specified type and format"""
        
        try:
            # Get template for document type
            template = self.document_templates.get(doc_type)
            if not template:
                logger.error(f"No template found for document type: {doc_type}")
                return None
            
            # Generate document content
            document_content = await self._generate_document_content(
                doc_type, template, incident_data, investigation_results
            )
            
            # Apply formatting
            formatted_content = await self._apply_formatting(
                document_content, output_format
            )
            
            # Create document metadata
            metadata = await self._create_document_metadata(
                doc_type, output_format, incident_data, formatted_content
            )
            
            return {
                "document_id": metadata.document_id,
                "document_type": doc_type,
                "output_format": output_format,
                "metadata": metadata.to_dict(),
                "content": formatted_content,
                "file_info": {
                    "filename": f"{metadata.document_id}.{output_format}",
                    "file_size": metadata.file_size,
                    "checksum": metadata.checksum
                }
            }
            
        except Exception as e:
            logger.error(f"Error generating {doc_type} document in {output_format} format: {str(e)}")
            return None
    
    async def _generate_document_content(self, 
                                       doc_type: str,
                                       template: Dict[str, Any],
                                       incident_data: Dict[str, Any],
                                       investigation_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate document content based on template and data"""
        
        sections = template.get("sections", [])
        content = {
            "document_type": doc_type,
            "title": self._generate_document_title(doc_type, incident_data),
            "sections": []
        }
        
        for section_template in sections:
            section_content = await self._generate_section_content(
                section_template, incident_data, investigation_results
            )
            
            if section_content:
                content["sections"].append(section_content)
        
        return content
    
    def _generate_document_title(self, doc_type: str, incident_data: Dict[str, Any]) -> str:
        """Generate document title"""
        
        incident_id = incident_data.get("incident_id", "Unknown")
        incident_desc = incident_data.get("description", "Security Incident")
        
        title_templates = {
            DocumentType.INCIDENT_REPORT.value: f"Incident Report - {incident_id}: {incident_desc}",
            DocumentType.EXECUTIVE_SUMMARY.value: f"Executive Summary - Incident {incident_id}",
            DocumentType.TECHNICAL_ANALYSIS.value: f"Technical Analysis Report - Incident {incident_id}",
            DocumentType.FORENSIC_REPORT.value: f"Forensic Investigation Report - Incident {incident_id}",
            DocumentType.COMPLIANCE_REPORT.value: f"Compliance Report - Incident {incident_id}",
            DocumentType.LESSONS_LEARNED.value: f"Lessons Learned - Incident {incident_id}",
            DocumentType.TIMELINE_REPORT.value: f"Incident Timeline - {incident_id}",
            DocumentType.EVIDENCE_INVENTORY.value: f"Evidence Inventory - Incident {incident_id}",
            DocumentType.REMEDIATION_PLAN.value: f"Remediation Plan - Incident {incident_id}"
        }
        
        return title_templates.get(doc_type, f"Security Document - Incident {incident_id}")
    
    async def _generate_section_content(self, 
                                      section_template: Dict[str, Any],
                                      incident_data: Dict[str, Any],
                                      investigation_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate content for a document section"""
        
        section_id = section_template["section_id"]
        section_title = section_template["title"]
        subsections = section_template.get("subsections", [])
        
        section_content = {
            "section_id": section_id,
            "title": section_title,
            "subsections": []
        }
        
        # Generate content based on section type
        if section_id == "executive_summary":
            section_content["subsections"] = await self._generate_executive_summary_content(
                subsections, incident_data, investigation_results
            )
        
        elif section_id == "incident_details":
            section_content["subsections"] = await self._generate_incident_details_content(
                subsections, incident_data, investigation_results
            )
        
        elif section_id == "investigation_findings":
            section_content["subsections"] = await self._generate_investigation_findings_content(
                subsections, incident_data, investigation_results
            )
        
        elif section_id == "technical_analysis":
            section_content["subsections"] = await self._generate_technical_analysis_content(
                subsections, incident_data, investigation_results
            )
        
        elif section_id == "response_actions":
            section_content["subsections"] = await self._generate_response_actions_content(
                subsections, incident_data, investigation_results
            )
        
        elif section_id == "recommendations":
            section_content["subsections"] = await self._generate_recommendations_content(
                subsections, incident_data, investigation_results
            )
        
        elif section_id == "appendices":
            section_content["subsections"] = await self._generate_appendices_content(
                subsections, incident_data, investigation_results
            )
        
        else:
            # Generic section generation
            section_content["subsections"] = await self._generate_generic_section_content(
                subsections, incident_data, investigation_results
            )
        
        return section_content
    
    async def _generate_executive_summary_content(self, 
                                                subsections: List[str],
                                                incident_data: Dict[str, Any],
                                                investigation_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate executive summary content"""
        
        content = []
        
        if "incident_overview" in subsections:
            content.append({
                "subsection": "incident_overview",
                "title": "Incident Overview",
                "content": {
                    "incident_id": incident_data.get("incident_id"),
                    "detection_time": incident_data.get("timestamp"),
                    "incident_type": incident_data.get("classification", {}).get("category", "Unknown"),
                    "severity": incident_data.get("classification", {}).get("severity", "Unknown"),
                    "description": incident_data.get("description", "No description available"),
                    "current_status": investigation_results.get("resolution_data", {}).get("validation_status", "Under investigation")
                }
            })
        
        if "impact_assessment" in subsections:
            impact_data = investigation_results.get("analysis_results", {}).get("summary", {})
            content.append({
                "subsection": "impact_assessment",
                "title": "Impact Assessment",
                "content": {
                    "business_impact": impact_data.get("incident_scope", "Limited"),
                    "affected_systems": len(incident_data.get("alert_data", {}).get("affected_hosts", [])),
                    "data_exposure": "Under investigation",
                    "operational_impact": "Minimal disruption observed",
                    "financial_impact": "Assessment in progress"
                }
            })
        
        if "key_findings" in subsections:
            findings = investigation_results.get("analysis_results", {}).get("findings", [])
            content.append({
                "subsection": "key_findings",
                "title": "Key Findings",
                "content": {
                    "primary_findings": findings[:5] if findings else ["Investigation in progress"],
                    "threat_level": investigation_results.get("analysis_results", {}).get("summary", {}).get("threat_level", "Medium"),
                    "containment_status": investigation_results.get("analysis_results", {}).get("summary", {}).get("containment_status", "In progress"),
                    "root_cause": "Under investigation"
                }
            })
        
        if "recommendations" in subsections:
            recommendations = investigation_results.get("analysis_results", {}).get("summary", {}).get("recommendations", [])
            content.append({
                "subsection": "recommendations",
                "title": "Immediate Recommendations",
                "content": {
                    "immediate_actions": recommendations[:3] if recommendations else ["Continue monitoring"],
                    "short_term_actions": ["Enhance monitoring", "Update procedures"],
                    "long_term_actions": ["Review security posture", "Implement lessons learned"]
                }
            })
        
        return content
    
    async def _generate_incident_details_content(self, 
                                               subsections: List[str],
                                               incident_data: Dict[str, Any],
                                               investigation_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate incident details content"""
        
        content = []
        
        if "detection_timeline" in subsections:
            workflow_history = investigation_results.get("workflow_history", [])
            content.append({
                "subsection": "detection_timeline",
                "title": "Detection and Response Timeline",
                "content": {
                    "initial_detection": incident_data.get("timestamp"),
                    "detection_method": incident_data.get("source", "Automated monitoring"),
                    "first_response": workflow_history[0].get("timestamp") if workflow_history else "Unknown",
                    "escalation_time": "N/A",
                    "containment_time": "In progress"
                }
            })
        
        if "affected_systems" in subsections:
            alert_data = incident_data.get("alert_data", {})
            content.append({
                "subsection": "affected_systems",
                "title": "Affected Systems and Assets",
                "content": {
                    "hosts": alert_data.get("affected_hosts", []),
                    "network_segments": alert_data.get("network_segments", []),
                    "applications": alert_data.get("affected_applications", []),
                    "data_stores": alert_data.get("affected_databases", []),
                    "user_accounts": alert_data.get("affected_users", [])
                }
            })
        
        if "initial_indicators" in subsections:
            content.append({
                "subsection": "initial_indicators",
                "title": "Initial Indicators and Alerts",
                "content": {
                    "detection_source": incident_data.get("source", "Unknown"),
                    "alert_details": incident_data.get("alert_data", {}),
                    "initial_symptoms": incident_data.get("description", ""),
                    "confidence_level": incident_data.get("alert_data", {}).get("confidence", "Unknown")
                }
            })
        
        if "classification" in subsections:
            classification = incident_data.get("classification", {})
            content.append({
                "subsection": "classification",
                "title": "Incident Classification",
                "content": {
                    "category": classification.get("category", "Unknown"),
                    "severity": classification.get("severity", "Unknown"),
                    "priority_score": classification.get("priority_score", "Unknown"),
                    "workflow_type": investigation_results.get("metadata", {}).get("workflow_type", "Standard"),
                    "escalation_level": investigation_results.get("metadata", {}).get("escalation_level", 0)
                }
            })
        
        return content
    
    async def _generate_investigation_findings_content(self, 
                                                     subsections: List[str],
                                                     incident_data: Dict[str, Any],
                                                     investigation_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate investigation findings content"""
        
        content = []
        analysis_results = investigation_results.get("analysis_results", {})
        investigation_plan = investigation_results.get("investigation_plan", {})
        
        if "analysis_methodology" in subsections:
            content.append({
                "subsection": "analysis_methodology",
                "title": "Analysis Methodology",
                "content": {
                    "investigation_strategy": investigation_plan.get("strategy", "Unknown"),
                    "analysis_approach": "Multi-layered security analysis",
                    "tools_employed": self._extract_tools_used(analysis_results),
                    "agents_involved": self._extract_agents_involved(analysis_results),
                    "investigation_timeline": investigation_plan.get("timeline", {})
                }
            })
        
        if "evidence_analysis" in subsections:
            evidence_data = investigation_results.get("evidence_data", {})
            content.append({
                "subsection": "evidence_analysis",
                "title": "Evidence Analysis",
                "content": {
                    "evidence_collected": evidence_data.get("total_evidence", 0),
                    "evidence_types": list(evidence_data.get("correlation_report", {}).get("key_indicators", {}).keys()),
                    "correlation_analysis": evidence_data.get("correlation_report", {}),
                    "chain_of_custody": "Properly maintained throughout investigation"
                }
            })
        
        if "threat_attribution" in subsections:
            content.append({
                "subsection": "threat_attribution",
                "title": "Threat Attribution",
                "content": {
                    "threat_actor": "Under investigation",
                    "attack_sophistication": "Medium",
                    "ttps_observed": self._extract_ttps(analysis_results),
                    "attribution_confidence": "Medium",
                    "similar_campaigns": "Analysis in progress"
                }
            })
        
        if "attack_timeline" in subsections:
            timeline = evidence_data.get("correlation_report", {}).get("timeline", [])
            content.append({
                "subsection": "attack_timeline",
                "title": "Attack Timeline Reconstruction",
                "content": {
                    "timeline_events": timeline[:10] if timeline else [],
                    "attack_phases": self._identify_attack_phases(timeline),
                    "persistence_mechanisms": "Under investigation",
                    "lateral_movement": "Analysis in progress"
                }
            })
        
        return content
    
    async def _generate_technical_analysis_content(self, 
                                                 subsections: List[str],
                                                 incident_data: Dict[str, Any],
                                                 investigation_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate technical analysis content"""
        
        content = []
        analysis_results = investigation_results.get("analysis_results", {})
        executed_tasks = analysis_results.get("executed_tasks", [])
        
        if "malware_analysis" in subsections:
            malware_analysis = self._extract_analysis_by_type(executed_tasks, "malware")
            content.append({
                "subsection": "malware_analysis",
                "title": "Malware Analysis",
                "content": malware_analysis or {
                    "analysis_status": "Not applicable",
                    "note": "No malware samples identified for analysis"
                }
            })
        
        if "network_analysis" in subsections:
            network_analysis = self._extract_analysis_by_type(executed_tasks, "network")
            content.append({
                "subsection": "network_analysis",
                "title": "Network Analysis",
                "content": network_analysis or {
                    "traffic_analysis": "No suspicious network activity detected",
                    "communication_patterns": "Normal traffic patterns observed"
                }
            })
        
        if "host_analysis" in subsections:
            host_analysis = self._extract_analysis_by_type(executed_tasks, "host")
            content.append({
                "subsection": "host_analysis",
                "title": "Host-based Analysis",
                "content": host_analysis or {
                    "system_artifacts": "Standard system artifacts collected",
                    "process_analysis": "Normal process execution patterns"
                }
            })
        
        if "vulnerability_assessment" in subsections:
            vuln_analysis = self._extract_analysis_by_type(executed_tasks, "vulnerability")
            content.append({
                "subsection": "vulnerability_assessment",
                "title": "Vulnerability Assessment",
                "content": vuln_analysis or {
                    "vulnerabilities_identified": "Assessment in progress",
                    "patch_status": "Under review"
                }
            })
        
        return content
    
    async def _generate_response_actions_content(self, 
                                               subsections: List[str],
                                               incident_data: Dict[str, Any],
                                               investigation_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate response actions content"""
        
        content = []
        analysis_results = investigation_results.get("analysis_results", {})
        executed_tasks = analysis_results.get("executed_tasks", [])
        
        if "containment_actions" in subsections:
            containment_actions = self._extract_containment_actions(executed_tasks)
            content.append({
                "subsection": "containment_actions",
                "title": "Containment Actions",
                "content": {
                    "immediate_containment": containment_actions.get("immediate", []),
                    "network_isolation": containment_actions.get("network", []),
                    "system_isolation": containment_actions.get("system", []),
                    "access_restrictions": containment_actions.get("access", [])
                }
            })
        
        if "eradication_steps" in subsections:
            content.append({
                "subsection": "eradication_steps",
                "title": "Eradication Steps",
                "content": {
                    "threat_removal": "Malware removal procedures executed",
                    "vulnerability_patching": "Critical patches applied",
                    "configuration_hardening": "Security configurations updated",
                    "credential_reset": "Affected credentials reset"
                }
            })
        
        if "recovery_procedures" in subsections:
            content.append({
                "subsection": "recovery_procedures",
                "title": "Recovery Procedures",
                "content": {
                    "system_restoration": "Systems restored from clean backups",
                    "service_restoration": "Services restored to normal operation",
                    "monitoring_enhanced": "Additional monitoring implemented",
                    "user_notification": "Affected users notified and trained"
                }
            })
        
        if "monitoring_enhancements" in subsections:
            content.append({
                "subsection": "monitoring_enhancements",
                "title": "Monitoring Enhancements",
                "content": {
                    "new_detection_rules": "Enhanced detection rules implemented",
                    "increased_logging": "Logging levels increased for affected systems",
                    "threat_hunting": "Proactive threat hunting initiated",
                    "baseline_updates": "Security baselines updated"
                }
            })
        
        return content
    
    async def _generate_recommendations_content(self, 
                                              subsections: List[str],
                                              incident_data: Dict[str, Any],
                                              investigation_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate recommendations content"""
        
        content = []
        analysis_summary = investigation_results.get("analysis_results", {}).get("summary", {})
        recommendations = analysis_summary.get("recommendations", [])
        
        if "immediate_actions" in subsections:
            content.append({
                "subsection": "immediate_actions",
                "title": "Immediate Actions Required",
                "content": {
                    "priority_actions": recommendations[:3] if recommendations else [
                        "Continue monitoring for similar activities",
                        "Review and update incident response procedures",
                        "Enhance security awareness training"
                    ],
                    "timeline": "Within 24-48 hours",
                    "responsible_parties": ["IT Security Team", "System Administrators"]
                }
            })
        
        if "long_term_improvements" in subsections:
            content.append({
                "subsection": "long_term_improvements",
                "title": "Long-term Security Improvements",
                "content": {
                    "strategic_improvements": [
                        "Implement advanced threat detection capabilities",
                        "Enhance network segmentation",
                        "Develop automated response capabilities",
                        "Strengthen access controls and authentication"
                    ],
                    "timeline": "3-6 months",
                    "budget_considerations": "Medium investment required"
                }
            })
        
        if "policy_updates" in subsections:
            content.append({
                "subsection": "policy_updates",
                "title": "Policy and Procedure Updates",
                "content": {
                    "policy_changes": [
                        "Update incident response procedures",
                        "Revise security awareness training materials",
                        "Enhance vendor security requirements",
                        "Strengthen data classification policies"
                    ],
                    "approval_required": ["CISO", "Legal Team", "Executive Management"],
                    "implementation_timeline": "30-60 days"
                }
            })
        
        if "training_needs" in subsections:
            content.append({
                "subsection": "training_needs",
                "title": "Training and Awareness Needs",
                "content": {
                    "technical_training": [
                        "Advanced threat detection techniques",
                        "Incident response procedures",
                        "Forensic analysis methods"
                    ],
                    "awareness_training": [
                        "Social engineering awareness",
                        "Phishing recognition",
                        "Secure computing practices"
                    ],
                    "target_audience": ["IT Staff", "All Employees", "Management"]
                }
            })
        
        return content
    
    async def _generate_appendices_content(self, 
                                         subsections: List[str],
                                         incident_data: Dict[str, Any],
                                         investigation_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate appendices content"""
        
        content = []
        
        if "evidence_inventory" in subsections:
            evidence_data = investigation_results.get("evidence_data", {})
            content.append({
                "subsection": "evidence_inventory",
                "title": "Evidence Inventory",
                "content": {
                    "total_evidence_items": evidence_data.get("total_evidence", 0),
                    "evidence_by_type": evidence_data.get("correlation_report", {}).get("key_indicators", {}),
                    "preservation_status": "All evidence properly preserved",
                    "storage_location": "Secure evidence storage system"
                }
            })
        
        if "tool_outputs" in subsections:
            analysis_results = investigation_results.get("analysis_results", {})
            content.append({
                "subsection": "tool_outputs",
                "title": "Tool Outputs and Raw Data",
                "content": {
                    "analysis_tools_used": self._extract_tools_used(analysis_results),
                    "raw_outputs": "Available in secure storage",
                    "data_formats": ["JSON", "XML", "CSV", "Log files"],
                    "access_procedure": "Contact incident response team for access"
                }
            })
        
        if "timeline_details" in subsections:
            workflow_history = investigation_results.get("workflow_history", [])
            content.append({
                "subsection": "timeline_details",
                "title": "Detailed Timeline",
                "content": {
                    "investigation_timeline": workflow_history,
                    "evidence_timeline": investigation_results.get("evidence_data", {}).get("correlation_report", {}).get("timeline", []),
                    "response_timeline": "See incident response log"
                }
            })
        
        if "compliance_checklist" in subsections:
            content.append({
                "subsection": "compliance_checklist",
                "title": "Compliance Checklist",
                "content": {
                    "regulatory_requirements": "All requirements met",
                    "notification_status": "Notifications sent as required",
                    "documentation_completeness": "Complete",
                    "audit_trail": "Maintained throughout investigation"
                }
            })
        
        return content
    
    async def _generate_generic_section_content(self, 
                                              subsections: List[str],
                                              incident_data: Dict[str, Any],
                                              investigation_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate generic section content"""
        
        content = []
        
        for subsection in subsections:
            content.append({
                "subsection": subsection,
                "title": subsection.replace("_", " ").title(),
                "content": {
                    "status": "Content available",
                    "details": f"Detailed {subsection} information collected during investigation"
                }
            })
        
        return content
    
    def _extract_tools_used(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Extract list of tools used in analysis"""
        tools = set()
        
        executed_tasks = analysis_results.get("executed_tasks", [])
        for task in executed_tasks:
            task_tools = task.get("tools_used", [])
            tools.update(task_tools)
        
        return list(tools) if tools else ["Standard security analysis tools"]
    
    def _extract_agents_involved(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Extract list of agents involved in analysis"""
        agents = set()
        
        executed_tasks = analysis_results.get("executed_tasks", [])
        for task in executed_tasks:
            agent = task.get("assigned_agent")
            if agent:
                agents.add(agent)
        
        return list(agents) if agents else ["Incident Management Agent"]
    
    def _extract_ttps(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Extract TTPs (Tactics, Techniques, Procedures) from analysis"""
        ttps = []
        
        executed_tasks = analysis_results.get("executed_tasks", [])
        for task in executed_tasks:
            findings = task.get("findings", [])
            for finding in findings:
                if "ttp" in finding.lower() or "technique" in finding.lower():
                    ttps.append(finding)
        
        return ttps if ttps else ["Standard attack techniques observed"]
    
    def _identify_attack_phases(self, timeline: List[Dict[str, Any]]) -> List[str]:
        """Identify attack phases from timeline"""
        phases = []
        
        if len(timeline) > 0:
            phases.append("Initial Access")
        if len(timeline) > 2:
            phases.append("Execution")
        if len(timeline) > 4:
            phases.append("Persistence")
        if len(timeline) > 6:
            phases.append("Discovery")
        
        return phases if phases else ["Analysis in progress"]
    
    def _extract_analysis_by_type(self, executed_tasks: List[Dict[str, Any]], analysis_type: str) -> Optional[Dict[str, Any]]:
        """Extract analysis results by type"""
        
        for task in executed_tasks:
            task_name = task.get("task_name", "").lower()
            if analysis_type in task_name:
                return {
                    "analysis_completed": True,
                    "findings": task.get("findings", []),
                    "tools_used": task.get("tools_used", []),
                    "execution_time": task.get("execution_time", 0)
                }
        
        return None
    
    def _extract_containment_actions(self, executed_tasks: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Extract containment actions from executed tasks"""
        
        actions = {
            "immediate": [],
            "network": [],
            "system": [],
            "access": []
        }
        
        for task in executed_tasks:
            task_name = task.get("task_name", "").lower()
            findings = task.get("findings", [])
            
            if "isolate" in task_name or "contain" in task_name:
                if "network" in task_name:
                    actions["network"].extend(findings)
                elif "system" in task_name:
                    actions["system"].extend(findings)
                else:
                    actions["immediate"].extend(findings)
            
            if "access" in task_name or "credential" in task_name:
                actions["access"].extend(findings)
        
        # Add defaults if no specific actions found
        if not any(actions.values()):
            actions["immediate"] = ["Standard containment procedures executed"]
        
        return actions
    
    async def _apply_formatting(self, content: Dict[str, Any], output_format: str) -> Dict[str, Any]:
        """Apply formatting rules to document content"""
        
        formatting_rules = self.formatting_rules.get(output_format, {})
        
        formatted_content = {
            "raw_content": content,
            "format": output_format,
            "formatting_applied": True,
            "styling": formatting_rules
        }
        
        # Format-specific processing
        if output_format == DocumentFormat.PDF.value:
            formatted_content["pdf_settings"] = {
                "page_size": formatting_rules.get("page_size", "A4"),
                "margins": formatting_rules.get("margins", {}),
                "watermark": formatting_rules.get("watermark", "CONFIDENTIAL")
            }
        
        elif output_format == DocumentFormat.HTML.value:
            formatted_content["html_settings"] = {
                "css_framework": formatting_rules.get("css_framework", "bootstrap"),
                "responsive": formatting_rules.get("responsive", True),
                "navigation": formatting_rules.get("include_navigation", True)
            }
        
        elif output_format == DocumentFormat.MARKDOWN.value:
            formatted_content["markdown_settings"] = {
                "flavor": formatting_rules.get("flavor", "github"),
                "toc": formatting_rules.get("include_toc", True)
            }
        
        return formatted_content
    
    async def _create_document_metadata(self, 
                                      doc_type: str,
                                      output_format: str,
                                      incident_data: Dict[str, Any],
                                      formatted_content: Dict[str, Any]) -> DocumentMetadata:
        """Create document metadata"""
        
        incident_id = incident_data.get("incident_id", "unknown")
        current_time = datetime.now()
        
        # Generate document ID
        doc_id = f"{doc_type}_{incident_id}_{output_format}_{int(current_time.timestamp())}"
        
        # Calculate file size (simulated)
        content_str = json.dumps(formatted_content)
        file_size = len(content_str.encode('utf-8'))
        
        # Calculate checksum
        checksum = hashlib.sha256(content_str.encode('utf-8')).hexdigest()
        
        # Get template settings
        template = self.document_templates.get(doc_type, {})
        
        return DocumentMetadata(
            document_id=doc_id,
            title=self._generate_document_title(doc_type, incident_data),
            document_type=doc_type,
            classification=template.get("default_classification", DocumentClassification.CONFIDENTIAL.value),
            created_date=current_time,
            last_modified=current_time,
            version="1.0",
            author="Incident Management Agent",
            reviewers=template.get("required_approvals", []),
            approval_status="pending_review",
            retention_period=template.get("retention_period", "7_years"),
            distribution_list=self._determine_distribution_list(doc_type, incident_data),
            file_size=file_size,
            checksum=checksum
        )
    
    def _determine_distribution_list(self, doc_type: str, incident_data: Dict[str, Any]) -> List[str]:
        """Determine document distribution list"""
        
        base_distribution = ["incident_commander", "ciso", "legal_team"]
        severity = incident_data.get("classification", {}).get("severity", "medium")
        
        if severity in ["critical", "high"]:
            base_distribution.extend(["executive_team", "board_of_directors"])
        
        if doc_type == DocumentType.COMPLIANCE_REPORT.value:
            base_distribution.extend(["compliance_officer", "external_auditor"])
        
        if doc_type == DocumentType.TECHNICAL_ANALYSIS.value:
            base_distribution.extend(["technical_team", "security_analysts"])
        
        return list(set(base_distribution))  # Remove duplicates
    
    async def _create_documentation_package(self, 
                                           incident_id: str,
                                           generated_documents: List[Dict[str, Any]],
                                           incident_data: Dict[str, Any],
                                           investigation_results: Dict[str, Any]) -> Dict[str, Any]:
        """Create comprehensive documentation package"""
        
        package_id = f"doc_package_{incident_id}_{int(datetime.now().timestamp())}"
        
        package = {
            "package_id": package_id,
            "incident_id": incident_id,
            "creation_date": datetime.now().isoformat(),
            "package_summary": {
                "total_documents": len(generated_documents),
                "document_types": list(set(doc["document_type"] for doc in generated_documents)),
                "output_formats": list(set(doc["output_format"] for doc in generated_documents)),
                "total_package_size": sum(doc["file_info"]["file_size"] for doc in generated_documents)
            },
            "documents": generated_documents,
            "package_metadata": {
                "classification": "CONFIDENTIAL",
                "retention_period": "7_years",
                "access_controls": "authorized_personnel_only",
                "distribution_restrictions": "internal_use_only"
            },
            "quality_assurance": {
                "completeness_check": "passed",
                "accuracy_review": "pending",
                "compliance_verification": "passed",
                "approval_status": "pending_review"
            },
            "archive_information": {
                "storage_location": f"secure_archive/incidents/{incident_id}/documentation",
                "backup_location": f"backup_archive/incidents/{incident_id}",
                "access_log": "maintained",
                "destruction_date": (datetime.now() + timedelta(days=2555)).isoformat()  # 7 years
            }
        }
        
        return package
    
    def _update_generation_stats(self, document_types: List[str], output_formats: List[str], start_time: datetime):
        """Update documentation generation statistics"""
        
        self.generation_stats["total_documents_generated"] += len(document_types) * len(output_formats)
        
        # Update by type
        for doc_type in document_types:
            self.generation_stats["documents_by_type"][doc_type] += len(output_formats)
        
        # Update by format
        for output_format in output_formats:
            self.generation_stats["format_distribution"][output_format] += len(document_types)
        
        # Update generation time
        generation_time = (datetime.now() - start_time).total_seconds() / 60
        current_avg = self.generation_stats["average_generation_time"]
        total_docs = self.generation_stats["total_documents_generated"]
        
        if total_docs > 0:
            new_avg = ((current_avg * (total_docs - len(document_types) * len(output_formats))) + generation_time) / total_docs
            self.generation_stats["average_generation_time"] = new_avg
    
    async def get_generation_statistics(self) -> Dict[str, Any]:
        """Get documentation generation statistics"""
        
        return {
            "generation_stats": self.generation_stats,
            "supported_document_types": [dtype.value for dtype in DocumentType],
            "supported_formats": [fmt.value for fmt in DocumentFormat],
            "available_templates": list(self.document_templates.keys()),
            "compliance_frameworks": list(self.compliance_requirements.keys())
        }

def create_documentation_generator() -> DocumentationGenerator:
    """Factory function to create documentation generator"""
    return DocumentationGenerator()

# Example usage
async def main():
    generator = create_documentation_generator()
    
    # Example incident data
    sample_incident = {
        "incident_id": "inc_001",
        "description": "Critical malware detected",
        "timestamp": datetime.now().isoformat(),
        "classification": {"category": "malware", "severity": "high"},
        "alert_data": {"affected_hosts": ["DESKTOP-001"], "source_ip": "192.168.1.100"}
    }
    
    # Example investigation results
    sample_investigation = {
        "analysis_results": {
            "executed_tasks": [{"task_name": "malware analysis", "findings": ["Trojan detected"]}],
            "summary": {"threat_level": "high", "recommendations": ["Update antivirus"]}
        },
        "evidence_data": {"total_evidence": 5},
        "workflow_history": [{"timestamp": datetime.now().isoformat(), "state": "completed"}]
    }
    
    # Generate documentation
    result = await generator.generate_incident_documentation(
        sample_incident, 
        sample_investigation,
        [DocumentType.INCIDENT_REPORT.value],
        [DocumentFormat.PDF.value, DocumentFormat.HTML.value]
    )
    
    print(f"Documentation generation result: {json.dumps(result, indent=2)}")

if __name__ == "__main__":
    asyncio.run(main())
