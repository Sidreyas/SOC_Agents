"""
Enterprise Compliance Module
Provides enterprise-grade compliance and governance features for all SOC agents
"""

import logging
import asyncio
import json
import hashlib
import hmac
import base64
from typing import Dict, Any, List, Optional, Union
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
import uuid
import secrets
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

class ComplianceFramework(Enum):
    """Compliance framework enumeration"""
    GDPR = "gdpr"
    HIPAA = "hipaa"
    SOX = "sox"
    PCI_DSS = "pci_dss"
    ISO_27001 = "iso_27001"
    NIST = "nist"
    FTC = "ftc"

class DataClassification(Enum):
    """Data classification levels"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"

class RetentionPeriod(Enum):
    """Data retention periods"""
    DAYS_30 = "30_days"
    DAYS_90 = "90_days"
    MONTHS_6 = "6_months"
    YEAR_1 = "1_year"
    YEARS_3 = "3_years"
    YEARS_7 = "7_years"
    YEARS_10 = "10_years"
    PERMANENT = "permanent"

class PrivacyAction(Enum):
    """Privacy action types"""
    COLLECT = "collect"
    PROCESS = "process"
    STORE = "store"
    SHARE = "share"
    DELETE = "delete"
    ANONYMIZE = "anonymize"
    EXPORT = "export"

@dataclass
class ComplianceRecord:
    """Compliance audit record"""
    record_id: str
    timestamp: datetime
    framework: str
    event_type: str
    data_subject: Optional[str]
    data_classification: str
    legal_basis: Optional[str]
    retention_period: str
    privacy_action: str
    metadata: Dict[str, Any]
    hash_signature: str

@dataclass
class DataProcessingActivity:
    """GDPR Article 30 processing activity record"""
    activity_id: str
    controller_name: str
    controller_contact: str
    purposes: List[str]
    categories_of_data_subjects: List[str]
    categories_of_personal_data: List[str]
    recipients: List[str]
    third_country_transfers: List[str]
    retention_periods: Dict[str, str]
    technical_measures: List[str]
    organizational_measures: List[str]
    created_date: datetime
    last_updated: datetime

class EnterpriseComplianceManager:
    """
    Enterprise Compliance Manager
    Handles regulatory compliance, data governance, and privacy controls
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.audit_storage = None
        self.privacy_manager = None
        self.retention_manager = None
        self.consent_manager = None
        self.data_classifier = None
        self._initialize_compliance_components()
    
    def _initialize_compliance_components(self):
        """Initialize all compliance components"""
        try:
            # Initialize audit storage
            self.audit_storage = ComplianceAuditStorage(self.config)
            
            # Initialize privacy manager
            self.privacy_manager = PrivacyManager(self.config)
            
            # Initialize retention manager
            self.retention_manager = DataRetentionManager(self.config)
            
            # Initialize consent manager
            self.consent_manager = ConsentManager(self.config)
            
            # Initialize data classifier
            self.data_classifier = DataClassifier(self.config)
            
            logger.info("Enterprise compliance components initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize compliance components: {str(e)}")
            raise
    
    async def log_compliance_event(self, framework: ComplianceFramework, 
                                 event_type: str, event_data: Dict[str, Any],
                                 data_subject: Optional[str] = None) -> str:
        """
        Log compliance event for regulatory audit trail
        """
        try:
            # Classify data
            data_classification = await self.data_classifier.classify_data(event_data)
            
            # Determine retention period
            retention_period = self._determine_retention_period(framework, event_type)
            
            # Determine legal basis (for GDPR)
            legal_basis = self._determine_legal_basis(framework, event_type)
            
            # Create compliance record
            record = ComplianceRecord(
                record_id=str(uuid.uuid4()),
                timestamp=datetime.now(),
                framework=framework.value,
                event_type=event_type,
                data_subject=data_subject,
                data_classification=data_classification.value,
                legal_basis=legal_basis,
                retention_period=retention_period.value,
                privacy_action=self._determine_privacy_action(event_type),
                metadata=event_data,
                hash_signature=self._create_record_hash(event_data)
            )
            
            # Store compliance record
            await self.audit_storage.store_compliance_record(record)
            
            # Check for privacy obligations
            if framework in [ComplianceFramework.GDPR, ComplianceFramework.HIPAA]:
                await self._check_privacy_obligations(record, event_data)
            
            logger.info(f"Compliance event logged: {framework.value} - {event_type}")
            return record.record_id
            
        except Exception as e:
            logger.error(f"Failed to log compliance event: {str(e)}")
            raise
    
    async def handle_data_subject_request(self, request_type: str, 
                                        data_subject: str, 
                                        request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle GDPR data subject requests (Access, Rectification, Erasure, Portability)
        """
        try:
            request_id = str(uuid.uuid4())
            
            # Log the request
            await self.log_compliance_event(
                ComplianceFramework.GDPR,
                f"data_subject_request_{request_type}",
                {
                    "request_id": request_id,
                    "data_subject": data_subject,
                    "request_details": request_data
                },
                data_subject=data_subject
            )
            
            response = {
                "request_id": request_id,
                "request_type": request_type,
                "data_subject": data_subject,
                "status": "processing",
                "created_at": datetime.now().isoformat()
            }
            
            # Process different request types
            if request_type == "access":
                response.update(await self._handle_access_request(data_subject, request_data))
            elif request_type == "rectification":
                response.update(await self._handle_rectification_request(data_subject, request_data))
            elif request_type == "erasure":
                response.update(await self._handle_erasure_request(data_subject, request_data))
            elif request_type == "portability":
                response.update(await self._handle_portability_request(data_subject, request_data))
            else:
                response["status"] = "unsupported_request_type"
                response["error"] = f"Request type '{request_type}' not supported"
            
            return response
            
        except Exception as e:
            logger.error(f"Failed to handle data subject request: {str(e)}")
            raise
    
    async def assess_privacy_impact(self, processing_activity: Dict[str, Any]) -> Dict[str, Any]:
        """
        Conduct Privacy Impact Assessment (PIA) for new processing activities
        """
        try:
            assessment_id = str(uuid.uuid4())
            
            # Classify data involved
            data_classification = await self.data_classifier.classify_data(processing_activity)
            
            # Assess privacy risks
            privacy_risks = await self._assess_privacy_risks(processing_activity)
            
            # Determine if DPIA is required
            dpia_required = await self._is_dpia_required(processing_activity, privacy_risks)
            
            # Generate recommendations
            recommendations = await self._generate_privacy_recommendations(
                processing_activity, privacy_risks
            )
            
            assessment = {
                "assessment_id": assessment_id,
                "timestamp": datetime.now().isoformat(),
                "data_classification": data_classification.value,
                "privacy_risks": privacy_risks,
                "dpia_required": dpia_required,
                "recommendations": recommendations,
                "compliance_status": "pending_review"
            }
            
            # Log assessment
            await self.log_compliance_event(
                ComplianceFramework.GDPR,
                "privacy_impact_assessment",
                assessment
            )
            
            return assessment
            
        except Exception as e:
            logger.error(f"Privacy impact assessment failed: {str(e)}")
            raise
    
    async def generate_compliance_report(self, framework: ComplianceFramework,
                                       start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """
        Generate compliance report for specified framework and time period
        """
        try:
            # Retrieve compliance records
            records = await self.audit_storage.get_compliance_records(
                framework, start_date, end_date
            )
            
            # Analyze compliance metrics
            metrics = await self._analyze_compliance_metrics(records, framework)
            
            # Check for violations
            violations = await self._identify_compliance_violations(records, framework)
            
            # Generate recommendations
            recommendations = await self._generate_compliance_recommendations(
                metrics, violations, framework
            )
            
            report = {
                "report_id": str(uuid.uuid4()),
                "framework": framework.value,
                "period": {
                    "start_date": start_date.isoformat(),
                    "end_date": end_date.isoformat()
                },
                "total_events": len(records),
                "metrics": metrics,
                "violations": violations,
                "recommendations": recommendations,
                "compliance_score": self._calculate_compliance_score(metrics, violations),
                "generated_at": datetime.now().isoformat()
            }
            
            # Store report
            await self.audit_storage.store_compliance_report(report)
            
            return report
            
        except Exception as e:
            logger.error(f"Compliance report generation failed: {str(e)}")
            raise
    
    async def implement_data_minimization(self, data: Dict[str, Any], 
                                        purpose: str) -> Dict[str, Any]:
        """
        Implement data minimization principle - only process necessary data
        """
        try:
            # Determine minimum required fields for purpose
            required_fields = await self._get_required_fields_for_purpose(purpose)
            
            # Filter data to minimum required
            minimized_data = {
                field: data[field] for field in required_fields 
                if field in data
            }
            
            # Log data minimization action
            await self.log_compliance_event(
                ComplianceFramework.GDPR,
                "data_minimization",
                {
                    "purpose": purpose,
                    "original_fields": list(data.keys()),
                    "minimized_fields": list(minimized_data.keys()),
                    "fields_removed": len(data) - len(minimized_data)
                }
            )
            
            return minimized_data
            
        except Exception as e:
            logger.error(f"Data minimization failed: {str(e)}")
            raise
    
    # Private helper methods
    def _determine_retention_period(self, framework: ComplianceFramework, 
                                  event_type: str) -> RetentionPeriod:
        """Determine retention period based on framework and event type"""
        retention_mapping = {
            ComplianceFramework.GDPR: {
                "authentication": RetentionPeriod.YEARS_3,
                "data_access": RetentionPeriod.YEARS_7,
                "security_incident": RetentionPeriod.YEARS_7,
                "default": RetentionPeriod.YEARS_3
            },
            ComplianceFramework.HIPAA: {
                "authentication": RetentionPeriod.YEARS_7,
                "data_access": RetentionPeriod.YEARS_7,
                "security_incident": RetentionPeriod.YEARS_10,
                "default": RetentionPeriod.YEARS_7
            },
            ComplianceFramework.SOX: {
                "authentication": RetentionPeriod.YEARS_7,
                "financial_data": RetentionPeriod.YEARS_7,
                "audit_log": RetentionPeriod.YEARS_7,
                "default": RetentionPeriod.YEARS_7
            }
        }
        
        framework_mapping = retention_mapping.get(framework, {})
        return framework_mapping.get(event_type, framework_mapping.get("default", RetentionPeriod.YEARS_3))
    
    def _determine_legal_basis(self, framework: ComplianceFramework, event_type: str) -> Optional[str]:
        """Determine legal basis for GDPR compliance"""
        if framework != ComplianceFramework.GDPR:
            return None
        
        legal_basis_mapping = {
            "authentication": "legitimate_interest",
            "security_monitoring": "legitimate_interest",
            "threat_detection": "legitimate_interest",
            "incident_response": "legitimate_interest",
            "compliance_audit": "legal_obligation",
            "user_consent": "consent"
        }
        
        return legal_basis_mapping.get(event_type, "legitimate_interest")
    
    def _determine_privacy_action(self, event_type: str) -> str:
        """Determine privacy action type"""
        action_mapping = {
            "authentication": PrivacyAction.PROCESS.value,
            "data_access": PrivacyAction.PROCESS.value,
            "data_storage": PrivacyAction.STORE.value,
            "data_collection": PrivacyAction.COLLECT.value,
            "data_deletion": PrivacyAction.DELETE.value,
            "data_anonymization": PrivacyAction.ANONYMIZE.value,
            "data_export": PrivacyAction.EXPORT.value,
            "data_sharing": PrivacyAction.SHARE.value
        }
        
        return action_mapping.get(event_type, PrivacyAction.PROCESS.value)
    
    def _create_record_hash(self, data: Dict[str, Any]) -> str:
        """Create hash signature for data integrity"""
        data_string = json.dumps(data, sort_keys=True)
        secret = self.config.get("integrity_secret", "default-secret")
        signature = hmac.new(
            secret.encode(),
            data_string.encode(),
            hashlib.sha256
        ).hexdigest()
        return signature
    
    async def _check_privacy_obligations(self, record: ComplianceRecord, 
                                       event_data: Dict[str, Any]):
        """Check for additional privacy obligations"""
        # Check consent requirements
        if record.legal_basis == "consent":
            await self.consent_manager.verify_consent(record.data_subject, record.event_type)
        
        # Check data retention
        await self.retention_manager.schedule_retention_action(record)
        
        # Check for data breach notification requirements
        if "security_incident" in record.event_type:
            await self._check_breach_notification_requirements(record, event_data)
    
    async def _handle_access_request(self, data_subject: str, 
                                   request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle GDPR Article 15 - Right of Access"""
        # Retrieve all data for the subject
        subject_data = await self.audit_storage.get_data_subject_records(data_subject)
        
        return {
            "status": "completed",
            "data_provided": True,
            "data_sources": len(subject_data),
            "data_export_url": f"/compliance/export/{data_subject}",
            "completed_at": datetime.now().isoformat()
        }
    
    async def _handle_rectification_request(self, data_subject: str, 
                                          request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle GDPR Article 16 - Right to Rectification"""
        # Update incorrect data
        corrections = request_data.get("corrections", {})
        updated_records = await self.audit_storage.update_data_subject_records(
            data_subject, corrections
        )
        
        return {
            "status": "completed",
            "records_updated": len(updated_records),
            "completed_at": datetime.now().isoformat()
        }
    
    async def _handle_erasure_request(self, data_subject: str, 
                                    request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle GDPR Article 17 - Right to Erasure"""
        # Delete or anonymize data
        deleted_records = await self.audit_storage.delete_data_subject_records(data_subject)
        
        return {
            "status": "completed",
            "records_deleted": len(deleted_records),
            "anonymization_applied": True,
            "completed_at": datetime.now().isoformat()
        }
    
    async def _handle_portability_request(self, data_subject: str, 
                                        request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle GDPR Article 20 - Right to Data Portability"""
        # Export data in structured format
        export_data = await self.audit_storage.export_data_subject_records(data_subject)
        
        return {
            "status": "completed",
            "export_format": "JSON",
            "export_url": f"/compliance/export/{data_subject}/portable",
            "completed_at": datetime.now().isoformat()
        }
    
    async def _assess_privacy_risks(self, processing_activity: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Assess privacy risks for processing activity"""
        risks = []
        
        # Check for high-risk processing
        if "biometric" in str(processing_activity).lower():
            risks.append({
                "risk_type": "biometric_processing",
                "severity": "high",
                "description": "Processing of biometric data for identification"
            })
        
        if "special_category" in processing_activity.get("data_types", []):
            risks.append({
                "risk_type": "special_category_data",
                "severity": "high", 
                "description": "Processing of special category personal data"
            })
        
        return risks
    
    async def _is_dpia_required(self, processing_activity: Dict[str, Any], 
                              privacy_risks: List[Dict[str, Any]]) -> bool:
        """Determine if Data Protection Impact Assessment is required"""
        # DPIA required for high-risk processing
        high_risk_indicators = [
            len([r for r in privacy_risks if r["severity"] == "high"]) > 0,
            "systematic_monitoring" in processing_activity.get("purposes", []),
            "automated_decision_making" in processing_activity.get("purposes", []),
            processing_activity.get("data_volume", 0) > 10000
        ]
        
        return any(high_risk_indicators)
    
    async def _generate_privacy_recommendations(self, processing_activity: Dict[str, Any],
                                              privacy_risks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate privacy recommendations"""
        recommendations = []
        
        if privacy_risks:
            recommendations.append({
                "type": "risk_mitigation",
                "priority": "high",
                "description": "Implement additional technical and organizational measures"
            })
        
        recommendations.append({
            "type": "privacy_by_design",
            "priority": "medium",
            "description": "Ensure privacy by design principles are implemented"
        })
        
        return recommendations
    
    async def _analyze_compliance_metrics(self, records: List[ComplianceRecord], 
                                        framework: ComplianceFramework) -> Dict[str, Any]:
        """Analyze compliance metrics from records"""
        if not records:
            return {}
        
        total_events = len(records)
        event_types = {}
        data_classifications = {}
        
        for record in records:
            event_types[record.event_type] = event_types.get(record.event_type, 0) + 1
            data_classifications[record.data_classification] = data_classifications.get(record.data_classification, 0) + 1
        
        return {
            "total_events": total_events,
            "event_type_distribution": event_types,
            "data_classification_distribution": data_classifications,
            "avg_events_per_day": total_events / 30 if total_events > 0 else 0
        }
    
    async def _identify_compliance_violations(self, records: List[ComplianceRecord],
                                            framework: ComplianceFramework) -> List[Dict[str, Any]]:
        """Identify potential compliance violations"""
        violations = []
        
        # Check for missing legal basis in GDPR records
        if framework == ComplianceFramework.GDPR:
            for record in records:
                if not record.legal_basis:
                    violations.append({
                        "violation_type": "missing_legal_basis",
                        "record_id": record.record_id,
                        "severity": "high",
                        "description": "Processing without valid legal basis"
                    })
        
        return violations
    
    async def _generate_compliance_recommendations(self, metrics: Dict[str, Any],
                                                 violations: List[Dict[str, Any]],
                                                 framework: ComplianceFramework) -> List[Dict[str, Any]]:
        """Generate compliance recommendations"""
        recommendations = []
        
        if violations:
            recommendations.append({
                "type": "violation_remediation",
                "priority": "critical",
                "description": f"Address {len(violations)} compliance violations"
            })
        
        if metrics.get("total_events", 0) > 10000:
            recommendations.append({
                "type": "monitoring_enhancement",
                "priority": "medium",
                "description": "Consider enhanced monitoring for high-volume processing"
            })
        
        return recommendations
    
    def _calculate_compliance_score(self, metrics: Dict[str, Any], 
                                  violations: List[Dict[str, Any]]) -> float:
        """Calculate overall compliance score"""
        base_score = 100.0
        
        # Deduct points for violations
        violation_penalty = len(violations) * 10
        
        # Deduct points for missing documentation
        documentation_penalty = 0
        if not metrics:
            documentation_penalty = 20
        
        final_score = max(0, base_score - violation_penalty - documentation_penalty)
        return final_score
    
    async def _get_required_fields_for_purpose(self, purpose: str) -> List[str]:
        """Get minimum required fields for processing purpose"""
        purpose_mapping = {
            "authentication": ["user_id", "timestamp", "ip_address"],
            "security_monitoring": ["event_type", "timestamp", "source"],
            "threat_detection": ["threat_type", "timestamp", "indicators"],
            "incident_response": ["incident_id", "timestamp", "severity"]
        }
        
        return purpose_mapping.get(purpose, ["timestamp", "event_type"])
    
    async def _check_breach_notification_requirements(self, record: ComplianceRecord,
                                                    event_data: Dict[str, Any]):
        """Check if security incident requires breach notification"""
        severity = event_data.get("severity", "low")
        affected_subjects = event_data.get("affected_subjects", 0)
        
        # GDPR requires notification within 72 hours for high-risk breaches
        if severity in ["high", "critical"] or affected_subjects > 100:
            # Schedule breach notification
            logger.warning(f"Security incident {record.record_id} may require breach notification")


class ComplianceAuditStorage:
    """Compliance audit trail storage"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.storage_backend = config.get("compliance_storage", "file")
        self.records = []  # In-memory storage for demo
    
    async def store_compliance_record(self, record: ComplianceRecord):
        """Store compliance record"""
        self.records.append(record)
        # In production, would store in secure, immutable storage
    
    async def get_compliance_records(self, framework: ComplianceFramework,
                                   start_date: datetime, end_date: datetime) -> List[ComplianceRecord]:
        """Retrieve compliance records for time period"""
        return [
            record for record in self.records
            if record.framework == framework.value and start_date <= record.timestamp <= end_date
        ]
    
    async def get_data_subject_records(self, data_subject: str) -> List[ComplianceRecord]:
        """Get all records for specific data subject"""
        return [record for record in self.records if record.data_subject == data_subject]
    
    async def update_data_subject_records(self, data_subject: str, 
                                        corrections: Dict[str, Any]) -> List[str]:
        """Update data subject records"""
        updated_records = []
        for record in self.records:
            if record.data_subject == data_subject:
                # Apply corrections
                record.metadata.update(corrections)
                updated_records.append(record.record_id)
        return updated_records
    
    async def delete_data_subject_records(self, data_subject: str) -> List[str]:
        """Delete/anonymize data subject records"""
        deleted_records = []
        for record in self.records:
            if record.data_subject == data_subject:
                # Anonymize instead of delete for audit trail
                record.data_subject = "anonymized"
                record.metadata = {"anonymized": True}
                deleted_records.append(record.record_id)
        return deleted_records
    
    async def export_data_subject_records(self, data_subject: str) -> Dict[str, Any]:
        """Export data subject records in portable format"""
        subject_records = await self.get_data_subject_records(data_subject)
        return {
            "data_subject": data_subject,
            "export_date": datetime.now().isoformat(),
            "records": [asdict(record) for record in subject_records]
        }
    
    async def store_compliance_report(self, report: Dict[str, Any]):
        """Store compliance report"""
        # In production, would store in secure reporting system
        pass


class PrivacyManager:
    """Privacy controls and consent management"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
    
    async def verify_consent(self, data_subject: str, processing_purpose: str) -> bool:
        """Verify consent for processing"""
        # Implementation would check consent database
        return True  # Placeholder


class DataRetentionManager:
    """Data retention policy management"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
    
    async def schedule_retention_action(self, record: ComplianceRecord):
        """Schedule data retention action"""
        # Implementation would schedule deletion based on retention period
        pass


class ConsentManager:
    """Consent management for GDPR compliance"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
    
    async def verify_consent(self, data_subject: str, processing_purpose: str) -> bool:
        """Verify valid consent exists"""
        # Implementation would verify consent records
        return True


class DataClassifier:
    """Data classification engine"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
    
    async def classify_data(self, data: Dict[str, Any]) -> DataClassification:
        """Classify data based on content"""
        # Simple classification logic
        data_str = str(data).lower()
        
        if any(keyword in data_str for keyword in ["password", "secret", "key", "token"]):
            return DataClassification.RESTRICTED
        elif any(keyword in data_str for keyword in ["email", "phone", "ssn", "personal"]):
            return DataClassification.CONFIDENTIAL
        elif any(keyword in data_str for keyword in ["internal", "employee", "company"]):
            return DataClassification.INTERNAL
        else:
            return DataClassification.PUBLIC
