"""
Incident Intake Module
State 1: Incident Reception, Validation, and Initial Classification
Handles incoming incidents from all SOC agents and external sources
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
import json
import uuid
from enum import Enum

logger = logging.getLogger(__name__)

class IncidentSeverity(Enum):
    """Incident severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

class IncidentStatus(Enum):
    """Incident status tracking"""
    NEW = "new"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"

class IncidentCategory(Enum):
    """Incident category classification"""
    MALWARE = "malware"
    PHISHING = "phishing"
    NETWORK_INTRUSION = "network_intrusion"
    DATA_EXFILTRATION = "data_exfiltration"
    INSIDER_THREAT = "insider_threat"
    ACCESS_VIOLATION = "access_violation"
    DDOS_ATTACK = "ddos_attack"
    CREDENTIAL_COMPROMISE = "credential_compromise"
    POWERSHELL_ABUSE = "powershell_abuse"
    HOST_COMPROMISE = "host_compromise"
    UNKNOWN = "unknown"

class IncidentIntakeProcessor:
    """
    Processes incoming incidents from SOC agents and external sources
    """
    
    def __init__(self):
        self.incident_queue = []
        self.processing_stats = {
            "total_received": 0,
            "total_processed": 0,
            "validation_failures": 0,
            "duplicate_incidents": 0
        }
        
    async def receive_incident(self, incident_data: Dict[str, Any], source_agent: str = None) -> Dict[str, Any]:
        """
        Receive and validate incoming incident
        
        Args:
            incident_data: Raw incident data from source
            source_agent: Name of the agent that detected the incident
            
        Returns:
            Processed incident with validation results
        """
        try:
            incident_id = str(uuid.uuid4())
            reception_time = datetime.now()
            
            logger.info(f"Receiving incident {incident_id} from {source_agent}")
            
            # Validate incident structure
            validation_result = await self._validate_incident_structure(incident_data)
            
            if not validation_result["valid"]:
                logger.error(f"Incident validation failed: {validation_result['errors']}")
                self.processing_stats["validation_failures"] += 1
                return {
                    "incident_id": incident_id,
                    "status": "validation_failed",
                    "errors": validation_result["errors"],
                    "reception_time": reception_time
                }
            
            # Check for duplicates
            duplicate_check = await self._check_for_duplicates(incident_data)
            
            if duplicate_check["is_duplicate"]:
                logger.info(f"Duplicate incident detected: {duplicate_check['original_incident_id']}")
                self.processing_stats["duplicate_incidents"] += 1
                return await self._handle_duplicate_incident(incident_id, duplicate_check)
            
            # Create standardized incident record
            standardized_incident = await self._create_standardized_incident(
                incident_id, incident_data, source_agent, reception_time
            )
            
            # Perform initial classification
            classification = await self._perform_initial_classification(standardized_incident)
            standardized_incident.update(classification)
            
            # Add to processing queue
            self.incident_queue.append(standardized_incident)
            
            # Update statistics
            self.processing_stats["total_received"] += 1
            
            logger.info(f"Incident {incident_id} successfully received and queued")
            
            return {
                "incident_id": incident_id,
                "status": "received",
                "severity": standardized_incident["severity"],
                "category": standardized_incident["category"],
                "estimated_processing_time": self._estimate_processing_time(standardized_incident),
                "reception_time": reception_time
            }
            
        except Exception as e:
            logger.error(f"Error receiving incident: {str(e)}")
            return {
                "incident_id": incident_id if 'incident_id' in locals() else "unknown",
                "status": "reception_error",
                "error": str(e),
                "reception_time": datetime.now()
            }
    
    async def _validate_incident_structure(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate incident data structure and required fields"""
        errors = []
        
        # Required fields
        required_fields = [
            "alert_data", "timestamp", "source", "description"
        ]
        
        for field in required_fields:
            if field not in incident_data:
                errors.append(f"Missing required field: {field}")
        
        # Validate timestamp
        if "timestamp" in incident_data:
            try:
                if isinstance(incident_data["timestamp"], str):
                    datetime.fromisoformat(incident_data["timestamp"].replace('Z', '+00:00'))
            except ValueError:
                errors.append("Invalid timestamp format")
        
        # Validate alert_data structure
        if "alert_data" in incident_data and not isinstance(incident_data["alert_data"], dict):
            errors.append("alert_data must be a dictionary")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors
        }
    
    async def _check_for_duplicates(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Check for duplicate incidents based on content similarity"""
        # Simple duplicate detection based on key characteristics
        # In production, this would use more sophisticated algorithms
        
        current_hash = self._calculate_incident_hash(incident_data)
        
        # Check recent incidents (last 24 hours) for duplicates
        recent_cutoff = datetime.now() - timedelta(hours=24)
        
        for existing_incident in self.incident_queue:
            if existing_incident["reception_time"] > recent_cutoff:
                existing_hash = self._calculate_incident_hash(existing_incident["original_data"])
                
                # Calculate similarity (simplified)
                similarity = self._calculate_similarity(current_hash, existing_hash)
                
                if similarity > 0.85:  # 85% similarity threshold
                    return {
                        "is_duplicate": True,
                        "original_incident_id": existing_incident["incident_id"],
                        "similarity_score": similarity
                    }
        
        return {"is_duplicate": False}
    
    def _calculate_incident_hash(self, incident_data: Dict[str, Any]) -> str:
        """Calculate hash for incident deduplication"""
        # Extract key identifying features
        key_features = {
            "source": incident_data.get("source", ""),
            "description": incident_data.get("description", ""),
            "alert_type": incident_data.get("alert_data", {}).get("alert_type", ""),
            "source_ip": incident_data.get("alert_data", {}).get("source_ip", ""),
            "destination_ip": incident_data.get("alert_data", {}).get("destination_ip", "")
        }
        
        # Create normalized string for hashing
        feature_string = json.dumps(key_features, sort_keys=True)
        return str(hash(feature_string))
    
    def _calculate_similarity(self, hash1: str, hash2: str) -> float:
        """Calculate similarity between two incident hashes"""
        # Simplified similarity calculation
        if hash1 == hash2:
            return 1.0
        
        # Character-level similarity for demonstration
        common_chars = sum(1 for a, b in zip(hash1, hash2) if a == b)
        max_length = max(len(hash1), len(hash2))
        
        return common_chars / max_length if max_length > 0 else 0.0
    
    async def _handle_duplicate_incident(self, new_incident_id: str, duplicate_info: Dict[str, Any]) -> Dict[str, Any]:
        """Handle duplicate incident detection"""
        return {
            "incident_id": new_incident_id,
            "status": "duplicate",
            "original_incident_id": duplicate_info["original_incident_id"],
            "similarity_score": duplicate_info["similarity_score"],
            "action": "merged_with_original",
            "reception_time": datetime.now()
        }
    
    async def _create_standardized_incident(self, incident_id: str, incident_data: Dict[str, Any], 
                                          source_agent: str, reception_time: datetime) -> Dict[str, Any]:
        """Create standardized incident record"""
        return {
            "incident_id": incident_id,
            "source_agent": source_agent,
            "reception_time": reception_time,
            "original_data": incident_data,
            "standardized_data": {
                "timestamp": incident_data.get("timestamp", reception_time.isoformat()),
                "description": incident_data.get("description", ""),
                "source": incident_data.get("source", "unknown"),
                "alert_data": incident_data.get("alert_data", {}),
                "severity_indicators": self._extract_severity_indicators(incident_data),
                "category_indicators": self._extract_category_indicators(incident_data)
            },
            "status": IncidentStatus.NEW.value,
            "assigned_analyst": None,
            "investigation_start_time": None,
            "estimated_resolution_time": None,
            "tags": [],
            "related_incidents": [],
            "evidence_collected": [],
            "actions_taken": []
        }
    
    def _extract_severity_indicators(self, incident_data: Dict[str, Any]) -> List[str]:
        """Extract indicators that suggest incident severity"""
        indicators = []
        
        # Check for high-severity keywords
        description = incident_data.get("description", "").lower()
        high_severity_keywords = [
            "critical", "breach", "compromise", "attack", "malware", 
            "ransomware", "exfiltration", "unauthorized access"
        ]
        
        for keyword in high_severity_keywords:
            if keyword in description:
                indicators.append(f"keyword_{keyword}")
        
        # Check alert data for severity indicators
        alert_data = incident_data.get("alert_data", {})
        
        if alert_data.get("severity") in ["critical", "high"]:
            indicators.append("alert_high_severity")
        
        if alert_data.get("confidence", 0) > 0.8:
            indicators.append("high_confidence")
        
        return indicators
    
    def _extract_category_indicators(self, incident_data: Dict[str, Any]) -> List[str]:
        """Extract indicators that suggest incident category"""
        indicators = []
        
        description = incident_data.get("description", "").lower()
        source = incident_data.get("source", "").lower()
        
        # Category mapping based on keywords and source
        category_keywords = {
            "malware": ["malware", "virus", "trojan", "backdoor", "ransomware"],
            "phishing": ["phishing", "email", "suspicious email", "credential harvesting"],
            "network": ["network", "traffic", "ddos", "scanning", "intrusion"],
            "access": ["access", "login", "authentication", "credential", "privilege"],
            "insider": ["insider", "employee", "internal", "privilege abuse"],
            "powershell": ["powershell", "script", "cmdlet", "execution policy"]
        }
        
        for category, keywords in category_keywords.items():
            for keyword in keywords:
                if keyword in description or keyword in source:
                    indicators.append(f"category_{category}")
                    break
        
        return indicators
    
    async def _perform_initial_classification(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Perform initial incident classification"""
        severity_indicators = incident["standardized_data"]["severity_indicators"]
        category_indicators = incident["standardized_data"]["category_indicators"]
        
        # Determine severity
        severity = self._calculate_severity(severity_indicators, incident)
        
        # Determine category
        category = self._determine_category(category_indicators, incident)
        
        # Calculate priority score
        priority_score = self._calculate_priority_score(severity, category, incident)
        
        return {
            "severity": severity,
            "category": category,
            "priority_score": priority_score,
            "classification_confidence": self._calculate_classification_confidence(
                severity_indicators, category_indicators
            ),
            "recommended_analyst_type": self._recommend_analyst_type(category),
            "estimated_complexity": self._estimate_complexity(incident)
        }
    
    def _calculate_severity(self, indicators: List[str], incident: Dict[str, Any]) -> str:
        """Calculate incident severity based on indicators"""
        high_severity_count = len([i for i in indicators if "critical" in i or "high" in i])
        
        if high_severity_count >= 2:
            return IncidentSeverity.CRITICAL.value
        elif high_severity_count == 1:
            return IncidentSeverity.HIGH.value
        elif len(indicators) >= 3:
            return IncidentSeverity.MEDIUM.value
        elif len(indicators) >= 1:
            return IncidentSeverity.LOW.value
        else:
            return IncidentSeverity.INFORMATIONAL.value
    
    def _determine_category(self, indicators: List[str], incident: Dict[str, Any]) -> str:
        """Determine incident category based on indicators"""
        # Count category indicators
        category_counts = {}
        
        for indicator in indicators:
            if indicator.startswith("category_"):
                category = indicator.replace("category_", "")
                category_counts[category] = category_counts.get(category, 0) + 1
        
        if category_counts:
            # Return most common category
            most_common_category = max(category_counts, key=category_counts.get)
            
            # Map to standard categories
            category_mapping = {
                "malware": IncidentCategory.MALWARE.value,
                "phishing": IncidentCategory.PHISHING.value,
                "network": IncidentCategory.NETWORK_INTRUSION.value,
                "access": IncidentCategory.ACCESS_VIOLATION.value,
                "insider": IncidentCategory.INSIDER_THREAT.value,
                "powershell": IncidentCategory.POWERSHELL_ABUSE.value
            }
            
            return category_mapping.get(most_common_category, IncidentCategory.UNKNOWN.value)
        
        return IncidentCategory.UNKNOWN.value
    
    def _calculate_priority_score(self, severity: str, category: str, incident: Dict[str, Any]) -> int:
        """Calculate priority score for incident processing order"""
        severity_scores = {
            IncidentSeverity.CRITICAL.value: 100,
            IncidentSeverity.HIGH.value: 75,
            IncidentSeverity.MEDIUM.value: 50,
            IncidentSeverity.LOW.value: 25,
            IncidentSeverity.INFORMATIONAL.value: 10
        }
        
        category_multipliers = {
            IncidentCategory.MALWARE.value: 1.2,
            IncidentCategory.DATA_EXFILTRATION.value: 1.3,
            IncidentCategory.CREDENTIAL_COMPROMISE.value: 1.2,
            IncidentCategory.DDOS_ATTACK.value: 1.1,
            IncidentCategory.INSIDER_THREAT.value: 1.2
        }
        
        base_score = severity_scores.get(severity, 25)
        multiplier = category_multipliers.get(category, 1.0)
        
        return int(base_score * multiplier)
    
    def _calculate_classification_confidence(self, severity_indicators: List[str], 
                                           category_indicators: List[str]) -> float:
        """Calculate confidence in classification"""
        total_indicators = len(severity_indicators) + len(category_indicators)
        
        if total_indicators >= 5:
            return 0.95
        elif total_indicators >= 3:
            return 0.80
        elif total_indicators >= 1:
            return 0.65
        else:
            return 0.40
    
    def _recommend_analyst_type(self, category: str) -> str:
        """Recommend analyst type based on incident category"""
        analyst_mapping = {
            IncidentCategory.MALWARE.value: "malware_specialist",
            IncidentCategory.PHISHING.value: "email_security_analyst",
            IncidentCategory.NETWORK_INTRUSION.value: "network_analyst",
            IncidentCategory.DATA_EXFILTRATION.value: "data_protection_analyst",
            IncidentCategory.INSIDER_THREAT.value: "insider_threat_specialist",
            IncidentCategory.ACCESS_VIOLATION.value: "identity_security_analyst",
            IncidentCategory.DDOS_ATTACK.value: "network_defense_analyst",
            IncidentCategory.CREDENTIAL_COMPROMISE.value: "identity_security_analyst",
            IncidentCategory.POWERSHELL_ABUSE.value: "endpoint_security_analyst",
            IncidentCategory.HOST_COMPROMISE.value: "endpoint_security_analyst"
        }
        
        return analyst_mapping.get(category, "general_analyst")
    
    def _estimate_complexity(self, incident: Dict[str, Any]) -> str:
        """Estimate incident complexity for resource planning"""
        complexity_indicators = 0
        
        # Check for complex indicators
        alert_data = incident["standardized_data"]["alert_data"]
        
        if len(alert_data) > 10:  # Many data points
            complexity_indicators += 1
        
        if incident["standardized_data"]["category_indicators"]:
            complexity_indicators += len(incident["standardized_data"]["category_indicators"])
        
        if complexity_indicators >= 5:
            return "high"
        elif complexity_indicators >= 3:
            return "medium"
        else:
            return "low"
    
    def _estimate_processing_time(self, incident: Dict[str, Any]) -> int:
        """Estimate processing time in minutes"""
        base_times = {
            IncidentSeverity.CRITICAL.value: 30,
            IncidentSeverity.HIGH.value: 60,
            IncidentSeverity.MEDIUM.value: 120,
            IncidentSeverity.LOW.value: 240,
            IncidentSeverity.INFORMATIONAL.value: 480
        }
        
        complexity_multipliers = {
            "high": 1.5,
            "medium": 1.2,
            "low": 1.0
        }
        
        base_time = base_times.get(incident["severity"], 120)
        complexity = incident.get("estimated_complexity", "low")
        multiplier = complexity_multipliers.get(complexity, 1.0)
        
        return int(base_time * multiplier)
    
    async def get_incident_queue(self, status_filter: str = None, 
                               priority_threshold: int = None) -> List[Dict[str, Any]]:
        """Get incidents from queue with optional filtering"""
        filtered_incidents = self.incident_queue
        
        if status_filter:
            filtered_incidents = [i for i in filtered_incidents if i["status"] == status_filter]
        
        if priority_threshold:
            filtered_incidents = [i for i in filtered_incidents 
                                if i.get("priority_score", 0) >= priority_threshold]
        
        # Sort by priority score (highest first)
        return sorted(filtered_incidents, key=lambda x: x.get("priority_score", 0), reverse=True)
    
    async def get_processing_statistics(self) -> Dict[str, Any]:
        """Get incident processing statistics"""
        queue_by_severity = {}
        queue_by_category = {}
        
        for incident in self.incident_queue:
            severity = incident.get("severity", "unknown")
            category = incident.get("category", "unknown")
            
            queue_by_severity[severity] = queue_by_severity.get(severity, 0) + 1
            queue_by_category[category] = queue_by_category.get(category, 0) + 1
        
        return {
            "processing_stats": self.processing_stats,
            "queue_length": len(self.incident_queue),
            "queue_by_severity": queue_by_severity,
            "queue_by_category": queue_by_category,
            "average_priority_score": sum(i.get("priority_score", 0) for i in self.incident_queue) / len(self.incident_queue) if self.incident_queue else 0
        }

def create_incident_intake_processor() -> IncidentIntakeProcessor:
    """Factory function to create incident intake processor"""
    return IncidentIntakeProcessor()

# Example usage for testing
async def main():
    processor = create_incident_intake_processor()
    
    # Example incident data
    sample_incident = {
        "timestamp": datetime.now().isoformat(),
        "source": "malware_agent",
        "description": "Critical malware detected on endpoint - ransomware suspected",
        "alert_data": {
            "alert_type": "malware_detection",
            "severity": "critical",
            "confidence": 0.95,
            "affected_hosts": ["DESKTOP-001", "DESKTOP-002"],
            "file_hash": "a1b2c3d4e5f6...",
            "source_ip": "192.168.1.100"
        }
    }
    
    result = await processor.receive_incident(sample_incident, "malware_agent")
    print(f"Incident processed: {result}")
    
    stats = await processor.get_processing_statistics()
    print(f"Processing statistics: {stats}")

if __name__ == "__main__":
    asyncio.run(main())
