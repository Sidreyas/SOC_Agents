"""
Evidence Correlation Module
State 2: Evidence Collection, Analysis, and Cross-Reference
Correlates evidence from multiple sources and agents
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from datetime import datetime, timedelta
import json
import hashlib
from collections import defaultdict
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger(__name__)

class EvidenceType(Enum):
    """Types of evidence that can be collected"""
    NETWORK_TRAFFIC = "network_traffic"
    FILE_HASH = "file_hash"
    EMAIL_HEADERS = "email_headers"
    LOG_ENTRY = "log_entry"
    PROCESS_EXECUTION = "process_execution"
    REGISTRY_MODIFICATION = "registry_modification"
    DNS_QUERY = "dns_query"
    USER_ACTIVITY = "user_activity"
    SYSTEM_ARTIFACT = "system_artifact"
    THREAT_INTELLIGENCE = "threat_intelligence"
    NETWORK_CONNECTION = "network_connection"
    FILE_MODIFICATION = "file_modification"

class EvidenceConfidence(Enum):
    """Evidence confidence levels"""
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNCERTAIN = "uncertain"

class CorrelationStrength(Enum):
    """Strength of correlation between evidence pieces"""
    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"
    NONE = "none"

@dataclass
class EvidenceItem:
    """Individual piece of evidence"""
    evidence_id: str
    incident_id: str
    source_agent: str
    evidence_type: str
    timestamp: datetime
    data: Dict[str, Any]
    confidence: str
    metadata: Dict[str, Any]
    tags: List[str]
    hash_value: str
    collection_method: str
    chain_of_custody: List[Dict[str, Any]]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert evidence item to dictionary"""
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        return result

class EvidenceCorrelator:
    """
    Correlates evidence from multiple sources and identifies patterns
    """
    
    def __init__(self):
        self.evidence_store = []
        self.correlation_rules = self._initialize_correlation_rules()
        self.evidence_graph = defaultdict(set)
        self.correlation_cache = {}
        self.processing_stats = {
            "total_evidence_processed": 0,
            "correlations_found": 0,
            "high_confidence_correlations": 0,
            "evidence_by_type": defaultdict(int),
            "evidence_by_agent": defaultdict(int)
        }
    
    def _initialize_correlation_rules(self) -> List[Dict[str, Any]]:
        """Initialize correlation rules for evidence analysis"""
        return [
            {
                "rule_id": "ip_correlation",
                "name": "IP Address Correlation",
                "description": "Correlate evidence containing same IP addresses",
                "evidence_types": ["network_traffic", "log_entry", "dns_query", "network_connection"],
                "correlation_fields": ["source_ip", "destination_ip", "remote_ip"],
                "strength": CorrelationStrength.STRONG.value,
                "time_window_hours": 24
            },
            {
                "rule_id": "hash_correlation",
                "name": "File Hash Correlation",
                "description": "Correlate evidence with matching file hashes",
                "evidence_types": ["file_hash", "system_artifact", "file_modification"],
                "correlation_fields": ["file_hash", "md5", "sha256", "sha1"],
                "strength": CorrelationStrength.STRONG.value,
                "time_window_hours": 168  # 7 days
            },
            {
                "rule_id": "user_correlation",
                "name": "User Activity Correlation",
                "description": "Correlate evidence by user accounts",
                "evidence_types": ["user_activity", "log_entry", "process_execution"],
                "correlation_fields": ["username", "user_id", "account_name"],
                "strength": CorrelationStrength.MODERATE.value,
                "time_window_hours": 72
            },
            {
                "rule_id": "hostname_correlation",
                "name": "Hostname Correlation",
                "description": "Correlate evidence from same hosts",
                "evidence_types": ["process_execution", "file_modification", "registry_modification", "system_artifact"],
                "correlation_fields": ["hostname", "computer_name", "host"],
                "strength": CorrelationStrength.MODERATE.value,
                "time_window_hours": 48
            },
            {
                "rule_id": "domain_correlation",
                "name": "Domain Correlation",
                "description": "Correlate evidence containing same domains",
                "evidence_types": ["dns_query", "network_traffic", "email_headers"],
                "correlation_fields": ["domain", "fqdn", "sender_domain"],
                "strength": CorrelationStrength.MODERATE.value,
                "time_window_hours": 48
            },
            {
                "rule_id": "temporal_correlation",
                "name": "Temporal Correlation",
                "description": "Correlate evidence occurring in close time proximity",
                "evidence_types": ["all"],
                "correlation_fields": [],
                "strength": CorrelationStrength.WEAK.value,
                "time_window_minutes": 30
            },
            {
                "rule_id": "ti_correlation",
                "name": "Threat Intelligence Correlation",
                "description": "Correlate evidence with threat intelligence indicators",
                "evidence_types": ["threat_intelligence"],
                "correlation_fields": ["ioc_value", "indicator"],
                "strength": CorrelationStrength.STRONG.value,
                "time_window_hours": 24
            }
        ]
    
    async def collect_evidence(self, incident_id: str, evidence_data: Dict[str, Any], 
                             source_agent: str) -> Dict[str, Any]:
        """
        Collect and process evidence for an incident
        
        Args:
            incident_id: ID of the incident
            evidence_data: Raw evidence data
            source_agent: Agent that collected the evidence
            
        Returns:
            Evidence collection result
        """
        try:
            # Validate evidence data
            validation_result = await self._validate_evidence(evidence_data)
            
            if not validation_result["valid"]:
                logger.error(f"Evidence validation failed: {validation_result['errors']}")
                return {
                    "status": "validation_failed",
                    "errors": validation_result["errors"]
                }
            
            # Create evidence item
            evidence_item = await self._create_evidence_item(
                incident_id, evidence_data, source_agent
            )
            
            # Store evidence
            self.evidence_store.append(evidence_item)
            
            # Update processing statistics
            self._update_processing_stats(evidence_item)
            
            # Perform immediate correlation analysis
            correlations = await self._analyze_correlations(evidence_item)
            
            # Update evidence graph
            await self._update_evidence_graph(evidence_item, correlations)
            
            logger.info(f"Evidence {evidence_item.evidence_id} collected for incident {incident_id}")
            
            return {
                "status": "collected",
                "evidence_id": evidence_item.evidence_id,
                "correlations_found": len(correlations),
                "confidence": evidence_item.confidence,
                "evidence_type": evidence_item.evidence_type
            }
            
        except Exception as e:
            logger.error(f"Error collecting evidence: {str(e)}")
            return {
                "status": "collection_error",
                "error": str(e)
            }
    
    async def _validate_evidence(self, evidence_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate evidence data structure"""
        errors = []
        
        # Required fields
        required_fields = ["type", "data", "timestamp"]
        
        for field in required_fields:
            if field not in evidence_data:
                errors.append(f"Missing required field: {field}")
        
        # Validate evidence type
        if "type" in evidence_data:
            if evidence_data["type"] not in [e.value for e in EvidenceType]:
                errors.append(f"Invalid evidence type: {evidence_data['type']}")
        
        # Validate timestamp
        if "timestamp" in evidence_data:
            try:
                if isinstance(evidence_data["timestamp"], str):
                    datetime.fromisoformat(evidence_data["timestamp"].replace('Z', '+00:00'))
            except ValueError:
                errors.append("Invalid timestamp format")
        
        # Validate data structure
        if "data" in evidence_data and not isinstance(evidence_data["data"], dict):
            errors.append("Evidence data must be a dictionary")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors
        }
    
    async def _create_evidence_item(self, incident_id: str, evidence_data: Dict[str, Any], 
                                  source_agent: str) -> EvidenceItem:
        """Create standardized evidence item"""
        evidence_id = self._generate_evidence_id(evidence_data)
        
        # Extract metadata
        metadata = evidence_data.get("metadata", {})
        metadata.update({
            "collection_time": datetime.now().isoformat(),
            "source_agent": source_agent,
            "incident_id": incident_id
        })
        
        # Calculate confidence
        confidence = self._calculate_evidence_confidence(evidence_data)
        
        # Generate hash for integrity
        hash_value = self._calculate_evidence_hash(evidence_data)
        
        # Create chain of custody entry
        chain_of_custody = [{
            "timestamp": datetime.now().isoformat(),
            "action": "collected",
            "agent": source_agent,
            "incident_id": incident_id,
            "hash": hash_value
        }]
        
        # Extract tags
        tags = self._extract_evidence_tags(evidence_data)
        
        return EvidenceItem(
            evidence_id=evidence_id,
            incident_id=incident_id,
            source_agent=source_agent,
            evidence_type=evidence_data["type"],
            timestamp=datetime.fromisoformat(evidence_data["timestamp"].replace('Z', '+00:00')),
            data=evidence_data["data"],
            confidence=confidence,
            metadata=metadata,
            tags=tags,
            hash_value=hash_value,
            collection_method=evidence_data.get("collection_method", "automated"),
            chain_of_custody=chain_of_custody
        )
    
    def _generate_evidence_id(self, evidence_data: Dict[str, Any]) -> str:
        """Generate unique evidence ID"""
        content = json.dumps(evidence_data, sort_keys=True)
        return f"ev_{hashlib.md5(content.encode()).hexdigest()[:16]}"
    
    def _calculate_evidence_confidence(self, evidence_data: Dict[str, Any]) -> str:
        """Calculate confidence level for evidence"""
        confidence_indicators = 0
        
        # Check for high-confidence indicators
        data = evidence_data.get("data", {})
        
        # Source reliability
        if evidence_data.get("source_reliability", "unknown") in ["high", "verified"]:
            confidence_indicators += 2
        
        # Data completeness
        if len(data) >= 5:  # Rich data
            confidence_indicators += 1
        
        # Verification status
        if evidence_data.get("verified", False):
            confidence_indicators += 2
        
        # Correlation with other evidence
        if evidence_data.get("correlated_count", 0) > 0:
            confidence_indicators += 1
        
        # Map to confidence levels
        if confidence_indicators >= 5:
            return EvidenceConfidence.CONFIRMED.value
        elif confidence_indicators >= 3:
            return EvidenceConfidence.HIGH.value
        elif confidence_indicators >= 2:
            return EvidenceConfidence.MEDIUM.value
        elif confidence_indicators >= 1:
            return EvidenceConfidence.LOW.value
        else:
            return EvidenceConfidence.UNCERTAIN.value
    
    def _calculate_evidence_hash(self, evidence_data: Dict[str, Any]) -> str:
        """Calculate hash for evidence integrity"""
        # Create deterministic representation
        content = json.dumps(evidence_data, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()
    
    def _extract_evidence_tags(self, evidence_data: Dict[str, Any]) -> List[str]:
        """Extract tags from evidence data"""
        tags = set()
        
        # Add type-based tags
        evidence_type = evidence_data.get("type", "")
        tags.add(f"type_{evidence_type}")
        
        # Add data-based tags
        data = evidence_data.get("data", {})
        
        # Network-related tags
        if "ip" in str(data).lower():
            tags.add("network_indicator")
        
        if "domain" in str(data).lower():
            tags.add("domain_indicator")
        
        # File-related tags
        if "hash" in str(data).lower() or "file" in str(data).lower():
            tags.add("file_indicator")
        
        # User-related tags
        if "user" in str(data).lower() or "account" in str(data).lower():
            tags.add("user_indicator")
        
        # Process-related tags
        if "process" in str(data).lower() or "command" in str(data).lower():
            tags.add("process_indicator")
        
        # Add custom tags from metadata
        custom_tags = evidence_data.get("tags", [])
        tags.update(custom_tags)
        
        return list(tags)
    
    def _update_processing_stats(self, evidence_item: EvidenceItem):
        """Update processing statistics"""
        self.processing_stats["total_evidence_processed"] += 1
        self.processing_stats["evidence_by_type"][evidence_item.evidence_type] += 1
        self.processing_stats["evidence_by_agent"][evidence_item.source_agent] += 1
    
    async def _analyze_correlations(self, new_evidence: EvidenceItem) -> List[Dict[str, Any]]:
        """Analyze correlations for new evidence"""
        correlations = []
        
        # Check against existing evidence
        for existing_evidence in self.evidence_store:
            if existing_evidence.evidence_id == new_evidence.evidence_id:
                continue
            
            # Apply correlation rules
            for rule in self.correlation_rules:
                correlation = await self._apply_correlation_rule(
                    rule, new_evidence, existing_evidence
                )
                
                if correlation:
                    correlations.append(correlation)
                    
                    # Update statistics
                    self.processing_stats["correlations_found"] += 1
                    
                    if correlation["strength"] in ["strong", "high"]:
                        self.processing_stats["high_confidence_correlations"] += 1
        
        return correlations
    
    async def _apply_correlation_rule(self, rule: Dict[str, Any], 
                                    evidence1: EvidenceItem, 
                                    evidence2: EvidenceItem) -> Optional[Dict[str, Any]]:
        """Apply a specific correlation rule to two evidence items"""
        
        # Check if evidence types match rule
        if rule["evidence_types"] != ["all"]:
            if (evidence1.evidence_type not in rule["evidence_types"] or 
                evidence2.evidence_type not in rule["evidence_types"]):
                return None
        
        # Check time window
        time_diff = abs((evidence1.timestamp - evidence2.timestamp).total_seconds())
        
        if "time_window_hours" in rule:
            max_time_diff = rule["time_window_hours"] * 3600
        elif "time_window_minutes" in rule:
            max_time_diff = rule["time_window_minutes"] * 60
        else:
            max_time_diff = 86400  # Default 24 hours
        
        if time_diff > max_time_diff:
            return None
        
        # Apply specific correlation logic
        correlation_score = 0.0
        matching_fields = []
        
        if rule["rule_id"] == "temporal_correlation":
            # Special handling for temporal correlation
            correlation_score = self._calculate_temporal_correlation(evidence1, evidence2)
        else:
            # Field-based correlation
            correlation_score, matching_fields = self._calculate_field_correlation(
                rule, evidence1, evidence2
            )
        
        if correlation_score > 0.5:  # Threshold for valid correlation
            return {
                "correlation_id": f"corr_{evidence1.evidence_id}_{evidence2.evidence_id}",
                "rule_id": rule["rule_id"],
                "evidence_1": evidence1.evidence_id,
                "evidence_2": evidence2.evidence_id,
                "strength": rule["strength"],
                "score": correlation_score,
                "matching_fields": matching_fields,
                "time_difference_seconds": time_diff,
                "description": f"Correlation found via {rule['name']}",
                "timestamp": datetime.now().isoformat()
            }
        
        return None
    
    def _calculate_temporal_correlation(self, evidence1: EvidenceItem, 
                                      evidence2: EvidenceItem) -> float:
        """Calculate temporal correlation score"""
        time_diff = abs((evidence1.timestamp - evidence2.timestamp).total_seconds())
        
        # Score decreases with time difference
        if time_diff <= 300:  # 5 minutes
            return 0.9
        elif time_diff <= 1800:  # 30 minutes
            return 0.7
        elif time_diff <= 3600:  # 1 hour
            return 0.5
        else:
            return 0.3
    
    def _calculate_field_correlation(self, rule: Dict[str, Any], 
                                   evidence1: EvidenceItem, 
                                   evidence2: EvidenceItem) -> Tuple[float, List[str]]:
        """Calculate field-based correlation score"""
        correlation_fields = rule["correlation_fields"]
        matching_fields = []
        total_matches = 0
        
        for field in correlation_fields:
            value1 = self._extract_field_value(evidence1.data, field)
            value2 = self._extract_field_value(evidence2.data, field)
            
            if value1 and value2 and self._values_match(value1, value2):
                matching_fields.append(field)
                total_matches += 1
        
        # Calculate score based on match ratio
        if correlation_fields:
            score = total_matches / len(correlation_fields)
        else:
            score = 0.0
        
        # Boost score for high-value matches
        high_value_fields = ["file_hash", "sha256", "md5", "source_ip", "destination_ip"]
        for field in matching_fields:
            if field in high_value_fields:
                score += 0.2
        
        return min(score, 1.0), matching_fields
    
    def _extract_field_value(self, data: Dict[str, Any], field: str) -> Optional[str]:
        """Extract field value from evidence data"""
        # Try direct field access
        if field in data:
            return str(data[field]).lower().strip()
        
        # Try nested access
        for key, value in data.items():
            if isinstance(value, dict) and field in value:
                return str(value[field]).lower().strip()
        
        # Try partial matches
        for key, value in data.items():
            if field.lower() in key.lower():
                return str(value).lower().strip()
        
        return None
    
    def _values_match(self, value1: str, value2: str) -> bool:
        """Check if two values match"""
        if not value1 or not value2:
            return False
        
        # Exact match
        if value1 == value2:
            return True
        
        # IP address normalization
        if self._is_ip_address(value1) and self._is_ip_address(value2):
            return self._normalize_ip(value1) == self._normalize_ip(value2)
        
        # Hash normalization
        if self._is_hash(value1) and self._is_hash(value2):
            return value1.lower() == value2.lower()
        
        return False
    
    def _is_ip_address(self, value: str) -> bool:
        """Check if value is an IP address"""
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ip_pattern, value))
    
    def _normalize_ip(self, ip: str) -> str:
        """Normalize IP address"""
        return ip.strip()
    
    def _is_hash(self, value: str) -> bool:
        """Check if value is a hash"""
        import re
        # Check for common hash formats
        hash_patterns = [
            r'^[a-fA-F0-9]{32}$',  # MD5
            r'^[a-fA-F0-9]{40}$',  # SHA1
            r'^[a-fA-F0-9]{64}$',  # SHA256
        ]
        
        return any(re.match(pattern, value) for pattern in hash_patterns)
    
    async def _update_evidence_graph(self, evidence_item: EvidenceItem, 
                                   correlations: List[Dict[str, Any]]):
        """Update evidence correlation graph"""
        evidence_id = evidence_item.evidence_id
        
        for correlation in correlations:
            other_evidence_id = (correlation["evidence_2"] if correlation["evidence_1"] == evidence_id 
                               else correlation["evidence_1"])
            
            self.evidence_graph[evidence_id].add(other_evidence_id)
            self.evidence_graph[other_evidence_id].add(evidence_id)
    
    async def get_incident_evidence(self, incident_id: str, 
                                  evidence_type: str = None) -> List[Dict[str, Any]]:
        """Get all evidence for an incident"""
        evidence_list = []
        
        for evidence in self.evidence_store:
            if evidence.incident_id == incident_id:
                if evidence_type is None or evidence.evidence_type == evidence_type:
                    evidence_list.append(evidence.to_dict())
        
        # Sort by timestamp
        return sorted(evidence_list, key=lambda x: x["timestamp"])
    
    async def get_evidence_correlations(self, evidence_id: str) -> List[Dict[str, Any]]:
        """Get correlations for specific evidence"""
        correlations = []
        
        for correlation in self.correlation_cache.values():
            if (correlation["evidence_1"] == evidence_id or 
                correlation["evidence_2"] == evidence_id):
                correlations.append(correlation)
        
        return correlations
    
    async def generate_correlation_report(self, incident_id: str) -> Dict[str, Any]:
        """Generate comprehensive correlation report for incident"""
        incident_evidence = await self.get_incident_evidence(incident_id)
        
        # Build correlation network
        correlation_network = self._build_correlation_network(incident_evidence)
        
        # Identify evidence clusters
        clusters = self._identify_evidence_clusters(correlation_network)
        
        # Calculate correlation statistics
        stats = self._calculate_correlation_statistics(incident_evidence, correlation_network)
        
        return {
            "incident_id": incident_id,
            "total_evidence_items": len(incident_evidence),
            "correlation_network": correlation_network,
            "evidence_clusters": clusters,
            "correlation_statistics": stats,
            "high_confidence_correlations": [
                corr for corr in correlation_network 
                if corr.get("strength") in ["strong", "confirmed"]
            ],
            "timeline": self._build_evidence_timeline(incident_evidence),
            "key_indicators": self._extract_key_indicators(incident_evidence),
            "report_generated": datetime.now().isoformat()
        }
    
    def _build_correlation_network(self, evidence_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build correlation network from evidence"""
        network = []
        evidence_ids = [e["evidence_id"] for e in evidence_list]
        
        for correlation in self.correlation_cache.values():
            if (correlation["evidence_1"] in evidence_ids and 
                correlation["evidence_2"] in evidence_ids):
                network.append(correlation)
        
        return network
    
    def _identify_evidence_clusters(self, correlation_network: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify clusters of highly correlated evidence"""
        # Simple clustering based on strong correlations
        clusters = []
        processed_evidence = set()
        
        for correlation in correlation_network:
            if correlation["strength"] in ["strong", "confirmed"]:
                evidence_1 = correlation["evidence_1"]
                evidence_2 = correlation["evidence_2"]
                
                if evidence_1 not in processed_evidence and evidence_2 not in processed_evidence:
                    cluster = {
                        "cluster_id": len(clusters) + 1,
                        "evidence_items": [evidence_1, evidence_2],
                        "correlation_strength": correlation["strength"],
                        "cluster_type": self._determine_cluster_type(correlation)
                    }
                    clusters.append(cluster)
                    processed_evidence.update([evidence_1, evidence_2])
        
        return clusters
    
    def _determine_cluster_type(self, correlation: Dict[str, Any]) -> str:
        """Determine the type of evidence cluster"""
        rule_id = correlation.get("rule_id", "")
        
        cluster_type_mapping = {
            "ip_correlation": "network_activity",
            "hash_correlation": "file_activity", 
            "user_correlation": "user_activity",
            "hostname_correlation": "host_activity",
            "domain_correlation": "domain_activity",
            "ti_correlation": "threat_intelligence"
        }
        
        return cluster_type_mapping.get(rule_id, "general")
    
    def _calculate_correlation_statistics(self, evidence_list: List[Dict[str, Any]], 
                                        correlation_network: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate correlation statistics"""
        if not evidence_list:
            return {}
        
        total_evidence = len(evidence_list)
        total_correlations = len(correlation_network)
        
        correlation_ratio = total_correlations / total_evidence if total_evidence > 0 else 0
        
        strength_distribution = {}
        for correlation in correlation_network:
            strength = correlation.get("strength", "unknown")
            strength_distribution[strength] = strength_distribution.get(strength, 0) + 1
        
        return {
            "total_evidence": total_evidence,
            "total_correlations": total_correlations,
            "correlation_ratio": correlation_ratio,
            "strength_distribution": strength_distribution,
            "average_correlations_per_evidence": total_correlations / total_evidence if total_evidence > 0 else 0
        }
    
    def _build_evidence_timeline(self, evidence_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build chronological timeline of evidence"""
        timeline = []
        
        for evidence in sorted(evidence_list, key=lambda x: x["timestamp"]):
            timeline.append({
                "timestamp": evidence["timestamp"],
                "evidence_id": evidence["evidence_id"],
                "evidence_type": evidence["evidence_type"],
                "source_agent": evidence["source_agent"],
                "confidence": evidence["confidence"],
                "summary": self._generate_evidence_summary(evidence)
            })
        
        return timeline
    
    def _generate_evidence_summary(self, evidence: Dict[str, Any]) -> str:
        """Generate brief summary of evidence"""
        evidence_type = evidence.get("evidence_type", "unknown")
        data = evidence.get("data", {})
        
        # Type-specific summaries
        if evidence_type == "network_traffic":
            src_ip = data.get("source_ip", "unknown")
            dst_ip = data.get("destination_ip", "unknown")
            return f"Network connection from {src_ip} to {dst_ip}"
        
        elif evidence_type == "file_hash":
            file_hash = data.get("hash", data.get("sha256", "unknown"))[:16]
            filename = data.get("filename", "unknown file")
            return f"File hash {file_hash}... for {filename}"
        
        elif evidence_type == "process_execution":
            process_name = data.get("process_name", "unknown")
            command_line = data.get("command_line", "")[:50]
            return f"Process {process_name}: {command_line}..."
        
        else:
            # Generic summary
            first_key = list(data.keys())[0] if data else "data"
            first_value = str(data.get(first_key, ""))[:30] if data else "no data"
            return f"{evidence_type}: {first_key}={first_value}..."
    
    def _extract_key_indicators(self, evidence_list: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Extract key indicators from evidence"""
        indicators = {
            "ip_addresses": set(),
            "file_hashes": set(),
            "domains": set(),
            "user_accounts": set(),
            "hostnames": set(),
            "processes": set()
        }
        
        for evidence in evidence_list:
            data = evidence.get("data", {})
            
            # Extract IPs
            for key, value in data.items():
                if "ip" in key.lower() and self._is_ip_address(str(value)):
                    indicators["ip_addresses"].add(str(value))
                
                if "hash" in key.lower() and self._is_hash(str(value)):
                    indicators["file_hashes"].add(str(value))
                
                if "domain" in key.lower():
                    indicators["domains"].add(str(value))
                
                if "user" in key.lower() or "account" in key.lower():
                    indicators["user_accounts"].add(str(value))
                
                if "host" in key.lower() or "computer" in key.lower():
                    indicators["hostnames"].add(str(value))
                
                if "process" in key.lower():
                    indicators["processes"].add(str(value))
        
        # Convert sets to lists
        return {key: list(value_set) for key, value_set in indicators.items()}
    
    async def get_processing_statistics(self) -> Dict[str, Any]:
        """Get evidence processing statistics"""
        return {
            "processing_stats": self.processing_stats,
            "evidence_store_size": len(self.evidence_store),
            "correlation_cache_size": len(self.correlation_cache),
            "evidence_graph_nodes": len(self.evidence_graph),
            "correlation_rules_count": len(self.correlation_rules)
        }

def create_evidence_correlator() -> EvidenceCorrelator:
    """Factory function to create evidence correlator"""
    return EvidenceCorrelator()

# Example usage
async def main():
    correlator = create_evidence_correlator()
    
    # Example evidence collection
    sample_evidence = {
        "type": "network_traffic",
        "timestamp": datetime.now().isoformat(),
        "data": {
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.50",
            "port": 443,
            "protocol": "HTTPS",
            "bytes_transferred": 1024
        },
        "metadata": {
            "source_reliability": "high",
            "verified": True
        }
    }
    
    result = await correlator.collect_evidence("incident_001", sample_evidence, "network_agent")
    print(f"Evidence collection result: {result}")
    
    # Generate correlation report
    report = await correlator.generate_correlation_report("incident_001")
    print(f"Correlation report: {report}")

if __name__ == "__main__":
    asyncio.run(main())
