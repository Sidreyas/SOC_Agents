"""
Permission Analyzer Module
State 1: Permission Analysis
Extracts permission-related entities and analyzes Azure AD audit logs and Azure Resource Manager activity
"""

import logging
from typing import Dict, Any, List, Tuple
from datetime import datetime, timedelta
import json

logger = logging.getLogger(__name__)

class PermissionAnalyzer:
    """
    Analyzes permission-related incidents and extracts relevant entities
    Handles privilege escalation attempts, role assignments, and resource creation
    """
    
    def __init__(self):
        self.permission_entities = {}
        self.azure_ad_client = None  # Will be initialized with actual Azure AD client
        self.arm_client = None       # Will be initialized with Azure Resource Manager client
        
    def extract_permission_entities(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract permission-related entities from incident data
        
        Returns:
            Dictionary containing user accounts, roles, resources, and administrative actions
        """
        logger.info(f"Extracting permission entities from incident {incident_data.get('incident_id')}")
        
        entities = {
            "user_accounts": [],
            "roles": [],
            "resources": [],
            "administrative_actions": [],
            "time_window": {
                "start": None,
                "end": None
            }
        }
        
        # Extract user accounts from incident entities
        for entity in incident_data.get("entities", []):
            if entity.get("type") == "user":
                entities["user_accounts"].append({
                    "upn": entity.get("value"),
                    "object_id": entity.get("object_id"),
                    "display_name": entity.get("display_name")
                })
            elif entity.get("type") == "role":
                entities["roles"].append({
                    "role_name": entity.get("value"),
                    "role_id": entity.get("role_id"),
                    "scope": entity.get("scope")
                })
            elif entity.get("type") == "resource":
                entities["resources"].append({
                    "resource_name": entity.get("value"),
                    "resource_type": entity.get("resource_type"),
                    "subscription_id": entity.get("subscription_id")
                })
        
        # Set time window for analysis (last 24 hours by default)
        incident_time = datetime.fromisoformat(
            incident_data.get("timestamp", datetime.now().isoformat())
        )
        entities["time_window"]["start"] = incident_time - timedelta(hours=24)
        entities["time_window"]["end"] = incident_time + timedelta(hours=1)
        
        # Extract administrative actions from alert rules
        for rule in incident_data.get("alert_rules", []):
            if any(keyword in rule.lower() for keyword in ["role", "permission", "privilege", "admin"]):
                entities["administrative_actions"].append({
                    "action_type": self._classify_admin_action(rule),
                    "rule_name": rule,
                    "severity": incident_data.get("severity", "Medium")
                })
        
        logger.info(f"Extracted {len(entities['user_accounts'])} users, {len(entities['roles'])} roles, {len(entities['resources'])} resources")
        return entities
    
    def analyze_azure_ad_logs(self, entities: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze Azure AD audit logs for permission-related activities
        
        Returns:
            Analysis results including role assignments, permission changes, and audit events
        """
        logger.info("Analyzing Azure AD audit logs for permission activities")
        
        analysis_result = {
            "role_assignments": [],
            "permission_changes": [],
            "audit_events": [],
            "suspicious_patterns": []
        }
        
        # Mock Azure AD log analysis (replace with actual Azure AD API calls)
        for user in entities["user_accounts"]:
            # Simulate role assignment analysis
            role_assignments = self._mock_azure_ad_role_query(
                user["upn"], 
                entities["time_window"]["start"],
                entities["time_window"]["end"]
            )
            analysis_result["role_assignments"].extend(role_assignments)
            
            # Simulate permission change analysis
            permission_changes = self._mock_azure_ad_permission_query(
                user["upn"],
                entities["time_window"]["start"],
                entities["time_window"]["end"]
            )
            analysis_result["permission_changes"].extend(permission_changes)
        
        # Analyze patterns for suspicious activity
        analysis_result["suspicious_patterns"] = self._identify_suspicious_patterns(
            analysis_result["role_assignments"], 
            analysis_result["permission_changes"]
        )
        
        logger.info(f"Found {len(analysis_result['role_assignments'])} role assignments, {len(analysis_result['permission_changes'])} permission changes")
        return analysis_result
    
    def analyze_arm_activity(self, entities: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze Azure Resource Manager activity for resource creation and modifications
        
        Returns:
            ARM activity analysis including resource operations and policy violations
        """
        logger.info("Analyzing Azure Resource Manager activity")
        
        arm_analysis = {
            "resource_operations": [],
            "policy_violations": [],
            "creation_events": [],
            "modification_events": []
        }
        
        # Mock ARM activity analysis (replace with actual ARM API calls)
        for resource in entities["resources"]:
            # Simulate resource operation analysis
            operations = self._mock_arm_operation_query(
                resource["resource_name"],
                entities["time_window"]["start"],
                entities["time_window"]["end"]
            )
            arm_analysis["resource_operations"].extend(operations)
            
            # Check for policy violations
            violations = self._mock_policy_violation_check(resource)
            arm_analysis["policy_violations"].extend(violations)
        
        logger.info(f"Found {len(arm_analysis['resource_operations'])} ARM operations, {len(arm_analysis['policy_violations'])} policy violations")
        return arm_analysis
    
    def _classify_admin_action(self, rule_name: str) -> str:
        """Classify the type of administrative action based on rule name"""
        rule_lower = rule_name.lower()
        
        if "role" in rule_lower and "assign" in rule_lower:
            return "role_assignment"
        elif "privilege" in rule_lower or "elevat" in rule_lower:
            return "privilege_escalation"
        elif "resource" in rule_lower and "creat" in rule_lower:
            return "resource_creation"
        elif "permission" in rule_lower:
            return "permission_change"
        else:
            return "administrative_action"
    
    def _mock_azure_ad_role_query(self, user_upn: str, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Mock Azure AD role assignment query"""
        return [
            {
                "user": user_upn,
                "role": "Global Administrator",
                "assignment_time": start_time + timedelta(hours=2),
                "assigned_by": "admin@company.com",
                "assignment_type": "permanent",
                "scope": "directory"
            },
            {
                "user": user_upn,
                "role": "Contributor",
                "assignment_time": start_time + timedelta(hours=5),
                "assigned_by": "manager@company.com",
                "assignment_type": "eligible",
                "scope": "/subscriptions/12345"
            }
        ]
    
    def _mock_azure_ad_permission_query(self, user_upn: str, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Mock Azure AD permission change query"""
        return [
            {
                "user": user_upn,
                "permission": "Directory.ReadWrite.All",
                "change_type": "granted",
                "change_time": start_time + timedelta(hours=3),
                "changed_by": "admin@company.com",
                "application": "Microsoft Graph"
            }
        ]
    
    def _mock_arm_operation_query(self, resource_name: str, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Mock ARM operation query"""
        return [
            {
                "resource": resource_name,
                "operation": "Microsoft.Compute/virtualMachines/write",
                "operation_time": start_time + timedelta(hours=4),
                "caller": "user@company.com",
                "status": "Succeeded",
                "properties": {
                    "vmSize": "Standard_D4s_v3",
                    "location": "eastus"
                }
            }
        ]
    
    def _mock_policy_violation_check(self, resource: Dict[str, Any]) -> List[Dict]:
        """Mock policy violation check"""
        return [
            {
                "resource": resource["resource_name"],
                "policy": "Require specific VM sizes",
                "violation_type": "non_compliant_vm_size",
                "severity": "Medium",
                "remediation": "Resize VM to compliant size"
            }
        ]
    
    def _identify_suspicious_patterns(self, role_assignments: List[Dict], permission_changes: List[Dict]) -> List[Dict]:
        """Identify suspicious patterns in role assignments and permission changes"""
        patterns = []
        
        # Pattern 1: Multiple high-privilege role assignments in short time
        admin_roles = [ra for ra in role_assignments if "admin" in ra.get("role", "").lower()]
        if len(admin_roles) > 1:
            patterns.append({
                "pattern": "multiple_admin_roles",
                "description": "Multiple administrative roles assigned in short timeframe",
                "severity": "High",
                "count": len(admin_roles)
            })
        
        # Pattern 2: Permission escalation outside business hours
        for change in permission_changes:
            change_time = change.get("change_time")
            if change_time and (change_time.hour < 7 or change_time.hour > 19):
                patterns.append({
                    "pattern": "after_hours_permission_change",
                    "description": "Permission change outside business hours",
                    "severity": "Medium",
                    "time": change_time
                })
        
        return patterns
