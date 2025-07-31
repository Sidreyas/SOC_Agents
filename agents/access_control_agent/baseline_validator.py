"""
Baseline Validator Module
State 2: Baseline Validation
Queries historical user behavior patterns and validates against organizational policies
"""

import logging
from typing import Dict, Any, List, Tuple
from datetime import datetime, timedelta
import json

logger = logging.getLogger(__name__)

class BaselineValidator:
    """
    Validates permission changes against historical baselines and organizational policies
    Establishes normal permission baselines and checks RBAC policy compliance
    """
    
    def __init__(self):
        self.user_baselines = {}
        self.organizational_policies = {}
        self.rbac_policies = {}
        self.cmdb_client = None  # Will be initialized with CMDB client
        
    def establish_user_baselines(self, user_accounts: List[Dict[str, Any]], time_window: Dict[str, datetime]) -> Dict[str, Any]:
        """
        Establish normal permission baselines for users based on historical data
        
        Returns:
            Dictionary containing baseline patterns for each user
        """
        logger.info(f"Establishing baselines for {len(user_accounts)} users")
        
        baselines = {}
        
        for user in user_accounts:
            user_upn = user["upn"]
            logger.info(f"Analyzing baseline for user: {user_upn}")
            
            # Query historical role assignments (look back 90 days)
            historical_start = time_window["start"] - timedelta(days=90)
            historical_roles = self._query_historical_roles(user_upn, historical_start, time_window["start"])
            
            # Query historical permission patterns
            historical_permissions = self._query_historical_permissions(user_upn, historical_start, time_window["start"])
            
            # Query historical resource access patterns
            resource_access = self._query_historical_resource_access(user_upn, historical_start, time_window["start"])
            
            baselines[user_upn] = {
                "typical_roles": self._analyze_typical_roles(historical_roles),
                "permission_patterns": self._analyze_permission_patterns(historical_permissions),
                "resource_access_patterns": self._analyze_resource_patterns(resource_access),
                "change_frequency": self._calculate_change_frequency(historical_roles, historical_permissions),
                "typical_hours": self._analyze_typical_hours(historical_roles + historical_permissions),
                "baseline_established": datetime.now()
            }
        
        logger.info(f"Established baselines for {len(baselines)} users")
        return baselines
    
    def validate_rbac_policies(self, role_assignments: List[Dict[str, Any]], permission_changes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate role assignments and permission changes against RBAC policies
        
        Returns:
            Validation results including policy violations and compliance status
        """
        logger.info("Validating against RBAC policies")
        
        validation_result = {
            "policy_violations": [],
            "compliance_status": "compliant",
            "risk_level": "low",
            "violations_by_policy": {},
            "recommendations": []
        }
        
        # Load organizational RBAC policies
        rbac_policies = self._load_rbac_policies()
        
        # Validate role assignments
        for assignment in role_assignments:
            violations = self._validate_role_assignment(assignment, rbac_policies)
            validation_result["policy_violations"].extend(violations)
        
        # Validate permission changes
        for change in permission_changes:
            violations = self._validate_permission_change(change, rbac_policies)
            validation_result["policy_violations"].extend(violations)
        
        # Determine overall compliance status
        if validation_result["policy_violations"]:
            violation_count = len(validation_result["policy_violations"])
            high_severity_violations = [v for v in validation_result["policy_violations"] if v.get("severity") == "High"]
            
            if high_severity_violations:
                validation_result["compliance_status"] = "non_compliant"
                validation_result["risk_level"] = "high"
            elif violation_count > 3:
                validation_result["compliance_status"] = "partially_compliant" 
                validation_result["risk_level"] = "medium"
            else:
                validation_result["compliance_status"] = "minor_violations"
                validation_result["risk_level"] = "low"
        
        # Generate recommendations
        validation_result["recommendations"] = self._generate_remediation_recommendations(
            validation_result["policy_violations"]
        )
        
        logger.info(f"Found {len(validation_result['policy_violations'])} policy violations")
        return validation_result
    
    def validate_change_management(self, administrative_actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate administrative actions against change management workflows
        
        Returns:
            Change management validation results
        """
        logger.info("Validating against change management workflows")
        
        cm_validation = {
            "approved_changes": [],
            "unapproved_changes": [],
            "emergency_changes": [],
            "policy_violations": [],
            "compliance_score": 0.0
        }
        
        for action in administrative_actions:
            # Query CMDB for change requests
            change_request = self._query_change_request(action)
            
            if change_request:
                if change_request.get("status") == "approved":
                    cm_validation["approved_changes"].append({
                        "action": action,
                        "change_request": change_request,
                        "compliance": "approved"
                    })
                elif change_request.get("type") == "emergency":
                    cm_validation["emergency_changes"].append({
                        "action": action,
                        "change_request": change_request,
                        "compliance": "emergency_approved"
                    })
            else:
                cm_validation["unapproved_changes"].append({
                    "action": action,
                    "compliance": "no_change_request",
                    "severity": "High"
                })
                
                cm_validation["policy_violations"].append({
                    "type": "unapproved_administrative_action",
                    "action": action,
                    "severity": "High",
                    "description": "Administrative action performed without approved change request"
                })
        
        # Calculate compliance score
        total_actions = len(administrative_actions)
        approved_actions = len(cm_validation["approved_changes"]) + len(cm_validation["emergency_changes"])
        cm_validation["compliance_score"] = approved_actions / total_actions if total_actions > 0 else 1.0
        
        logger.info(f"Change management compliance score: {cm_validation['compliance_score']:.2f}")
        return cm_validation
    
    def validate_azure_policy_compliance(self, arm_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate resource operations against Azure Policy compliance
        
        Returns:
            Azure Policy compliance validation results
        """
        logger.info("Validating Azure Policy compliance")
        
        policy_validation = {
            "compliant_resources": [],
            "non_compliant_resources": [],
            "policy_violations": [],
            "compliance_percentage": 0.0,
            "remediation_actions": []
        }
        
        # Analyze existing policy violations from ARM analysis
        for violation in arm_analysis.get("policy_violations", []):
            policy_validation["policy_violations"].append(violation)
            policy_validation["non_compliant_resources"].append(violation["resource"])
        
        # Check additional compliance requirements
        for operation in arm_analysis.get("resource_operations", []):
            compliance_check = self._check_azure_policy_compliance(operation)
            
            if compliance_check["compliant"]:
                policy_validation["compliant_resources"].append(operation["resource"])
            else:
                policy_validation["non_compliant_resources"].append(operation["resource"])
                policy_validation["policy_violations"].extend(compliance_check["violations"])
        
        # Calculate compliance percentage
        total_resources = len(set(policy_validation["compliant_resources"] + policy_validation["non_compliant_resources"]))
        compliant_count = len(set(policy_validation["compliant_resources"]))
        policy_validation["compliance_percentage"] = compliant_count / total_resources if total_resources > 0 else 1.0
        
        # Generate remediation actions
        policy_validation["remediation_actions"] = self._generate_policy_remediation_actions(
            policy_validation["policy_violations"]
        )
        
        logger.info(f"Azure Policy compliance: {policy_validation['compliance_percentage']:.1%}")
        return policy_validation
    
    def _query_historical_roles(self, user_upn: str, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Mock query for historical role assignments"""
        return [
            {
                "user": user_upn,
                "role": "Contributor",
                "assignment_time": start_time + timedelta(days=30),
                "assignment_type": "permanent",
                "scope": "/subscriptions/12345"
            },
            {
                "user": user_upn,
                "role": "Reader",
                "assignment_time": start_time + timedelta(days=60),
                "assignment_type": "permanent",
                "scope": "/subscriptions/12345"
            }
        ]
    
    def _query_historical_permissions(self, user_upn: str, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Mock query for historical permission changes"""
        return [
            {
                "user": user_upn,
                "permission": "Directory.Read.All",
                "change_type": "granted",
                "change_time": start_time + timedelta(days=45),
                "application": "Microsoft Graph"
            }
        ]
    
    def _query_historical_resource_access(self, user_upn: str, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Mock query for historical resource access patterns"""
        return [
            {
                "user": user_upn,
                "resource": "/subscriptions/12345/resourceGroups/prod-rg",
                "access_time": start_time + timedelta(days=i),
                "operation": "read"
            } for i in range(0, 90, 7)  # Weekly access pattern
        ]
    
    def _analyze_typical_roles(self, historical_roles: List[Dict]) -> Dict[str, Any]:
        """Analyze typical roles for a user"""
        role_frequency = {}
        for role_assignment in historical_roles:
            role = role_assignment["role"]
            role_frequency[role] = role_frequency.get(role, 0) + 1
        
        return {
            "common_roles": [role for role, count in role_frequency.items() if count >= 2],
            "role_stability": len(role_frequency) <= 3,  # Stable if <= 3 different roles
            "total_role_changes": len(historical_roles)
        }
    
    def _analyze_permission_patterns(self, historical_permissions: List[Dict]) -> Dict[str, Any]:
        """Analyze permission change patterns"""
        permission_frequency = {}
        for perm_change in historical_permissions:
            permission = perm_change["permission"]
            permission_frequency[permission] = permission_frequency.get(permission, 0) + 1
        
        return {
            "common_permissions": list(permission_frequency.keys()),
            "change_frequency": len(historical_permissions) / 90,  # Changes per day
            "typical_change_types": ["granted"]  # Most common change type
        }
    
    def _analyze_resource_patterns(self, resource_access: List[Dict]) -> Dict[str, Any]:
        """Analyze resource access patterns"""
        resource_frequency = {}
        for access in resource_access:
            resource = access["resource"]
            resource_frequency[resource] = resource_frequency.get(resource, 0) + 1
        
        return {
            "frequently_accessed": [r for r, count in resource_frequency.items() if count >= 4],
            "access_frequency": len(resource_access) / 90,
            "typical_operations": ["read"]
        }
    
    def _calculate_change_frequency(self, roles: List[Dict], permissions: List[Dict]) -> float:
        """Calculate average change frequency per week"""
        total_changes = len(roles) + len(permissions)
        return total_changes / 12.86  # 90 days = ~12.86 weeks
    
    def _analyze_typical_hours(self, all_changes: List[Dict]) -> Dict[str, Any]:
        """Analyze typical hours for permission changes"""
        hours = []
        for change in all_changes:
            if "assignment_time" in change:
                hours.append(change["assignment_time"].hour)
            elif "change_time" in change:
                hours.append(change["change_time"].hour)
        
        if not hours:
            return {"business_hours": True, "typical_range": [9, 17]}
        
        avg_hour = sum(hours) / len(hours)
        return {
            "business_hours": 8 <= avg_hour <= 18,
            "typical_range": [min(hours), max(hours)],
            "average_hour": avg_hour
        }
    
    def _load_rbac_policies(self) -> Dict[str, Any]:
        """Load organizational RBAC policies"""
        return {
            "role_assignment_policies": {
                "Global Administrator": {
                    "max_assignments": 5,
                    "requires_approval": True,
                    "assignment_duration": "temporary"
                },
                "Contributor": {
                    "max_assignments": 50,
                    "requires_approval": False,
                    "assignment_duration": "permanent"
                }
            },
            "permission_policies": {
                "Directory.ReadWrite.All": {
                    "requires_approval": True,
                    "restricted_users": [],
                    "business_justification_required": True
                }
            }
        }
    
    def _validate_role_assignment(self, assignment: Dict[str, Any], policies: Dict[str, Any]) -> List[Dict]:
        """Validate a single role assignment against policies"""
        violations = []
        role = assignment.get("role")
        
        if role in policies["role_assignment_policies"]:
            policy = policies["role_assignment_policies"][role]
            
            # Check if approval is required but missing
            if policy.get("requires_approval") and not assignment.get("approved"):
                violations.append({
                    "type": "missing_approval",
                    "severity": "High",
                    "role": role,
                    "description": f"Role {role} requires approval but none found",
                    "user": assignment.get("user")
                })
            
            # Check assignment duration policy
            if policy.get("assignment_duration") == "temporary" and assignment.get("assignment_type") == "permanent":
                violations.append({
                    "type": "incorrect_assignment_duration",
                    "severity": "Medium", 
                    "role": role,
                    "description": f"Role {role} should be temporary assignment",
                    "user": assignment.get("user")
                })
        
        return violations
    
    def _validate_permission_change(self, change: Dict[str, Any], policies: Dict[str, Any]) -> List[Dict]:
        """Validate a single permission change against policies"""
        violations = []
        permission = change.get("permission")
        
        if permission in policies["permission_policies"]:
            policy = policies["permission_policies"][permission]
            
            if policy.get("requires_approval") and not change.get("approved"):
                violations.append({
                    "type": "missing_permission_approval",
                    "severity": "High",
                    "permission": permission,
                    "description": f"Permission {permission} requires approval",
                    "user": change.get("user")
                })
        
        return violations
    
    def _generate_remediation_recommendations(self, violations: List[Dict]) -> List[str]:
        """Generate remediation recommendations based on violations"""
        recommendations = []
        
        for violation in violations:
            if violation["type"] == "missing_approval":
                recommendations.append(f"Obtain retroactive approval for {violation['role']} assignment to {violation['user']}")
            elif violation["type"] == "incorrect_assignment_duration":
                recommendations.append(f"Convert permanent assignment to temporary for {violation['role']}")
            elif violation["type"] == "missing_permission_approval":
                recommendations.append(f"Review and approve {violation['permission']} grant to {violation['user']}")
        
        return list(set(recommendations))  # Remove duplicates
    
    def _query_change_request(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """Mock query for change requests in CMDB"""
        # Mock response - in real implementation, query actual CMDB
        return {
            "change_request_id": "CHG123456",
            "status": "approved",
            "type": "standard",
            "approved_by": "manager@company.com",
            "approval_date": datetime.now() - timedelta(hours=2)
        }
    
    def _check_azure_policy_compliance(self, operation: Dict[str, Any]) -> Dict[str, Any]:
        """Check operation against Azure Policy compliance"""
        violations = []
        
        # Mock compliance check
        if operation.get("operation") == "Microsoft.Compute/virtualMachines/write":
            vm_size = operation.get("properties", {}).get("vmSize")
            if vm_size and "D4s" in vm_size:
                violations.append({
                    "policy": "VM Size Restriction",
                    "violation": f"VM size {vm_size} exceeds allowed size",
                    "severity": "Medium"
                })
        
        return {
            "compliant": len(violations) == 0,
            "violations": violations
        }
    
    def _generate_policy_remediation_actions(self, violations: List[Dict]) -> List[str]:
        """Generate remediation actions for policy violations"""
        actions = []
        
        for violation in violations:
            if "VM size" in violation.get("violation", ""):
                actions.append("Resize VM to comply with organizational policy")
            elif "network" in violation.get("violation", "").lower():
                actions.append("Reconfigure network settings to meet security requirements")
        
        return list(set(actions))
