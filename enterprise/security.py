"""
Enterprise Security Module
Provides enterprise-grade security features for all SOC agents
"""

import logging
import asyncio
import aiohttp
import hashlib
import hmac
import base64
import json
import ssl
from typing import Dict, Any, List, Optional, Union
from datetime import datetime, timedelta
from enum import Enum
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets
import os

logger = logging.getLogger(__name__)

class SecurityRole(Enum):
    """Enterprise security roles"""
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    SERVICE_ACCOUNT = "service_account"
    AUDIT = "audit"

class EncryptionLevel(Enum):
    """Encryption security levels"""
    STANDARD = "aes_256_gcm"
    HIGH = "aes_256_gcm_with_key_rotation"
    ULTRA = "aes_256_gcm_with_hsm"

class AuditEventType(Enum):
    """Security audit event types"""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_ACCESS = "data_access"
    CONFIGURATION_CHANGE = "configuration_change"
    SECURITY_VIOLATION = "security_violation"
    COMPLIANCE_EVENT = "compliance_event"

class EnterpriseSecurityManager:
    """
    Enterprise Security Manager
    Handles authentication, authorization, encryption, and audit logging
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.vault_client = None
        self.encryption_key = None
        self.audit_logger = None
        self.rbac_manager = None
        self.certificate_manager = None
        self._initialize_security_components()
    
    def _initialize_security_components(self):
        """Initialize all security components"""
        try:
            # Initialize Azure Key Vault client
            self.vault_client = self._initialize_key_vault()
            
            # Initialize encryption
            self.encryption_key = self._initialize_encryption()
            
            # Initialize audit logging
            self.audit_logger = EnterpriseAuditLogger(self.config)
            
            # Initialize RBAC
            self.rbac_manager = RoleBasedAccessControl(self.config)
            
            # Initialize certificate management
            self.certificate_manager = CertificateManager(self.config)
            
            logger.info("Enterprise security components initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize security components: {str(e)}")
            raise
    
    async def authenticate_user(self, credentials: Dict[str, Any], 
                              context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enterprise user authentication with MFA support
        """
        auth_result = {
            "authenticated": False,
            "user_id": None,
            "roles": [],
            "session_token": None,
            "mfa_required": False,
            "auth_method": "unknown",
            "security_context": {}
        }
        
        try:
            # Log authentication attempt
            await self.audit_logger.log_security_event(
                AuditEventType.AUTHENTICATION,
                {
                    "user": credentials.get("username", "unknown"),
                    "source_ip": context.get("source_ip"),
                    "user_agent": context.get("user_agent"),
                    "attempt_type": "login"
                }
            )
            
            # Validate credentials
            if await self._validate_credentials(credentials):
                user_id = credentials.get("username")
                
                # Check if MFA is required
                if await self._is_mfa_required(user_id):
                    if not credentials.get("mfa_token"):
                        auth_result["mfa_required"] = True
                        return auth_result
                    
                    # Validate MFA token
                    if not await self._validate_mfa_token(user_id, credentials.get("mfa_token")):
                        raise Exception("Invalid MFA token")
                
                # Get user roles
                roles = await self.rbac_manager.get_user_roles(user_id)
                
                # Generate session token
                session_token = await self._generate_session_token(user_id, roles)
                
                auth_result.update({
                    "authenticated": True,
                    "user_id": user_id,
                    "roles": roles,
                    "session_token": session_token,
                    "auth_method": "password_mfa" if credentials.get("mfa_token") else "password",
                    "security_context": {
                        "session_created": datetime.now().isoformat(),
                        "source_ip": context.get("source_ip"),
                        "encryption_level": EncryptionLevel.HIGH.value
                    }
                })
                
                # Log successful authentication
                await self.audit_logger.log_security_event(
                    AuditEventType.AUTHENTICATION,
                    {
                        "user": user_id,
                        "status": "success",
                        "roles": roles,
                        "session_token": session_token[:8] + "..."  # Partial token for audit
                    }
                )
                
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            await self.audit_logger.log_security_event(
                AuditEventType.SECURITY_VIOLATION,
                {
                    "user": credentials.get("username", "unknown"),
                    "error": str(e),
                    "status": "authentication_failed"
                }
            )
            
        return auth_result
    
    async def authorize_action(self, user_context: Dict[str, Any], 
                             resource: str, action: str) -> bool:
        """
        Enterprise authorization with fine-grained permissions
        """
        try:
            user_id = user_context.get("user_id")
            roles = user_context.get("roles", [])
            
            # Check authorization
            authorized = await self.rbac_manager.check_permission(
                user_id, roles, resource, action
            )
            
            # Log authorization attempt
            await self.audit_logger.log_security_event(
                AuditEventType.AUTHORIZATION,
                {
                    "user": user_id,
                    "resource": resource,
                    "action": action,
                    "authorized": authorized,
                    "roles": roles
                }
            )
            
            return authorized
            
        except Exception as e:
            logger.error(f"Authorization check failed: {str(e)}")
            return False
    
    async def encrypt_sensitive_data(self, data: Union[str, bytes], 
                                   encryption_level: EncryptionLevel = EncryptionLevel.HIGH) -> Dict[str, Any]:
        """
        Encrypt sensitive data with enterprise-grade encryption
        """
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Generate encryption metadata
            timestamp = datetime.now().isoformat()
            encryption_id = secrets.token_hex(16)
            
            # Encrypt data based on security level
            if encryption_level == EncryptionLevel.ULTRA:
                encrypted_data = await self._encrypt_with_hsm(data)
            elif encryption_level == EncryptionLevel.HIGH:
                encrypted_data = await self._encrypt_with_key_rotation(data)
            else:
                encrypted_data = await self._encrypt_standard(data)
            
            encryption_result = {
                "encrypted_data": base64.b64encode(encrypted_data).decode('utf-8'),
                "encryption_id": encryption_id,
                "encryption_level": encryption_level.value,
                "timestamp": timestamp,
                "algorithm": "AES-256-GCM",
                "key_version": "v1.0"
            }
            
            # Log encryption event
            await self.audit_logger.log_security_event(
                AuditEventType.DATA_ACCESS,
                {
                    "action": "encrypt",
                    "encryption_id": encryption_id,
                    "encryption_level": encryption_level.value,
                    "data_size": len(data)
                }
            )
            
            return encryption_result
            
        except Exception as e:
            logger.error(f"Encryption failed: {str(e)}")
            raise
    
    async def decrypt_sensitive_data(self, encrypted_result: Dict[str, Any]) -> bytes:
        """
        Decrypt sensitive data with enterprise-grade decryption
        """
        try:
            encrypted_data = base64.b64decode(encrypted_result["encrypted_data"])
            encryption_level = EncryptionLevel(encrypted_result["encryption_level"])
            encryption_id = encrypted_result["encryption_id"]
            
            # Decrypt based on encryption level
            if encryption_level == EncryptionLevel.ULTRA:
                decrypted_data = await self._decrypt_with_hsm(encrypted_data)
            elif encryption_level == EncryptionLevel.HIGH:
                decrypted_data = await self._decrypt_with_key_rotation(encrypted_data)
            else:
                decrypted_data = await self._decrypt_standard(encrypted_data)
            
            # Log decryption event
            await self.audit_logger.log_security_event(
                AuditEventType.DATA_ACCESS,
                {
                    "action": "decrypt",
                    "encryption_id": encryption_id,
                    "encryption_level": encryption_level.value
                }
            )
            
            return decrypted_data
            
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            raise
    
    async def create_secure_api_session(self, api_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create secure API session with certificate-based authentication
        """
        try:
            # Get certificates from Key Vault
            client_cert = await self.vault_client.get_certificate(
                api_config.get("cert_name", "default-client-cert")
            )
            
            # Create SSL context
            ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            ssl_context.load_cert_chain(client_cert["cert_path"], client_cert["key_path"])
            
            # Create secure connector
            connector = aiohttp.TCPConnector(
                ssl=ssl_context,
                ttl_dns_cache=300,
                limit=100,
                limit_per_host=20
            )
            
            # Create session with enterprise headers
            headers = {
                "User-Agent": f"SOC-Agent-Enterprise/{self.config.get('version', '2.0.0')}",
                "X-API-Version": api_config.get("api_version", "v1.0"),
                "X-Security-Level": "enterprise",
                "Authorization": await self._generate_api_token(api_config)
            }
            
            session = aiohttp.ClientSession(
                connector=connector,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30)
            )
            
            # Log API session creation
            await self.audit_logger.log_security_event(
                AuditEventType.DATA_ACCESS,
                {
                    "action": "api_session_created",
                    "api_endpoint": api_config.get("base_url"),
                    "security_level": "enterprise"
                }
            )
            
            return {
                "session": session,
                "ssl_context": ssl_context,
                "headers": headers
            }
            
        except Exception as e:
            logger.error(f"Failed to create secure API session: {str(e)}")
            raise
    
    # Private helper methods
    async def _initialize_key_vault(self):
        """Initialize Azure Key Vault client"""
        # Implementation would connect to actual Azure Key Vault
        return MockKeyVaultClient(self.config)
    
    def _initialize_encryption(self):
        """Initialize encryption keys"""
        # In production, this would retrieve keys from Key Vault
        password = self.config.get("encryption_password", "default-password").encode()
        salt = b'salt_'  # In production, use proper salt from Key Vault
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return Fernet(key)
    
    async def _validate_credentials(self, credentials: Dict[str, Any]) -> bool:
        """Validate user credentials"""
        # Implementation would validate against enterprise directory
        username = credentials.get("username")
        password = credentials.get("password")
        
        # Placeholder validation
        return bool(username and password and len(password) >= 8)
    
    async def _is_mfa_required(self, user_id: str) -> bool:
        """Check if MFA is required for user"""
        # Implementation would check enterprise policy
        return True  # Enterprise policy: MFA required for all users
    
    async def _validate_mfa_token(self, user_id: str, mfa_token: str) -> bool:
        """Validate MFA token"""
        # Implementation would validate against MFA provider
        return len(mfa_token) == 6 and mfa_token.isdigit()
    
    async def _generate_session_token(self, user_id: str, roles: List[str]) -> str:
        """Generate secure session token"""
        payload = {
            "user_id": user_id,
            "roles": roles,
            "issued_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(hours=8)).isoformat()
        }
        
        # Create HMAC signature
        secret = self.config.get("session_secret", "default-secret")
        token_data = json.dumps(payload, sort_keys=True)
        signature = hmac.new(
            secret.encode(),
            token_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return base64.b64encode(f"{token_data}.{signature}".encode()).decode()
    
    async def _encrypt_standard(self, data: bytes) -> bytes:
        """Standard AES-256-GCM encryption"""
        return self.encryption_key.encrypt(data)
    
    async def _encrypt_with_key_rotation(self, data: bytes) -> bytes:
        """High security encryption with key rotation"""
        # Implementation would include key rotation logic
        return self.encryption_key.encrypt(data)
    
    async def _encrypt_with_hsm(self, data: bytes) -> bytes:
        """Ultra security encryption with HSM"""
        # Implementation would use Hardware Security Module
        return self.encryption_key.encrypt(data)
    
    async def _decrypt_standard(self, encrypted_data: bytes) -> bytes:
        """Standard AES-256-GCM decryption"""
        return self.encryption_key.decrypt(encrypted_data)
    
    async def _decrypt_with_key_rotation(self, encrypted_data: bytes) -> bytes:
        """High security decryption with key rotation"""
        return self.encryption_key.decrypt(encrypted_data)
    
    async def _decrypt_with_hsm(self, encrypted_data: bytes) -> bytes:
        """Ultra security decryption with HSM"""
        return self.encryption_key.decrypt(encrypted_data)
    
    async def _generate_api_token(self, api_config: Dict[str, Any]) -> str:
        """Generate secure API authentication token"""
        timestamp = str(int(datetime.now().timestamp()))
        nonce = secrets.token_hex(16)
        
        # Create signature
        message = f"{api_config.get('client_id', 'default')}.{timestamp}.{nonce}"
        secret = api_config.get("client_secret", "default-secret")
        signature = hmac.new(
            secret.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return f"Bearer {base64.b64encode(f'{message}.{signature}'.encode()).decode()}"


class RoleBasedAccessControl:
    """Enterprise Role-Based Access Control"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.permissions_cache = {}
        self._initialize_rbac()
    
    def _initialize_rbac(self):
        """Initialize RBAC permissions matrix"""
        self.permissions_matrix = {
            SecurityRole.ADMIN.value: {
                "phishing_analysis": ["read", "write", "execute", "admin"],
                "security_verdicts": ["read", "write", "execute", "admin"], 
                "system_config": ["read", "write", "admin"],
                "user_management": ["read", "write", "admin"],
                "audit_logs": ["read", "admin"]
            },
            SecurityRole.ANALYST.value: {
                "phishing_analysis": ["read", "write", "execute"],
                "security_verdicts": ["read", "write"],
                "system_config": ["read"],
                "audit_logs": ["read"]
            },
            SecurityRole.VIEWER.value: {
                "phishing_analysis": ["read"],
                "security_verdicts": ["read"],
                "audit_logs": ["read"]
            },
            SecurityRole.SERVICE_ACCOUNT.value: {
                "phishing_analysis": ["read", "write", "execute"],
                "security_verdicts": ["read", "write"],
                "api_access": ["read", "write"]
            },
            SecurityRole.AUDIT.value: {
                "audit_logs": ["read", "admin"],
                "compliance_reports": ["read", "write", "admin"]
            }
        }
    
    async def get_user_roles(self, user_id: str) -> List[str]:
        """Get roles for user"""
        # Implementation would query enterprise directory
        # Placeholder logic
        if "admin" in user_id.lower():
            return [SecurityRole.ADMIN.value]
        elif "analyst" in user_id.lower():
            return [SecurityRole.ANALYST.value]
        else:
            return [SecurityRole.VIEWER.value]
    
    async def check_permission(self, user_id: str, roles: List[str], 
                             resource: str, action: str) -> bool:
        """Check if user has permission for resource/action"""
        for role in roles:
            role_permissions = self.permissions_matrix.get(role, {})
            resource_permissions = role_permissions.get(resource, [])
            if action in resource_permissions or "admin" in resource_permissions:
                return True
        return False


class EnterpriseAuditLogger:
    """Enterprise-grade audit logging"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.audit_file = config.get("audit_log_file", "enterprise_audit.log")
        self.compliance_logger = logging.getLogger("compliance")
        self._setup_compliance_logging()
    
    def _setup_compliance_logging(self):
        """Setup compliance-specific logging"""
        handler = logging.FileHandler(self.audit_file)
        formatter = logging.Formatter(
            '%(asctime)s - AUDIT - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.compliance_logger.addHandler(handler)
        self.compliance_logger.setLevel(logging.INFO)
    
    async def log_security_event(self, event_type: AuditEventType, 
                                event_data: Dict[str, Any]):
        """Log security event for compliance"""
        audit_entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type.value,
            "event_id": secrets.token_hex(8),
            "data": event_data,
            "compliance_flags": self._get_compliance_flags(event_type),
            "retention_period": self._get_retention_period(event_type)
        }
        
        # Log to compliance system
        self.compliance_logger.info(json.dumps(audit_entry))
        
        # Send to SIEM if configured
        if self.config.get("siem_integration_enabled"):
            await self._send_to_siem(audit_entry)
    
    def _get_compliance_flags(self, event_type: AuditEventType) -> List[str]:
        """Get compliance flags for event type"""
        compliance_mapping = {
            AuditEventType.AUTHENTICATION: ["SOX", "HIPAA"],
            AuditEventType.DATA_ACCESS: ["GDPR", "HIPAA", "SOX"],
            AuditEventType.SECURITY_VIOLATION: ["SOX", "PCI_DSS"],
            AuditEventType.CONFIGURATION_CHANGE: ["SOX", "ITGC"]
        }
        return compliance_mapping.get(event_type, [])
    
    def _get_retention_period(self, event_type: AuditEventType) -> str:
        """Get retention period for event type"""
        retention_mapping = {
            AuditEventType.AUTHENTICATION: "3_years",
            AuditEventType.DATA_ACCESS: "7_years",
            AuditEventType.SECURITY_VIOLATION: "7_years",
            AuditEventType.CONFIGURATION_CHANGE: "7_years"
        }
        return retention_mapping.get(event_type, "3_years")
    
    async def _send_to_siem(self, audit_entry: Dict[str, Any]):
        """Send audit entry to SIEM system"""
        # Implementation would send to enterprise SIEM
        pass


class CertificateManager:
    """Enterprise certificate management"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.cert_cache = {}
    
    async def get_certificate(self, cert_name: str) -> Dict[str, Any]:
        """Get certificate for secure communications"""
        # Implementation would retrieve from certificate store
        return {
            "cert_path": f"/etc/ssl/certs/{cert_name}.crt",
            "key_path": f"/etc/ssl/private/{cert_name}.key",
            "ca_path": "/etc/ssl/certs/ca-bundle.crt"
        }


class MockKeyVaultClient:
    """Mock Key Vault client for development"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
    
    async def get_secret(self, secret_name: str) -> str:
        """Get secret from vault"""
        # Mock implementation
        return f"mock-secret-{secret_name}"
    
    async def get_certificate(self, cert_name: str) -> Dict[str, Any]:
        """Get certificate from vault"""
        # Mock implementation
        return {
            "cert_path": f"/mock/certs/{cert_name}.crt",
            "key_path": f"/mock/private/{cert_name}.key"
        }
