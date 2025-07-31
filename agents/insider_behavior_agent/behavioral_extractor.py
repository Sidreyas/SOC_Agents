"""
Behavioral Extractor Module
State 1: Behavioral Pattern Extraction
Extracts user behavior patterns from authentication, file access, and application usage logs
"""

import logging
from typing import Dict, Any, List, Tuple
from datetime import datetime, timedelta
import json
import statistics

logger = logging.getLogger(__name__)

class BehavioralExtractor:
    """
    Extracts and analyzes user behavioral patterns from multiple data sources
    Identifies normal patterns and detects deviations for insider threat detection
    """
    
    def __init__(self):
        self.behavior_profiles = {}
        self.pattern_extractors = {}
        self.data_sources = [
            "authentication_logs",
            "file_access_logs", 
            "email_logs",
            "application_usage",
            "network_activity",
            "system_events"
        ]
        
    def extract_authentication_patterns(self, auth_logs: List[Dict[str, Any]], time_window: Dict[str, datetime]) -> Dict[str, Any]:
        """
        Extract authentication behavior patterns from logs
        
        Returns:
            Authentication behavior analysis including login patterns, locations, devices, and timing
        """
        logger.info(f"Extracting authentication patterns from {len(auth_logs)} log entries")
        
        auth_patterns = {
            "login_frequency": {},
            "time_patterns": {},
            "location_patterns": {},
            "device_patterns": {},
            "authentication_methods": {},
            "failure_patterns": {},
            "anomalous_behaviors": []
        }
        
        # Group logs by user
        user_logs = {}
        for log in auth_logs:
            user = log.get("user", "unknown")
            if user not in user_logs:
                user_logs[user] = []
            user_logs[user].append(log)
        
        # Analyze patterns for each user
        for user, logs in user_logs.items():
            logger.info(f"Analyzing authentication patterns for user: {user}")
            
            # Extract login frequency patterns
            auth_patterns["login_frequency"][user] = self._analyze_login_frequency(logs, time_window)
            
            # Extract time-based patterns
            auth_patterns["time_patterns"][user] = self._analyze_time_patterns(logs)
            
            # Extract location patterns
            auth_patterns["location_patterns"][user] = self._analyze_location_patterns(logs)
            
            # Extract device patterns
            auth_patterns["device_patterns"][user] = self._analyze_device_patterns(logs)
            
            # Extract authentication method patterns
            auth_patterns["authentication_methods"][user] = self._analyze_auth_methods(logs)
            
            # Extract failure patterns
            auth_patterns["failure_patterns"][user] = self._analyze_failure_patterns(logs)
            
            # Identify anomalous behaviors
            anomalies = self._identify_auth_anomalies(logs, user)
            if anomalies:
                auth_patterns["anomalous_behaviors"].extend(anomalies)
        
        logger.info(f"Authentication pattern extraction complete for {len(user_logs)} users")
        return auth_patterns
    
    def extract_file_access_patterns(self, file_logs: List[Dict[str, Any]], time_window: Dict[str, datetime]) -> Dict[str, Any]:
        """
        Extract file access behavior patterns
        
        Returns:
            File access behavior analysis including access patterns, sensitive file interactions, and anomalies
        """
        logger.info(f"Extracting file access patterns from {len(file_logs)} log entries")
        
        file_patterns = {
            "access_frequency": {},
            "file_types": {},
            "sensitive_file_access": {},
            "unusual_access_times": {},
            "bulk_access_patterns": {},
            "permission_escalations": {},
            "anomalous_behaviors": []
        }
        
        # Group logs by user
        user_logs = {}
        for log in file_logs:
            user = log.get("user", "unknown")
            if user not in user_logs:
                user_logs[user] = []
            user_logs[user].append(log)
        
        # Analyze patterns for each user
        for user, logs in user_logs.items():
            logger.info(f"Analyzing file access patterns for user: {user}")
            
            # Extract access frequency patterns
            file_patterns["access_frequency"][user] = self._analyze_file_access_frequency(logs, time_window)
            
            # Extract file type patterns
            file_patterns["file_types"][user] = self._analyze_file_type_patterns(logs)
            
            # Extract sensitive file access patterns
            file_patterns["sensitive_file_access"][user] = self._analyze_sensitive_file_access(logs)
            
            # Extract unusual access time patterns
            file_patterns["unusual_access_times"][user] = self._analyze_unusual_access_times(logs)
            
            # Extract bulk access patterns
            file_patterns["bulk_access_patterns"][user] = self._analyze_bulk_access_patterns(logs)
            
            # Extract permission escalation patterns
            file_patterns["permission_escalations"][user] = self._analyze_permission_escalations(logs)
            
            # Identify anomalous behaviors
            anomalies = self._identify_file_access_anomalies(logs, user)
            if anomalies:
                file_patterns["anomalous_behaviors"].extend(anomalies)
        
        logger.info(f"File access pattern extraction complete for {len(user_logs)} users")
        return file_patterns
    
    def extract_email_behavior_patterns(self, email_logs: List[Dict[str, Any]], time_window: Dict[str, datetime]) -> Dict[str, Any]:
        """
        Extract email behavior patterns including communication analysis
        
        Returns:
            Email behavior analysis including communication patterns, external contacts, and suspicious activities
        """
        logger.info(f"Extracting email behavior patterns from {len(email_logs)} log entries")
        
        email_patterns = {
            "communication_frequency": {},
            "external_communications": {},
            "attachment_patterns": {},
            "forwarding_patterns": {},
            "large_email_patterns": {},
            "unusual_recipients": {},
            "anomalous_behaviors": []
        }
        
        # Group logs by user
        user_logs = {}
        for log in email_logs:
            user = log.get("sender", log.get("user", "unknown"))
            if user not in user_logs:
                user_logs[user] = []
            user_logs[user].append(log)
        
        # Analyze patterns for each user
        for user, logs in user_logs.items():
            logger.info(f"Analyzing email patterns for user: {user}")
            
            # Extract communication frequency patterns
            email_patterns["communication_frequency"][user] = self._analyze_email_frequency(logs, time_window)
            
            # Extract external communication patterns
            email_patterns["external_communications"][user] = self._analyze_external_communications(logs)
            
            # Extract attachment patterns
            email_patterns["attachment_patterns"][user] = self._analyze_attachment_patterns(logs)
            
            # Extract forwarding patterns
            email_patterns["forwarding_patterns"][user] = self._analyze_forwarding_patterns(logs)
            
            # Extract large email patterns
            email_patterns["large_email_patterns"][user] = self._analyze_large_email_patterns(logs)
            
            # Extract unusual recipient patterns
            email_patterns["unusual_recipients"][user] = self._analyze_unusual_recipients(logs)
            
            # Identify anomalous behaviors
            anomalies = self._identify_email_anomalies(logs, user)
            if anomalies:
                email_patterns["anomalous_behaviors"].extend(anomalies)
        
        logger.info(f"Email pattern extraction complete for {len(user_logs)} users")
        return email_patterns
    
    def extract_application_usage_patterns(self, app_logs: List[Dict[str, Any]], time_window: Dict[str, datetime]) -> Dict[str, Any]:
        """
        Extract application usage behavior patterns
        
        Returns:
            Application usage analysis including usage patterns, privileged application access, and anomalies
        """
        logger.info(f"Extracting application usage patterns from {len(app_logs)} log entries")
        
        app_patterns = {
            "application_frequency": {},
            "privileged_app_usage": {},
            "unusual_applications": {},
            "off_hours_usage": {},
            "data_export_activities": {},
            "administrative_tools": {},
            "anomalous_behaviors": []
        }
        
        # Group logs by user
        user_logs = {}
        for log in app_logs:
            user = log.get("user", "unknown")
            if user not in user_logs:
                user_logs[user] = []
            user_logs[user].append(log)
        
        # Analyze patterns for each user
        for user, logs in user_logs.items():
            logger.info(f"Analyzing application usage patterns for user: {user}")
            
            # Extract application frequency patterns
            app_patterns["application_frequency"][user] = self._analyze_app_frequency(logs, time_window)
            
            # Extract privileged application usage
            app_patterns["privileged_app_usage"][user] = self._analyze_privileged_app_usage(logs)
            
            # Extract unusual application usage
            app_patterns["unusual_applications"][user] = self._analyze_unusual_applications(logs)
            
            # Extract off-hours usage patterns
            app_patterns["off_hours_usage"][user] = self._analyze_off_hours_app_usage(logs)
            
            # Extract data export activities
            app_patterns["data_export_activities"][user] = self._analyze_data_export_activities(logs)
            
            # Extract administrative tool usage
            app_patterns["administrative_tools"][user] = self._analyze_admin_tool_usage(logs)
            
            # Identify anomalous behaviors
            anomalies = self._identify_app_usage_anomalies(logs, user)
            if anomalies:
                app_patterns["anomalous_behaviors"].extend(anomalies)
        
        logger.info(f"Application usage pattern extraction complete for {len(user_logs)} users")
        return app_patterns
    
    def _analyze_login_frequency(self, logs: List[Dict[str, Any]], time_window: Dict[str, datetime]) -> Dict[str, Any]:
        """Analyze login frequency patterns"""
        logins_per_day = {}
        
        for log in logs:
            if log.get("event_type") == "login" and log.get("status") == "success":
                date = log.get("timestamp", datetime.now()).date()
                logins_per_day[date] = logins_per_day.get(date, 0) + 1
        
        if logins_per_day:
            avg_logins = statistics.mean(logins_per_day.values())
            max_logins = max(logins_per_day.values())
            min_logins = min(logins_per_day.values())
        else:
            avg_logins = max_logins = min_logins = 0
        
        return {
            "average_logins_per_day": avg_logins,
            "max_logins_per_day": max_logins,
            "min_logins_per_day": min_logins,
            "total_login_days": len(logins_per_day),
            "login_consistency": self._calculate_consistency_score(list(logins_per_day.values()))
        }
    
    def _analyze_time_patterns(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze time-based patterns"""
        login_hours = []
        
        for log in logs:
            if log.get("event_type") == "login" and log.get("status") == "success":
                hour = log.get("timestamp", datetime.now()).hour
                login_hours.append(hour)
        
        if login_hours:
            typical_start = min(login_hours)
            typical_end = max(login_hours)
            peak_hour = statistics.mode(login_hours) if login_hours else 9
        else:
            typical_start = typical_end = peak_hour = 9
        
        return {
            "typical_start_hour": typical_start,
            "typical_end_hour": typical_end,
            "peak_login_hour": peak_hour,
            "business_hours_percentage": self._calculate_business_hours_percentage(login_hours),
            "weekend_activity": self._analyze_weekend_activity(logs)
        }
    
    def _analyze_location_patterns(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze location-based patterns"""
        locations = []
        ip_addresses = []
        
        for log in logs:
            if log.get("event_type") == "login":
                location = log.get("location")
                ip = log.get("source_ip")
                
                if location:
                    locations.append(location)
                if ip:
                    ip_addresses.append(ip)
        
        unique_locations = len(set(locations)) if locations else 0
        unique_ips = len(set(ip_addresses)) if ip_addresses else 0
        
        return {
            "unique_locations": unique_locations,
            "unique_ip_addresses": unique_ips,
            "primary_location": statistics.mode(locations) if locations else "Unknown",
            "location_consistency": 1.0 - (unique_locations / max(len(locations), 1)),
            "suspicious_locations": self._identify_suspicious_locations(locations)
        }
    
    def _analyze_device_patterns(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze device usage patterns"""
        devices = []
        user_agents = []
        
        for log in logs:
            if log.get("event_type") == "login":
                device = log.get("device")
                user_agent = log.get("user_agent")
                
                if device:
                    devices.append(device)
                if user_agent:
                    user_agents.append(user_agent)
        
        unique_devices = len(set(devices)) if devices else 0
        
        return {
            "unique_devices": unique_devices,
            "device_consistency": 1.0 - (unique_devices / max(len(devices), 1)),
            "primary_device": statistics.mode(devices) if devices else "Unknown",
            "mobile_usage_percentage": self._calculate_mobile_usage(devices),
            "new_device_registrations": self._identify_new_devices(logs)
        }
    
    def _analyze_auth_methods(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze authentication method patterns"""
        auth_methods = []
        mfa_usage = 0
        total_logins = 0
        
        for log in logs:
            if log.get("event_type") == "login":
                method = log.get("auth_method", "password")
                auth_methods.append(method)
                total_logins += 1
                
                if log.get("mfa_used", False):
                    mfa_usage += 1
        
        return {
            "primary_auth_method": statistics.mode(auth_methods) if auth_methods else "password",
            "mfa_usage_percentage": (mfa_usage / max(total_logins, 1)) * 100,
            "auth_method_diversity": len(set(auth_methods)),
            "password_only_percentage": (auth_methods.count("password") / max(len(auth_methods), 1)) * 100
        }
    
    def _analyze_failure_patterns(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze authentication failure patterns"""
        failures = []
        failure_times = []
        
        for log in logs:
            if log.get("event_type") == "login" and log.get("status") == "failed":
                failures.append(log)
                failure_times.append(log.get("timestamp", datetime.now()))
        
        return {
            "total_failures": len(failures),
            "failure_rate": len(failures) / max(len(logs), 1),
            "consecutive_failures": self._analyze_consecutive_failures(logs),
            "failure_time_clustering": self._analyze_failure_clustering(failure_times),
            "lockout_events": self._count_lockout_events(logs)
        }
    
    def _identify_auth_anomalies(self, logs: List[Dict[str, Any]], user: str) -> List[Dict[str, Any]]:
        """Identify authentication anomalies"""
        anomalies = []
        
        # Check for unusual login times
        unusual_times = self._detect_unusual_login_times(logs)
        if unusual_times:
            anomalies.append({
                "type": "unusual_login_times",
                "user": user,
                "details": unusual_times,
                "severity": "medium"
            })
        
        # Check for impossible travel
        impossible_travel = self._detect_impossible_travel(logs)
        if impossible_travel:
            anomalies.append({
                "type": "impossible_travel",
                "user": user,
                "details": impossible_travel,
                "severity": "high"
            })
        
        # Check for brute force patterns
        brute_force = self._detect_brute_force_patterns(logs)
        if brute_force:
            anomalies.append({
                "type": "brute_force_attempt",
                "user": user,
                "details": brute_force,
                "severity": "high"
            })
        
        return anomalies
    
    def _analyze_file_access_frequency(self, logs: List[Dict[str, Any]], time_window: Dict[str, datetime]) -> Dict[str, Any]:
        """Analyze file access frequency patterns"""
        daily_access = {}
        
        for log in logs:
            date = log.get("timestamp", datetime.now()).date()
            daily_access[date] = daily_access.get(date, 0) + 1
        
        if daily_access:
            avg_access = statistics.mean(daily_access.values())
            max_access = max(daily_access.values())
        else:
            avg_access = max_access = 0
        
        return {
            "average_daily_access": avg_access,
            "max_daily_access": max_access,
            "total_access_days": len(daily_access),
            "access_consistency": self._calculate_consistency_score(list(daily_access.values()))
        }
    
    def _analyze_file_type_patterns(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze file type access patterns"""
        file_types = []
        
        for log in logs:
            file_path = log.get("file_path", "")
            if "." in file_path:
                file_type = file_path.split(".")[-1].lower()
                file_types.append(file_type)
        
        type_counts = {}
        for file_type in file_types:
            type_counts[file_type] = type_counts.get(file_type, 0) + 1
        
        return {
            "file_type_distribution": type_counts,
            "most_accessed_type": max(type_counts, key=type_counts.get) if type_counts else "unknown",
            "file_type_diversity": len(type_counts),
            "document_access_percentage": self._calculate_document_percentage(file_types)
        }
    
    def _analyze_sensitive_file_access(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze sensitive file access patterns"""
        sensitive_patterns = ["confidential", "secret", "personal", "financial", "hr", "salary"]
        sensitive_access = []
        
        for log in logs:
            file_path = log.get("file_path", "").lower()
            if any(pattern in file_path for pattern in sensitive_patterns):
                sensitive_access.append(log)
        
        return {
            "sensitive_file_access_count": len(sensitive_access),
            "sensitive_access_percentage": (len(sensitive_access) / max(len(logs), 1)) * 100,
            "sensitive_file_types": self._categorize_sensitive_files(sensitive_access),
            "off_hours_sensitive_access": self._count_off_hours_access(sensitive_access)
        }
    
    def _analyze_unusual_access_times(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze unusual file access times"""
        access_hours = []
        
        for log in logs:
            hour = log.get("timestamp", datetime.now()).hour
            access_hours.append(hour)
        
        off_hours_count = sum(1 for hour in access_hours if hour < 7 or hour > 19)
        weekend_count = self._count_weekend_access(logs)
        
        return {
            "off_hours_access_count": off_hours_count,
            "off_hours_percentage": (off_hours_count / max(len(logs), 1)) * 100,
            "weekend_access_count": weekend_count,
            "most_unusual_hour": min(access_hours) if access_hours else 0
        }
    
    def _analyze_bulk_access_patterns(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze bulk file access patterns"""
        time_buckets = {}
        
        for log in logs:
            time_bucket = log.get("timestamp", datetime.now()).replace(minute=0, second=0, microsecond=0)
            time_buckets[time_bucket] = time_buckets.get(time_bucket, 0) + 1
        
        bulk_sessions = [count for count in time_buckets.values() if count > 10]
        
        return {
            "bulk_access_sessions": len(bulk_sessions),
            "max_hourly_access": max(time_buckets.values()) if time_buckets else 0,
            "bulk_access_threshold_exceeded": len(bulk_sessions) > 0,
            "average_bulk_session_size": statistics.mean(bulk_sessions) if bulk_sessions else 0
        }
    
    def _analyze_permission_escalations(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze permission escalation attempts in file access"""
        escalations = []
        
        for log in logs:
            if log.get("access_denied", False) or log.get("permission_error", False):
                escalations.append(log)
        
        return {
            "permission_escalation_attempts": len(escalations),
            "escalation_rate": (len(escalations) / max(len(logs), 1)) * 100,
            "failed_access_patterns": self._analyze_failed_access_patterns(escalations),
            "privilege_seeking_behavior": len(escalations) > 5
        }
    
    def _identify_file_access_anomalies(self, logs: List[Dict[str, Any]], user: str) -> List[Dict[str, Any]]:
        """Identify file access anomalies"""
        anomalies = []
        
        # Check for mass file downloads
        bulk_downloads = self._detect_bulk_downloads(logs)
        if bulk_downloads:
            anomalies.append({
                "type": "bulk_file_downloads",
                "user": user,
                "details": bulk_downloads,
                "severity": "high"
            })
        
        # Check for unusual file type access
        unusual_files = self._detect_unusual_file_access(logs)
        if unusual_files:
            anomalies.append({
                "type": "unusual_file_access",
                "user": user,
                "details": unusual_files,
                "severity": "medium"
            })
        
        return anomalies
    
    def _analyze_email_frequency(self, logs: List[Dict[str, Any]], time_window: Dict[str, datetime]) -> Dict[str, Any]:
        """Analyze email communication frequency"""
        daily_emails = {}
        
        for log in logs:
            date = log.get("timestamp", datetime.now()).date()
            daily_emails[date] = daily_emails.get(date, 0) + 1
        
        if daily_emails:
            avg_emails = statistics.mean(daily_emails.values())
            max_emails = max(daily_emails.values())
        else:
            avg_emails = max_emails = 0
        
        return {
            "average_daily_emails": avg_emails,
            "max_daily_emails": max_emails,
            "email_consistency": self._calculate_consistency_score(list(daily_emails.values())),
            "communication_spike_detected": max_emails > avg_emails * 3 if avg_emails > 0 else False
        }
    
    def _analyze_external_communications(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze external email communications"""
        external_domains = []
        internal_count = 0
        external_count = 0
        
        company_domains = ["company.com", "corp.com"]  # Mock company domains
        
        for log in logs:
            recipients = log.get("recipients", [])
            for recipient in recipients:
                if "@" in recipient:
                    domain = recipient.split("@")[1]
                    if domain in company_domains:
                        internal_count += 1
                    else:
                        external_count += 1
                        external_domains.append(domain)
        
        return {
            "external_communication_count": external_count,
            "external_percentage": (external_count / max(internal_count + external_count, 1)) * 100,
            "unique_external_domains": len(set(external_domains)),
            "suspicious_domains": self._identify_suspicious_domains(external_domains),
            "external_communication_spike": external_count > internal_count
        }
    
    def _analyze_attachment_patterns(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze email attachment patterns"""
        attachments = []
        large_attachments = 0
        
        for log in logs:
            email_attachments = log.get("attachments", [])
            attachments.extend(email_attachments)
            
            for attachment in email_attachments:
                size = attachment.get("size", 0)
                if size > 10 * 1024 * 1024:  # 10MB threshold
                    large_attachments += 1
        
        return {
            "total_attachments": len(attachments),
            "large_attachment_count": large_attachments,
            "attachment_types": self._categorize_attachments(attachments),
            "suspicious_attachment_detected": self._detect_suspicious_attachments(attachments)
        }
    
    def _analyze_forwarding_patterns(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze email forwarding patterns"""
        forwarded_emails = []
        external_forwards = 0
        
        for log in logs:
            if log.get("action") == "forward":
                forwarded_emails.append(log)
                
                recipients = log.get("recipients", [])
                for recipient in recipients:
                    if "@" in recipient and not recipient.endswith("company.com"):
                        external_forwards += 1
        
        return {
            "forwarded_email_count": len(forwarded_emails),
            "external_forward_count": external_forwards,
            "forwarding_rate": (len(forwarded_emails) / max(len(logs), 1)) * 100,
            "bulk_forwarding_detected": len(forwarded_emails) > 10
        }
    
    def _analyze_large_email_patterns(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze large email patterns"""
        large_emails = []
        
        for log in logs:
            size = log.get("email_size", 0)
            if size > 25 * 1024 * 1024:  # 25MB threshold
                large_emails.append(log)
        
        return {
            "large_email_count": len(large_emails),
            "large_email_percentage": (len(large_emails) / max(len(logs), 1)) * 100,
            "largest_email_size": max([log.get("email_size", 0) for log in large_emails]) if large_emails else 0,
            "data_exfiltration_risk": len(large_emails) > 5
        }
    
    def _analyze_unusual_recipients(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze unusual recipient patterns"""
        all_recipients = []
        
        for log in logs:
            recipients = log.get("recipients", [])
            all_recipients.extend(recipients)
        
        recipient_frequency = {}
        for recipient in all_recipients:
            recipient_frequency[recipient] = recipient_frequency.get(recipient, 0) + 1
        
        # Identify one-off recipients (contacted only once)
        one_off_recipients = [r for r, count in recipient_frequency.items() if count == 1]
        
        return {
            "unique_recipients": len(set(all_recipients)),
            "one_off_recipients": len(one_off_recipients),
            "recipient_diversity": len(set(all_recipients)) / max(len(all_recipients), 1),
            "unusual_recipient_pattern": len(one_off_recipients) > len(set(all_recipients)) * 0.5
        }
    
    def _identify_email_anomalies(self, logs: List[Dict[str, Any]], user: str) -> List[Dict[str, Any]]:
        """Identify email anomalies"""
        anomalies = []
        
        # Check for mass email forwarding
        mass_forwarding = self._detect_mass_forwarding(logs)
        if mass_forwarding:
            anomalies.append({
                "type": "mass_email_forwarding",
                "user": user,
                "details": mass_forwarding,
                "severity": "high"
            })
        
        # Check for data exfiltration via email
        data_exfiltration = self._detect_email_data_exfiltration(logs)
        if data_exfiltration:
            anomalies.append({
                "type": "email_data_exfiltration",
                "user": user,
                "details": data_exfiltration,
                "severity": "critical"
            })
        
        return anomalies
    
    def _analyze_app_frequency(self, logs: List[Dict[str, Any]], time_window: Dict[str, datetime]) -> Dict[str, Any]:
        """Analyze application usage frequency"""
        app_usage = {}
        
        for log in logs:
            app = log.get("application", "unknown")
            app_usage[app] = app_usage.get(app, 0) + 1
        
        return {
            "applications_used": len(app_usage),
            "most_used_application": max(app_usage, key=app_usage.get) if app_usage else "unknown",
            "application_diversity": len(app_usage),
            "usage_distribution": app_usage
        }
    
    def _analyze_privileged_app_usage(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze privileged application usage"""
        privileged_apps = ["admin_console", "database_manager", "security_tools", "system_utilities"]
        privileged_usage = []
        
        for log in logs:
            app = log.get("application", "")
            if any(priv_app in app.lower() for priv_app in privileged_apps):
                privileged_usage.append(log)
        
        return {
            "privileged_app_usage_count": len(privileged_usage),
            "privileged_usage_percentage": (len(privileged_usage) / max(len(logs), 1)) * 100,
            "privileged_apps_accessed": list(set([log.get("application") for log in privileged_usage])),
            "elevated_access_pattern": len(privileged_usage) > 10
        }
    
    def _analyze_unusual_applications(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze unusual application usage"""
        typical_apps = ["office_suite", "email_client", "web_browser", "file_manager"]
        unusual_apps = []
        
        for log in logs:
            app = log.get("application", "")
            if not any(typical_app in app.lower() for typical_app in typical_apps):
                unusual_apps.append(app)
        
        return {
            "unusual_app_count": len(unusual_apps),
            "unusual_app_percentage": (len(unusual_apps) / max(len(logs), 1)) * 100,
            "unique_unusual_apps": list(set(unusual_apps)),
            "suspicious_app_usage": len(set(unusual_apps)) > 5
        }
    
    def _analyze_off_hours_app_usage(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze off-hours application usage"""
        off_hours_usage = []
        
        for log in logs:
            hour = log.get("timestamp", datetime.now()).hour
            if hour < 7 or hour > 19:  # Off-hours defined as before 7 AM or after 7 PM
                off_hours_usage.append(log)
        
        return {
            "off_hours_usage_count": len(off_hours_usage),
            "off_hours_percentage": (len(off_hours_usage) / max(len(logs), 1)) * 100,
            "off_hours_applications": list(set([log.get("application") for log in off_hours_usage])),
            "suspicious_off_hours_pattern": len(off_hours_usage) > len(logs) * 0.3
        }
    
    def _analyze_data_export_activities(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze data export activities"""
        export_activities = []
        export_keywords = ["export", "download", "backup", "copy", "transfer"]
        
        for log in logs:
            activity = log.get("activity", "").lower()
            if any(keyword in activity for keyword in export_keywords):
                export_activities.append(log)
        
        return {
            "data_export_count": len(export_activities),
            "export_activity_percentage": (len(export_activities) / max(len(logs), 1)) * 100,
            "export_applications": list(set([log.get("application") for log in export_activities])),
            "bulk_export_detected": len(export_activities) > 20
        }
    
    def _analyze_admin_tool_usage(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze administrative tool usage"""
        admin_tools = ["powershell", "cmd", "registry_editor", "task_manager", "admin_console"]
        admin_usage = []
        
        for log in logs:
            app = log.get("application", "").lower()
            if any(tool in app for tool in admin_tools):
                admin_usage.append(log)
        
        return {
            "admin_tool_usage_count": len(admin_usage),
            "admin_usage_percentage": (len(admin_usage) / max(len(logs), 1)) * 100,
            "admin_tools_used": list(set([log.get("application") for log in admin_usage])),
            "suspicious_admin_activity": len(admin_usage) > 15
        }
    
    def _identify_app_usage_anomalies(self, logs: List[Dict[str, Any]], user: str) -> List[Dict[str, Any]]:
        """Identify application usage anomalies"""
        anomalies = []
        
        # Check for unusual application installations
        new_apps = self._detect_new_application_usage(logs)
        if new_apps:
            anomalies.append({
                "type": "new_application_usage",
                "user": user,
                "details": new_apps,
                "severity": "medium"
            })
        
        # Check for excessive administrative tool usage
        excessive_admin = self._detect_excessive_admin_usage(logs)
        if excessive_admin:
            anomalies.append({
                "type": "excessive_admin_tool_usage",
                "user": user,
                "details": excessive_admin,
                "severity": "high"
            })
        
        return anomalies
    
    # Helper methods for calculations and analysis
    def _calculate_consistency_score(self, values: List[float]) -> float:
        """Calculate consistency score based on variance"""
        if not values or len(values) < 2:
            return 1.0
        
        mean_val = statistics.mean(values)
        variance = statistics.variance(values)
        
        # Normalize variance to a 0-1 consistency score
        if mean_val == 0:
            return 1.0
        
        coefficient_of_variation = (variance ** 0.5) / mean_val
        consistency = max(0.0, 1.0 - coefficient_of_variation)
        
        return consistency
    
    def _calculate_business_hours_percentage(self, hours: List[int]) -> float:
        """Calculate percentage of activity during business hours"""
        if not hours:
            return 0.0
        
        business_hours_count = sum(1 for hour in hours if 9 <= hour <= 17)
        return (business_hours_count / len(hours)) * 100
    
    def _analyze_weekend_activity(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze weekend activity patterns"""
        weekend_logs = []
        
        for log in logs:
            timestamp = log.get("timestamp", datetime.now())
            if timestamp.weekday() >= 5:  # Saturday = 5, Sunday = 6
                weekend_logs.append(log)
        
        return {
            "weekend_activity_count": len(weekend_logs),
            "weekend_percentage": (len(weekend_logs) / max(len(logs), 1)) * 100,
            "weekend_pattern_detected": len(weekend_logs) > 0
        }
    
    def _identify_suspicious_locations(self, locations: List[str]) -> List[str]:
        """Identify suspicious or unusual locations"""
        known_locations = ["Office", "Home", "Branch Office"]
        return [loc for loc in set(locations) if loc not in known_locations]
    
    def _calculate_mobile_usage(self, devices: List[str]) -> float:
        """Calculate percentage of mobile device usage"""
        if not devices:
            return 0.0
        
        mobile_indicators = ["mobile", "phone", "tablet", "ios", "android"]
        mobile_count = sum(1 for device in devices if any(indicator in device.lower() for indicator in mobile_indicators))
        
        return (mobile_count / len(devices)) * 100
    
    def _identify_new_devices(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify new device registrations"""
        new_devices = []
        
        for log in logs:
            if log.get("event_type") == "new_device_registration":
                new_devices.append(log)
        
        return new_devices
    
    def _analyze_consecutive_failures(self, logs: List[Dict[str, Any]]) -> int:
        """Analyze consecutive authentication failures"""
        consecutive_count = 0
        max_consecutive = 0
        
        for log in logs:
            if log.get("event_type") == "login":
                if log.get("status") == "failed":
                    consecutive_count += 1
                    max_consecutive = max(max_consecutive, consecutive_count)
                else:
                    consecutive_count = 0
        
        return max_consecutive
    
    def _analyze_failure_clustering(self, failure_times: List[datetime]) -> Dict[str, Any]:
        """Analyze temporal clustering of failures"""
        if len(failure_times) < 2:
            return {"clustered": False, "cluster_count": 0}
        
        # Sort times and check for clusters (failures within 5 minutes)
        sorted_times = sorted(failure_times)
        clusters = []
        current_cluster = [sorted_times[0]]
        
        for i in range(1, len(sorted_times)):
            time_diff = (sorted_times[i] - sorted_times[i-1]).total_seconds()
            if time_diff <= 300:  # 5 minutes
                current_cluster.append(sorted_times[i])
            else:
                if len(current_cluster) > 1:
                    clusters.append(current_cluster)
                current_cluster = [sorted_times[i]]
        
        if len(current_cluster) > 1:
            clusters.append(current_cluster)
        
        return {
            "clustered": len(clusters) > 0,
            "cluster_count": len(clusters),
            "largest_cluster_size": max([len(cluster) for cluster in clusters]) if clusters else 0
        }
    
    def _count_lockout_events(self, logs: List[Dict[str, Any]]) -> int:
        """Count account lockout events"""
        return sum(1 for log in logs if log.get("event_type") == "account_lockout")
    
    def _detect_unusual_login_times(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect unusual login times"""
        unusual_logins = []
        
        for log in logs:
            if log.get("event_type") == "login" and log.get("status") == "success":
                hour = log.get("timestamp", datetime.now()).hour
                day_of_week = log.get("timestamp", datetime.now()).weekday()
                
                # Flag as unusual if login is very early, very late, or on weekend
                if hour < 6 or hour > 22 or day_of_week >= 5:
                    unusual_logins.append(log)
        
        return unusual_logins
    
    def _detect_impossible_travel(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect impossible travel scenarios"""
        # This is a simplified implementation
        # In practice, would use geolocation and time analysis
        location_logs = [log for log in logs if log.get("location") and log.get("event_type") == "login"]
        impossible_travel = []
        
        for i in range(1, len(location_logs)):
            prev_log = location_logs[i-1]
            curr_log = location_logs[i]
            
            # Simple check for different countries in short time
            if (prev_log.get("location") != curr_log.get("location") and
                abs((curr_log.get("timestamp", datetime.now()) - 
                     prev_log.get("timestamp", datetime.now())).total_seconds()) < 3600):
                impossible_travel.append({
                    "from_location": prev_log.get("location"),
                    "to_location": curr_log.get("location"),
                    "time_difference": abs((curr_log.get("timestamp", datetime.now()) - 
                                          prev_log.get("timestamp", datetime.now())).total_seconds())
                })
        
        return impossible_travel
    
    def _detect_brute_force_patterns(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect brute force attack patterns"""
        failed_logins = [log for log in logs if log.get("event_type") == "login" and log.get("status") == "failed"]
        
        if len(failed_logins) > 10:  # More than 10 failures
            return [{
                "pattern": "multiple_failed_attempts",
                "failure_count": len(failed_logins),
                "time_span": "analysis_period"
            }]
        
        return []
    
    # Additional helper methods for other analysis functions would continue here...
    # For brevity, I'm including representative examples of the pattern
    
    def _calculate_document_percentage(self, file_types: List[str]) -> float:
        """Calculate percentage of document file access"""
        if not file_types:
            return 0.0
        
        doc_types = ["doc", "docx", "pdf", "xls", "xlsx", "ppt", "pptx", "txt"]
        doc_count = sum(1 for ft in file_types if ft in doc_types)
        return (doc_count / len(file_types)) * 100
    
    def _categorize_sensitive_files(self, sensitive_access: List[Dict[str, Any]]) -> Dict[str, int]:
        """Categorize types of sensitive files accessed"""
        categories = {"financial": 0, "hr": 0, "confidential": 0, "personal": 0}
        
        for access in sensitive_access:
            file_path = access.get("file_path", "").lower()
            if "financial" in file_path or "finance" in file_path:
                categories["financial"] += 1
            elif "hr" in file_path or "human" in file_path:
                categories["hr"] += 1
            elif "confidential" in file_path or "secret" in file_path:
                categories["confidential"] += 1
            elif "personal" in file_path:
                categories["personal"] += 1
        
        return categories
    
    def _count_off_hours_access(self, logs: List[Dict[str, Any]]) -> int:
        """Count off-hours access to sensitive files"""
        off_hours_count = 0
        
        for log in logs:
            hour = log.get("timestamp", datetime.now()).hour
            if hour < 7 or hour > 19:
                off_hours_count += 1
        
        return off_hours_count
    
    def _count_weekend_access(self, logs: List[Dict[str, Any]]) -> int:
        """Count weekend access events"""
        weekend_count = 0
        
        for log in logs:
            day_of_week = log.get("timestamp", datetime.now()).weekday()
            if day_of_week >= 5:  # Saturday or Sunday
                weekend_count += 1
        
        return weekend_count
    
    def _analyze_failed_access_patterns(self, escalations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze patterns in failed access attempts"""
        if not escalations:
            return {"pattern_detected": False}
        
        # Group by file path to see repeated attempts
        file_attempts = {}
        for escalation in escalations:
            file_path = escalation.get("file_path", "unknown")
            file_attempts[file_path] = file_attempts.get(file_path, 0) + 1
        
        return {
            "pattern_detected": max(file_attempts.values()) > 3,
            "most_attempted_file": max(file_attempts, key=file_attempts.get),
            "repeated_attempts": max(file_attempts.values())
        }
    
    def _detect_bulk_downloads(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect bulk file download patterns"""
        download_logs = [log for log in logs if log.get("action") == "download"]
        
        if len(download_logs) > 50:  # More than 50 downloads
            return {
                "detected": True,
                "download_count": len(download_logs),
                "time_span": "analysis_period"
            }
        
        return {"detected": False}
    
    def _detect_unusual_file_access(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect access to unusual file types or locations"""
        unusual_access = []
        unusual_extensions = [".exe", ".bat", ".cmd", ".ps1", ".vbs"]
        
        for log in logs:
            file_path = log.get("file_path", "")
            if any(ext in file_path.lower() for ext in unusual_extensions):
                unusual_access.append(log)
        
        if unusual_access:
            return {
                "detected": True,
                "unusual_file_count": len(unusual_access),
                "file_types": list(set([log.get("file_path", "").split(".")[-1] for log in unusual_access]))
            }
        
        return {"detected": False}
