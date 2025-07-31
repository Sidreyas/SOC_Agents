"""
PowerShell Script Content Analyzer Module
State 1: Script Content Analysis and Decoding
Extracts, decodes, deobfuscates, and analyzes PowerShell scripts from various sources
"""

import logging
import base64
import re
import json
import zlib
import urllib.parse
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
import hashlib
import binascii

# Configure logger
logger = logging.getLogger(__name__)

@dataclass
class ScriptElement:
    """Individual script element container"""
    content: str
    element_type: str  # command, variable, function, etc.
    encoding: str
    obfuscation_level: str
    risk_score: float
    extraction_confidence: float

@dataclass
class DecodedScript:
    """Decoded script container"""
    original_script: str
    decoded_script: str
    encoding_methods: List[str]
    obfuscation_techniques: List[str]
    extraction_success: bool
    confidence_score: float

class PowerShellScriptAnalyzer:
    """
    PowerShell Script Content Analysis Engine
    Extracts, decodes, and analyzes PowerShell scripts for malicious indicators
    """
    
    def __init__(self):
        """Initialize the PowerShell Script Analyzer"""
        self.encoding_patterns = self._initialize_encoding_patterns()
        self.obfuscation_patterns = self._initialize_obfuscation_patterns()
        self.suspicious_patterns = self._initialize_suspicious_patterns()
        self.command_categories = self._initialize_command_categories()
        
    def extract_script_content(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract PowerShell script content from various log sources
        
        Args:
            log_data: Log data containing PowerShell execution information
            
        Returns:
            Extracted script content and metadata
        """
        logger.info("Starting PowerShell script content extraction")
        
        extraction_results = {
            "extracted_scripts": [],
            "script_sources": [],
            "extraction_metadata": {
                "total_scripts": 0,
                "successful_extractions": 0,
                "failed_extractions": 0,
                "extraction_timestamp": datetime.now()
            },
            "parent_processes": [],
            "execution_context": {},
            "script_relationships": []
        }
        
        # Extract from different log sources
        extraction_results.update(self._extract_from_sysmon_logs(log_data))
        extraction_results.update(self._extract_from_powershell_logs(log_data))
        extraction_results.update(self._extract_from_winevent_logs(log_data))
        extraction_results.update(self._extract_from_edr_logs(log_data))
        
        # Analyze extraction completeness
        extraction_results["extraction_completeness"] = self._assess_extraction_completeness(
            extraction_results
        )
        
        # Identify script relationships
        extraction_results["script_relationships"] = self._identify_script_relationships(
            extraction_results["extracted_scripts"]
        )
        
        logger.info(f"Script extraction completed - {extraction_results['extraction_metadata']['total_scripts']} scripts found")
        return extraction_results
    
    def decode_and_deobfuscate(self, extraction_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decode and deobfuscate extracted PowerShell scripts
        
        Args:
            extraction_results: Results from script extraction
            
        Returns:
            Decoded and deobfuscated script analysis
        """
        logger.info("Starting script decoding and deobfuscation")
        
        decoding_results = {
            "decoded_scripts": [],
            "decoding_statistics": {
                "total_scripts": len(extraction_results.get("extracted_scripts", [])),
                "successfully_decoded": 0,
                "partially_decoded": 0,
                "decoding_failed": 0
            },
            "encoding_techniques": [],
            "obfuscation_techniques": [],
            "decoding_confidence": 0.0,
            "advanced_analysis": {}
        }
        
        extracted_scripts = extraction_results.get("extracted_scripts", [])
        
        for script_data in extracted_scripts:
            try:
                # Decode script content
                decoded_script = self._decode_script_content(script_data)
                
                # Deobfuscate script
                deobfuscated_script = self._deobfuscate_script(decoded_script)
                
                # Analyze script elements
                script_analysis = self._analyze_script_elements(deobfuscated_script)
                
                decoding_results["decoded_scripts"].append({
                    "original_script": script_data,
                    "decoded_script": decoded_script,
                    "deobfuscated_script": deobfuscated_script,
                    "script_analysis": script_analysis,
                    "decoding_success": True
                })
                
                decoding_results["decoding_statistics"]["successfully_decoded"] += 1
                
            except Exception as e:
                logger.warning(f"Failed to decode script: {str(e)}")
                decoding_results["decoded_scripts"].append({
                    "original_script": script_data,
                    "decoding_error": str(e),
                    "decoding_success": False
                })
                decoding_results["decoding_statistics"]["decoding_failed"] += 1
        
        # Compile encoding and obfuscation techniques
        decoding_results["encoding_techniques"] = self._compile_encoding_techniques(
            decoding_results["decoded_scripts"]
        )
        decoding_results["obfuscation_techniques"] = self._compile_obfuscation_techniques(
            decoding_results["decoded_scripts"]
        )
        
        # Calculate overall decoding confidence
        decoding_results["decoding_confidence"] = self._calculate_decoding_confidence(
            decoding_results
        )
        
        # Perform advanced analysis
        decoding_results["advanced_analysis"] = self._perform_advanced_script_analysis(
            decoding_results["decoded_scripts"]
        )
        
        logger.info("Script decoding and deobfuscation completed")
        return decoding_results
    
    def analyze_script_structure(self, decoding_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze PowerShell script structure and components
        
        Args:
            decoding_results: Results from decoding and deobfuscation
            
        Returns:
            Script structure analysis results
        """
        logger.info("Starting script structure analysis")
        
        structure_analysis = {
            "script_components": {},
            "function_analysis": {},
            "variable_analysis": {},
            "command_analysis": {},
            "import_analysis": {},
            "execution_flow": {},
            "complexity_metrics": {},
            "risk_indicators": [],
            "structure_confidence": 0.0
        }
        
        decoded_scripts = decoding_results.get("decoded_scripts", [])
        
        for script_data in decoded_scripts:
            if script_data.get("decoding_success", False):
                script_content = script_data.get("deobfuscated_script", {}).get("decoded_script", "")
                
                # Analyze script components
                structure_analysis["script_components"].update(
                    self._analyze_script_components(script_content)
                )
                
                # Analyze functions
                structure_analysis["function_analysis"].update(
                    self._analyze_script_functions(script_content)
                )
                
                # Analyze variables
                structure_analysis["variable_analysis"].update(
                    self._analyze_script_variables(script_content)
                )
                
                # Analyze commands
                structure_analysis["command_analysis"].update(
                    self._analyze_script_commands(script_content)
                )
                
                # Analyze imports and modules
                structure_analysis["import_analysis"].update(
                    self._analyze_script_imports(script_content)
                )
                
                # Analyze execution flow
                structure_analysis["execution_flow"].update(
                    self._analyze_execution_flow(script_content)
                )
        
        # Calculate complexity metrics
        structure_analysis["complexity_metrics"] = self._calculate_complexity_metrics(
            structure_analysis
        )
        
        # Identify risk indicators
        structure_analysis["risk_indicators"] = self._identify_structure_risk_indicators(
            structure_analysis
        )
        
        # Calculate structure analysis confidence
        structure_analysis["structure_confidence"] = self._calculate_structure_confidence(
            structure_analysis, len(decoded_scripts)
        )
        
        logger.info("Script structure analysis completed")
        return structure_analysis
    
    def generate_script_analysis_report(self, extraction_results: Dict[str, Any],
                                      decoding_results: Dict[str, Any],
                                      structure_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive script analysis report
        
        Args:
            extraction_results: Script extraction results
            decoding_results: Decoding and deobfuscation results
            structure_analysis: Script structure analysis results
            
        Returns:
            Comprehensive script analysis report
        """
        logger.info("Generating script analysis report")
        
        analysis_report = {
            "executive_summary": {},
            "technical_analysis": {},
            "risk_assessment": {},
            "indicators_of_compromise": [],
            "recommendations": [],
            "detailed_findings": {},
            "analysis_metadata": {
                "report_timestamp": datetime.now(),
                "analysis_version": "1.0",
                "report_id": f"PSA-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            }
        }
        
        # Create executive summary
        analysis_report["executive_summary"] = self._create_executive_summary(
            extraction_results, decoding_results, structure_analysis
        )
        
        # Compile technical analysis
        analysis_report["technical_analysis"] = self._compile_technical_analysis(
            extraction_results, decoding_results, structure_analysis
        )
        
        # Assess risk
        analysis_report["risk_assessment"] = self._assess_script_risk(
            extraction_results, decoding_results, structure_analysis
        )
        
        # Extract IOCs
        analysis_report["indicators_of_compromise"] = self._extract_script_iocs(
            decoding_results, structure_analysis
        )
        
        # Generate recommendations
        analysis_report["recommendations"] = self._generate_script_recommendations(
            analysis_report["risk_assessment"]
        )
        
        # Compile detailed findings
        analysis_report["detailed_findings"] = self._compile_detailed_findings(
            extraction_results, decoding_results, structure_analysis
        )
        
        logger.info("Script analysis report generation completed")
        return analysis_report
    
    def _initialize_encoding_patterns(self) -> Dict[str, Any]:
        """Initialize encoding detection patterns"""
        return {
            "base64": {
                "pattern": r"[A-Za-z0-9+/]{4,}={0,2}",
                "indicators": ["FromBase64String", "::decode", "-enc"],
                "confidence_threshold": 0.8
            },
            "hex": {
                "pattern": r"0x[0-9A-Fa-f]+",
                "indicators": ["0x", "\\x"],
                "confidence_threshold": 0.7
            },
            "url_encoding": {
                "pattern": r"%[0-9A-Fa-f]{2}",
                "indicators": ["%20", "%2F", "%3A"],
                "confidence_threshold": 0.6
            },
            "ascii": {
                "pattern": r"\[[0-9,\s]+\]",
                "indicators": ["[char]", "ASCII"],
                "confidence_threshold": 0.7
            }
        }
    
    def _initialize_obfuscation_patterns(self) -> Dict[str, Any]:
        """Initialize obfuscation detection patterns"""
        return {
            "string_concatenation": {
                "pattern": r"[\'\"][^\'\"]*[\'\"][\s]*\+[\s]*[\'\"][^\'\"]*[\'\"]",
                "indicators": ["'+", '"+', " + "],
                "risk_level": "medium"
            },
            "character_substitution": {
                "pattern": r"\$[a-zA-Z0-9_]+\[[0-9,\s\-]+\]",
                "indicators": ["[0]", "[-1]", "[1.."],
                "risk_level": "high"
            },
            "format_string": {
                "pattern": r"\-f\s*[\'\"][^\'\"]*\{[0-9,\s]+\}",
                "indicators": ["-f", "{0}", "{1}"],
                "risk_level": "medium"
            },
            "invoke_expression": {
                "pattern": r"(iex|Invoke-Expression)",
                "indicators": ["iex", "Invoke-Expression", "IEX"],
                "risk_level": "critical"
            }
        }
    
    def _initialize_suspicious_patterns(self) -> Dict[str, Any]:
        """Initialize suspicious PowerShell pattern detection"""
        return {
            "download_patterns": {
                "patterns": [
                    r"(DownloadString|DownloadFile|WebClient|System\.Net)",
                    r"(wget|curl|Invoke-WebRequest|iwr)"
                ],
                "risk_score": 0.8,
                "category": "network_activity"
            },
            "execution_patterns": {
                "patterns": [
                    r"(cmd\.exe|powershell\.exe|Start-Process)",
                    r"(Invoke-Command|Invoke-Expression|iex)"
                ],
                "risk_score": 0.7,
                "category": "code_execution"
            },
            "persistence_patterns": {
                "patterns": [
                    r"(Registry|HKLM|HKCU|Run|RunOnce)",
                    r"(ScheduledTask|WMI|CIM)"
                ],
                "risk_score": 0.9,
                "category": "persistence"
            },
            "evasion_patterns": {
                "patterns": [
                    r"(Hidden|WindowStyle|ExecutionPolicy|Bypass)",
                    r"(AMSI|Defender|AntiVirus)"
                ],
                "risk_score": 0.85,
                "category": "defense_evasion"
            }
        }
    
    def _initialize_command_categories(self) -> Dict[str, Any]:
        """Initialize PowerShell command categorization"""
        return {
            "system_information": [
                "Get-ComputerInfo", "Get-Process", "Get-Service", "whoami",
                "hostname", "Get-NetAdapter", "Get-WmiObject"
            ],
            "file_operations": [
                "Get-Content", "Set-Content", "Copy-Item", "Move-Item",
                "Remove-Item", "New-Item", "Test-Path"
            ],
            "network_operations": [
                "Invoke-WebRequest", "Invoke-RestMethod", "Test-Connection",
                "nslookup", "ping", "telnet"
            ],
            "registry_operations": [
                "Get-ItemProperty", "Set-ItemProperty", "New-ItemProperty",
                "Remove-ItemProperty", "Get-ChildItem"
            ],
            "administrative": [
                "Set-ExecutionPolicy", "Import-Module", "Get-Module",
                "Enable-PSRemoting", "New-PSSession"
            ]
        }
    
    def _extract_from_sysmon_logs(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract PowerShell scripts from Sysmon logs"""
        sysmon_extraction = {
            "sysmon_scripts": [],
            "process_creation_events": [],
            "command_line_analysis": {}
        }
        
        # Simulate Sysmon log processing
        sysmon_events = log_data.get("sysmon_logs", [])
        
        for event in sysmon_events:
            if event.get("event_id") == 1:  # Process creation
                command_line = event.get("command_line", "")
                if "powershell" in command_line.lower():
                    sysmon_extraction["sysmon_scripts"].append({
                        "command_line": command_line,
                        "process_id": event.get("process_id"),
                        "parent_process": event.get("parent_process"),
                        "timestamp": event.get("timestamp"),
                        "user": event.get("user")
                    })
        
        return sysmon_extraction
    
    def _extract_from_powershell_logs(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract scripts from PowerShell operational logs"""
        ps_extraction = {
            "powershell_scripts": [],
            "script_blocks": [],
            "module_loads": []
        }
        
        # Simulate PowerShell log processing
        ps_logs = log_data.get("powershell_logs", [])
        
        for log_entry in ps_logs:
            if log_entry.get("event_id") == 4104:  # Script Block Logging
                ps_extraction["script_blocks"].append({
                    "script_block": log_entry.get("script_block", ""),
                    "script_id": log_entry.get("script_id"),
                    "timestamp": log_entry.get("timestamp"),
                    "user": log_entry.get("user")
                })
        
        return ps_extraction
    
    def _extract_from_winevent_logs(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract scripts from Windows Event logs"""
        return {
            "winevent_scripts": [],
            "security_events": [],
            "application_events": []
        }
    
    def _extract_from_edr_logs(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract scripts from EDR solution logs"""
        return {
            "edr_scripts": [],
            "process_trees": [],
            "behavioral_analysis": {}
        }
    
    def _decode_script_content(self, script_data: Dict[str, Any]) -> DecodedScript:
        """Decode PowerShell script content"""
        script_content = script_data.get("command_line", "")
        encoding_methods = []
        decoded_content = script_content
        
        # Try Base64 decoding
        if self._is_base64_encoded(script_content):
            try:
                decoded_base64 = base64.b64decode(script_content).decode('utf-8')
                decoded_content = decoded_base64
                encoding_methods.append("base64")
            except Exception:
                pass
        
        # Try URL decoding
        if "%" in script_content:
            try:
                decoded_url = urllib.parse.unquote(script_content)
                if decoded_url != script_content:
                    decoded_content = decoded_url
                    encoding_methods.append("url_encoding")
            except Exception:
                pass
        
        # Try hex decoding
        hex_matches = re.findall(r'0x[0-9A-Fa-f]+', script_content)
        if hex_matches:
            try:
                decoded_hex = ''.join([chr(int(h, 16)) for h in hex_matches])
                encoding_methods.append("hex")
            except Exception:
                pass
        
        return DecodedScript(
            original_script=script_content,
            decoded_script=decoded_content,
            encoding_methods=encoding_methods,
            obfuscation_techniques=[],
            extraction_success=True,
            confidence_score=0.9 if encoding_methods else 0.7
        )
    
    def _deobfuscate_script(self, decoded_script: DecodedScript) -> Dict[str, Any]:
        """Deobfuscate PowerShell script"""
        script_content = decoded_script.decoded_script
        deobfuscation_techniques = []
        deobfuscated_content = script_content
        
        # Remove string concatenation obfuscation
        if "+" in script_content and ("'" in script_content or '"' in script_content):
            # Simplified string concatenation removal
            deobfuscated_content = re.sub(r"'(\s*\+\s*)'", "", deobfuscated_content)
            deobfuscation_techniques.append("string_concatenation")
        
        # Handle character substitution
        char_substitution_pattern = r'\$[a-zA-Z0-9_]+\[[0-9,\s\-]+\]'
        if re.search(char_substitution_pattern, script_content):
            deobfuscation_techniques.append("character_substitution")
        
        # Handle format string obfuscation
        if "-f" in script_content and "{" in script_content:
            deobfuscation_techniques.append("format_string")
        
        return {
            "original_script": decoded_script.original_script,
            "decoded_script": decoded_script.decoded_script,
            "deobfuscated_script": deobfuscated_content,
            "deobfuscation_techniques": deobfuscation_techniques,
            "deobfuscation_success": len(deobfuscation_techniques) > 0,
            "confidence_score": 0.8 if deobfuscation_techniques else 0.6
        }
    
    def _analyze_script_elements(self, deobfuscated_script: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze individual script elements"""
        script_content = deobfuscated_script.get("deobfuscated_script", "")
        
        elements = {
            "commands": self._extract_commands(script_content),
            "variables": self._extract_variables(script_content),
            "functions": self._extract_functions(script_content),
            "imports": self._extract_imports(script_content),
            "strings": self._extract_strings(script_content),
            "suspicious_indicators": self._extract_suspicious_indicators(script_content)
        }
        
        return elements
    
    def _extract_commands(self, script_content: str) -> List[Dict[str, Any]]:
        """Extract PowerShell commands from script"""
        commands = []
        
        # Common PowerShell cmdlet pattern
        cmdlet_pattern = r'([A-Z][a-z]+-[A-Z][a-zA-Z]+)'
        cmdlets = re.findall(cmdlet_pattern, script_content)
        
        for cmdlet in cmdlets:
            commands.append({
                "command": cmdlet,
                "category": self._categorize_command(cmdlet),
                "risk_level": self._assess_command_risk(cmdlet)
            })
        
        return commands
    
    def _extract_variables(self, script_content: str) -> List[Dict[str, Any]]:
        """Extract variables from script"""
        variables = []
        
        # PowerShell variable pattern
        var_pattern = r'\$([a-zA-Z_][a-zA-Z0-9_]*)'
        var_matches = re.findall(var_pattern, script_content)
        
        for var in set(var_matches):
            variables.append({
                "name": var,
                "suspicious": self._is_suspicious_variable(var)
            })
        
        return variables
    
    def _extract_functions(self, script_content: str) -> List[Dict[str, Any]]:
        """Extract function definitions from script"""
        functions = []
        
        # Function definition pattern
        func_pattern = r'function\s+([a-zA-Z_][a-zA-Z0-9_]*)'
        func_matches = re.findall(func_pattern, script_content, re.IGNORECASE)
        
        for func in func_matches:
            functions.append({
                "name": func,
                "suspicious": self._is_suspicious_function(func)
            })
        
        return functions
    
    def _extract_imports(self, script_content: str) -> List[Dict[str, Any]]:
        """Extract module imports from script"""
        imports = []
        
        # Import patterns
        import_patterns = [
            r'Import-Module\s+([a-zA-Z0-9\._-]+)',
            r'Add-Type\s+.*-Name\s+([a-zA-Z0-9_]+)'
        ]
        
        for pattern in import_patterns:
            matches = re.findall(pattern, script_content, re.IGNORECASE)
            for match in matches:
                imports.append({
                    "module": match,
                    "suspicious": self._is_suspicious_module(match)
                })
        
        return imports
    
    def _extract_strings(self, script_content: str) -> List[Dict[str, Any]]:
        """Extract string literals from script"""
        strings = []
        
        # String literal patterns
        string_patterns = [
            r'"([^"]*)"',  # Double quoted strings
            r"'([^']*)'",  # Single quoted strings
        ]
        
        for pattern in string_patterns:
            matches = re.findall(pattern, script_content)
            for match in matches:
                if len(match) > 5:  # Only analyze meaningful strings
                    strings.append({
                        "content": match[:100],  # Truncate for analysis
                        "length": len(match),
                        "suspicious": self._is_suspicious_string(match)
                    })
        
        return strings
    
    def _extract_suspicious_indicators(self, script_content: str) -> List[Dict[str, Any]]:
        """Extract suspicious indicators from script content"""
        indicators = []
        
        for category, patterns in self.suspicious_patterns.items():
            for pattern in patterns["patterns"]:
                matches = re.findall(pattern, script_content, re.IGNORECASE)
                if matches:
                    indicators.append({
                        "category": patterns["category"],
                        "pattern": pattern,
                        "matches": len(matches),
                        "risk_score": patterns["risk_score"],
                        "examples": matches[:3]  # First 3 matches as examples
                    })
        
        return indicators
    
    def _categorize_command(self, command: str) -> str:
        """Categorize PowerShell command by function"""
        for category, commands in self.command_categories.items():
            if command in commands:
                return category
        
        # Basic categorization based on verb
        verb = command.split('-')[0] if '-' in command else command
        verb_categories = {
            'Get': 'information_gathering',
            'Set': 'configuration',
            'New': 'creation',
            'Remove': 'deletion',
            'Invoke': 'execution',
            'Start': 'execution',
            'Stop': 'control',
            'Test': 'validation'
        }
        
        return verb_categories.get(verb, 'unknown')
    
    def _assess_command_risk(self, command: str) -> str:
        """Assess risk level of PowerShell command"""
        high_risk_commands = [
            'Invoke-Expression', 'Invoke-Command', 'Start-Process',
            'Add-Type', 'Set-ExecutionPolicy', 'Invoke-WebRequest',
            'DownloadString', 'DownloadFile'
        ]
        
        medium_risk_commands = [
            'Get-Content', 'Set-Content', 'Copy-Item',
            'Move-Item', 'Remove-Item', 'New-Item'
        ]
        
        if command in high_risk_commands:
            return "high"
        elif command in medium_risk_commands:
            return "medium"
        else:
            return "low"
    
    def _is_suspicious_variable(self, variable_name: str) -> bool:
        """Check if variable name is suspicious"""
        suspicious_indicators = [
            'temp', 'tmp', 'shell', 'cmd', 'exec', 'payload',
            'download', 'upload', 'bypass', 'decode', 'encode'
        ]
        
        return any(indicator in variable_name.lower() for indicator in suspicious_indicators)
    
    def _is_suspicious_function(self, function_name: str) -> bool:
        """Check if function name is suspicious"""
        suspicious_indicators = [
            'decrypt', 'decode', 'bypass', 'inject', 'exploit',
            'payload', 'shell', 'backdoor', 'stealth'
        ]
        
        return any(indicator in function_name.lower() for indicator in suspicious_indicators)
    
    def _is_suspicious_module(self, module_name: str) -> bool:
        """Check if module name is suspicious"""
        suspicious_modules = [
            'reflection', 'system.security', 'cryptography',
            'compression', 'diagnostics'
        ]
        
        return any(module in module_name.lower() for module in suspicious_modules)
    
    def _is_suspicious_string(self, string_content: str) -> bool:
        """Check if string content is suspicious"""
        suspicious_indicators = [
            'http://', 'https://', 'ftp://', 'base64',
            'powershell', 'cmd.exe', 'bypass', 'hidden'
        ]
        
        return any(indicator in string_content.lower() for indicator in suspicious_indicators)
    
    def _is_base64_encoded(self, content: str) -> bool:
        """Check if content appears to be Base64 encoded"""
        if len(content) < 4:
            return False
        
        # Check for Base64 pattern and length divisible by 4
        base64_pattern = r'^[A-Za-z0-9+/]+={0,2}$'
        return bool(re.match(base64_pattern, content)) and len(content) % 4 == 0
    
    def _assess_extraction_completeness(self, extraction_results: Dict[str, Any]) -> float:
        """Assess completeness of script extraction"""
        total_sources = 4  # Sysmon, PowerShell, WinEvent, EDR
        successful_sources = 0
        
        if extraction_results.get("sysmon_scripts"):
            successful_sources += 1
        if extraction_results.get("powershell_scripts"):
            successful_sources += 1
        if extraction_results.get("winevent_scripts"):
            successful_sources += 1
        if extraction_results.get("edr_scripts"):
            successful_sources += 1
        
        return successful_sources / total_sources
    
    def _identify_script_relationships(self, extracted_scripts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify relationships between extracted scripts"""
        relationships = []
        
        # Simple relationship detection based on shared elements
        for i, script1 in enumerate(extracted_scripts):
            for j, script2 in enumerate(extracted_scripts[i+1:], i+1):
                similarity = self._calculate_script_similarity(script1, script2)
                if similarity > 0.7:
                    relationships.append({
                        "script1_index": i,
                        "script2_index": j,
                        "relationship_type": "similar_content",
                        "similarity_score": similarity
                    })
        
        return relationships
    
    def _calculate_script_similarity(self, script1: Dict[str, Any], script2: Dict[str, Any]) -> float:
        """Calculate similarity between two scripts"""
        content1 = script1.get("command_line", "")
        content2 = script2.get("command_line", "")
        
        # Simple similarity calculation based on common substrings
        if not content1 or not content2:
            return 0.0
        
        # Calculate Jaccard similarity of words
        words1 = set(content1.lower().split())
        words2 = set(content2.lower().split())
        
        intersection = len(words1.intersection(words2))
        union = len(words1.union(words2))
        
        return intersection / union if union > 0 else 0.0
    
    def _compile_encoding_techniques(self, decoded_scripts: List[Dict[str, Any]]) -> List[str]:
        """Compile list of encoding techniques found"""
        techniques = set()
        
        for script in decoded_scripts:
            decoded_script = script.get("decoded_script", {})
            if hasattr(decoded_script, 'encoding_methods'):
                techniques.update(decoded_script.encoding_methods)
        
        return list(techniques)
    
    def _compile_obfuscation_techniques(self, decoded_scripts: List[Dict[str, Any]]) -> List[str]:
        """Compile list of obfuscation techniques found"""
        techniques = set()
        
        for script in decoded_scripts:
            deobfuscated_script = script.get("deobfuscated_script", {})
            if isinstance(deobfuscated_script, dict):
                techniques.update(deobfuscated_script.get("deobfuscation_techniques", []))
        
        return list(techniques)
    
    def _calculate_decoding_confidence(self, decoding_results: Dict[str, Any]) -> float:
        """Calculate overall confidence in decoding results"""
        stats = decoding_results.get("decoding_statistics", {})
        total = stats.get("total_scripts", 0)
        successful = stats.get("successfully_decoded", 0)
        
        if total == 0:
            return 0.0
        
        return successful / total
    
    def _perform_advanced_script_analysis(self, decoded_scripts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Perform advanced analysis on decoded scripts"""
        return {
            "script_entropy": self._calculate_script_entropy(decoded_scripts),
            "cross_script_correlation": self._correlate_scripts(decoded_scripts),
            "behavioral_patterns": self._identify_behavioral_patterns(decoded_scripts),
            "threat_indicators": self._extract_threat_indicators(decoded_scripts)
        }
    
    def _calculate_script_entropy(self, decoded_scripts: List[Dict[str, Any]]) -> Dict[str, float]:
        """Calculate entropy of script content"""
        entropy_results = {}
        
        for i, script in enumerate(decoded_scripts):
            script_content = script.get("deobfuscated_script", {}).get("deobfuscated_script", "")
            if script_content:
                entropy = self._calculate_shannon_entropy(script_content)
                entropy_results[f"script_{i}"] = entropy
        
        return entropy_results
    
    def _calculate_shannon_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of string data"""
        if not data:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in data:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        data_len = len(data)
        entropy = 0.0
        
        for count in char_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def _correlate_scripts(self, decoded_scripts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Correlate patterns across multiple scripts"""
        correlation = {
            "common_patterns": [],
            "shared_variables": [],
            "similar_functions": [],
            "correlation_matrix": {}
        }
        
        # Find common patterns across scripts
        all_patterns = []
        for script in decoded_scripts:
            script_analysis = script.get("script_analysis", {})
            indicators = script_analysis.get("suspicious_indicators", [])
            for indicator in indicators:
                all_patterns.append(indicator.get("category"))
        
        # Count pattern frequencies
        pattern_counts = {}
        for pattern in all_patterns:
            pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1
        
        # Identify common patterns (appearing in multiple scripts)
        correlation["common_patterns"] = [
            pattern for pattern, count in pattern_counts.items() if count > 1
        ]
        
        return correlation
    
    def _identify_behavioral_patterns(self, decoded_scripts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Identify behavioral patterns in scripts"""
        patterns = {
            "execution_patterns": [],
            "persistence_patterns": [],
            "network_patterns": [],
            "evasion_patterns": []
        }
        
        for script in decoded_scripts:
            script_analysis = script.get("script_analysis", {})
            indicators = script_analysis.get("suspicious_indicators", [])
            
            for indicator in indicators:
                category = indicator.get("category")
                if category in patterns:
                    patterns[category].append(indicator)
        
        return patterns
    
    def _extract_threat_indicators(self, decoded_scripts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract threat indicators from decoded scripts"""
        threat_indicators = []
        
        for script in decoded_scripts:
            script_analysis = script.get("script_analysis", {})
            indicators = script_analysis.get("suspicious_indicators", [])
            
            for indicator in indicators:
                if indicator.get("risk_score", 0) > 0.7:
                    threat_indicators.append({
                        "type": "high_risk_pattern",
                        "category": indicator.get("category"),
                        "risk_score": indicator.get("risk_score"),
                        "description": f"High-risk {indicator.get('category')} pattern detected"
                    })
        
        return threat_indicators
    
    def _analyze_script_components(self, script_content: str) -> Dict[str, Any]:
        """Analyze script components and structure"""
        components = {
            "total_lines": len(script_content.split('\n')),
            "total_characters": len(script_content),
            "cmdlet_count": len(re.findall(r'[A-Z][a-z]+-[A-Z][a-zA-Z]+', script_content)),
            "variable_count": len(re.findall(r'\$[a-zA-Z_][a-zA-Z0-9_]*', script_content)),
            "function_count": len(re.findall(r'function\s+[a-zA-Z_][a-zA-Z0-9_]*', script_content, re.IGNORECASE)),
            "comment_count": len(re.findall(r'#.*', script_content)),
            "string_literals": len(re.findall(r'["\'][^"\']*["\']', script_content))
        }
        
        return components
    
    def _analyze_script_functions(self, script_content: str) -> Dict[str, Any]:
        """Analyze function definitions in script"""
        functions = {}
        
        # Find function definitions
        func_pattern = r'function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\{'
        matches = re.finditer(func_pattern, script_content, re.IGNORECASE)
        
        for match in matches:
            func_name = match.group(1)
            func_start = match.start()
            
            # Try to find function body (simplified)
            brace_count = 0
            func_end = func_start
            for i, char in enumerate(script_content[func_start:]):
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        func_end = func_start + i + 1
                        break
            
            func_body = script_content[func_start:func_end]
            functions[func_name] = {
                "body_length": len(func_body),
                "parameter_count": len(re.findall(r'param\s*\(', func_body, re.IGNORECASE)),
                "return_statements": len(re.findall(r'return\s+', func_body, re.IGNORECASE)),
                "risk_indicators": self._count_risk_indicators_in_text(func_body)
            }
        
        return functions
    
    def _analyze_script_variables(self, script_content: str) -> Dict[str, Any]:
        """Analyze variable usage in script"""
        variables = {}
        
        # Find variable assignments
        var_pattern = r'\$([a-zA-Z_][a-zA-Z0-9_]*)\s*='
        assignments = re.findall(var_pattern, script_content)
        
        # Find variable references
        ref_pattern = r'\$([a-zA-Z_][a-zA-Z0-9_]*)'
        references = re.findall(ref_pattern, script_content)
        
        all_vars = set(assignments + references)
        
        for var in all_vars:
            assignment_count = assignments.count(var)
            reference_count = references.count(var)
            
            variables[var] = {
                "assignments": assignment_count,
                "references": reference_count,
                "suspicious": self._is_suspicious_variable(var),
                "scope": "global" if assignment_count > 0 else "reference_only"
            }
        
        return variables
    
    def _analyze_script_commands(self, script_content: str) -> Dict[str, Any]:
        """Analyze PowerShell commands in script"""
        commands = {}
        
        # Find cmdlets
        cmdlet_pattern = r'([A-Z][a-z]+-[A-Z][a-zA-Z]+)'
        cmdlets = re.findall(cmdlet_pattern, script_content)
        
        for cmdlet in set(cmdlets):
            count = cmdlets.count(cmdlet)
            commands[cmdlet] = {
                "usage_count": count,
                "category": self._categorize_command(cmdlet),
                "risk_level": self._assess_command_risk(cmdlet),
                "parameters": self._extract_command_parameters(script_content, cmdlet)
            }
        
        return commands
    
    def _analyze_script_imports(self, script_content: str) -> Dict[str, Any]:
        """Analyze module imports and type definitions"""
        imports = {
            "modules": [],
            "assemblies": [],
            "types": []
        }
        
        # Import-Module
        module_pattern = r'Import-Module\s+([a-zA-Z0-9\._-]+)'
        modules = re.findall(module_pattern, script_content, re.IGNORECASE)
        imports["modules"] = list(set(modules))
        
        # Add-Type
        type_pattern = r'Add-Type\s+.*-Name\s+([a-zA-Z0-9_]+)'
        types = re.findall(type_pattern, script_content, re.IGNORECASE)
        imports["types"] = list(set(types))
        
        # Assembly loading
        assembly_pattern = r'\[Reflection\.Assembly\]::Load'
        if re.search(assembly_pattern, script_content, re.IGNORECASE):
            imports["assemblies"].append("Dynamic_Assembly_Loading")
        
        return imports
    
    def _analyze_execution_flow(self, script_content: str) -> Dict[str, Any]:
        """Analyze script execution flow and control structures"""
        flow_analysis = {
            "conditional_statements": 0,
            "loop_statements": 0,
            "try_catch_blocks": 0,
            "function_calls": 0,
            "pipeline_operations": 0,
            "complexity_score": 0.0
        }
        
        # Count conditional statements
        flow_analysis["conditional_statements"] = len(re.findall(r'\bif\s*\(', script_content, re.IGNORECASE))
        
        # Count loops
        loop_patterns = [r'\bfor\s*\(', r'\bwhile\s*\(', r'\bforeach\s*\(']
        for pattern in loop_patterns:
            flow_analysis["loop_statements"] += len(re.findall(pattern, script_content, re.IGNORECASE))
        
        # Count try-catch blocks
        flow_analysis["try_catch_blocks"] = len(re.findall(r'\btry\s*\{', script_content, re.IGNORECASE))
        
        # Count function calls
        flow_analysis["function_calls"] = len(re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*\s*\(', script_content))
        
        # Count pipeline operations
        flow_analysis["pipeline_operations"] = script_content.count('|')
        
        # Calculate complexity score
        flow_analysis["complexity_score"] = (
            flow_analysis["conditional_statements"] * 0.2 +
            flow_analysis["loop_statements"] * 0.3 +
            flow_analysis["try_catch_blocks"] * 0.1 +
            flow_analysis["function_calls"] * 0.05 +
            flow_analysis["pipeline_operations"] * 0.1
        )
        
        return flow_analysis
    
    def _extract_command_parameters(self, script_content: str, cmdlet: str) -> List[str]:
        """Extract parameters used with a specific cmdlet"""
        parameters = []
        
        # Find cmdlet usage contexts
        cmdlet_pattern = rf'{re.escape(cmdlet)}\s+([^|;]+)'
        matches = re.findall(cmdlet_pattern, script_content, re.IGNORECASE)
        
        for match in matches:
            # Extract parameter-like patterns
            param_pattern = r'-([a-zA-Z]+)'
            params = re.findall(param_pattern, match)
            parameters.extend(params)
        
        return list(set(parameters))
    
    def _count_risk_indicators_in_text(self, text: str) -> int:
        """Count risk indicators in a text block"""
        risk_count = 0
        
        for category, patterns in self.suspicious_patterns.items():
            for pattern in patterns["patterns"]:
                matches = re.findall(pattern, text, re.IGNORECASE)
                risk_count += len(matches)
        
        return risk_count
    
    def _calculate_complexity_metrics(self, structure_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate script complexity metrics"""
        complexity = {
            "overall_complexity": 0.0,
            "structural_complexity": 0.0,
            "functional_complexity": 0.0,
            "command_complexity": 0.0
        }
        
        # Structural complexity
        execution_flow = structure_analysis.get("execution_flow", {})
        complexity["structural_complexity"] = execution_flow.get("complexity_score", 0.0)
        
        # Functional complexity
        functions = structure_analysis.get("function_analysis", {})
        func_count = len(functions)
        avg_func_complexity = sum(func.get("risk_indicators", 0) for func in functions.values()) / max(func_count, 1)
        complexity["functional_complexity"] = min(avg_func_complexity * 0.1, 1.0)
        
        # Command complexity
        commands = structure_analysis.get("command_analysis", {})
        high_risk_commands = sum(1 for cmd in commands.values() if cmd.get("risk_level") == "high")
        complexity["command_complexity"] = min(high_risk_commands * 0.2, 1.0)
        
        # Overall complexity
        complexity["overall_complexity"] = (
            complexity["structural_complexity"] * 0.4 +
            complexity["functional_complexity"] * 0.3 +
            complexity["command_complexity"] * 0.3
        )
        
        return complexity
    
    def _identify_structure_risk_indicators(self, structure_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify risk indicators from structure analysis"""
        risk_indicators = []
        
        # Check commands
        commands = structure_analysis.get("command_analysis", {})
        for cmd, details in commands.items():
            if details.get("risk_level") == "high":
                risk_indicators.append({
                    "type": "high_risk_command",
                    "indicator": cmd,
                    "risk_score": 0.8,
                    "description": f"High-risk PowerShell command: {cmd}"
                })
        
        # Check complexity
        complexity = structure_analysis.get("complexity_metrics", {})
        if complexity.get("overall_complexity", 0.0) > 0.7:
            risk_indicators.append({
                "type": "high_complexity",
                "indicator": "complex_script_structure",
                "risk_score": 0.6,
                "description": "Script has high complexity indicating potential obfuscation"
            })
        
        # Check imports
        imports = structure_analysis.get("import_analysis", {})
        suspicious_modules = ["reflection", "system.security", "cryptography"]
        for module in imports.get("modules", []):
            if any(sus in module.lower() for sus in suspicious_modules):
                risk_indicators.append({
                    "type": "suspicious_import",
                    "indicator": module,
                    "risk_score": 0.7,
                    "description": f"Suspicious module import: {module}"
                })
        
        return risk_indicators
    
    def _calculate_structure_confidence(self, structure_analysis: Dict[str, Any], script_count: int) -> float:
        """Calculate confidence in structure analysis"""
        confidence_factors = []
        
        # Script count factor
        if script_count > 0:
            confidence_factors.append(min(script_count * 0.1, 0.8))
        
        # Analysis completeness factor
        analysis_sections = ["script_components", "command_analysis", "variable_analysis"]
        completed_sections = sum(1 for section in analysis_sections if structure_analysis.get(section))
        completeness = completed_sections / len(analysis_sections)
        confidence_factors.append(completeness)
        
        # Data quality factor
        commands = structure_analysis.get("command_analysis", {})
        if len(commands) > 0:
            confidence_factors.append(0.9)
        else:
            confidence_factors.append(0.5)
        
        return sum(confidence_factors) / len(confidence_factors) if confidence_factors else 0.0
    
    def _create_executive_summary(self, extraction_results: Dict[str, Any],
                                decoding_results: Dict[str, Any],
                                structure_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Create executive summary of script analysis"""
        total_scripts = extraction_results.get("extraction_metadata", {}).get("total_scripts", 0)
        decoded_scripts = decoding_results.get("decoding_statistics", {}).get("successfully_decoded", 0)
        risk_indicators = len(structure_analysis.get("risk_indicators", []))
        
        return {
            "total_scripts_analyzed": total_scripts,
            "successfully_decoded": decoded_scripts,
            "risk_indicators_found": risk_indicators,
            "overall_risk_level": self._calculate_overall_risk_level(structure_analysis),
            "key_findings": self._extract_key_findings(structure_analysis),
            "immediate_actions_required": risk_indicators > 5
        }
    
    def _compile_technical_analysis(self, extraction_results: Dict[str, Any],
                                  decoding_results: Dict[str, Any],
                                  structure_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Compile technical analysis details"""
        return {
            "extraction_summary": extraction_results.get("extraction_metadata", {}),
            "decoding_summary": decoding_results.get("decoding_statistics", {}),
            "structure_summary": {
                "complexity_metrics": structure_analysis.get("complexity_metrics", {}),
                "command_analysis": len(structure_analysis.get("command_analysis", {})),
                "function_analysis": len(structure_analysis.get("function_analysis", {})),
                "variable_analysis": len(structure_analysis.get("variable_analysis", {}))
            },
            "encoding_techniques": decoding_results.get("encoding_techniques", []),
            "obfuscation_techniques": decoding_results.get("obfuscation_techniques", [])
        }
    
    def _assess_script_risk(self, extraction_results: Dict[str, Any],
                          decoding_results: Dict[str, Any],
                          structure_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall risk of analyzed scripts"""
        risk_factors = []
        
        # Obfuscation risk
        obfuscation_techniques = decoding_results.get("obfuscation_techniques", [])
        if obfuscation_techniques:
            risk_factors.append({
                "factor": "obfuscation",
                "score": min(len(obfuscation_techniques) * 0.3, 1.0),
                "description": f"Script uses {len(obfuscation_techniques)} obfuscation techniques"
            })
        
        # Command risk
        commands = structure_analysis.get("command_analysis", {})
        high_risk_commands = sum(1 for cmd in commands.values() if cmd.get("risk_level") == "high")
        if high_risk_commands > 0:
            risk_factors.append({
                "factor": "high_risk_commands",
                "score": min(high_risk_commands * 0.2, 1.0),
                "description": f"Script contains {high_risk_commands} high-risk commands"
            })
        
        # Complexity risk
        complexity = structure_analysis.get("complexity_metrics", {}).get("overall_complexity", 0.0)
        if complexity > 0.5:
            risk_factors.append({
                "factor": "complexity",
                "score": complexity,
                "description": f"Script has high complexity score: {complexity:.2f}"
            })
        
        overall_risk = sum(factor["score"] for factor in risk_factors) / max(len(risk_factors), 1)
        
        return {
            "overall_risk_score": overall_risk,
            "risk_level": self._score_to_risk_level(overall_risk),
            "risk_factors": risk_factors,
            "mitigation_priority": "high" if overall_risk > 0.7 else "medium" if overall_risk > 0.4 else "low"
        }
    
    def _extract_script_iocs(self, decoding_results: Dict[str, Any],
                           structure_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract indicators of compromise from script analysis"""
        iocs = []
        
        # Extract from risk indicators
        risk_indicators = structure_analysis.get("risk_indicators", [])
        for indicator in risk_indicators:
            iocs.append({
                "type": "behavioral",
                "value": indicator.get("indicator"),
                "description": indicator.get("description"),
                "confidence": indicator.get("risk_score")
            })
        
        # Extract from suspicious patterns
        decoded_scripts = decoding_results.get("decoded_scripts", [])
        for script in decoded_scripts:
            script_analysis = script.get("script_analysis", {})
            indicators = script_analysis.get("suspicious_indicators", [])
            
            for indicator in indicators:
                for example in indicator.get("examples", []):
                    iocs.append({
                        "type": "pattern",
                        "value": example,
                        "category": indicator.get("category"),
                        "confidence": indicator.get("risk_score")
                    })
        
        return iocs
    
    def _generate_script_recommendations(self, risk_assessment: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate recommendations based on risk assessment"""
        recommendations = []
        
        risk_level = risk_assessment.get("risk_level", "low")
        risk_factors = risk_assessment.get("risk_factors", [])
        
        if risk_level == "high":
            recommendations.append({
                "priority": "critical",
                "action": "Immediate containment required",
                "description": "Scripts show high-risk characteristics requiring immediate investigation"
            })
        
        for factor in risk_factors:
            if factor["factor"] == "obfuscation":
                recommendations.append({
                    "priority": "high",
                    "action": "Analyze obfuscation techniques",
                    "description": "Further analysis needed to understand obfuscation purpose"
                })
            elif factor["factor"] == "high_risk_commands":
                recommendations.append({
                    "priority": "high",
                    "action": "Review command usage",
                    "description": "Validate legitimacy of high-risk PowerShell commands"
                })
        
        return recommendations
    
    def _compile_detailed_findings(self, extraction_results: Dict[str, Any],
                                 decoding_results: Dict[str, Any],
                                 structure_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Compile detailed analysis findings"""
        return {
            "script_extraction": {
                "total_sources": 4,
                "successful_extractions": extraction_results.get("extraction_metadata", {}).get("successful_extractions", 0),
                "extraction_completeness": extraction_results.get("extraction_completeness", 0.0)
            },
            "script_decoding": {
                "encoding_techniques": decoding_results.get("encoding_techniques", []),
                "obfuscation_techniques": decoding_results.get("obfuscation_techniques", []),
                "decoding_confidence": decoding_results.get("decoding_confidence", 0.0)
            },
            "script_structure": {
                "complexity_analysis": structure_analysis.get("complexity_metrics", {}),
                "risk_indicators": structure_analysis.get("risk_indicators", []),
                "structure_confidence": structure_analysis.get("structure_confidence", 0.0)
            }
        }
    
    def _calculate_overall_risk_level(self, structure_analysis: Dict[str, Any]) -> str:
        """Calculate overall risk level"""
        risk_indicators = structure_analysis.get("risk_indicators", [])
        high_risk_count = sum(1 for indicator in risk_indicators if indicator.get("risk_score", 0) > 0.7)
        
        if high_risk_count >= 3:
            return "critical"
        elif high_risk_count >= 1:
            return "high"
        elif len(risk_indicators) > 0:
            return "medium"
        else:
            return "low"
    
    def _extract_key_findings(self, structure_analysis: Dict[str, Any]) -> List[str]:
        """Extract key findings from structure analysis"""
        findings = []
        
        # Check for high-risk commands
        commands = structure_analysis.get("command_analysis", {})
        high_risk_commands = [cmd for cmd, details in commands.items() if details.get("risk_level") == "high"]
        if high_risk_commands:
            findings.append(f"High-risk commands detected: {', '.join(high_risk_commands[:3])}")
        
        # Check complexity
        complexity = structure_analysis.get("complexity_metrics", {}).get("overall_complexity", 0.0)
        if complexity > 0.7:
            findings.append(f"High script complexity detected: {complexity:.2f}")
        
        # Check risk indicators
        risk_indicators = structure_analysis.get("risk_indicators", [])
        if len(risk_indicators) > 2:
            findings.append(f"{len(risk_indicators)} risk indicators identified")
        
        return findings
    
    def _score_to_risk_level(self, score: float) -> str:
        """Convert risk score to risk level"""
        if score >= 0.8:
            return "critical"
        elif score >= 0.6:
            return "high"
        elif score >= 0.4:
            return "medium"
        else:
            return "low"
    
    def _extract_strings(self, script_content: str) -> List[Dict[str, Any]]:
        """Extract string literals from script"""
        strings = []
        
        # String patterns
        string_patterns = [
            r'"([^"]+)"',
            r"'([^']+)'"
        ]
        
        for pattern in string_patterns:
            matches = re.findall(pattern, script_content)
            for match in matches:
                if len(match) > 5:  # Only include meaningful strings
                    strings.append({
                        "content": match,
                        "suspicious": self._is_suspicious_string(match)
                    })
        
        return strings[:20]  # Limit to prevent overflow
    
    def _extract_suspicious_indicators(self, script_content: str) -> List[Dict[str, Any]]:
        """Extract suspicious indicators from script"""
        indicators = []
        
        for category, patterns in self.suspicious_patterns.items():
            for pattern in patterns["patterns"]:
                matches = re.findall(pattern, script_content, re.IGNORECASE)
                if matches:
                    indicators.append({
                        "category": category,
                        "pattern": pattern,
                        "matches": len(matches),
                        "risk_score": patterns["risk_score"]
                    })
        
        return indicators
    
    def _is_base64_encoded(self, content: str) -> bool:
        """Check if content appears to be Base64 encoded"""
        try:
            # Remove potential PowerShell Base64 indicators
            clean_content = re.sub(r'[^A-Za-z0-9+/=]', '', content)
            if len(clean_content) < 4 or len(clean_content) % 4 != 0:
                return False
            base64.b64decode(clean_content)
            return True
        except Exception:
            return False
    
    def _categorize_command(self, command: str) -> str:
        """Categorize PowerShell command"""
        for category, commands in self.command_categories.items():
            if command in commands:
                return category
        return "unknown"
    
    def _assess_command_risk(self, command: str) -> str:
        """Assess risk level of PowerShell command"""
        high_risk_commands = [
            "Invoke-Expression", "Invoke-Command", "Start-Process",
            "Add-Type", "New-Object", "Invoke-WebRequest"
        ]
        
        medium_risk_commands = [
            "Set-ExecutionPolicy", "Import-Module", "Get-WmiObject",
            "Remove-Item", "Copy-Item"
        ]
        
        if command in high_risk_commands:
            return "high"
        elif command in medium_risk_commands:
            return "medium"
        else:
            return "low"
    
    def _is_suspicious_variable(self, var_name: str) -> bool:
        """Check if variable name is suspicious"""
        suspicious_vars = [
            "payload", "shellcode", "exploit", "backdoor",
            "virus", "malware", "trojan", "keylog"
        ]
        return any(sus in var_name.lower() for sus in suspicious_vars)
    
    def _is_suspicious_function(self, func_name: str) -> bool:
        """Check if function name is suspicious"""
        suspicious_funcs = [
            "invoke", "execute", "download", "decrypt",
            "bypass", "disable", "hide", "stealth"
        ]
        return any(sus in func_name.lower() for sus in suspicious_funcs)
    
    def _is_suspicious_module(self, module_name: str) -> bool:
        """Check if module name is suspicious"""
        suspicious_modules = [
            "reflection", "cryptography", "compression",
            "security", "management"
        ]
        return any(sus in module_name.lower() for sus in suspicious_modules)
    
    def _is_suspicious_string(self, string_content: str) -> bool:
        """Check if string content is suspicious"""
        suspicious_strings = [
            "http://", "https://", "ftp://", "cmd.exe",
            "powershell.exe", "rundll32", "regsvr32"
        ]
        return any(sus in string_content.lower() for sus in suspicious_strings)
    
    def _assess_extraction_completeness(self, extraction_results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess completeness of script extraction"""
        total_sources = 4  # sysmon, powershell, winevent, edr
        available_sources = 0
        
        if extraction_results.get("sysmon_scripts"):
            available_sources += 1
        if extraction_results.get("powershell_scripts"):
            available_sources += 1
        if extraction_results.get("winevent_scripts"):
            available_sources += 1
        if extraction_results.get("edr_scripts"):
            available_sources += 1
        
        completeness_score = available_sources / total_sources
        
        return {
            "completeness_score": completeness_score,
            "available_sources": available_sources,
            "total_sources": total_sources,
            "missing_sources": total_sources - available_sources
        }
    
    def _identify_script_relationships(self, extracted_scripts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify relationships between extracted scripts"""
        relationships = []
        
        # Simple relationship detection based on timing and process hierarchy
        for i, script1 in enumerate(extracted_scripts):
            for j, script2 in enumerate(extracted_scripts[i+1:], i+1):
                relationship_score = self._calculate_relationship_score(script1, script2)
                if relationship_score > 0.5:
                    relationships.append({
                        "script1_index": i,
                        "script2_index": j,
                        "relationship_type": "execution_chain",
                        "relationship_score": relationship_score
                    })
        
        return relationships
    
    def _calculate_relationship_score(self, script1: Dict[str, Any], script2: Dict[str, Any]) -> float:
        """Calculate relationship score between two scripts"""
        score = 0.0
        
        # Check if scripts are from same process tree
        if script1.get("parent_process") == script2.get("process_id"):
            score += 0.5
        
        # Check temporal proximity
        time1 = script1.get("timestamp", datetime.min)
        time2 = script2.get("timestamp", datetime.min)
        if isinstance(time1, str):
            time1 = datetime.now()
        if isinstance(time2, str):
            time2 = datetime.now()
            
        time_diff = abs((time1 - time2).total_seconds())
        if time_diff < 60:  # Within 1 minute
            score += 0.3
        
        return min(score, 1.0)
    
    def _compile_encoding_techniques(self, decoded_scripts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Compile encoding techniques found across scripts"""
        techniques = {}
        
        for script in decoded_scripts:
            if script.get("decoding_success"):
                decoded_data = script.get("decoded_script", {})
                encoding_methods = decoded_data.get("encoding_methods", [])
                
                for method in encoding_methods:
                    if method not in techniques:
                        techniques[method] = {"count": 0, "scripts": []}
                    techniques[method]["count"] += 1
                    techniques[method]["scripts"].append(script.get("original_script", {}).get("process_id"))
        
        return [{"technique": k, **v} for k, v in techniques.items()]
    
    def _compile_obfuscation_techniques(self, decoded_scripts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Compile obfuscation techniques found across scripts"""
        techniques = {}
        
        for script in decoded_scripts:
            if script.get("decoding_success"):
                deobfuscated_data = script.get("deobfuscated_script", {})
                obfuscation_methods = deobfuscated_data.get("deobfuscation_techniques", [])
                
                for method in obfuscation_methods:
                    if method not in techniques:
                        techniques[method] = {"count": 0, "risk_level": "medium"}
                    techniques[method]["count"] += 1
        
        return [{"technique": k, **v} for k, v in techniques.items()]
    
    def _calculate_decoding_confidence(self, decoding_results: Dict[str, Any]) -> float:
        """Calculate overall decoding confidence"""
        stats = decoding_results.get("decoding_statistics", {})
        total = stats.get("total_scripts", 1)
        successful = stats.get("successfully_decoded", 0)
        
        if total == 0:
            return 0.0
        
        return successful / total
    
    def _perform_advanced_script_analysis(self, decoded_scripts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Perform advanced analysis on decoded scripts"""
        advanced_analysis = {
            "entropy_analysis": {},
            "pattern_correlation": {},
            "threat_indicators": [],
            "behavioral_predictions": {}
        }
        
        # Analyze entropy of scripts
        for script in decoded_scripts:
            if script.get("decoding_success"):
                script_content = script.get("deobfuscated_script", {}).get("deobfuscated_script", "")
                entropy = self._calculate_entropy(script_content)
                advanced_analysis["entropy_analysis"][script.get("original_script", {}).get("process_id", "unknown")] = entropy
        
        # Correlate patterns across scripts
        advanced_analysis["pattern_correlation"] = self._correlate_patterns_across_scripts(decoded_scripts)
        
        # Identify threat indicators
        advanced_analysis["threat_indicators"] = self._identify_threat_indicators(decoded_scripts)
        
        return advanced_analysis
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate entropy of text (measure of randomness)"""
        if not text:
            return 0.0
        
        # Calculate character frequency
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_length = len(text)
        
        for count in char_counts.values():
            probability = count / text_length
            if probability > 0:
                entropy -= probability * (probability ** 0.5)  # Simplified entropy calculation
        
        return entropy
    
    def _correlate_patterns_across_scripts(self, decoded_scripts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Correlate patterns across multiple scripts"""
        correlations = {
            "common_commands": {},
            "shared_variables": {},
            "similar_functions": {}
        }
        
        all_commands = []
        all_variables = []
        all_functions = []
        
        for script in decoded_scripts:
            if script.get("decoding_success"):
                script_analysis = script.get("script_analysis", {})
                all_commands.extend([cmd.get("command") for cmd in script_analysis.get("commands", [])])
                all_variables.extend([var.get("name") for var in script_analysis.get("variables", [])])
                all_functions.extend([func.get("name") for func in script_analysis.get("functions", [])])
        
        # Find common elements
        correlations["common_commands"] = self._find_common_elements(all_commands)
        correlations["shared_variables"] = self._find_common_elements(all_variables)
        correlations["similar_functions"] = self._find_common_elements(all_functions)
        
        return correlations
    
    def _find_common_elements(self, elements: List[str]) -> Dict[str, int]:
        """Find common elements and their frequency"""
        element_counts = {}
        for element in elements:
            if element:
                element_counts[element] = element_counts.get(element, 0) + 1
        
        # Return only elements that appear more than once
        return {k: v for k, v in element_counts.items() if v > 1}
    
    def _identify_threat_indicators(self, decoded_scripts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify threat indicators across scripts"""
        indicators = []
        
        for script in decoded_scripts:
            if script.get("decoding_success"):
                script_analysis = script.get("script_analysis", {})
                suspicious_indicators = script_analysis.get("suspicious_indicators", [])
                
                for indicator in suspicious_indicators:
                    indicators.append({
                        "indicator_type": indicator.get("category"),
                        "pattern": indicator.get("pattern"),
                        "risk_score": indicator.get("risk_score"),
                        "script_id": script.get("original_script", {}).get("process_id", "unknown")
                    })
        
        return indicators
