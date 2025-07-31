"""
Incident Management Agent Package
Complete incident lifecycle management with 8-state workflow
"""

from .incident_management_graph import IncidentManagementAgent, create_incident_management_agent
from .incident_intake import IncidentIntakeProcessor, create_incident_intake_processor
from .evidence_correlator import EvidenceCorrelator, create_evidence_correlator
from .investigation_planner import InvestigationPlanner, create_investigation_planner
from .analysis_executor import AnalysisExecutor, create_analysis_executor
from .documentation_generator import DocumentationGenerator, create_documentation_generator
from .resolution_validator import ResolutionValidator, create_resolution_validator
from .sentinel_integrator import SentinelIntegrator, create_sentinel_integrator
from .case_closure import CaseClosureManager, create_case_closure_manager
from .config import get_config, get_config_section

__version__ = "1.0.0"
__author__ = "SOC Automation Team"

# Package exports
__all__ = [
    # Main agent
    "IncidentManagementAgent",
    "create_incident_management_agent",
    
    # State processors
    "IncidentIntakeProcessor",
    "EvidenceCorrelator", 
    "InvestigationPlanner",
    "AnalysisExecutor",
    "DocumentationGenerator",
    "ResolutionValidator",
    "SentinelIntegrator",
    "CaseClosureManager",
    
    # Factory functions
    "create_incident_intake_processor",
    "create_evidence_correlator",
    "create_investigation_planner", 
    "create_analysis_executor",
    "create_documentation_generator",
    "create_resolution_validator",
    "create_sentinel_integrator",
    "create_case_closure_manager",
    
    # Configuration
    "get_config",
    "get_config_section"
]

# Package metadata
PACKAGE_INFO = {
    "name": "incident_management_agent",
    "version": __version__,
    "description": "Complete incident management agent with 8-state workflow for SOC operations",
    "author": __author__,
    "states": [
        "incident_intake",
        "evidence_correlation", 
        "investigation_planning",
        "analysis_execution",
        "documentation_generation",
        "resolution_validation",
        "sentinel_integration",
        "case_closure"
    ],
    "capabilities": [
        "Automated incident intake and classification",
        "Multi-source evidence correlation",
        "Dynamic investigation planning",
        "Parallel analysis execution",
        "Comprehensive documentation generation",
        "Resolution validation and verification",
        "Microsoft Sentinel integration",
        "Complete case closure with lessons learned"
    ],
    "integrations": [
        "Microsoft Sentinel",
        "All 9 SOC agents",
        "MITRE ATT&CK framework",
        "Compliance frameworks (GDPR, HIPAA, PCI-DSS, SOX)"
    ]
}

def get_package_info():
    """Get package information"""
    return PACKAGE_INFO
