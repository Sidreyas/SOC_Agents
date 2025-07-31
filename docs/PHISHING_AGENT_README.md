# SOC Phishing Agent - Comprehensive Email Security Analysis

## Overview

The SOC Phishing Agent is a sophisticated, multi-state email security analysis system designed for Security Operations Centers (SOCs). It provides comprehensive phishing detection and response capabilities through a 6-state analysis workflow that combines multiple security analysis techniques, threat intelligence correlation, and automated risk assessment.

## Architecture

### 6-State Analysis Workflow

The agent implements a comprehensive analysis pipeline consisting of 6 specialized states:

1. **State 1: Email Entity Extraction and Pattern Analysis**
   - Extracts entities (URLs, emails, phone numbers, dates, etc.)
   - Performs pattern analysis for urgency indicators
   - Identifies suspicious content patterns
   - File: `agents/phishing_agent/email_entity_extractor.py` (700+ lines)

2. **State 2: Email Security Analysis and Authentication Validation**
   - Validates SPF, DKIM, and DMARC authentication
   - Analyzes email headers and routing
   - Detects social engineering techniques
   - Performs content security analysis
   - File: `agents/phishing_agent/email_security_analyzer.py` (1000+ lines)

3. **State 3: Sender Reputation Assessment**
   - Assesses sender reputation across multiple sources
   - Analyzes domain reputation and history
   - Performs historical pattern analysis
   - Evaluates sender behavior patterns
   - File: `agents/phishing_agent/sender_reputation_assessor.py` (1600+ lines)

4. **State 4: URL and Attachment Security Analysis**
   - Analyzes URLs for malicious content
   - Performs attachment security scanning
   - Executes sandbox analysis for dynamic behavior
   - Correlates with threat databases
   - File: `agents/phishing_agent/url_attachment_analyzer.py` (1800+ lines)

5. **State 5: Threat Intelligence Correlation**
   - Correlates findings with external threat feeds (MISP, TAXII, OTX)
   - Maps to MITRE ATT&CK framework
   - Performs campaign and actor attribution
   - Analyzes attack lifecycle and progression
   - File: `agents/phishing_agent/threat_intelligence_correlator.py` (1300+ lines)

6. **State 6: Risk Assessment and Classification**
   - Synthesizes all analysis results
   - Generates risk scores and threat classifications
   - Provides actionable recommendations
   - Creates executive summaries and detailed reports
   - File: `agents/phishing_agent/risk_assessment_classifier.py` (1750+ lines)

### Main Orchestrator

The main orchestrator coordinates all states and provides a unified API:
- File: `agents/phishing_agent/phishing_agent_main.py` (600+ lines)
- Manages state dependencies and data flow
- Provides comprehensive result compilation
- Handles error management and retry logic

## Features

### Core Capabilities

- **Multi-State Analysis**: Comprehensive 6-state workflow for thorough email analysis
- **Threat Intelligence Integration**: Real-time correlation with external threat feeds
- **MITRE ATT&CK Mapping**: Attack technique identification and lifecycle analysis
- **Advanced Authentication Validation**: SPF, DKIM, DMARC verification with detailed analysis
- **Dynamic Sandbox Analysis**: Behavioral analysis of attachments and URLs
- **Machine Learning Integration**: Pattern recognition and anomaly detection
- **Campaign Attribution**: Threat actor and campaign correlation
- **Risk Scoring**: Weighted multi-dimensional risk assessment
- **Automated Recommendations**: Context-aware actionable response guidance

### Analysis Outputs

- **Executive Summary**: High-level threat assessment for leadership
- **Detailed Technical Report**: Comprehensive analysis for security teams
- **Actionable Recommendations**: Immediate, short-term, and long-term actions
- **Threat Intelligence Report**: IOC correlation and attribution analysis
- **Confidence Metrics**: Data quality and analysis reliability assessment

### Supported Data Sources

- **Email Formats**: EML, MSG, Raw Email, JSON
- **Threat Intelligence**: MISP, TAXII, OTX, VirusTotal, Custom feeds
- **Reputation Services**: Multiple domain and IP reputation sources
- **Sandbox Platforms**: Automated malware analysis environments
- **Authentication Systems**: SPF, DKIM, DMARC validation

## Installation

### Prerequisites

```bash
Python 3.8+
Required packages listed in requirements.txt
```

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd SOC_Agents
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure threat intelligence feeds (optional):
```python
# Update configuration in agent initialization
config = {
    "threat_feeds": {
        "misp": {"api_key": "your-misp-key", "url": "https://misp.local"},
        "otx": {"api_key": "your-otx-key"},
        "virustotal": {"api_key": "your-vt-key"}
    }
}
```

## Usage

### Basic Usage

```python
import asyncio
from agents.phishing_agent.phishing_agent_main import PhishingAgent

async def analyze_email():
    # Initialize agent
    agent = PhishingAgent()
    
    # Email data
    email_data = {
        "subject": "Suspicious email subject",
        "from": "sender@suspicious-domain.com",
        "to": ["recipient@company.com"],
        "content": "Email content...",
        "headers": {...},
        "attachments": [...]
    }
    
    # Perform analysis
    result = await agent.analyze_email(email_data)
    
    # Access results
    print(f"Threat Level: {result.final_assessment['overall_threat_level']}")
    print(f"Risk Score: {result.final_assessment['risk_score']}")
    
    return result

# Run analysis
asyncio.run(analyze_email())
```

### Advanced Configuration

```python
config = {
    "parallel_processing": True,
    "timeout_per_state": 300,
    "max_retries": 3,
    "enable_caching": True,
    "detailed_logging": True,
    "threat_feeds": {
        "misp": {"enabled": True, "api_key": "key"},
        "otx": {"enabled": True, "api_key": "key"},
        "virustotal": {"enabled": True, "api_key": "key"}
    }
}

agent = PhishingAgent(config)
```

### Running the Demo

```bash
python phishing_agent_demo.py
```

## API Reference

### PhishingAgent Class

#### Methods

- `analyze_email(email_data: Dict[str, Any]) -> PhishingAnalysisResult`
  - Performs comprehensive 6-state phishing analysis
  - Returns complete analysis result with assessments and recommendations

- `get_agent_info() -> Dict[str, Any]`
  - Returns agent capabilities and configuration information

- `get_processing_statistics() -> Dict[str, Any]`
  - Returns processing statistics and performance metrics

### PhishingAnalysisResult

#### Attributes

- `analysis_id`: Unique identifier for the analysis
- `email_metadata`: Email metadata and basic information
- `state_results`: Detailed results from each analysis state
- `final_assessment`: Comprehensive threat assessment
- `recommendations`: Actionable recommendations
- `executive_summary`: Executive-level summary
- `detailed_report`: Technical analysis report
- `analysis_timeline`: Processing timeline and performance
- `confidence_metrics`: Analysis confidence and data quality
- `processing_metadata`: Technical processing information

## Configuration

### Threat Intelligence Feeds

Configure external threat intelligence sources:

```python
threat_feeds = {
    "misp": {
        "enabled": True,
        "api_endpoint": "https://misp.local/",
        "api_key": "your-api-key"
    },
    "taxii": {
        "enabled": True,
        "discovery_url": "https://taxii.local/taxii/"
    },
    "otx": {
        "enabled": True,
        "api_key": "your-otx-key"
    },
    "virustotal": {
        "enabled": True,
        "api_key": "your-vt-key"
    }
}
```

### Risk Assessment Thresholds

Customize threat classification thresholds:

```python
classification_thresholds = {
    "benign": (0.0, 0.3),
    "suspicious": (0.3, 0.6),
    "malicious": (0.6, 0.85),
    "critical": (0.85, 1.0)
}
```

### Analysis Weights

Adjust component weights for risk scoring:

```python
risk_weights = {
    "entity_extraction": 0.15,
    "security_analysis": 0.25,
    "reputation_analysis": 0.20,
    "url_attachment": 0.25,
    "threat_intelligence": 0.15
}
```

## Integration

### SOAR Platform Integration

The agent can be integrated with SOAR platforms for automated response:

```python
# Example SOAR integration
async def soar_integration(email_data):
    agent = PhishingAgent()
    result = await agent.analyze_email(email_data)
    
    # Trigger automated response based on threat level
    if result.final_assessment['overall_threat_level'] in ['critical', 'malicious']:
        await trigger_incident_response(result)
        await block_sender(email_data['from'])
        await quarantine_email(email_data)
    
    return result
```

### SIEM Integration

Export results to SIEM platforms:

```python
def export_to_siem(result: PhishingAnalysisResult):
    siem_event = {
        "timestamp": result.processing_metadata['start_time'],
        "event_type": "phishing_analysis",
        "threat_level": result.final_assessment['overall_threat_level'],
        "risk_score": result.final_assessment['risk_score'],
        "indicators": result.final_assessment['threat_indicators'],
        "recommendations": result.final_assessment['recommended_actions']
    }
    # Send to SIEM
    send_to_siem(siem_event)
```

## Performance

### Metrics

- **Average Processing Time**: ~30-60 seconds per email (depending on configuration)
- **Throughput**: 50-100 emails per minute (with parallel processing)
- **Memory Usage**: ~500MB base + ~50MB per concurrent analysis
- **CPU Usage**: Moderate (optimized for multi-core systems)

### Optimization

- Enable parallel processing for improved throughput
- Use caching for repeated analyses
- Configure appropriate timeouts for external services
- Implement rate limiting for threat intelligence APIs

## Security Considerations

- Store API keys securely (environment variables, key management systems)
- Implement network segmentation for sandbox environments
- Use TLS for all external communications
- Regular updates of threat intelligence feeds
- Audit logging for all analysis activities

## Troubleshooting

### Common Issues

1. **Timeout Errors**: Increase `timeout_per_state` configuration
2. **API Rate Limiting**: Implement appropriate delays and retry logic
3. **Memory Issues**: Reduce concurrent analysis count
4. **Network Connectivity**: Verify external service connectivity

### Logging

Enable detailed logging for troubleshooting:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Submit a pull request

## License

[Specify license information]

## Support

For support and questions:
- Create an issue in the repository
- Contact the development team
- Review documentation and examples

## Changelog

### Version 1.0
- Initial release with 6-state analysis workflow
- Complete threat intelligence integration
- Comprehensive risk assessment and reporting
- Executive summary and detailed report generation
- Multi-format email support
- Extensive configuration options
