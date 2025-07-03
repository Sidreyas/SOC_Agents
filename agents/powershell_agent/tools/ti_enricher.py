from state import AgentState
import logging

logger = logging.getLogger("AgentLogger")

def threat_intel_node(state: AgentState) -> AgentState:
    logger.info("🌐 [Step 5] Running threat intelligence enrichment...")

    decoded = state.decoded_script or ""
    dummy_url = "http://malicious-domain.fake"
    dummy_hash = "e3b0c44298fc1c14"

    enriched = [
        {"type": "url", "value": dummy_url, "malicious": True, "source": "VirusTotal"},
        {"type": "hash", "value": dummy_hash, "malicious": False, "source": "VirusTotal"}
    ]

    logger.info(f"Found IOCs: {len(enriched)}")
    state.enriched_iocs = enriched
    state.logs.append("[5] Threat intelligence applied to script.")
    return state
