from state import AgentState
import logging
import json

logger = logging.getLogger("AgentLogger")

def documenter_node(state: AgentState) -> AgentState:
    logger.info("📝 [Step 7] Documenting investigation findings...")

    summary = {
        "alert_id": state.alert_data.get("alert_id"),
        "decoded_script": state.decoded_script[:200],
        "parent_process": state.process_info.get("parent_process"),
        "user": state.azure_context.get("user"),
        "iocs": state.enriched_iocs,
        "correlated_alerts": state.related_alerts,
        "verdict": "suspicious" if any(ioc["malicious"] for ioc in state.enriched_iocs) else "benign"
    }

    state.final_report = summary
    logger.info("Final Report:\n" + json.dumps(summary, indent=2))
    state.logs.append("[7] Documentation complete.")
    return state
