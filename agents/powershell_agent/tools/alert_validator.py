from state import AgentState
import logging

logger = logging.getLogger("AgentLogger")

def alert_validator_node(state: AgentState) -> AgentState:
    logger.info("🔎 [Step 1] Validating alert...")
    alert = state.alert_data or {"alert_id": state.alert_id, "source": "Microsoft Sentinel", "trigger": "PowerShell"}

    required_fields = ["alert_id", "source", "trigger"]
    missing = [field for field in required_fields if field not in alert]

    if missing:
        logger.warning(f"⚠️ Missing alert fields: {missing}")
    else:
        logger.info("✅ Alert contains required fields")

    state.alert_data = alert
    state.logs.append("[1] Alert validated.")
    return state
