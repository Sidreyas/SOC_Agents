from state import AgentState
import logging

logger = logging.getLogger("AgentLogger")

def escalator_node(state: AgentState) -> AgentState:
    logger.info("🚨 [Step 8] Escalating if needed...")

    verdict = state.final_report.get("verdict", "unknown")
    escalate = verdict == "suspicious"

    if escalate:
        logger.warning("🔺 Escalation triggered: Incident flagged as suspicious.")
        state.escalation_status = "escalated"
    else:
        logger.info("✅ No escalation needed: Verdict is benign.")
        state.escalation_status = "not_escalated"

    state.logs.append(f"[8] Escalation decision: {state.escalation_status}")
    return state
