from state import AgentState
import logging

logger = logging.getLogger("AgentLogger")

def user_host_context_node(state: AgentState) -> AgentState:
    logger.info("👤 [Step 4] Reviewing user/host context...")

    user = state.process_info.get("initiating_user", "unknown")
    context = {
        "user": user,
        "host_risk": "medium",
        "suspicious_login": False,
        "vm_type": "Azure VM"
    }

    logger.info(f"User: {user} | Risk: {context['host_risk']}")
    state.azure_context = context
    state.logs.append("[4] User and host context validated.")
    return state
