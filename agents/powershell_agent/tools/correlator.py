from state import AgentState
import logging

logger = logging.getLogger("AgentLogger")

def correlator_node(state: AgentState) -> AgentState:
    logger.info("🧠 [Step 6] Correlating with other alerts...")

    host = state.azure_context.get("vm_name", "demo-vm")
    simulated_related_alerts = [
        {"type": "privilege_escalation", "timestamp": "2024-07-01T10:00Z"},
        {"type": "suspicious_login", "timestamp": "2024-07-01T10:15Z"}
    ]

    logger.info(f"Found {len(simulated_related_alerts)} related alerts on {host}")
    state.related_alerts = simulated_related_alerts
    state.logs.append("[6] Correlation complete: related alerts found.")
    return state

