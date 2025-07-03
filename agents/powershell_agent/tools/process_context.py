from state import AgentState
import logging

logger = logging.getLogger("AgentLogger")

def process_context_node(state: AgentState) -> AgentState:
    logger.info("🔗 [Step 3] Checking parent process...")
    sysmon_data = {
        "parent_process": "winword.exe",
        "child_process": "powershell.exe",
        "initiating_user": "user@corp.local"
    }

    logger.info(f"Parent process: {sysmon_data['parent_process']}")
    state.process_info = sysmon_data
    state.logs.append("[3] Parent-child process relationship reviewed.")
    return state
