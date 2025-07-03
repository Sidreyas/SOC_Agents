import logging
from state import AgentState
from graph import build_graph

# Setup logging
logging.basicConfig(
    filename="agent_run.log",
    filemode="w",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logging.getLogger("AgentLogger").addHandler(console)

if __name__ == "__main__":
    print("⚡ Starting SOC PowerShell Agent...")

    initial_state = AgentState(
        alert_data={
            "alert_id": "ALERT-123",
            "encoded_command": "ZWNobyAiU3VzcGljaW91cyBQb3dlclNoZWxsIEV4ZWN1dGlvbiIK",  # Base64 of: echo "Suspicious PowerShell Execution"
            "host": "vm-demo-01",
            "user": "testuser"
        }
    )

    graph = build_graph()
    final_state = graph.invoke(initial_state)

    print("\n✅ Final Escalation Status:", final_state.escalation_status)
    print("📄 Investigation Log:\n" + "\n".join(final_state.logs))
