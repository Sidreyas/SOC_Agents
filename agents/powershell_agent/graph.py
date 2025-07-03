from langgraph.graph import StateGraph
from state import AgentState

# Import all 8 nodes
from tools.alert_validator import alert_validator_node
from tools.script_decoder import script_decoder_node
from tools.user_host_context import user_host_context_node
from tools.ti_enricher import threat_intel_node
from tools.correlator import correlator_node
from tools.evidence_recorder import documenter_node
from tools.escalation_trigger import escalator_node

def build_graph():
    builder = StateGraph(AgentState)

    builder.add_node("validate_alert", alert_validator_node)
    builder.add_node("decode_script", script_decoder_node)
    builder.add_node("check_user_host", user_host_context_node)
    builder.add_node("enrich_iocs", threat_intel_node)
    builder.add_node("correlate_events", correlator_node)
    builder.add_node("record_findings", documenter_node)
    builder.add_node("escalate", escalator_node)

    # Define edges (linear flow)
    builder.set_entry_point("validate_alert")
    builder.add_edge("validate_alert", "decode_script")
    builder.add_edge("decode_script", "check_parent_process")
    builder.add_edge("check_parent_process", "check_user_host")
    builder.add_edge("check_user_host", "enrich_iocs")
    builder.add_edge("enrich_iocs", "correlate_events")
    builder.add_edge("correlate_events", "record_findings")
    builder.add_edge("record_findings", "escalate")

    builder.set_finish_point("escalate")

    return builder.compile()
