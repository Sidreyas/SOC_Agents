import logging
import os
from dotenv import load_dotenv
from langgraph.graph import StateGraph, END
from pydantic import BaseModel, Field
from typing import Any, Dict, Optional
from agents.phishing_agent import (
    validate_email,
    header_parser,
    link_extractor,
    attachment_analyzer,
    llm_classifier,
    escalation,
    logger as phishing_logger
)

load_dotenv()
print(f"LANGSMITH_API_KEY: {os.getenv('LANGSMITH_API_KEY')}")


phishing_logger.setup_logger()

# Define the state schema for LangGraph
class EmailState(BaseModel):
    email: Dict[str, Any]
    valid: Optional[bool] = None
    header_info: Optional[Dict[str, Any]] = None
    links: Optional[Any] = None
    attachments: Optional[Any] = None
    llm_result: Optional[Dict[str, Any]] = None
    severity: Optional[int] = None
    verdict: Optional[str] = None
    reason: Optional[str] = None

# Node: Validate Email
def node_validate_email(state):
    logging.info(f"Input to graph: {state}")  # Log input here where state is defined
    email = state.email
    valid = validate_email.validate_email(email)
    logging.info(f"[ValidateEmail] Email ID {email.get('id', 'N/A')} valid: {valid}")
    return {"email": email, "valid": valid}

# Router node after validate_email
def router_validate_email(state):
    if state.valid:
        return "parse_headers"
    else:
        return END

# Node: Parse Headers
def node_parse_headers(state):
    email = state.email
    header_info = header_parser.parse_headers(email["raw_headers"])
    logging.info(f"[HeaderParser] Email ID {email.get('id', 'N/A')} header info: {header_info}")
    return {**state.dict(), "header_info": header_info}

# Node: Extract Links
def node_extract_links(state):
    email = state.email
    links = link_extractor.extract_links(email["body"])
    logging.info(f"[LinkExtractor] Email ID {email.get('id', 'N/A')} links: {links}")
    return {**state.dict(), "links": links}

# Node: Analyze Attachments
def node_analyze_attachments(state):
    email = state.email
    attachments = attachment_analyzer.analyze_attachments(email["attachments"])
    logging.info(f"[AttachmentAnalyzer] Email ID {email.get('id', 'N/A')} attachments: {attachments}")
    return {**state.dict(), "attachments": attachments}

# Node: LLM Classifier
def node_llm_classifier(state):
    email = state.email
    llm_result = llm_classifier.classify_email_with_llm(email)
    logging.info(f"[LLMClassifier] Email ID {email.get('id', 'N/A')} LLM result: {llm_result}")
    return {**state.dict(), "llm_result": llm_result}

# Node: Severity and Verdict
def node_severity_verdict(state):
    llm_result = state.llm_result
    classification = llm_result.get("classification", "Unknown")
    reason = llm_result.get("reason", "No explanation.")
    if classification == "Phishing":
        severity = 89
    elif classification == "Legitimate":
        severity = 20
    else:
        severity = 50
    if severity >= 70:
        verdict = "Phishing"
    elif severity <= 40:
        verdict = "Legitimate"
    else:
        verdict = "Unknown"
    logging.info(f"[SeverityVerdict] Classification: {classification}, Severity: {severity}, Verdict: {verdict}, Reason: {reason}")
    return {**state.dict(), "severity": severity, "verdict": verdict, "reason": reason}

# Node: Escalation
def node_escalation(state):
    email = state.email
    verdict = state.verdict
    escalation.escalate_or_close(email["id"], verdict.lower())
    logging.info(f"[Escalation] Email ID {email.get('id', 'N/A')} escalated/closed with verdict: {verdict}")
    return state.dict()

# Build the graph
graph = StateGraph(EmailState)
graph.add_node("validate_email", node_validate_email)
graph.add_node("parse_headers", node_parse_headers)
graph.add_node("extract_links", node_extract_links)
graph.add_node("analyze_attachments", node_analyze_attachments)
graph.add_node("llm_classifier", node_llm_classifier)
graph.add_node("severity_verdict", node_severity_verdict)
graph.add_node("escalation", node_escalation)
# Register router node as a dummy node for compatibility
graph.add_node("router_validate_email", lambda state: None)

graph.set_entry_point("validate_email")
graph.add_edge("validate_email", "router_validate_email")
graph.add_conditional_edges(
    "router_validate_email",
    router_validate_email,
    {"parse_headers": "parse_headers", "END": END}
)
graph.add_edge("parse_headers", "extract_links")
graph.add_edge("extract_links", "analyze_attachments")
graph.add_edge("analyze_attachments", "llm_classifier")
graph.add_edge("llm_classifier", "severity_verdict")
graph.add_edge("severity_verdict", "escalation")
graph.add_edge("escalation", END)

# Export the graph for use
phishing_email_graph = graph.compile()

# Example usage (to be used in a loop for all emails):
# for email in emails:
#     state = {"email": email}
#     result = phishing_email_graph(state)
#     # result contains all intermediate and final states