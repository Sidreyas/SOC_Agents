from typing import Optional, List, Dict
from pydantic import BaseModel

class AgentState(BaseModel):
    alert_id: Optional[str] = None
    alert_data: Optional[Dict] = None
    decoded_script: Optional[str] = None
    process_info: Optional[Dict] = None
    enriched_iocs: Optional[List[Dict]] = None
    correlation_summary: Optional[str] = None
    azure_context: Optional[Dict] = None
    evidence: List[str] = []
    should_escalate: Optional[bool] = False
    logs: List[str] = []
