import json
import os
import sqlite3
from typing import List

from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from langchain_groq import ChatGroq
from langgraph.graph import END, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode

from db import insert_events, reset_logs_db
from events_feed import event_stream
from tools.event_analysis import event_analysis
from tools.notifier import notify
from tools.sql_lookup import sql_lookup
from tools.threat_intel import threat_intel
from tools.web_search import web_search

TOOLS = [event_analysis, sql_lookup, threat_intel, web_search, notify]

SYSTEM_PROMPT = SystemMessage(
    content=(
        "You are a cybersecurity orchestrator with these tools:\n"
        "• event_analysis(event) – always run first; returns risk_score and reasons.\n"
        "• (Input events may include ml_is_anomaly/ml_anomaly_score from a lightweight ML pre-screener; treat this as extra signal.)\n"
        "• sql_lookup(ip, username?) – summarize login history context.\n"
        "• threat_intel(ip) – AbuseIPDB reputation for the IP.\n"
        "• web_search(ip?, abuse_score?, threat_signature?, cve_ids?) – public references.\n"
        "• notify(...) – log one finalized entry per event to a per-model log file. "
        "Call notify exactly once at the very end.\n\n"
        "Rules / workflow:\n"
        "1. Call event_analysis with the raw event JSON.\n"
        "2. Let risk=risk_score from event_analysis.\n"
        "3. If risk >= 30, call sql_lookup(ip, username) for context.\n"
        "4. If threat_intel data is not present yet and risk >= 30, call threat_intel(ip).\n"
        "5. If abuse_score is >= 50 or is_attack_ip is true, call web_search with ip and abuse_score.\n"
        "6. Always call notify(...) exactly once at the end with:\n"
        "   - timestamp, src_ip, username, country, device, login_success, is_attack_ip, is_account_takeover from the event\n"
        "   - risk (risk_score)\n"
        "   - summary: include tool outputs in a compact `example.log`-like format:\n"
        "       [event_analysis] score=... rules=...\n"
        "       [sql_lookup] ... (if called)\n"
        "       [threat_intel] ... (if called)\n"
        "       [web_search] ... (if called)\n"
        "       Then verdict lines: CLEAR/WATCH/ALERT + action.\n"
        "   - links: up to 3 URLs gathered from web_search results (or empty list)\n"
    )
)


def build_app(model_name: str):
    llm = ChatGroq(model=model_name, temperature=0).bind_tools(TOOLS)

    def supervisor(state: MessagesState) -> MessagesState:
        resp: BaseMessage = llm.invoke(state["messages"])
        state["messages"].append(resp)
        return state

    g = StateGraph(MessagesState)
    g.add_node("supervisor", supervisor)
    g.add_node("tool", ToolNode(TOOLS))
    g.set_entry_point("supervisor")
    g.add_conditional_edges(
        "supervisor",
        lambda s: "tool"
        if getattr(s["messages"][-1], "additional_kwargs", {}).get("tool_calls")
        else END,
    )
    g.add_edge("tool", "supervisor")
    return g.compile()


def _safe_model_label(model_name: str) -> str:
    return model_name.replace("/", "-")


if __name__ == "__main__":
    # Test with a max of 10 rows from the RBA CSV.
    SAMPLE_LIMIT = int(os.getenv("SAMPLE_LIMIT", "10"))

    # Compare these 3 models.
    MODEL_NAMES = [
        # "openai/gpt-oss-120b",
        # "llama-3.1-8b-instant",
        "qwen/qwen3-32b",
    ]

    # Load sample events once, then seed SQLite once.
    events = list(event_stream(limit=SAMPLE_LIMIT))

    if os.getenv("RESET_LOGINS_DB", "1").strip() == "1":
        reset_logs_db()
    insert_events(events, reset=False)

    # Deterministic heuristic scores for session summary.
    event_scoring = []
    for evt in events:
        result = event_analysis(evt)
        event_scoring.append(
            {
                "risk": int(result.get("risk_score", 0) or 0),
                "reasons": result.get("reasons", []),
            }
        )

    session_dataset_label = os.getenv("SESSION_DATASET_LABEL", "RBA Dataset Prototype")
    os.environ["SESSION_DATASET_LABEL"] = session_dataset_label

    reset_log_files = os.getenv("RESET_LOG_FILES", "0").strip() == "1"

    for model_name in MODEL_NAMES:
        slug = _safe_model_label(model_name)
        log_path = os.path.join(os.path.dirname(__file__), f"alerts-{slug}.log")

        os.environ["CURRENT_MODEL_LABEL"] = model_name
        os.environ["ALERT_LOG_FILE"] = log_path

        if reset_log_files and os.path.exists(log_path):
            os.remove(log_path)

        app = build_app(model_name)

        for idx, evt in enumerate(events, 1):
            print(f"\n===== EVENT {idx} ({slug}) =====")
            msgs: List[BaseMessage] = [
                SYSTEM_PROMPT,
                HumanMessage(
                    content="EVENT:\n```json\n" + json.dumps(evt) + "\n```"
                ),
            ]
            # Tool calling happens inside APP; `notify` appends to the per-model log file.
            app.invoke({"messages": msgs})

        # Append a session summary to match the `example.log` style.
        clear_cnt = sum(1 for s in event_scoring if s["risk"] < 30)
        watch_cnt = sum(1 for s in event_scoring if 30 <= s["risk"] < 80)
        alert_cnt = sum(1 for s in event_scoring if s["risk"] >= 80)

        ranked = sorted(
            [(i + 1, s["risk"], events[i]["src_ip"]) for i, s in enumerate(event_scoring)],
            key=lambda x: x[1],
            reverse=True,
        )[:5]

        with open(log_path, "a", encoding="utf-8") as f:
            f.write("\n" + "=" * 80 + "\n")
            f.write("SESSION SUMMARY\n")
            f.write("  " + f"Events processed : {len(events)}\n")
            f.write(f"  ✔ CLEAR  (Risk < 30)    : {clear_cnt}\n")
            f.write(f"  ▲ WATCH  (Risk 30–79)   : {watch_cnt}\n")
            f.write(f"  ██ ALERT (Risk >= 80)    : {alert_cnt}\n\n")
            f.write("Top threats\n")
            for rank, (event_idx, risk, ip) in enumerate(ranked, start=1):
                f.write(f"  {rank}. #{event_idx}  score={risk}  ip={ip}\n")
            f.write("=" * 80 + "\n")
