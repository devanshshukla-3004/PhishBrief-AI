from __future__ import annotations

import json
import os
import re
from datetime import datetime
from typing import Any

import requests
import streamlit as st

APP_NAME = "PhishBrief AI"
OLLAMA_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/")
DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "granite3.2-vision")
MAX_MESSAGE_CHARS = 12000

from core import APP_NAME, DEFAULT_MODEL, MAX_MESSAGE_CHARS, analyze_message, heuristic_preview


st.set_page_config(page_title=APP_NAME, page_icon="🛡️", layout="wide")
st.markdown("""
<style>
:root { --ink: #17211e; --muted: #68756f; --line: #dfe7e2; --green: #226b52; }
.block-container { max-width: 1180px; padding-top: 2rem; padding-bottom: 3rem; }
.hero { padding: 1.4rem 1.6rem; border: 1px solid var(--line); border-radius: 18px; background: linear-gradient(120deg,#f5f8f5,#fff); margin-bottom: 1.2rem; }
.eyebrow { color: var(--green); font-size: .78rem; letter-spacing: .14em; font-weight: 800; text-transform: uppercase; }
.small-muted { color: var(--muted); font-size: .92rem; }
.result-card { border: 1px solid var(--line); border-radius: 14px; padding: 1rem 1.1rem; margin: .5rem 0; }
div.stButton > button[kind="primary"] { background: #226b52; border-color: #226b52; }
</style>
<div class="hero">
  <div class="eyebrow">LOCAL-FIRST SECURITY WORKSPACE</div>
  <h1 style="margin:.3rem 0 .4rem 0">🛡️ PhishBrief AI</h1>
  <p style="font-size:1.05rem;margin:0">Turn suspicious messages into understandable, evidence-led security decisions.</p>
  <p class="small-muted" style="margin:.7rem 0 0 0">Built for small teams without a dedicated security operations centre.</p>
</div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.header("Analysis settings")
    model = st.text_input("Local Ollama model", value=DEFAULT_MODEL, help="Use a model installed in your local Ollama instance.")
    demo_mode = st.toggle("Use demo preview (no AI)", value=False, help="For a quick UI walkthrough only. Results use simple keyword rules and are clearly labelled.")
    st.divider()
    st.caption("Privacy by design")
    st.write("Messages are processed by your local Ollama server in AI mode. This app does not send message content to a hosted AI API or store a history by default.")
    st.caption("Local setup")
    st.code("ollama serve\nollama pull " + (model.strip() or DEFAULT_MODEL), language="bash")

left, right = st.columns([1.15, .85], gap="large")
with left:
    st.subheader("1. Paste a suspicious message")
    sample = "Subject: Urgent — mailbox access will be suspended\n\nHello,\n\nYour account will be disabled today. Verify your password immediately at http://example.invalid/account to prevent suspension.\n\nIT Support"
    message = st.text_area("Email, SMS, chat message, or payment request", height=290, placeholder="Paste the message text here…", max_chars=MAX_MESSAGE_CHARS, label_visibility="collapsed", key="message_input")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("Load sample message", use_container_width=True):
            st.session_state["message_input"] = sample
            st.rerun()
    with c2:
        run_analysis = st.button("Analyze message →", type="primary", use_container_width=True)
    st.caption(f"{len(message):,} / {MAX_MESSAGE_CHARS:,} characters · Avoid pasting sensitive personal or customer data into demos.")
with right:
    st.subheader("What you'll get")
    st.markdown("- **Risk rating** with a 0–100 score\n- **Evidence-led indicators** with message excerpts\n- **Plain-English explanation** of each clue\n- **Safe next steps** for the recipient or IT team")
    st.info("A risk score is a triage aid, not a guarantee. A low score does not prove a message is safe.")


if run_analysis:
    with st.spinner("Reviewing message locally…" if not demo_mode else "Building a rule-based demo preview…"):
        try:
            result = heuristic_preview(message) if demo_mode else analyze_message(message, model.strip() or DEFAULT_MODEL)
            st.session_state["last_result"] = result
        except (ValueError, RuntimeError) as exc:
            st.error(str(exc))

result = st.session_state.get("last_result")
if result:
    st.divider()
    st.subheader("2. Analysis brief")
    st.caption(f"Mode: {result.get('analysis_mode', 'Unknown')} · Model: {result.get('model', 'Not specified')} · Generated locally at {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    score_col, level_col, summary_col = st.columns([.7, .8, 2.5])
    score_col.metric("Risk score", f"{result['risk_score']}/100")
    level_col.metric("Risk level", result["risk_level"])
    summary_col.markdown("**Summary**\n\n" + result["summary"])
    st.progress(result["risk_score"] / 100)
    st.markdown("#### Indicators to review")
    if result["indicators"]:
        for item in result["indicators"]:
            with st.container(border=True):
                st.markdown(f"**{item['title']}**")
                st.markdown(f"> {item['evidence']}")
                st.write(item["why_it_matters"])
    else:
        st.write("No specific indicators were returned. This does not mean the message is safe.")
    action_col, limits_col = st.columns(2, gap="large")
    with action_col:
        st.markdown("#### Recommended next steps")
        for action in result["recommended_actions"]:
            st.markdown(f"- {action}")
    with limits_col:
        st.markdown("#### Limitations")
        for limitation in result["limitations"]:
            st.markdown(f"- {limitation}")
    export = json.dumps({"product": APP_NAME, "created_at": datetime.now().isoformat(timespec="seconds"), "result": result}, indent=2, ensure_ascii=False)
    st.download_button("Download analysis JSON", data=export, file_name="phishbrief-analysis.json", mime="application/json")

st.divider()
st.caption("PhishBrief AI is an assistive triage tool, not a malware scanner, URL reputation service, or substitute for security review. Only analyze messages you are authorized to handle.")
