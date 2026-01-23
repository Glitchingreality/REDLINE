import streamlit as st
from collections import defaultdict
from datetime import datetime
import re
import io

# -------------------------
# IMPORT YOUR ANALYSIS MODULE
# -------------------------
from redline import (
    parse_log_line,
    parse_timestamp,
    analyze_line,
    threatlocker_recommendation,
    explain_decision,
    severity_color,
)

# -------------------------
# STATE
# -------------------------
TIMELINE = defaultdict(list)

# -------------------------
# UI SETUP
# -------------------------
st.set_page_config(page_title="Redline Threat Hunter", layout="wide")
st.title("🚨 Redline Threat Hunter")
st.markdown("Analyze log files for suspicious activity with execution chains, LOLBIN detection, and obfuscation indicators.")

# -------------------------
# FILE UPLOAD
# -------------------------
uploaded_file = st.file_uploader("Upload a log file", type=["csv", "txt"])
if uploaded_file:
    raw_lines = uploaded_file.read().decode("utf-8").splitlines()

    for lineno, line in enumerate(raw_lines, 1):
        context = parse_log_line(line)
        score, findings = analyze_line(line, context)
        recommendation = threatlocker_recommendation(score, findings)
        explanation = explain_decision(score, findings, context)

        TIMELINE[context["user"]].append({
            "time": parse_timestamp(context["timestamp"]),
            "process": context["process"],
            "parent": context["parent"],
            "action": context["action"],
            "path": context["path"],
            "score": score,
            "findings": findings,
            "policy": context["policy"],
            "recommendation": recommendation,
            "explanation": explanation
        })

    st.success(f"✅ Processed {len(raw_lines)} log lines!")

# -------------------------
# TIMELINE VISUALIZATION
# -------------------------
for user, events in TIMELINE.items():
    st.markdown(f"## Execution Timeline for **{user}**")

    for e in sorted(events, key=lambda x: x["time"] or datetime.min):
        color = "#ff0000" if e["score"] >= 8 else "#ffa500" if e["score"] >= 5 else "#00bcd4" if e["score"] >= 3 else "#4caf50"
        with st.expander(f"{e['time'].strftime('%H:%M:%S') if e['time'] else 'UNKNOWN'} | {e['parent']} → {e['process']} | Score={e['score']} | {e['recommendation']}"):
            st.markdown(f"<span style='color:{color}; font-weight:bold'>Action: {e['action']}</span>", unsafe_allow_html=True)
            st.markdown(f"<span style='color:{color}'>Reason: {e['explanation']}</span>", unsafe_allow_html=True)
            for f in e["findings"]:
                st.markdown(f"- {f}")

# -------------------------
# SUMMARY METRICS
# -------------------------
if TIMELINE:
    total_events = sum(len(v) for v in TIMELINE.values())
    total_high_risk = sum(1 for events in TIMELINE.values() for e in events if e["score"] >= 8)
    total_users = len(TIMELINE)
    st.sidebar.markdown("## 📊 Summary")
    st.sidebar.metric("Total Users", total_users)
    st.sidebar.metric("Total Events", total_events)
    st.sidebar.metric("High-Risk Events", total_high_risk)

# -------------------------
# DOWNLOAD REPORT
# -------------------------
if TIMELINE:
    output = io.StringIO()
    output.write("timestamp,user,process,parent,action,path,score,recommendation,explanation,policy\n")
    for user, events in TIMELINE.items():
        for e in events:
            output.write(f"{e['time']},{user},{e['process']},{e['parent']},{e['action']},{e['path']},{e['score']},{e['recommendation']},{e['explanation']},{e['policy']}\n")

    st.download_button(
        label="📥 Download Analysis Report",
        data=output.getvalue(),
        file_name="redline_analysis.csv",
        mime="text/csv"
    )

