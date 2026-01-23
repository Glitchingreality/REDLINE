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
# TIMELINE VISUALIZATION WITH TOGGLE EXPAND BUTTONS
# -------------------------
for user, events in TIMELINE.items():
    st.markdown(f"## Execution Timeline for **{user}**")

    # Initialize session state for expand toggles per user
    if f"{user}_expand_mode" not in st.session_state:
        st.session_state[f"{user}_expand_mode"] = {"all": False, "green": False, "red": False}

    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button(f"🔽 Expand All ({user})"):
            # Toggle the button state
            st.session_state[f"{user}_expand_mode"]["all"] = not st.session_state[f"{user}_expand_mode"]["all"]
            # Reset others
            st.session_state[f"{user}_expand_mode"]["green"] = False
            st.session_state[f"{user}_expand_mode"]["red"] = False
    with col2:
        if st.button(f"🟢 Expand Green ({user})"):
            st.session_state[f"{user}_expand_mode"]["green"] = not st.session_state[f"{user}_expand_mode"]["green"]
            st.session_state[f"{user}_expand_mode"]["all"] = False
            st.session_state[f"{user}_expand_mode"]["red"] = False
    with col3:
        if st.button(f"🔴 Expand Red ({user})"):
            st.session_state[f"{user}_expand_mode"]["red"] = not st.session_state[f"{user}_expand_mode"]["red"]
            st.session_state[f"{user}_expand_mode"]["all"] = False
            st.session_state[f"{user}_expand_mode"]["green"] = False

    # Determine which events to show based on toggle
    mode_state = st.session_state[f"{user}_expand_mode"]
    if mode_state["all"]:
        filtered_events = events
    elif mode_state["green"]:
        filtered_events = [e for e in events if e["score"] < 5]
    elif mode_state["red"]:
        filtered_events = [e for e in events if e["score"] >= 5]
    else:
        filtered_events = []  # collapse all if no toggle active

    # Render filtered events
    for e in sorted(filtered_events, key=lambda x: x["time"] or datetime.min):
        color = "#ff0000" if e["score"] >= 8 else "#ffa500" if e["score"] >= 5 else "#00bcd4" if e["score"] >= 3 else "#4caf50"
        expanded_default = True if mode_state["all"] else False  # Expand all default only if "all" is active

        with st.expander(f"{e['time'].strftime('%H:%M:%S') if e['time'] else 'UNKNOWN'} | {e['parent']} → {e['process']} | Score={e['score']} | {e.get('recommendation','')}", expanded=expanded_default):
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



