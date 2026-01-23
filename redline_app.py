import streamlit as st
from collections import defaultdict
from datetime import datetime
import io

# -------------------------
# SESSION STATE DEFAULTS
# -------------------------
if "expand_all" not in st.session_state:
    st.session_state.expand_all = False

if "show_green" not in st.session_state:
    st.session_state.show_green = True

if "show_red" not in st.session_state:
    st.session_state.show_red = True

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
st.markdown(
    "Analyze log files for suspicious activity with execution chains, LOLBIN detection, "
    "and obfuscation indicators."
)

# -------------------------
# TOP-LEVEL CONTROLS
# -------------------------
col1, col2, col3 = st.columns(3)
with col1:
    if st.button("🔽 Expand All" if not st.session_state.expand_all else "🔼 Collapse All"):
        st.session_state.expand_all = not st.session_state.expand_all
with col2:
    if st.button("🟢 Green Line ON" if st.session_state.show_green else "⚪ Green Line OFF"):
        st.session_state.show_green = not st.session_state.show_green
with col3:
    if st.button("🔴 Redlines ON" if st.session_state.show_red else "⚪ Redlines OFF"):
        st.session_state.show_red = not st.session_state.show_red

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

    # Initialize session state for per-entry expanders
    for lineno, e in enumerate(sorted(events, key=lambda x: x["time"] or datetime.min)):
        entry_key = f"{user}_{lineno}_{e['process']}_{e['time']}"
        if entry_key not in st.session_state:
            # Default expanded if top-level expand_all is True
            st.session_state[entry_key] = st.session_state.expand_all

    for lineno, e in enumerate(sorted(events, key=lambda x: x["time"] or datetime.min)):
        entry_key = f"{user}_{lineno}_{e['process']}_{e['time']}"
        score = e["score"]
        color = "#ff0000" if score >= 8 else "#ffa500" if score >= 5 else "#00bcd4" if score >= 3 else "#4caf50"

        # Visibility filter based on top-level buttons
        visible = True
        if not st.session_state.show_green and score < 5:
            visible = False
        if not st.session_state.show_red and score >= 5:
            visible = False

        if visible:
            with st.expander(
                f"{e['time'].strftime('%H:%M:%S') if e['time'] else 'UNKNOWN'} | "
                f"{e['parent']} → {e['process']} | Score={score} | {e.get('recommendation','')}",
                expanded=st.session_state[entry_key],
                key=entry_key
            ):
                st.markdown(f"<span style='color:{color}; font-weight:bold'>Action: {e['action']}</span>", unsafe_allow_html=True)
                st.markdown(f"<span style='color:{color}'>Reason: {e['explanation']}</span>", unsafe_allow_html=True)
                for f in e["findings"]:
                    st.markdown(f"- {f}")

# -------------------------
# NARRATIVE SUMMARY
# -------------------------
st.markdown("## 🧠 Narrative Summary")
for user, events in TIMELINE.items():
    if not events:
        continue
    events_sorted = sorted(events, key=lambda x: x["time"] or datetime.min)
    start_time = events_sorted[0]["time"].strftime("%H:%M:%S") if events_sorted[0]["time"] else "UNKNOWN"
    escalation_event = next((e for e in events_sorted if e["score"] >= 5), events_sorted[0])
    behaviors = set()
    for e in events_sorted:
        behaviors.update(e["findings"])
    behaviors_list = "; ".join(behaviors)
    st.markdown(
        f"**User {user}** exhibited suspicious activity beginning at {start_time}. "
        f"The activity progressed through {len(events_sorted)} notable events, showing increasing behavioral risk over time. "
        f"An escalation point was detected at {escalation_event['process']} around "
        f"{escalation_event['time'].strftime('%H:%M:%S') if escalation_event['time'] else 'UNKNOWN'}, indicating probable malicious intent. "
        f"Key observed behaviors include: {behaviors_list}."
    )

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
