import streamlit as st
from collections import defaultdict
from datetime import datetime
import io

# -------------------------
# SESSION STATE DEFAULTS
# -------------------------
st.session_state.setdefault("expand_all", False)
st.session_state.setdefault("collapse_all", False)
st.session_state.setdefault("show_green", True)
st.session_state.setdefault("show_red", True)

# -------------------------
# IMPORT ANALYSIS MODULE
# -------------------------
from redline import (
    parse_log_line,
    parse_timestamp,
    analyze_line,
    threatlocker_recommendation,
    explain_decision,
)

# -------------------------
# STATE
# -------------------------
TIMELINE = defaultdict(list)

# -------------------------
# UI SETUP
# -------------------------
st.set_page_config(page_title="Redline Threat Hunter", layout="wide")
st.markdown(
    """
    <div style="display:flex; align-items:center; gap:10px;">
        <h1 style="margin:0;">❗Redline❗ Threat Hunting Engine</h1>
        <span title="Developed by Chance Bowers" 
              style="
                  display:inline-block; 
                  background-color:#e0e0e0; 
                  color:#333; 
                  border-radius:50%; 
                  width:22px; 
                  height:22px; 
                  text-align:center; 
                  line-height:22px; 
                  font-size:14px; 
                  cursor:help;
              ">
              ℹ️
        </span>
    </div>
    """,
    unsafe_allow_html=True
)

st.markdown(
    "Analyze log files for suspicious activity using execution chains, LOLBIN detection, and behavioral correlation."
)

# -------------------------
# GLOBAL CONTROLS
# -------------------------
st.markdown("### Timeline Controls")

c1, c2, c3, c4 = st.columns(4)

with c1:
    if st.button("🔼 Expand All"):
        st.session_state.expand_all = True
        st.session_state.collapse_all = False

with c2:
    if st.button("🔽 Collapse All"):
        st.session_state.collapse_all = True
        st.session_state.expand_all = False

with c3:
    st.session_state.show_green = st.toggle(
        "🟢 Green Line",
        value=st.session_state.show_green,
        help="Toggle low-risk baseline activity",
    )

with c4:
    st.session_state.show_red = st.toggle(
        "🔴 Redlines",
        value=st.session_state.show_red,
        help="Toggle high-risk escalation activity",
    )

st.divider()


# -------------------------
# FILE UPLOAD
# -------------------------
uploaded_file = st.file_uploader("Upload a log file", type=["csv", "txt"])

if uploaded_file:
    raw_lines = uploaded_file.read().decode("utf-8").splitlines()

    for line in raw_lines:
        context = parse_log_line(line)
        score, findings = analyze_line(line, context)

        TIMELINE[context["user"]].append(
            {
                "time": parse_timestamp(context["timestamp"]),
                "process": context["process"],
                "parent": context["parent"],
                "action": context["action"],
                "path": context["path"],
                "score": score,
                "findings": findings,
                "recommendation": threatlocker_recommendation(score, findings),
                "explanation": explain_decision(score, findings, context),
                "policy": context["policy"],
            }
        )

    st.success(f"✅ Processed {len(raw_lines)} log lines")

# -------------------------
# TIMELINE RENDER
# -------------------------
for user, events in TIMELINE.items():
    st.markdown(f"## Execution Timeline for **{user}**")

    for e in sorted(events, key=lambda x: x["time"] or datetime.min):
        is_red = e["score"] >= 5
        is_green = e["score"] < 5

        # FILTER VISIBILITY
        if is_red and not st.session_state.show_red:
            continue
        if is_green and not st.session_state.show_green:
            continue

        # EXPANSION LOGIC
        expanded = False
        if st.session_state.collapse_all:
            expanded = False
        elif st.session_state.expand_all:
            expanded = True
        elif is_red and st.session_state.show_red:
            expanded = True
        elif is_green and st.session_state.show_green:
            expanded = False  # visible but collapsed

        color = (
            "#ff4b4b"
            if e["score"] >= 8
            else "#ffa500"
            if e["score"] >= 5
            else "#4caf50"
        )

        label = (
            f"{e['time'].strftime('%H:%M:%S') if e['time'] else 'UNKNOWN'} | "
            f"{e['parent']} → {e['process']} | "
            f"Score={e['score']} | {e['recommendation']}"
        )

        with st.expander(label, expanded=expanded):
            st.markdown(
                f"<span style='color:{color}; font-weight:bold'>Action: {e['action']}</span>",
                unsafe_allow_html=True,
            )
            st.markdown(
                f"<span style='color:{color}'>Reason: {e['explanation']}</span>",
                unsafe_allow_html=True,
            )
            for f in e["findings"]:
                st.markdown(f"- {f}")

    st.divider()

# -------------------------
# RESET COLLAPSE (MOMENTARY ACTION)
# -------------------------
st.session_state.collapse_all = False

# -------------------------
# SIDEBAR METRICS
# -------------------------
if TIMELINE:
    total_events = sum(len(v) for v in TIMELINE.values())
    high_risk = sum(1 for v in TIMELINE.values() for e in v if e["score"] >= 8)

    st.sidebar.markdown("## 📊 Summary")
    st.sidebar.metric("Users", len(TIMELINE))
    st.sidebar.metric("Total Events", total_events)
    st.sidebar.metric("High-Risk Events", high_risk)

# -------------------------
# DOWNLOAD REPORT
# -------------------------
if TIMELINE:
    output = io.StringIO()
    output.write(
        "timestamp,user,process,parent,action,path,score,recommendation,explanation,policy\n"
    )

    for user, events in TIMELINE.items():
        for e in events:
            output.write(
                f"{e['time']},{user},{e['process']},{e['parent']},{e['action']},"
                f"{e['path']},{e['score']},{e['recommendation']},"
                f"{e['explanation']},{e['policy']}\n"
            )

    st.download_button(
        "📥 Download Analysis Report",
        data=output.getvalue(),
        file_name="redline_analysis.csv",
        mime="text/csv",
    )

