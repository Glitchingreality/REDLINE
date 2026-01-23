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
# GENERATE NARRATIVE
# -------------------------
def generate_narrative(user, events):
    if not events:
        return None

    events = sorted(events, key=lambda e: e["time"] or datetime.min)

    start_time = events[0]["time"]
    end_time = events[-1]["time"]

    escalation = next((e for e in events if e["score"] >= 8), None)

    key_findings = set()
    for e in events:
        for f in e["findings"]:
            if any(k in f.lower() for k in ["lolbin", "encoded", "network", "signal"]):
                key_findings.add(f)

    summary = []
    summary.append(
        f"User **{user}** exhibited suspicious activity beginning at "
        f"**{start_time.strftime('%H:%M:%S') if start_time else 'UNKNOWN'}**."
    )

    summary.append(
        f"The activity progressed through **{len(events)} notable events**, "
        f"showing increasing behavioral risk over time."
    )

    if escalation:
        summary.append(
            f"An escalation point was detected at "
            f"**{escalation['process']}** "
            f"around **{escalation['time'].strftime('%H:%M:%S') if escalation['time'] else 'UNKNOWN'}**, "
            f"indicating probable malicious intent."
        )
    else:
        summary.append(
            "No single high-confidence escalation point was observed, "
            "but multiple low-to-medium risk indicators were present."
        )

    if key_findings:
        summary.append(
            "Key observed behaviors include: "
            + "; ".join(list(key_findings)[:5])
            + "."
        )

    return " ".join(summary)

# -------------------------
# UI SETUP
# -------------------------
st.set_page_config(page_title="Redline Threat Hunter", layout="wide")
st.title("❗Redline❗ Threat Hunting Engine  ")
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
        "🔴 Red Line",
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

    # Generate narrative per user
    narrative = generate_narrative(user, events)
    if narrative:
        with st.expander("🧠 Narrative Summary", expanded=True):
            st.markdown(narrative)

    # Initialize filter state for this user
    if f"{user}_filter_mode" not in st.session_state:
        st.session_state[f"{user}_filter_mode"] = {"all": False, "green": True, "red": True}

    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button(f"🔽 Expand All ({user})", key=f"{user}_all_btn"):
            st.session_state[f"{user}_filter_mode"]["all"] = not st.session_state[f"{user}_filter_mode"]["all"]
            st.session_state[f"{user}_filter_mode"]["green"] = True
            st.session_state[f"{user}_filter_mode"]["red"] = True
    with col2:
        if st.button(f"🟢 Green Line ({user})", key=f"{user}_green_btn"):
            st.session_state[f"{user}_filter_mode"]["green"] = not st.session_state[f"{user}_filter_mode"]["green"]
            st.session_state[f"{user}_filter_mode"]["all"] = False
    with col3:
        if st.button(f"🔴 Red Line ({user})", key=f"{user}_red_btn"):
            st.session_state[f"{user}_filter_mode"]["red"] = not st.session_state[f"{user}_filter_mode"]["red"]
            st.session_state[f"{user}_filter_mode"]["all"] = False

    mode_state = st.session_state[f"{user}_filter_mode"]

    # Render each event according to filter
    for e in sorted(events, key=lambda x: x["time"] or datetime.min):
        score = e["score"]
        color = "#ff0000" if score >= 8 else "#ffa500" if score >= 5 else "#00bcd4" if score >= 3 else "#4caf50"

        # Apply filters
        if not mode_state["red"] and score >= 5:
            continue
        if not mode_state["green"] and score < 5:
            continue

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








