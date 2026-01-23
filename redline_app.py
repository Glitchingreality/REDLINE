import streamlit as st
from datetime import datetime
from collections import defaultdict
from threat_hunter import process_log, TIMELINE, parse_log_line, parse_timestamp, severity_color, threatlocker_recommendation, explain_decision, print_timeline

st.set_page_config(
    page_title="Redline Threat Hunter",
    page_icon="🛑",
    layout="wide"
)

st.title("🛑 Redline Threat Hunter")
st.markdown("""
Upload your log file and let Redline analyze suspicious behaviors.
""")

uploaded_file = st.file_uploader("Choose a log file", type=["txt", "csv", "log"])

if uploaded_file is not None:
    st.text("Processing log file...")

    # Save the uploaded file to a temporary location
    temp_path = "temp_uploaded_log.txt"
    with open(temp_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    # Clear previous timeline
    TIMELINE.clear()

    # Process the uploaded log
    process_log(temp_path)

    st.success("Analysis complete!")

    # Display per-user timeline and narrative
    for user in TIMELINE:
        st.markdown(f"### Execution Timeline for **{user}**")

        events = sorted(TIMELINE[user], key=lambda e: e["time"] or datetime.min)
        escalation_detected = False
        narrative_findings = []

        for e in events:
            t = e["time"].strftime("%H:%M:%S") if e["time"] else "UNKNOWN"
            color = severity_color(e["score"])
            line_str = f"[{t}] {e['parent']} → {e['process']} | {e['action']} | Score={e['score']}"
            st.markdown(f"<span style='color:{color};'>{line_str}</span>", unsafe_allow_html=True)
            
            for f in e["findings"]:
                narrative_findings.append(f)
                st.markdown(f"<span style='color:{color};'>• {f}</span>", unsafe_allow_html=True)

            if e["score"] >= 5:
                escalation_detected = True

        # Narrative summary
        if events:
            first_time = events[0]["time"].strftime("%H:%M:%S") if events[0]["time"] else "UNKNOWN"
            last_time = events[-1]["time"].strftime("%H:%M:%S") if events[-1]["time"] else "UNKNOWN"
            st.markdown(f"**Narrative Summary:**\nUser '{user}' exhibited suspicious behavior starting at {first_time}, ending at {last_time}. Key behaviors include: {', '.join(narrative_findings[:10])}...")

        if escalation_detected:
            pivot_event = next((e for e in events if e["score"] >= 5), None)
            if pivot_event:
                st.markdown(f"⚠ **Escalation detected at {pivot_event['process']} ({pivot_event['time'].strftime('%H:%M:%S') if pivot_event['time'] else 'UNKNOWN'})**")
