import streamlit as st
import pandas as pd
import json
import os
import plotly.express as px
import pathlib

BASE_DIR = pathlib.Path(__file__).resolve().parent
EVENTS_DIR = BASE_DIR / "logs"

HONEYPOT_FILE = EVENTS_DIR / "honeypot_events.jsonl"
SYSLOG_FILE   = EVENTS_DIR / "received_syslog.log"

st.set_page_config(
    page_title = "SIEM Dashboard",
    layout = "wide"
)

st.title("SIEM Security Dashboard")
st.markdown("Real-time view of Honeypot and Syslog activity")

def load_honeypot_events():
    if not os.path.exists(HONEYPOT_FILE):
        return pd.DataFrame()

    rows = []
    with open(HONEYPOT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                rows.append(json.loads(line))
            except json.decoder.JSONDecodeError:
                continue

    return  pd.DataFrame(rows)

def load_syslog_alerts():
    if not os.path.exists(SYSLOG_FILE):
        return pd.DataFrame()

    rows = []
    with open(SYSLOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.split("|", 3)
            if len(parts) != 3:
                continue

            rows.append({
                "timestamp": parts[0].strip(),
                "protocol": parts[1].strip(),
                "msg": parts[2].strip(),
            })

    return pd.DataFrame(rows)

tab1, tab2 = st.tabs(["Honeypot Events", "Syslog Alerts"])

with tab1:
    st.header("Honeypot Activity")

    df = load_honeypot_events()

    if df.empty:
        st.info("No Honeypot events found")
    else:
        col1, col2, col3 = st.columns(3)

        col1.metric("Total Attacks", len(df))
        col2.metric("Unique IPs", df["source"].nunique())

        st.subheader("Recent Events")
        st.dataframe(df.tail(50))

        fig = px.bar(df["attack_type"].value_counts(), labels={"value": "Count", "index": "Attack Type"})
        st.subheader("Attack Types Distribution")
        st.plotly_chart(fig)


with tab2:
    st.header("Syslog Receiver Alerts")

    df_sys = load_syslog_alerts()

    if df_sys.empty:
        st.info("No Syslog alerts received yet.")
    else:
        st.subheader("Recent Syslog Alerts")
        st.dataframe(df_sys.tail(50))

        proto_counts = df_sys["protocol"].value_counts()
        fig2 = px.pie(
            values=proto_counts.values,
            names=proto_counts.index,
            title="Syslog Protocol Share",
        )
        st.plotly_chart(fig2)
