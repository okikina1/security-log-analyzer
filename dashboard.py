import streamlit as st
from parser import parse_logs
from detector import detect_alerts


# Page configuration
st.set_page_config(
    page_title="Security Log Analyzer",
    page_icon="🔐",
    layout="wide"
)


# Load data
df = parse_logs("logs_security.log")
alerts_df = detect_alerts(df)


# Title
st.title("🔐 Security Log Analyzer")
st.write("Analyze security logs and identify suspicious activity.")


# Metrics
total_events = len(df)
failed_logins = (df["event"] == "LOGIN_FAILED").sum()
total_alerts = len(alerts_df)
high_alerts = (alerts_df["severity"] == "HIGH").sum()
medium_alerts = (alerts_df["severity"] == "MEDIUM").sum()


col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Total Events", total_events)
col2.metric("Failed Logins", failed_logins)
col3.metric("Total Alerts", total_alerts)
col4.metric("High Severity Alerts", high_alerts)
col5.metric("Medium Severity Alerts", medium_alerts)

# Activity over time
st.subheader("Security Events Over Time")

events_over_time = (
    df.set_index("timestamp")
    .resample("1h")
    .size()
)

st.line_chart(events_over_time)

# Security alerts
st.subheader("Security Alerts")

# Filters
severity_filter = st.selectbox(
    "Severity",
    ["All"] + sorted(alerts_df["severity"].unique())
)

rule_filter = st.selectbox(
    "Rule",
    ["All"] + sorted(alerts_df["rule"].unique())
)

user_filter = st.selectbox(
    "User",
    ["All"] + sorted(alerts_df["user"].dropna().unique())
)


# Apply filters
filtered_alerts = alerts_df.copy()

if severity_filter != "All":
    filtered_alerts = filtered_alerts[
        filtered_alerts["severity"] == severity_filter
    ]

if rule_filter != "All":
    filtered_alerts = filtered_alerts[
        filtered_alerts["rule"] == rule_filter
    ]

if user_filter != "All":
    filtered_alerts = filtered_alerts[
        filtered_alerts["user"] == user_filter
    ]


# Display filtered alerts
st.dataframe(
    filtered_alerts,
    use_container_width=True
)