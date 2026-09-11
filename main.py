from parser import parse_logs
from detector import detect_alerts


df = parse_logs("logs_security.log")

alerts_df = detect_alerts(df)

print(alerts_df)

print("\nAlert Summary:")
print(alerts_df["rule"].value_counts())
