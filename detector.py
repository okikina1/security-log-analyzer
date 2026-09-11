import pandas as pd


def detect_alerts(df):

    all_alerts = []

    # ==========================================
    # Rule 1: Brute Force
    # ==========================================

    failed = df[df["event"] == "LOGIN_FAILED"].copy()
    failed = failed.sort_values("timestamp")

    for (user, ip), group in failed.groupby(["user", "ip"]):

        timestamps = group["timestamp"].tolist()

        for i in range(len(timestamps)):

            count = 1

            for j in range(i + 1, len(timestamps)):

                difference = timestamps[j] - timestamps[i]

                if difference <= pd.Timedelta(minutes=5):
                    count += 1
                else:
                    break

            if count >= 5:

                all_alerts.append({
                    "rule": "BRUTE_FORCE",
                    "user": user,
                    "ip": ip,
                    "timestamp": timestamps[i],
                    "severity": "HIGH",
                    "description": f"{count} failed login attempts within 5 minutes"
                })

                break


    # ==========================================
    # Rule 2: Login After Repeated Failures
    # ==========================================

    successes = df[df["event"] == "LOGIN_SUCCESS"].copy()
    successes = successes.sort_values("timestamp")

    for _, success in successes.iterrows():

        user = success["user"]
        ip = success["ip"]
        success_time = success["timestamp"]

        recent_failures = failed[
            (failed["user"] == user) &
            (failed["ip"] == ip) &
            (failed["timestamp"] < success_time) &
            (failed["timestamp"] >= success_time - pd.Timedelta(minutes=5))
        ]

        if len(recent_failures) >= 3:

            all_alerts.append({
                "rule": "LOGIN_AFTER_FAILURES",
                "user": user,
                "ip": ip,
                "timestamp": success_time,
                "severity": "HIGH",
                "description": f"Successful login after {len(recent_failures)} failed attempts"
            })


    # ==========================================
    # Rule 3: Unknown IP
    # ==========================================

    known_ips = {}

    for _, login in successes.iterrows():

        user = login["user"]
        ip = login["ip"]
        timestamp = login["timestamp"]

        if user not in known_ips:
            known_ips[user] = set()

        if ip not in known_ips[user]:

            # Don't flag the user's very first IP
            if len(known_ips[user]) > 0:

                all_alerts.append({
                    "rule": "UNKNOWN_IP",
                    "user": user,
                    "ip": ip,
                    "timestamp": timestamp,
                    "severity": "MEDIUM",
                    "description": "Successful login from previously unseen IP address"
                })

        known_ips[user].add(ip)


    # ==========================================
    # Rule 4: After-Hours Login
    # ==========================================

    for _, login in successes.iterrows():

        user = login["user"]
        ip = login["ip"]
        timestamp = login["timestamp"]

        hour = timestamp.hour

        # Normal working hours: 08:00 - 17:59
        if hour < 8 or hour >= 18:

            all_alerts.append({
                "rule": "AFTER_HOURS_LOGIN",
                "user": user,
                "ip": ip,
                "timestamp": timestamp,
                "severity": "MEDIUM",
                "description": "Successful login occurred outside normal working hours"
            })


    # ==========================================
    # Rule 5: Excessive User Activity
    # ==========================================

    activity_counts = df["user"].value_counts()

    for user, count in activity_counts.items():

        if count > 10:
            user_events = df[df["user"] == user]
            latest_event = user_events.sort_values("timestamp").iloc[-1]
            
            all_alerts.append({
                "rule": "EXCESSIVE_ACTIVITY",
                "user": user,
                "ip": latest_event["ip"],
                "timestamp": latest_event["timestamp"],
                "severity": "MEDIUM",
                "description": f"User generated {count} events"
            })


    # ==========================================
    # Create final alerts DataFrame
    # ==========================================

    alerts_df = pd.DataFrame(all_alerts, columns=[
        "rule",
        "user",
        "ip",
        "timestamp",
        "severity",
        "description"
    ])

    return alerts_df