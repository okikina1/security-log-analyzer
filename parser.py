import pandas as pd


def parse_logs(filename):

    data_list = []

    with open(filename, "r", encoding="utf-8") as log_file:

        for line in log_file:

            # Skip blank lines
            if not line.strip():
                continue

            parts = line.split()

            timestamp = f"{parts[0]} {parts[1]}"
            event = parts[2]

            data = {
                "timestamp": timestamp,
                "event": event,
            }

            for part in parts[3:]:
                key, value = part.split("=", 1)
                data[key] = value

            data_list.append(data)

    df = pd.DataFrame(data_list)

    df["timestamp"] = pd.to_datetime(df["timestamp"])

    return df