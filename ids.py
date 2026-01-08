import re
from datetime import datetime, timedelta

LOG_FILE = "sample_auth.log"
FAIL_THRESHOLD = 5
TIME_WINDOW = timedelta(minutes=2)

log_pattern = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*Failed password.*from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

def parse_time(month, day, time_str):
    hour, minute, second = map(int, time_str.split(":"))
    return datetime(2025, MONTHS[month], int(day), hour, minute, second)

def main():
    failures = {}

    with open(LOG_FILE, "r") as log:
        for line in log:
            match = log_pattern.search(line)
            if match:
                timestamp = parse_time(
                    match.group("month"),
                    match.group("day"),
                    match.group("time")
                )
                ip = match.group("ip")

                failures.setdefault(ip, []).append(timestamp)

    print("\nSuspicious IPs (Possible Brute Force):")
    print("-" * 45)

    for ip, times in failures.items():
        times.sort()
        for i in range(len(times)):
            window = [t for t in times if times[i] <= t <= times[i] + TIME_WINDOW]
            if len(window) >= FAIL_THRESHOLD:
                print(f"{ip} → {len(window)} failed attempts in 2 minutes")
                break

if __name__ == "__main__":
    main()
