# ICE engine
def collect_ports_by_ip(events):

    ports_by_ip = {}

    for event in events:
        timestamp, ip, port, status = event

        if ip not in ports_by_ip:
            ports_by_ip[ip] = set()

        ports_by_ip[ip].add(port)

    return ports_by_ip

def detect_port_scanner(ports_by_ip, threshold):
         
    
    scanners = []

    for ip, ports in ports_by_ip.items():
        if len(ports) >= threshold:
            scanners.append(ip)


    return scanners

def detect_bruteforce(events, threshold):

    fail_count = {}

    for event in events:
        timestamp, ip, port, status = event

        # On regarde seulement les FAIL
        if status == "FAIL":

            if ip not in fail_count:
                fail_count[ip] = 0

            fail_count[ip] += 1

    attackers = []

    for ip, count in fail_count.items():

        if count >= threshold:
            attackers.append(ip)

    return attackers

def detect_bruteforce_by_port(events, threshold):
    fail_count = {}

    for event in events:
        timestamp, ip, port, status = event

        if status == "FAIL":
            key = (ip, port)

            if key not in fail_count:
                fail_count[key] = 0

            fail_count[key] += 1

    attackers = []

    for key, count in fail_count.items():
        if count >= threshold:
            attackers.append(key)

    return attackers

def detect_rapid_bruteforce_by_port(events, threshold, time_window):
    fail_times = {}

    for event in events:
        timestamp, ip, port, status = event

        if status == "FAIL":
            key = (ip, port)

            if key not in fail_times:
                fail_times[key] = []

            fail_times[key].append(timestamp)

    attackers = []

    for key, timestamps in fail_times.items():
        timestamps.sort()

        for i in range(len(timestamps) - threshold + 1):
            first_time = timestamps[i]
            last_time = timestamps[i + threshold - 1]

            if last_time - first_time <= time_window:
                attackers.append(key)
                break

    return attackers

def build_threat_scores(events, scanner_threshold, bruteforce_threshold, targeted_threshold, rapid_threshold, time_window):
    ports_by_ip = collect_ports_by_ip(events)
    scanners = detect_port_scanner(ports_by_ip, scanner_threshold)
    attackers = detect_bruteforce(events, bruteforce_threshold)
    attackers_by_port = detect_bruteforce_by_port(events, targeted_threshold)
    rapid_attackers_by_port = detect_rapid_bruteforce_by_port(events, rapid_threshold, time_window)

    targeted_ips = set()
    for ip, port in attackers_by_port:
        targeted_ips.add(ip)

    rapid_targeted_ips = set()
    for ip, port in rapid_attackers_by_port:
        rapid_targeted_ips.add(ip)

    threat_report = {}

    for ip in ports_by_ip:
        threat_report[ip] = {
            "score": 0,
            "reasons": []
        }

        if ip in scanners:
            threat_report[ip]["score"] += 40
            threat_report[ip]["reasons"].append("port_scan")

        if ip in attackers:
            threat_report[ip]["score"] += 30
            threat_report[ip]["reasons"].append("bruteforce_global")

        if ip in targeted_ips:
            threat_report[ip]["score"] += 50
            threat_report[ip]["reasons"].append("bruteforce_targeted")

        if ip in rapid_targeted_ips:
            threat_report[ip]["score"] += 70
            threat_report[ip]["reasons"].append("rapid_bruteforce_targeted")

    return threat_report

def apply_countermeasures(threat_report):
    for ip, data in threat_report.items():
        score = data["score"]

        if score == 0:
            data["action"] = "ALLOW"
        elif score < 60:
            data["action"] = "WATCH"
        elif score < 100:
            data["action"] = "BLOCK"
        else:
            data["action"] = "BLACKLIST"

    return threat_report

