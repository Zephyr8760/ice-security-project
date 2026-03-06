from data.sample_events import EVENTS
from ice.engine import (
    collect_ports_by_ip,
    detect_port_scanner,
    detect_bruteforce,
    build_threat_scores,
    apply_countermeasures,
    detect_bruteforce_by_port,
    detect_rapid_bruteforce_by_port
)

def display_report(report):
    sorted_items = sorted(
        report.items(),
        key=lambda item: item[1]["score"],
        reverse=True
    )

    for ip, data in sorted_items:
        if data["reasons"]:
            reasons_text = ", ".join(data["reasons"])
        else:
            reasons_text = "none"

        print("=" * 40)
        print("IP:", ip)
        print("Score:", data["score"])
        print("Reasons:", reasons_text)
        print("Action:", data["action"])

    print("=" * 40)

ports_by_ip = collect_ports_by_ip(EVENTS)
scanners = detect_port_scanner(ports_by_ip, 3)
attackers = detect_bruteforce(EVENTS, 3)
threat_report = build_threat_scores(EVENTS, 3, 3, 2, 3, 5)
final_report = apply_countermeasures(threat_report)
attackers_by_port = detect_bruteforce_by_port(EVENTS, 2)
rapid_attackers = detect_rapid_bruteforce_by_port(EVENTS, 3, 5)

print("Ports par IP:", ports_by_ip, "\n")
print("Scanners détectés:", scanners, "\n")
print("Bruteforce détecté:", attackers, "\n")
print("Bruteforce par port détecté:", attackers_by_port, "\n")
print("Rapid bruteforce par port détecté:", rapid_attackers)

display_report(final_report)
