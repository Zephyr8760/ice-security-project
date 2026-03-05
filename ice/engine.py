# ICE engine
def collect_ports_by_ip(events):

    ports_by_ip = {}

    for event in events:
        timestamp, ip, port, status = event

        if ip not in ports_by_ip:
            ports_by_ip[ip] = set()

        ports_by_ip[ip].add(port)

    return ports_by_ip
