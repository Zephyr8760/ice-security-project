from data.sample_events import EVENTS
from ice.engine import collect_ports_by_ip

result = collect_ports_by_ip(EVENTS)

print(result)
