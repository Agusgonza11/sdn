import json

TCP = 6
UDP = 17

def get_configuration_values():
    with open('rules.json', 'r') as file:
        rules_data = json.load(file)

    for r in rules_data:
        prot = r.get("protocol")
        if prot and prot == "tcp":
            r["protocol"] = TCP
        if prot  and prot == "udp":
            r["protocol"] = UDP
    
    return rules_data

print(get_configuration_values())