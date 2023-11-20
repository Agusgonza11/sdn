import json
import pox.openflow.libopenflow_01 as openflow
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr


# The Network Protocol allows that through a central controller, policies can be defined on how packets should be
# sent and classified. The radical advantage that OpenFlow offers is the independence of the hardware to perform
# these actions.

class NetworkProtocol:
    def __init__(self):
        self.controller = openflow
        self.network_rules = self._load_rules()

    def add_rules(self):
        block_match = openflow.ofp_match()

        for rule in self.network_rules["firewall"]["network_rules"]:
            self._add_rule(rule, block_match)

        message = self._create_message_from_rules(block_match)
        self.controller.send(message)

    def _add_transport_rule(self, rule, block_match):
        if "tcp" in rule:
            block_match.nw_proto = pkt.tcp
        if "udp" in rule:
            block_match.nw_proto = pkt.udp
        if "source_port" in rule:
            block_match.tp_src = rule["transport"]["source_port"]
        if "destination_port" in rule:
            block_match.tp_dst = rule["transport"]["destination_port"]

    def _add_network_rule(self, rule, block_match):
        if "source_ip" in rule:
            block_match.nw_src = IPAddr(rule["host"]["source_ip"])
        if "destination_ip" in rule:
            block_match.nw_dst = IPAddr(rule["host"]["destination_ip"])

    def _add_rule(self, rule, block_match):
        self._add_transport_rule(rule, block_match)
        self._add_network_rule(rule, block_match)

    def _create_message_from_rules(self, block_match):
        message = self._get_message_for_flow_entry()
        message.match = block_match

        return message

    def _get_message_for_flow_entry(self):
        return self.controller.ofp_flow_mod()

    def print_rules(self):
        formatted_data = json.dumps(self.network_rules, indent=4)
        print(formatted_data)

    def _load_rules(self, file_path="firewall_rules.json"):
        try:
            with open(file_path, "r") as json_file:
                rules = json.load(json_file)
                return rules
        except FileNotFoundError:
            print(f"Error: Configuration file '{file_path}' not found.")
            return None
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON format in '{file_path}'.")
            return None
