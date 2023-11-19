import json
import pox.openflow.libopenflow_01 as openflow


class NetworkProtocol:
    def __init__(self):
        self.controller = openflow
        self.network_rules = self._load_rules()

    def add_rules(self):
        block_match = openflow.ofp_match()

        for rule in self.network_rules:
            self._add_rule(rule, block_match)

        message = self._create_message_from_rules(block_match)
        self.controller.send(message)

    def _add_transport_rule(self, rule, block_match):
        if "source_port" in rule:
            block_match.tp_src = rule["transport"]["source_port"]
        if "destination_port" in rule:
            block_match.tp_dst = rule["transport"]["destination_port"]

    def _add_xxx_rule(self):
        pass

    def _add_yyy_rule(self):
        pass

    def _add_rule(self, rule, block_match):
        self._add_transport_rule(rule, block_match)
        self._add_xxx_rule()
        self._add_yyy_rule()

    def _create_message_from_rules(self, block_match):
        message = self._get_message_for_flow_entry()
        message.match = block_match

        return message

    def _get_message_for_flow_entry(self):
        return self.controller.ofp_flow_mod()

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
