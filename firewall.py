from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import json
import os

TCP = 6
UDP = 17
IP = 0X800

log = core.getLogger()

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

class Firewall(EventMixin):

    def __init__(self, switch_id):
        self.listenTo(core.openflow)
        log.debug("Enabling Firewall Module")
        self.rules = get_configuration_values()
        self.switch_name = "switch_" + str(switch_id)
        log.debug(f"Switch ID: {switch_id}")

    def _handle_ConnectionUp(self, event):
        log.debug(f"Event PORT NAME: {event.connection.ports[of.OFPP_LOCAL].name}")
        if event.connection.ports[of.OFPP_LOCAL].name != self.switch_name:
            return
        for rule in self.rules:
            self.filter_for_rule(event, rule)

    def filter_for_rule(self, event, rule):
        block = of.ofp_match()
        if 'source_mac' in rule:
            block.dl_src = EthAddr(rule['source_mac'])
        if 'dest_mac' in rule:
            block.dl_dst = EthAddr(rule['dest_mac'])
        if 'source_ip' in rule:
            block.nw_src = rule['source_ip']
        if 'destination_ip' in rule:
            block.nw_dst = rule['destination_ip']
        if 'protocol' in rule:
            block.dl_type = IP
            block.nw_proto = rule['protocol']
        if 'destination_port' in rule:
            block.dl_type = IP
            if 'protocol' in rule and rule['protocol'] == UDP:
                block.nw_proto = UDP
            else:
                block.nw_proto = TCP
            block.tp_dst = int(rule['destination_port'])
        openflow_packet = of.ofp_flow_mod()
        openflow_packet.match = block
        event.connection.send(openflow_packet)


def launch(switch_id=1):
    core.registerNew(Firewall, switch_id)
