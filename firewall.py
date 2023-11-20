from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os
import argparse
import json

log = core.getLogger()

# Add your global variables here ...

TCP = 6
UDP = 17

class Firewall(EventMixin):
    def __init__(self, switch_id=1):
        self.listenTo(core.openflow)
        log.debug("Enabling Firewall Module")
        # Lista de diccionarios con las reglas
        self.rules = get_configuration_values()
        self.switch_id = switch_id
        log.debug("Firewall initialized for switch %s", switch_id)
        log.debug("hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola hola ")

    def _handle_ConnectionUp(self, event):
        log.debug("handle connectionup")
        if event.dpid != self.switch_id:
            continue
        msg = of.ofp_flow_mod()
        self.handle_event(event, msg, rule)

    def handle_event(self, event):
        for r in self.rules:
            msg.match.dl_type = ethernet.IP_TYPE
            if "source_ip" in rule:
                log.debug(
                    "Rule installed: dropping packet from IP address %s", rule["source_ip"]
                )
                msg.match.nw_src = rule["source_ip"]
            if "dest_ip" in rule:
                log.debug(
                    "Rule installed: dropping packet to IP address %s", rule["dest_ip"]
                )
                msg.match.nw_dst = rule["dest_ip"]
            if "source_port" in rule:
                log.debug("Rule installed: dropping packet from port %i", rule["source_port"])
                msg.match.tp_src = rule["source_port"]
            if "dest_port" in rule:
                log.debug("Rule installed: dropping packet to port %i", rule["dest_port"])
                msg.match.tp_dst = rule["dest_port"]
            if "source_mac" in rule:
                log.debug("Rule installed: dropping packet from MAC %s", rule["source_mac"])
                msg.match.dl_src = EthAddr(rule["source_mac"])
            if "dest_mac" in rule:
                log.debug("Rule installed: dropping packet to MAC %s", rule["dest_mac"])
                msg.match.dl_dst = EthAddr(rule["dest_mac"])
            if rule.get("protocol", None) == "tcp":
                log.debug("Rule installed: dropping packet over TCP")
                msg.match.nw_proto = ipv4.TCP_PROTOCOL
            if rule.get("protocol", None) == "udp":
                log.debug("Rule installed: dropping packet over UDP")
                msg.match.nw_proto = ipv4.UDP_PROTOCOL

        event.connection.send(msg)

    def _handle_PacketIn(self, event):
        pass

def launch(switch_id=1):
    log.debug("\nLAUNCHING FIREWALL\n")
    core.registerNew(Firewall, switch_id=switch_id)

def get_configuration_values(config_file='rules.json'):
    with open(config_file, 'r') as file:
        rules_data = json.load(file)
    
    return rules_data