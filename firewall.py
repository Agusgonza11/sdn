from pox.pox.core import core
import pox.pox.openflow.libopenflow_01 as of
from pox.pox.lib.revent import *
from pox.pox.lib.util import dpidToStr
from pox.pox.lib.addresses import EthAddr
from src.config import get_configuration_values
from collections import namedtuple
import os
import argparse

log = core.getLogger()
# Add your global variables here ...

TCP = 6
UDP = 17

class Firewall(EventMixin):
    def __init__(self, switch_id=1):
        self.listenTo(core.openflow)
        log.debug("Enabling Firewall Module")
        self.rules = get_configuration_values()
        self.switch_id = switch_id

    def _handle_ConnectionUp(self, event):
        log.debug("The switch %s is connected", event.dpid)

    def _handle_PacketIn(self, event):
        if self.switch_id is not None and self.switch_id != event.dpid:
            return
        packet = event.parsed
        if packet.type == packet.IP_TYPE:
            ip_packet = packet.find("ipv4")
            protocol = ip_packet.protocol
            src_host = self.get_host_from_ip(ip_packet.srcip)
            dst_host = self.get_host_from_ip(ip_packet.dstip)
            src_ip = ip_packet.src_ip
            dst_ip = ip_packet.src_ip
            if ip_packet.protocol == TCP:
                packet = ip_packet.find("tcp")
            if ip_packet.protocol == UDP:
                packet = ip_packet.find("udp")
            src_port = packet.srcport
            dst_port = packet.dstport
            self.filter_packet(event, protocol, src_ip, dst_ip, src_port, dst_port, src_host, dst_host)

    def get_host_from_ip(self, ip_address):
        for host_number, ip_addresses in self.topology.hosts.items():
            if ip_address in ip_addresses:
                return host_number
        return None

    def filter_packet(self, event, protocol, src_ip, dst_ip, src_port, dst_port, src_host, dst_host):
        if protocol in self.rules["protocol"]:
            self.drop_packet(event)
            return
        if src_ip in self.rules["src_host"] or dst_ip in self.rules["dst_host"]:
            self.drop_packet(event)
            return
        if str(src_port) in self.rules["src_port"] or str(dst_port) in self.rules["dst_port"]:
            self.drop_packet(event)
            return
        if (src_host, dst_host) in self.rules["incommunicable_hosts"] or (dst_host, src_host) in self.rules["incommunicable_hosts"]:
            self.drop_packet(event)
            return

    def drop_packet(self, event):
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        event.connection.send(msg)

    def launch(switch_id=1):
        core.registerNew(Firewall, switch_id=switch_id)
