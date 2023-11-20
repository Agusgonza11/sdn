from pox.pox.core import core
import pox.pox.openflow.libopenflow_01 as of
from pox.pox.lib.revent import *
from pox.pox.lib.util import dpidToStr
from pox.pox.lib.addresses import EthAddr
from src.rules import get_configuration_values
from collections import namedtuple
import os
import argparse

log = core.getLogger()
log.setLevel("DEBUG")

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

    def _handle_ConnectionUp(self, event):
        pass

    def _handle_PacketIn(self, event):
        if self.switch_id != event.dpid:
            return
        packet = event.parsed
        log.debug("El paquete que llego es %s ", packet)
        if packet.type == packet.IP_TYPE:
            ip_packet = packet.find("ipv4")
            if ip_packet:
                log.debug("El paquete ip que llego es %s ", ip_packet)
                if ip_packet.protocol == TCP:
                    transport_packet = ip_packet.find("tcp")
                elif ip_packet.protocol == UDP:
                    transport_packet = ip_packet.find("udp")
                else:
                    transport_packet = None

                if transport_packet:
                    src_ip = ip_packet.srcip
                    dst_ip = ip_packet.dstip
                    src_port = transport_packet.srcport
                    dst_port = transport_packet.dstport
                    src_host = self.get_host_from_ip(src_ip, event.topology)
                    dst_host = self.get_host_from_ip(dst_ip, event.topology)

                    self.filter_packet(packet)

    def get_host_from_ip(self, ip_address, topology):
        for host_number, ip_addresses in topology.hosts.items():
            if ip_address in ip_addresses:
                return host_number
        return None

    def filter_packet(self, event, protocol, src_ip, dst_ip, src_port, dst_port, src_host, dst_host):
        for r in self.rules:
            # puerto de destino 80

            # source host_1, puerto 5001, protocolo UDP

            # Conexion entre 2 y 4 bloqueada

    def drop_packet(self, event):
        log.debug("Entra a romper el paquete")

        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        event.connection.send(msg)

    @classmethod
    def launch(switch_id=1):
        core.registerNew(Firewall, switch_id=switch_id)
