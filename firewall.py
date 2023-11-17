from pox.pox.core import core
import pox.pox.openflow.libopenflow_01 as of
from pox.pox.lib.revent import *
from pox.pox.lib.util import dpidToStr
from pox.pox.lib.addresses import EthAddr
from collections import namedtuple
import os

log = core . getLogger()
# Add your global variables here ...


class Firewall(EventMixin):
    def __init__(self):
        self.listenTo(core.openflow)
        log.debug("Enabling Firewall Module")

    def _handle_ConnectionUp(self, event):
        # Add your logic here ...
        pass

    def launch(self):
        # Starting the Firewall module
        core.registerNew(Firewall)
