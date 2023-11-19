import json

from pox.pox.core import core
from pox.pox.lib.revent import *

from network_protocol import NetworkProtocol
from pox.lib.revent import EventMixin

# Global Logger

log = core.getLogger()


# The Firewall is a security network component who is in charge of monitor  / outgoing traffic network
# and who is also responsible for managing the entrance or blocking of specific traffic according to a set of rules

class Firewall(EventMixin):
    def __init__(self):
        log.debug("Enabling Firewall Module")
        self.listenTo(core.openflow)
        self.network_protocol = NetworkProtocol()

    def _handle_ConnectionUp(self, event):
        # Add your logic here ...
        pass

    def launch(self):
        # Starting the Firewall module
        core.registerNew(Firewall)
