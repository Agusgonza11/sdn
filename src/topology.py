# -*- coding: utf-8 -*-
from mininet.topo import Topo


class CustomTopology(Topo):
    def __init__(self, switches=2):
        if switches < 2:
            exit("El número de switches debe ser al menos 2")
        Topo.__init__(self)

        hosts = [self.addHost("host_{}".format(i)) for i in range(1, 5)]
        switches = [self.addSwitch("switch_{}".format(i))
                    for i in range(1, switches + 1)]

        for i in range(switches - 1):
            self.addLink(switches[i], switches[i + 1])

        self.addLink(hosts[0], switches[0])
        self.addLink(hosts[1], switches[0])
        self.addLink(hosts[2], switches[-1])
        self.addLink(hosts[3], switches[-1])
