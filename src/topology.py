from mininet.topo import Topo

class CustomTopology(Topo):
    def __init__(self, len_switches=2):
        if len_switches < 2:
            exit("El número de switches debe ser al menos 2")
        
        hosts = [self.addHost(f"host_{i}") for i in range(1, 5)]
        switches = [self.addSwitch(f"switch_{i}") for i in range(1, len_switches + 1)]
        
        for i in range(len_switches - 1):
            self.addLink(switches[i], switches[i + 1])

        self.addLink(hosts[0], switches[0])
        self.addLink(hosts[1], switches[0])
        self.addLink(hosts[2], switches[-1])
        self.addLink(hosts[3], switches[-1])
