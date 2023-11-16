# SDN

If you want to interact with [POX](https://github.com/noxrepo/pox), you can run the folowing commands standing from the root of the project:

```python
cd pox
./pox.py samples.pretty_log forwarding.l2_learning
```

If you want to run the default topology, make sure you run this command:

```python
sudo mn --custom ./src/topology.py --topo topologia --arp --mac --switch ovsk --controller remote
```
