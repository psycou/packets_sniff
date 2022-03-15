# packets_sniff

A packet analyzer, also known as packet sniffer, protocol analyzer, or network analyzer,is a computer program or computer hardware such as a packet capture appliance, that can intercept and log traffic that passes over a computer network or part of a network.Packet capture is the process of intercepting and logging traffic. As data streams flow across the network, the analyzer captures each packet and, if needed, decodes the packet's raw data, showing the values of various fields in the packet, and analyzes its content according to the appropriate RFC or other specifications.

You Must Be Man-in-the-middle To Intercept traffic

requierment:

scapy: follow This insctruction to install scapy

root@root:~$ pip install --pre scapy[basic]

Usage

root@root:~$ python packets_snif.py -t <Exemple: 192.168.1.3>
