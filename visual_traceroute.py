# requirements: scapy, graphviz

from scapy.all import *

# can also provide a list of targets [''],['']
result, unanswered = traceroute(['www.microsoft.com'])

res.graph(target="> /tmp/graph.csv")
