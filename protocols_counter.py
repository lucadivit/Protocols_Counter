from scapy.all import *
import operator, glob
import sys
import argparse as agp

parser = agp.ArgumentParser(description="Compute the protocols involved in a list of pcaps")
parser.add_argument('path', help='Path of the folder that contains pcaps')
try:
    path = parser.parse_args().path
except:
    parser.print_help()
    sys.exit(0)

if(path.endswith("/") is False):
    path = path + "/"

protocols = {}
total_pkts = 0
pcaps = glob.glob(path + "*.pcap")
sys.setrecursionlimit(100000)
i = 0
for pcap in pcaps:
    print ("Pcap " + str(i) + " " + pcap)
    pkts = rdpcap(pcap)
    total_pkts = total_pkts + len(pkts)
    pkt_counter = 0
    for pkt in pkts:
        counter = 0
        print ("Pkt " + str(pkt_counter))
        while True:
            layer = pkt.getlayer(counter)
            if(layer is None):
                break
            else:
                p_name = str(layer.name)
                val = protocols.get(p_name, None)
                if(val is None):
                    protocols[p_name] = 1
                else:
                    new_val = val + 1
                    protocols[p_name] = new_val
            counter += 1
            print ("Counter Layer " + str(counter) + ": " + p_name)
        pkt_counter+=1
    i += 1

protocols_sorted = sorted(protocols.items(), key=operator.itemgetter(1))
file_w = open("prot_res.txt", "w")
file_w.write(str(protocols_sorted) + "\n")
file_w.write("Pcap = " + str(len(pcaps)) + "\n")
file_w.write("Pkts analyzed " + str(total_pkts) + "\n")
file_w.close()
print(protocols_sorted)
print("Pcap = " + str(len(pcaps)))
print("Pkts analyzed " + str(total_pkts))