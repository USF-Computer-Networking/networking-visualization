from scapy.all import *
from threading import Thread
import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
np.random.seed(sum(map(ord, "aesthetics")))

# Dictionary mapping all of the routes
packets = []


def get_dns_resp(packet):
    # https://thepacketgeek.com/scapy-p-09-scapy-and-dns/
    return sr1(IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=packet[DNSQR].qname)), verbose=False)


def add_dns_route_entry(packet, dns_resp):
    print packet.show()
    routelist = []
    for x in range(dns_resp[DNS].ancount):
        if dns_resp[DNSRR] != None:
            routelist.append(dns_resp[DNSRR][x].rdata)
    routes[packet[DNSQR].qname] = routelist


def add_packet_route(packet):
    dns_resp = get_dns_resp(packet)
    add_dns_route_entry(packet, dns_resp)


def packet_found(packet):
    packets.append(packet)


def run_sniff():
    print "Sniffing\n"
    sniff(prn=packet_found)


def usage():
    print "Available actions"
    print "     -h (Help)"
    print "     ls (Lists all of the available DNS Routes)"
    print "     route <domain> (Prints the DNS route for the given domain)"
    print "     graph (Prints a full graph of all sniffed DNS records)"


def ls():
    if not any(packets):
        print "No routes"
        return

    for entry in packets:
        print entry


def print_route(domain):
    route = routes.get(domain)
    sys.stdout.write('\t')
    for stop in route:
        sys.stdout.write(stop + " --> ")
    sys.stdout.write(domain + '\n')
    sys.stdout.write('\t')
    sys.stdout.write('Details:' +'\n')
    sys.stdout.write('\t\tHostname: ' + domain + '\n')
    sys.stdout.write('\t\tHops: ' + str(len(route)))
    sys.stdout.flush()


def print_graph():
    print "DNS GRAPH\n"
    dns = 0
    tcp = 0
    ntp = 0
    arp = 0
    for packet in packets:
        if packet.haslayer(DNS):
            dns = dns + 1
        elif packet.haslayer(TCP):
            tcp = tcp + 1
        elif packet.haslayer(NTP):
            ntp = ntp + 1
        elif packet.haslayer(ARP):
            arp = arp + 1
    df = pd.DataFrame()
    df['dns'] = [dns]
    df['tcp'] = [tcp]
    df['ntp'] = [ntp]
    df['arp'] = [arp]
    sns.barplot(data=df)
    plt.show()

if __name__ == '__main__':
    thread = Thread(target=run_sniff)
    thread.start()

    running = True
    while (running):
        print "Enter command or help for more info"
        action = raw_input()
        if action == "help":
            usage()
        elif action == "ls":
            ls()
        elif action == "graph":
            print_graph()
        elif action == "exit":
            plt.close()
        elif action.startswith("route"):
            argv = action.split(" ")
            if len(argv) != 2:
                usage()
                continue
            domain = argv[1]
            print_route(domain)
        else:
            print "Invalid command"
            usage()
