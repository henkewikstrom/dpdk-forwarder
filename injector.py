import sys
import random
from scapy.all import *

def random_ip():
    return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <num_flows> <num_pkts> <tx_interface>")
        sys.exit(1)

    num_flows = int(sys.argv[1])
    num_pkts  = int(sys.argv[2])
    interface = str(sys.argv[3])

    protos = [TCP, UDP]

    seen = set()
    flows = []
    while len(flows) < num_flows:
        src   = random_ip()
        dst   = random_ip()
        proto = random.choice(protos)
        sport = random.randint(1024, 65535)
        dport = random.randint(1, 1023)
        key = (src, dst, proto.__name__, sport, dport)
        if key not in seen:
            seen.add(key)
            flows.append(Ether()/IP(src=src, dst=dst)/proto(sport=sport, dport=dport))

    all_pkts = flows * num_pkts
    random.shuffle(all_pkts)
    sendp(all_pkts, iface=interface, verbose=False)
    print(f"Sent {len(all_pkts)} packets across {num_flows} flows ({num_pkts} pkts/flow)")

if __name__ == "__main__":
    main()