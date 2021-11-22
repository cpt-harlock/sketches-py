import numpy as np
import argparse
import hashlib
from ddsketch.ddsketch import *


class PacketRtt:
    def __init__(self, ipsrc, ipdst, sport, dport, rtt):
        self.ipsrc = ipsrc
        self.ipdst = ipdst 
        self.sport = sport 
        self.dport = dport
        self.rtt = rtt



if __name__ == "__main__":

    argparser = argparse.ArgumentParser()
    argparser.add_argument("files", metavar="FILE(S)", type=str, nargs="+", 
            help="Files to be processed", required=True)
    argparser.add_argument("--threshold", type=int, help="Long/short threshold") 
    argparser.add_argument("--bin_limit", type=int, help="Bin amount for DDSketch") 
    argparser.add_argument("--max_value", type=float, help="Max RTT") 
    argparser.add_argument("--min_value", type=int, help="Min RTT") 
    args = argparser.parse_args()   
    packets = []
    for file in args.files:
        temp = np.load(file, allow_pickle=True).item()
        for pkt in temp:
            packets.append(PacketRtt(pkt[0], pkt[1], pkt[2], pkt[3], pkt[4]))
    # dictionary packet_hash -> ddsketch
    huge_flows = {}
    # dictionary packet_hash -> list of rtt
    small_flows = {}
    # hashing object
    hasher = hashlib.sha256()
    # count how many times we switch structure
    switch_structure_counter = 0
    # iterate over list of packets 
    for packet in packets:
        # compute packet hash
        hasher.update((packet.ipsrc, packet.ipdst, packet.sport, packet.dport))
        key = hasher.hexdigest()
        if key in huge_flows:
            huge_flows[key].add(packet.rtt)
        else:
            if key in small_flows:
                small_flows[key].append(packet.rtt)
                if len(small_flows[key]) > args.threshold:
                    huge_flows[key] = FixedSizeDDSketch(args.max_value, args.min_value, bin_limit=args.bin_limit)
                    for rtt in small_flows[key]:
                        huge_flows[key].add(rtt)
                    del small_flows[key]
            else:
                small_flows[key] = [packet.rtt]
