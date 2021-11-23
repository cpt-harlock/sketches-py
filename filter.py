import numpy as np
import argparse
from ddsketch.ddsketch import *


class PacketRtt:
    def __init__(self, ipsrc, ipdst, sport, dport, ts):
        self.ipsrc = ipsrc
        self.ipdst = ipdst 
        self.sport = sport 
        self.dport = dport
        self.ts = ts 



if __name__ == "__main__":

    argparser = argparse.ArgumentParser()
    argparser.add_argument("files", metavar="FILE(S)", type=str, nargs="+", 
            help="Files to be processed")
    argparser.add_argument("--threshold", type=int, help="Long/short threshold", required=True) 
    argparser.add_argument("--bin_limit", type=int, help="Bin amount for DDSketch", required=True) 
    argparser.add_argument("--max_value", type=float, help="Max Interarrival time", required=True) 
    argparser.add_argument("--min_value", type=float, help="Min Interarrival time", required=True) 
    args = argparser.parse_args()   
    packets = []
    for file in args.files:
        temp = np.load(file, allow_pickle=True).item()
        # temp structure:
        # temp = { 'x' : <list-of-keys>, 'y' : <list-of-arrival-time> }
        # key = ( <ipsrc>, <ipdst>, <sport>, <dport> )
        for i, key in enumerate(temp['x']):
            packets.append(PacketRtt(key[0], key[1], key[2], key[3], temp['y'][i]))
    

    # key stat
    stat = {}
    # dictionary packet_hash -> ddsketch
    huge_flows = {}
    # dictionary packet_hash -> list of rtt
    small_flows = {}
    # count how many times we switch structure
    switch_structure_counter = 0
    # iterate over list of packets 
    for packet in packets:
        key = ( packet.ipsrc, packet.ipdst, packet.sport, packet.dport)
        if key in stat:
            stat[key]['count'] += 1
            # compute interarrival time
            interarrival = packet.ts - stat[key]['last']
            # update last packet for this flow
            stat[key]['last'] = packet.ts
            # if packet belongs to huge flow
            if key in huge_flows:
                huge_flows[key].add(interarrival)
            else:
                if key in small_flows:
                    small_flows[key].append(interarrival)
                    if len(small_flows[key]) > args.threshold:
                        huge_flows[key] = FixedSizeDDSketch(args.max_value, args.min_value, bin_limit=args.bin_limit)
                        for value in small_flows[key]:
                            huge_flows[key].add(value)
                        del small_flows[key]
                else:
                    small_flows[key] = [interarrival]
        else:
            stat[key] = {'count':0, 'first':packet.ts,'last':packet.ts}


    print(huge_flows[('102.6.156.146', '221.46.220.227', 54654, 80)].get_quantile_value(0.9))
    # alla fine dell'esperimento:
    # calcolo accuracy
    # calcolo long/short e big/small flows
    # sparsita (# bucket diversi da zero)

