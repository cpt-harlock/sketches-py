import numpy as np
import argparse
from ddsketch.ddsketch import *
import decimal
import matplotlib.pyplot as plot
from scipy.interpolate import make_interp_spline, BSpline

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
    argparser.add_argument("--bin_limit", type=int, help="Bin(s) amount for DDSketch", required=True, nargs='+') 
    argparser.add_argument("--max_value", type=float, help="Max Interarrival time", required=True) 
    argparser.add_argument("--min_value", type=float, help="Min Interarrival time", required=True) 
    argparser.add_argument("--bytes_per_bin", type=int, help="Bytes per bin", default=1) 
    args = argparser.parse_args()   
    packets = []
    for file in args.files:
        temp = np.load(file, allow_pickle=True).item()
        # temp structure:
        # temp = { 'x' : <list-of-keys>, 'y' : <list-of-arrival-time> }
        # key = ( <ipsrc>, <ipdst>, <sport>, <dport> )
        for i, key in enumerate(temp['x']):
            packets.append(PacketRtt(key[0], key[1], key[2], key[3], temp['y'][i]))
    

    print(len(packets))
    # final stats
    # dictionary where keys = range of bin_limit
    final_stats = {}
    for bin_limit in args.bin_limit:
        # key stat
        stat = {}
        # dictionary packet_hash -> ddsketch
        huge_flows = {}
        # dictionary packet_hash -> list of interarrival times 
        small_flows = {}
        # true interarrival times
        true_flows = {}
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
                # update true interarrival time structure
                true_flows[key].append(interarrival)
                # if packet belongs to huge flow
                if key in huge_flows:
                    huge_flows[key].add(interarrival)
                else:
                    if key in small_flows:
                        small_flows[key].append(interarrival)
                        if len(small_flows[key]) > args.threshold:
                            # update counter
                            switch_structure_counter += 1
                            huge_flows[key] = FixedSizeDDSketch(args.max_value, args.min_value, bin_limit=bin_limit, bytes_per_bin=args.bytes_per_bin)
                            for value in small_flows[key]:
                                huge_flows[key].add(value)
                            del small_flows[key]
                    else:
                        small_flows[key] = [interarrival]
            else:
                stat[key] = {'count':1, 'first':packet.ts,'last':packet.ts}
                true_flows[key] = []

        # save experiment data
        #np.save("huge_flows.npy", allow_pickle=True, arr=huge_flows)
        #np.save("small_flows.npy", allow_pickle=True, arr=small_flows)
        #np.save("true_flows.npy", allow_pickle=True, arr=true_flows)
        # compute accuracy
        quantile_list = [0.5, 0.75, 0.9, 0.95, 1]
        # dictionary for accuracy
        # key: flow_key
        # value: list of tuple (true_quantile, estimated_quantile) for each quantile 
        # in quantile_list
        accuracy = {}
        for key in huge_flows:
            estimated_quantiles = [ huge_flows[key].get_quantile_value(k) for k in quantile_list]
            true_quantiles = np.quantile(true_flows[key], quantile_list)
            accuracy[key] = [ (decimal.Decimal(true_quantiles[k]), decimal.Decimal(estimated_quantiles[k])) for k in range(len(estimated_quantiles))] 
        # TODO: useless, same values
        for key in small_flows:
            # just a check
            assert key not in huge_flows
            estimated_quantiles = np.quantile(small_flows[key], quantile_list)
            true_quantiles = np.quantile(true_flows[key], quantile_list)
            accuracy[key] = [ (decimal.Decimal(true_quantiles[k]), estimated_quantiles[k]) for k in range(len(estimated_quantiles))] 
        # save accuracy
        #np.save("accuracy.npy", allow_pickle=True, arr=accuracy)
        # save stats
        #np.save("stats.npy", allow_pickle=True, arr=stat)

        # compute average relative accuracy for each quantile (averaging over flows)
        average_accuracy = {}
        # count samples for each quantile (avoid division by 0)
        count = {}
        for q in quantile_list:
            average_accuracy[q] = decimal.Decimal(0.0)
            count[q] = 0

        # iterate over flows
        for key in accuracy:
            # iterate over quantile true value/estimate for each flow
            for i, (true_value, estimate_value) in enumerate(accuracy[key]):
                # if relative error can be computed
                if true_value != decimal.Decimal(0.0):
                    count[quantile_list[i]] += 1
                    average_accuracy[quantile_list[i]] += abs(true_value - estimate_value)/true_value
        for q in average_accuracy:
            average_accuracy[q] /= count[q]

        # compute memory occupancy in bytes
        total_memory = sum([k.store.get_total_memory() for k in huge_flows.values()])
        total_memory += len(small_flows)*args.threshold*4
        # compute unused memory
        unused_memory = sum([k.store.get_unused_memory() for k in huge_flows.values()])
        for _, value in small_flows.items():
            unused_memory += 4*(args.threshold-len(value))
        # compute occupied memory
        occupied_memory = total_memory - unused_memory

        # TODO: dummy to save same value each iteration
        final_stats['huge_flows'] = len(huge_flows)
        final_stats['small_flows'] = len(small_flows)
        final_stats['single_packet_flows'] = len(stat)-(len(huge_flows) + len(small_flows))
        final_stats[bin_limit] = {}
        final_stats[bin_limit]['average_quantile_accuracy'] = average_accuracy
        final_stats[bin_limit]['total_memory'] = total_memory
        final_stats[bin_limit]['occupied_memory'] = occupied_memory 
        final_stats[bin_limit]['unused_memory'] = unused_memory 

    # plot
    x_accuracy = [final_stats[k]['average_quantile_accuracy'][0.95] for k in args.bin_limit]
    y_total_memory = [final_stats[k]['total_memory'] for k in args.bin_limit]
    y_memory_efficiency = [final_stats[k]['occupied_memory']/final_stats[k]['total_memory'] for k in args.bin_limit]
    #print(x_accuracy)
    #print(y_total_memory)
    # interpolate
    #xnew = np.linspace(float(min(x_accuracy)), float(max(x_accuracy)), 300)
    #temp = zip(x_accuracy, y_total_memory)
    #print(list(temp))
    #print(x_accuracy)
    #print(y_total_memory)
    #spl = make_interp_spline(x_accuracy.sort(), np.array(y_total_memory.sort(reverse=True)), k=3)  # type: BSpline
    #y_smooth = spl(x_accuracy)

    fig = plot.figure()
    ax = fig.add_subplot(111)
    ax.plot(np.array(x_accuracy).dot(100), np.array(y_total_memory).dot(0.001), 'bo--')
    plot.xlabel("95-quantile average relative accuracy (%)")
    plot.ylabel("Total memory occupation (Kb)")
    for b in args.bin_limit:
        ax.annotate("B={0}".format(b), xy = (final_stats[b]['average_quantile_accuracy'][0.95]*100, 0.001*final_stats[b]['total_memory']), textcoords='data')
    plot.show()

    fig = plot.figure()
    ax = fig.add_subplot(111)
    ax.plot(np.array(x_accuracy).dot(100), np.array(y_memory_efficiency).dot(100), 'bo--')
    plot.xlabel("95-quantile average relative accuracy (%)")
    plot.ylabel("Memory efficiency (%)")
    for b in args.bin_limit:
        ax.annotate("B={0}".format(b), xy = (final_stats[b]['average_quantile_accuracy'][0.95]*100, 100*final_stats[b]['occupied_memory']/final_stats[b]['total_memory']), textcoords='data')
    plot.show()

    print(final_stats)

    # alla fine dell'esperimento:
    # calcolo accuracy
    # TODO: calcolo long/short e big/small flows
    # sparsita (# bucket diversi da zero)

