import argparse
import numpy as np
from scapy.all import *
from scapy.layers.inet import UDP, TCP
import socket

# dictionary for flow packet counting
flows_packets = {}
flows_bytes = {}
# dictionary for flow interarrival stats
flows_interarrival_time = {}
# dictionary to keep record of last packet received + ts for each flow
flows_last_packet = {}
# list of packets
packet_list = []
# list of timestamps
packet_ts_list = []



def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


if __name__ == "__main__":
    argparser = argparse.ArgumentParser()
    # filename(s) argument
    argparser.add_argument("--file", help="PCAP file(s) to be parsed", type=str, nargs="*", required=True)
    # output directory argument
    argparser.add_argument("--output_dir", help="output directory", type=str, default="./")
    # output filename
    argparser.add_argument("--output_file", help="output filename", type=str, default="parsed_data.npy")
    # add interarrival time to packet (time from previous packet of the same flow)
    argparser.add_argument("--interarrival", help="save interarrival time", action='store_true')
    # add flow size
    argparser.add_argument("--flow_size", help="save flow size", action='store_true')
    # parse arguments
    args = argparser.parse_args()
    # assert all input files exists
    for file in args.file:
        assert os.path.exists(file), "Input file {0} doesn't exist".format(file)
    # assert output dir exists
    assert os.path.exists(args.output_dir), "Output dir {0} doesn't exist".format(args.output_dir)
    # iterate over input files and read
    # NOTE: if handling many consecutive traces, file must be fed in chronological order
    # from the oldest to the most recent trace
    for input_file in args.file:
        # lazy reader
        reader = PcapReader(input_file)
        for packet in reader: 
            if packet.version == 4: 
                if packet.haslayer(TCP):
                    #packet.show()
                    key = (packet.src, packet.dst, packet[TCP].sport, packet[TCP].dport)
                    packet_list.append(key)
                    packet_ts_list.append(packet.time)
                    # if I want to compute flow size
                    if args.flow_size:
                        if key in flows_packets:
                            flows_packets[key] += 1
                            flows_bytes[key] += len(packet)
                        else:
                            flows_packets[key] = 1
                            flows_bytes[key] = len(packet)
                    # if I want to compute interarrival time
                    if args.interarrival:
                        if key in flows_last_packet:
                            interarrival = packet.time - flows_last_packet[key]
                            # if already computed one interarrival time
                            if key in flows_interarrival_time:
                                flows_interarrival_time[key].append(interarrival)
                            else:
                                flows_interarrival_time[key] = [ interarrival ]
                            flows_last_packet[key] = packet.time
                        else:
                            flows_last_packet[key] = packet.time

    # DEBUG
    print("Finished parsing files")
    output = { 'x' : [], 'y' : [] }
    for packet, ts in zip(packet_list, packet_ts_list):
        print(packet,ts)
        output['x'].append(packet)
        output['y'].append(ts)
    np.save(os.path.join(args.output_dir, "timestamp_"+args.output_file), output)

    if flows_packets:
        # save as numpy array
        output = { 'x': [], 'y': [] }
        for key, value in flows_packets.items():
            output['x'].append(key)
            output['y'].append(value)
        np.save(os.path.join(args.output_dir, "flows_size_"+args.output_file), output)

    if flows_interarrival_time:
        # save as numpy array
        output = { 'x': [], 'y': [] }
        for key, time_list in flows_interarrival_time.items():
            for value in time_list:
                output['x'].append(key)
                output['y'].append(value)
        np.save(os.path.join(args.output_dir, "flows_interarrival_"+args.output_file), output)



