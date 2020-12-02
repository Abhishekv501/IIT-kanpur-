from sys import argv
import dpkt
import socket


def detect_anomaly(packet_capture):
    """
    Process a dpkt packet capture to determine if any syn scan is detected. For every IP address address that are
    detected as suspicious. We define "suspicious" as having sent more than three times as many SYN packets as the
    number of SYN+ACK packets received.
    :param packet_capture: dpkt packet capture object for processing
    """
    ip_syn = {}
    ip_syn_ack = {}
    count = 0
    for timestamp, buf in packet_capture:
    	count = count + 1
    	print("Packet count :"+str(count))
    	try:
		eth = dpkt.ethernet.Ethernet(buf)
		if not isinstance(eth.data, dpkt.ip.IP):
			continue
		ip = eth.data
		if ip.p==dpkt.ip.IP_PROTO_TCP:
			src = socket.inet_ntoa(ip.src)
			dst = socket.inet_ntoa(ip.dst)
			tcp = ip.data
			syn_count = 0 
			syn_ack_count = 0
			if ((tcp.flags & dpkt.tcp.TH_SYN) and (tcp.flags & dpkt.tcp.TH_ACK)):
				if src in ip_syn_ack.keys():
					syn_ack_count  = ip_syn_ack[src]
				syn_ack_count = syn_ack_count + 1
				ip_syn_ack[src] = syn_ack_count
			elif (tcp.flags & dpkt.tcp.TH_SYN):
				if src in ip_syn.keys():
					syn_count  = ip_syn[src]
				syn_count = syn_count + 1
				ip_syn[src] = syn_count
	except:
		pass
    print("IP Addresses performing scan are as follows:")
    for skey in ip_syn.keys():
    	syncount = 0
    	synackcount = 0
    	syncount = ip_syn[skey]
    	if skey in  ip_syn_ack.keys():
	    synackcount = ip_syn_ack[skey]
	syn_check = synackcount * 3
	if syncount > syn_check:
		print(skey)

# parse the command line argument and open the file specified
if __name__ == '__main__':
    if len(argv) != 2:
        print('usage: python detector.py capture.pcap')
        exit(-1)

    with open(argv[1], 'rb') as f:
        pcap_obj = dpkt.pcap.Reader(f)
        detect_anomaly(pcap_obj)

