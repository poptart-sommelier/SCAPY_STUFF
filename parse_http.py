from scapy.all import *
from scapy.layers import http

ipcap = '/home/rich/Downloads/http/2018-06-30-traffic-analysis-exercise.pcap'

pkts = rdpcap(ipcap)

payload = []

sessions = pkts.sessions()

http_requests = []
http_responses = []

for session in sessions:
	http_request = ''
	http_response = ''
	for packet in sessions[session]:
		try:
			if packet[TCP].dport == 80 and packet.haslayer(http.HTTPRequest):
				http_request += str(packet[http.HTTP])
			if packet[TCP].sport == 80 and packet.haslayer(http.HTTPResponse):
				http_response += str(packet[http.HTTP])
		except:
			pass

	http_requests.append(http_request)
	http_responses.append(http_responses)

for htreq in http_requests:
	print("*" * 80)
	print(htreq)

for htresp in http_responses:
	print("*" * 80)
	print(htresp)
