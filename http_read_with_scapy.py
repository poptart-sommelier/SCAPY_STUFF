from scapy.all import *
import chardet
import string
import re

# tcpflow one liner for urls:
# tcpflow -c -r http.cap | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | sort | uniq

pcp = '/home/rich/Downloads/http.cap'

rgx = 'https?:\/\/[a-zA-Z0-9./?=_-]*'

pkts = rdpcap(pcp)

for pkt in pkts:
    # print(pkt[IP].src)
    # print(pkt[IP].dst)

    if pkt.haslayer('TCP'):
        if 'ethereal' in str(pkt[TCP]):
            # print(str(pkt[TCP]))
            try:
                encoding = chardet.detect(pkt[TCP].original)
                pkt_body_with_bad_chars = pkt[TCP].original.decode(encoding['encoding'])
                pkt_body = ''.join(filter(lambda x: x in string.printable, pkt_body_with_bad_chars))
                print(pkt_body.replace('\\n', '\n'))
                print('\n******************************************************************************************\n')
                print('\n'.join(re.findall(rgx, pkt_body)))
                print('\n******************************************************************************************\n')
            except UnicodeDecodeError as unierr:
                pkt_body_with_bad_chars = str(pkt[TCP].original)
                pkt_body = ''.join(filter(lambda x: x in string.printable, pkt_body_with_bad_chars))
                print(pkt_body.replace('\\n', '\n'))
                print('\n******************************************************************************************\n')
                print('\n'.join(re.findall(rgx, pkt_body)))
                print('\n******************************************************************************************\n')
