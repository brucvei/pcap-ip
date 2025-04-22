import pyshark

cap = pyshark.FileCapture('arquivos/parte_00000_20250112020000.pcap', display_filter='ip', keep_packets=False)
for pkt in cap:
    # print(pkt)/
    if pkt.ip.proto == 0 or pkt.ip.proto == 4:
        print(pkt)
        print("----------")
