import pyshark

cap = pyshark.FileCapture('arquivos-filtrados/parte_00000_20250112020000_ip.pcap')
# if len(cap) > 0:
for pkt in cap:
    # print(pkt)/
    # if pkt.ip.proto == 0 or pkt.ip.proto == 4:
    print(pkt)
    print("----------")
# else:
#     print("Nenhum pacote encontrado com o filtro especificado.")
