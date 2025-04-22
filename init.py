import pyshark
import pandas as pd

cap = pyshark.FileCapture('arquivos/parte_00000_20250112020000.pcap', display_filter='ip', keep_packets=False)

data = []

# Carregar pacotes IP com timestamp
for pkt in cap:
    try:
        timestamp = float(pkt.sniff_timestamp)
        length = int(pkt.length)
        src = pkt.ip.src
        dst = pkt.ip.dst
        data.append([timestamp, length, src, dst])
    except AttributeError:
        continue

df = pd.DataFrame(data, columns=['timestamp', 'length', 'src_ip', 'dst_ip'])
df.sort_values('timestamp', inplace=True)

# IPG (Inter-Packet Gap)
df['ipg'] = df['timestamp'].diff().fillna(0)


# Tamanho médio dos pacotes por IP
df['time_bin'] = pd.to_datetime(df['timestamp'], unit='s').dt.floor('1Min')
packets_per_min = df.groupby(['time_bin', 'src_ip']).size().unstack(fill_value=0)

# Distribuição temporal de pacotes por IP
df['time_bin'] = pd.to_datetime(df['timestamp'], unit='s').dt.floor('1Min')
packets_per_min = df.groupby(['time_bin', 'src_ip']).size().unstack(fill_value=0)

# Burstness (medida de explosão de tráfego)
burstness = packets_per_min.max() / (packets_per_min.mean() + 1e-6)

# Distribuição de pacotes por janelas de tempo
windowed = df.set_index(pd.to_datetime(df['timestamp'], unit='s')).resample('10S').size()
windowed.plot(title="Pacotes por Janela de 10s")

# CDF do tamanho de pacotes
import numpy as np
import matplotlib.pyplot as plt

sorted_len = np.sort(df['length'])
cdf = np.arange(len(sorted_len)) / float(len(sorted_len))
plt.plot(sorted_len, cdf)
plt.xlabel('Tamanho do Pacote')
plt.ylabel('CDF')
plt.grid()
plt.title('CDF dos Tamanhos de Pacote')

# Skewness e Kurtosis do IPG
from scipy.stats import skew, kurtosis

ipg_skew = skew(df['ipg'])
ipg_kurt = kurtosis(df['ipg'])

print("Skewness do IPG:", ipg_skew)
print("Kurtosis do IPG:", ipg_kurt)

# Horizontal scan (muitos destinos únicos por IP)
unique_dests = df.groupby('src_ip')['dst_ip'].nunique().sort_values(ascending=False)
suspicious = unique_dests[unique_dests > 50]  # Threshold ajustável
print(suspicious)

# Top 10 IPs mais ativos (em número de pacotes enviados)
top_10_ips = df['src_ip'].value_counts().head(10)
print(top_10_ips)

# IPG médio e desvio padrão por IP
df['ipg'] = df['timestamp'].diff().fillna(0)
df['prev_src'] = df['src_ip'].shift(1)
df['ipg_src'] = df['ipg'].where(df['src_ip'] == df['prev_src'])

ipg_stats = df.groupby('src_ip')['ipg_src'].agg(['mean', 'std']).fillna(0)
print(ipg_stats)

#  Entropia da distribuição de IPs de origem
from scipy.stats import entropy

src_counts = df['src_ip'].value_counts()
src_probs = src_counts / src_counts.sum()
src_entropy = entropy(src_probs, base=2)

print("Entropia dos IPs de origem:", src_entropy)

# Volume total de bytes transmitidos por IP
bytes_per_ip = df.groupby('src_ip')['length'].sum().sort_values(ascending=False)
print(bytes_per_ip.head(10))

# Variação de tráfego ao longo do tempo (janelas de 1s ou 5s)
df_time = df.set_index(pd.to_datetime(df['timestamp'], unit='s'))
packets_1s = df_time.resample('1S').size()
packets_5s = df_time.resample('5S').size()

packets_5s.plot(title="Pacotes por Janela de 5 segundos", xlabel='Tempo', ylabel='Nº de Pacotes')

# Relação entre tamanho dos pacotes e frequência de envio
# Agrupar por IP, tirando tamanho médio e taxa de envio (pacotes por segundo)
duration = df['timestamp'].max() - df['timestamp'].min()
df_freq = df.groupby('src_ip').agg({
    'length': 'mean',
    'timestamp': 'count'
}).rename(columns={'timestamp': 'packet_count'})

df_freq['pps'] = df_freq['packet_count'] / duration  # pacotes por segundo
print(df_freq[['length', 'pps']].head(10))

# Identificação de padrões anômalos de comunicação
# Detectar bursts e gaps por IP
from collections import defaultdict

bursts = defaultdict(list)
gaps = defaultdict(list)

for ip, group in df.groupby('src_ip'):
    times = group['timestamp'].sort_values().values
    ipg = np.diff(times)
    bursts[ip] = ipg[ipg < 0.01]  # Bursts: pacotes muito próximos
    gaps[ip] = ipg[ipg > 5]       # Silêncios: gaps maiores que 5s

# Exibir IPs com muitos bursts ou longos silêncios
suspicious_ips = {
    ip: {'bursts': len(bursts[ip]), 'long_gaps': len(gaps[ip])}
    for ip in df['src_ip'].unique()
    if len(bursts[ip]) > 10 or len(gaps[ip]) > 3
}

for ip, info in suspicious_ips.items():
    print(f"{ip} -> Bursts: {info['bursts']}, Long gaps: {info['long_gaps']}")

