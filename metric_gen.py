import pyshark
import pandas as pd
import numpy as np
from scipy.stats import skew, kurtosis, entropy
from collections import defaultdict
import os
from glob import glob

# Garantir que o diretório 'metricas' exista
print("Criando diretório 'metricas'...")
os.makedirs('metricas', exist_ok=True)

# Inicializar variáveis cumulativas
data = []

# Processar todos os arquivos na pasta 'arquivos-filtrados'
print("Processando arquivos na pasta 'arquivos-filtrados'...")
file_list = sorted(glob('arquivos-filtrados/*.pcap'))
for file in file_list:
    print(f"Processando arquivo: {file}")
    cap = pyshark.FileCapture(file)
    for pkt in cap:
        try:
            timestamp = float(pkt.sniff_timestamp)
            length = int(pkt.length)
            src = pkt.ip.src
            dst = pkt.ip.dst
            data.append([timestamp, length, src, dst])
        except AttributeError:
            continue
    cap.close()

# Criar DataFrame com todos os dados
print("Criando DataFrame com os dados capturados...")
df = pd.DataFrame(data, columns=['timestamp', 'length', 'src_ip', 'dst_ip'])
df.sort_values('timestamp', inplace=True)

# IPG (Inter-Packet Gap)
print("Calculando IPG (Inter-Packet Gap)...")
df['ipg'] = df['timestamp'].diff().fillna(0)
df.to_csv('metricas/ipg.csv', index=False)

# Tamanho médio dos pacotes por IP
print("Calculando tamanho médio dos pacotes por IP...")
df['time_bin'] = pd.to_datetime(df['timestamp'], unit='s').dt.floor('1Min')
packets_per_min = df.groupby(['time_bin', 'src_ip']).size().unstack(fill_value=0)
packets_per_min.to_csv('metricas/packets_per_min.csv')

# Burstness (medida de explosão de tráfego)
print("Calculando burstness...")
burstness = packets_per_min.max() / (packets_per_min.mean() + 1e-6)
burstness.to_csv('metricas/burstness.csv')

# Distribuição de pacotes por janelas de tempo
print("Calculando distribuição de pacotes por janelas de tempo...")
windowed = df.set_index(pd.to_datetime(df['timestamp'], unit='s')).resample('10s').size()
windowed.to_csv('metricas/windowed_packets.csv')

# CDF do tamanho de pacotes
print("Calculando CDF do tamanho de pacotes...")
sorted_len = np.sort(df['length'])
cdf = np.arange(len(sorted_len)) / float(len(sorted_len))
np.savetxt('metricas/cdf_packet_sizes.csv', np.column_stack((sorted_len, cdf)), delimiter=',', header='Packet Size,CDF', comments='')

# Skewness e Kurtosis do IPG
print("Calculando skewness e kurtosis do IPG...")
ipg_skew = skew(df['ipg'])
ipg_kurt = kurtosis(df['ipg'])
with open('metricas/ipg_stats.txt', 'w') as f:
    f.write(f"Skewness do IPG: {ipg_skew}\n")
    f.write(f"Kurtosis do IPG: {ipg_kurt}\n")

# Horizontal scan (muitos destinos únicos por IP)
print("Identificando IPs com muitos destinos únicos...")
unique_dests = df.groupby('src_ip')['dst_ip'].nunique().sort_values(ascending=False)
suspicious = unique_dests[unique_dests > 50]  # Threshold ajustável
suspicious.to_csv('metricas/suspicious_ips.csv')

# Top 10 IPs mais ativos (em número de pacotes enviados)
print("Calculando os top 10 IPs mais ativos...")
top_10_ips = df['src_ip'].value_counts().head(10)
top_10_ips.to_csv('metricas/top_10_ips.csv')

# IPG médio e desvio padrão por IP
print("Calculando IPG médio e desvio padrão por IP...")
df['prev_src'] = df['src_ip'].shift(1)
df['ipg_src'] = df['ipg'].where(df['src_ip'] == df['prev_src'])
ipg_stats = df.groupby('src_ip')['ipg_src'].agg(['mean', 'std']).fillna(0)
ipg_stats.to_csv('metricas/ipg_stats_per_ip.csv')

# Entropia da distribuição de IPs de origem
print("Calculando entropia da distribuição de IPs de origem...")
src_counts = df['src_ip'].value_counts()
src_probs = src_counts / src_counts.sum()
src_entropy = entropy(src_probs, base=2)
with open('metricas/src_entropy.txt', 'w') as f:
    f.write(f"Entropia dos IPs de origem: {src_entropy}\n")

# Volume total de bytes transmitidos por IP
print("Calculando volume total de bytes transmitidos por IP...")
bytes_per_ip = df.groupby('src_ip')['length'].sum().sort_values(ascending=False)
bytes_per_ip.to_csv('metricas/bytes_per_ip.csv')

# Variação de tráfego ao longo do tempo (janelas de 1s ou 5s)
print("Calculando variação de tráfego ao longo do tempo...")
df_time = df.set_index(pd.to_datetime(df['timestamp'], unit='s'))
packets_1s = df_time.resample('1s').size()
packets_5s = df_time.resample('5s').size()
packets_5s.to_csv('metricas/packets_5s.csv')

# Relação entre tamanho dos pacotes e frequência de envio
print("Calculando relação entre tamanho dos pacotes e frequência de envio...")
duration = df['timestamp'].max() - df['timestamp'].min()
df_freq = df.groupby('src_ip').agg({
    'length': 'mean',
    'timestamp': 'count'
}).rename(columns={'timestamp': 'packet_count'})
df_freq['pps'] = df_freq['packet_count'] / duration
df_freq[['length', 'pps']].to_csv('metricas/packet_size_frequency.csv')

# Identificação de padrões anômalos de comunicação
print("Identificando padrões anômalos de comunicação...")
bursts = defaultdict(list)
gaps = defaultdict(list)

for ip, group in df.groupby('src_ip'):
    times = group['timestamp'].sort_values().values
    ipg = np.diff(times)
    bursts[ip] = ipg[ipg < 0.01]
    gaps[ip] = ipg[ipg > 5]

suspicious_ips = {
    ip: {'bursts': len(bursts[ip]), 'long_gaps': len(gaps[ip])}
    for ip in df['src_ip'].unique()
    if len(bursts[ip]) > 10 or len(gaps[ip]) > 3
}

with open('metricas/suspicious_patterns.txt', 'w') as f:
    for ip, info in suspicious_ips.items():
        f.write(f"{ip} -> Bursts: {info['bursts']}, Long gaps: {info['long_gaps']}\n")

print("Execução concluída.")
