# Tratamento do arquivo pcap

``` powershell

editcap -c 10000000 arquivo.pcap parte.pcap
$saidaDir = ".\ips"


if (-not (Test-Path $saidaDir)) {
    New-Item -ItemType Directory -Path $saidaDir | Out-Null
}

Get-ChildItem -Filter "parte_*.pcap" | ForEach-Object {
    $inputFile = $_.FullName
    $outputFile = Join-Path $saidaDir "$($_.BaseName)_ip.pcap"

    Write-Host "Processando $inputFile -> $outputFile"
    tshark -r $inputFile -Y "ip.proto == 47" -w $outputFile
}

Write-Host "Concluído!"
```

# Métricas selecionadas

As métricas calculadas são salvas nos seguintes formatos:

- **IPG (Inter-Packet Gap):** Salvo em `metricas/ipg.csv`.
- **Tamanho médio dos pacotes por IP:** Salvo em `metricas/packets_per_min.csv`.
- **Distribuição temporal de pacotes por IP:** Salvo em `metricas/packets_per_min.csv`.
- **Burstness:** Salvo em `metricas/burstness.csv`.
- **Distribuição de pacotes por janelas de tempo:** Salvo em `metricas/windowed_packets.csv` e gráfico em `metricas/windowed_packets.png`.
- **CDF (Cumulative Distribution Function) do tamanho de pacotes:** Gráfico salvo em `metricas/cdf_packet_sizes.png`.
- **Skewness e Kurtosis do IPG:** Valores salvos em `metricas/ipg_stats.txt`.
- **IPs com número desproporcional de destinos únicos (horizontal scan):** Salvo em `metricas/suspicious_ips.csv`.
- **Top 10 IPs mais ativos:** Salvo em `metricas/top_10_ips.csv`.
- **IPG médio e desvio padrão por IP:** Salvo em `metricas/ipg_stats_per_ip.csv`.
- **Entropia da distribuição de IPs de origem:** Valor salvo em `metricas/src_entropy.txt`.
- **Volume total de bytes transmitidos por IP:** Salvo em `metricas/bytes_per_ip.csv`.
- **Variação de tráfego ao longo do tempo:** Salvo em `metricas/packets_5s.csv` e gráfico em `metricas/packets_5s.png`.
- **Relação entre tamanho dos pacotes e frequência de envio:** Salvo em `metricas/packet_size_frequency.csv`.
- **Identificação de padrões anômalos de comunicação:** Salvo em `metricas/suspicious_patterns.txt`.

`