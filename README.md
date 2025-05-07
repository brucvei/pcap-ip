# Trabalho 1 - Análise de Tráfego de Rede
## Bruna Caetano, Fabrício Thomas e Gustavo Freitas

# Processo de Tratamento e Geração de Métricas

O processo de tratamento dos arquivos PCAP e a geração das métricas seguem as etapas descritas abaixo:

1. **Divisão dos Arquivos PCAP**  
   Os arquivos PCAP originais são divididos em partes menores utilizando o comando `editcap`. Isso facilita o processamento de grandes volumes de dados.

2. **Filtragem de Pacotes**  
   Após a divisão, os pacotes são filtrados com base em critérios específicos (por exemplo, `ip.proto == 47`) usando o `tshark`. Os arquivos filtrados são salvos em um diretório específico.

3. **Extração de Dados**  
   Os pacotes filtrados são processados para extrair informações como timestamp, tamanho do pacote, IP de origem e IP de destino. Esses dados são organizados em um DataFrame para análise.

4. **Cálculo de Métricas**  
   No arquivo `metric_gen.py` foi gerados arquivos csv ou txt com as métricas selecionadas. Diversas métricas são calculadas a partir dos dados extraídos, incluindo:
   - **IPG (Inter-Packet Gap):** Intervalo entre pacotes consecutivos.
   - **Tamanho médio dos pacotes por IP:** Média do tamanho dos pacotes enviados por cada IP.
   - **Burstness:** Medida de explosão de tráfego.
   - **Entropia dos IPs de origem:** Quantifica a dispersão dos IPs de origem.
   - **Top 10 IPs mais ativos:** Identifica os IPs que enviaram mais pacotes.
   - **Padrões anômalos de comunicação:** Detecta bursts e longos períodos de silêncio.

5. **Geração de Gráficos**  
   No arquivo `graph_gen.py` foi gerados imagens dos gráficos das métricas em gráficos selecionados. Gráficos são criados para visualização de métricas específicas, como:
   - Distribuição de pacotes por janelas de tempo.
   - Variação de tráfego ao longo do tempo.
   - CDF (Cumulative Distribution Function) do tamanho dos pacotes.

6. **Dashboard Interativo**  
   No arquivo `main.py` foi gerado um dashboard interativo foi desenvolvido utilizando `Tkinter` para exibir as métricas e gráficos. Ele permite:
   - Visualizar tabelas de métricas.
   - Exibir gráficos gerados.
   - Ler arquivos de texto com informações detalhadas.

# Código para Divisão e Filtragem de Arquivos PCAP
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