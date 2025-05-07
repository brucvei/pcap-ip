import pandas as pd
import matplotlib.pyplot as plt


# Função genérica para ler e plotar CSVs
def plot_csv(csv_path, x_column, y_column, title, output_path):
    df = pd.read_csv(csv_path)

    # Se não forem especificadas as colunas, usa as duas primeiras
    if not x_column or not y_column:
        x_column, y_column = df.columns[:2]

    # Cria o gráfico
    plt.figure(None, (10.0, 6.0))
    plt.plot(df[x_column], df[y_column], 'o-')
    plt.title(title if title else f'Gráfico de {y_column} vs {x_column}')
    plt.xlabel(x_column)
    plt.ylabel(y_column)
    plt.grid(True)

    # Salva a imagem se o caminho de saída for dado
    if output_path:
        plt.savefig(output_path)
    else:
        plt.show()

    plt.close()


# 1. Distribuição de pacotes por janelas de tempo
plot_csv(
    'metricas/windowed_packets.csv',
    'timestamp',
    '0',
    'Distribuição de Pacotes por Janela de Tempo',
    'metricas/windowed_packets.png'
)

# 2. Variação de tráfego ao longo do tempo
plot_csv(
    'metricas/packets_5s.csv',
    'timestamp',
    '0',
    'Variação de Tráfego em Intervalos de 5s',
    'metricas/packets_5s.png'
)

# 3. CDF do tamanho de pacotes
plot_csv(
    'metricas/cdf_packet_sizes.csv',
    'Packet Size',
    'CDF',
    'CDF do Tamanho de Pacotes',
    'metricas/cdf_packet_sizes.png'
)