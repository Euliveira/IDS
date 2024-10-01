import os
import socket
import psutil
import scapy.all as scapy
import time
import numpy as np
from sklearn.ensemble import IsolationForest
from win10toast import ToastNotifier  # Para exibir notificações na tela (no Windows)

# Inicializa o sistema de notificação (para Windows)
toaster = ToastNotifier()

# Função para capturar pacotes de rede
def capturar_pacotes(rede_interface="eth0"):
    pacotes = scapy.sniff(iface=rede_interface, count=100)
    return pacotes

# Função para monitorar o status do sistema (uso de CPU, memória, etc.)
def monitorar_sistema():
    uso_cpu = psutil.cpu_percent(interval=1)
    uso_memoria = psutil.virtual_memory().percent
    uso_disco = psutil.disk_usage('/').percent
    return [uso_cpu, uso_memoria, uso_disco]

# Verifica se o firewall está ativo
def verificar_firewall():
    firewall_status = os.system("netsh advfirewall show allprofiles state")
    if firewall_status == 0:
        print("Firewall ativo.")
        return True
    else:
        print("Firewall desativado!")
        return False

# Verifica portas abertas (potenciais vulnerabilidades)
def verificar_portas_abertas():
    portas_abertas = []
    for porta in range(20, 1025):  # Verifica as portas comuns
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        resultado = sock.connect_ex(('127.0.0.1', porta))
        if resultado == 0:
            portas_abertas.append(porta)
        sock.close()
    return portas_abertas

# Função de treinamento de IA para detecção de anomalias
def treinar_modelo(dados_treino):
    modelo = IsolationForest(contamination=0.01)
    modelo.fit(dados_treino)
    return modelo

# Função para detecção de anomalias
def detectar_anomalias(modelo, dados_atual):
    predicao = modelo.predict([dados_atual])
    if predicao == -1:
        return True  # Anomalia detectada
    return False

# Função principal de análise
def monitorar_rede_sistema():
    # Inicialmente, coletamos dados de rede e sistema por um período
    dados_treino = []
    print("Coletando dados iniciais para o modelo de IA...")

    # Coleta de dados de 100 ciclos para treinamento
    for _ in range(100):
        sistema_status = monitorar_sistema()
        dados_treino.append(sistema_status)
        time.sleep(1)

    # Treinamento do modelo
    modelo = treinar_modelo(dados_treino)

    print("Modelo treinado. Iniciando monitoramento em tempo real...")

    while True:
        # Verifica estado do firewall
        if not verificar_firewall():
            toaster.show_toast("IDS Alerta", "Firewall está desativado!", duration=5)
        
        # Verifica portas abertas
        portas_abertas = verificar_portas_abertas()
        if len(portas_abertas) > 0:
            print(f"Portas abertas detectadas: {portas_abertas}")
            toaster.show_toast("IDS Alerta", f"Portas abertas detectadas: {portas_abertas}", duration=5)
        
        # Monitora o status do sistema e rede
        sistema_status = monitorar_sistema()
        pacotes = capturar_pacotes()

        # Verifica anomalias no sistema
        if detectar_anomalias(modelo, sistema_status):
            print("Anomalia no sistema detectada!")
            toaster.show_toast("IDS Alerta", "Anomalia detectada no sistema!", duration=5)

        time.sleep(10)  # Aguarda um pouco antes de repetir a verificação

if __name__ == "__main__":
    monitorar_rede_sistema()
