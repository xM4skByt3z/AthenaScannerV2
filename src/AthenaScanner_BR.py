#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ferramenta de Segurança de Rede
==============================

Uma ferramenta completa para varredura de rede, detecção de vulnerabilidades e análise de arquivos maliciosos.
Desenvolvida para profissionais e entusiastas de segurança.

Funcionalidades:
- Varredura de rede e classificação de dispositivos
- Detecção de portas abertas e análise de serviços
- Validação de vulnerabilidades usando IA
- Detecção de arquivos maliciosos com VirusTotal
- Sistema de Detecção de Intrusão (IDS) com Snort
- Análise de syscalls para atividades suspeitas

Autor: xM4skByt3z
GitHub: https://github.com/xM4skByt3z
Licença: MIT
"""

import os
import time
import socket
import requests
import ipaddress
import netifaces as ni
import nmap
from scapy.all import ARP, Ether, srp, sr1, IP, ICMP
from rich.console import Console
from rich.spinner import Spinner
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from functools import wraps
import hashlib
import subprocess
from datetime import datetime

# Arte ASCII para a ferramenta
arte_ascii = """

⠀     ⠀⠀⠀     ⠀⠀⠀⠀⠀⠀⣀⣀⣠⣤⣤⣤⣦⣶⣤⣤⣤⣤⣤⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        ▄▀▀▀▄ ▀▀█▀▀ █   █ █▀▀▀▀ █▄  █ ▄▀▀▀▄ 
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣴⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        █▀▀▀█   █   █▀▀▀█ █▀▀   █ ▀▄█ █▀▀▀█ 
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣶⣿⣿⣿⣿⡿⠿⠛⠛⠉⠉⠁⠀⠀⣀⣀⣀⣀⡀⠀⠀⠀⠈⠉⠛⠛⠿⢿⣿⣿⣶⣤⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀        ▀   ▀   ▀   ▀   ▀ ▀▀▀▀▀ ▀   ▀ ▀   ▀ 
⠀⠲⢶⣶⣶⣶⣶⣿⣿⣿⠿⠿⠛⠋⠉⠀⠀⣀⣠⣤⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣦⣤⣀⠀⠀⠀⠉⠙⠻⠿⢿⣿⣷⣶⣦⣤⣤⣄⡄        ▄▀▀▀▀ ▄▀▀▀▀ ▄▀▀▀▄ █▄  █ █▄  █ █▀▀▀▀ █▀▀▀▄ 
⠀⠀⠀⠀⠉⠉⠉⠁⠀⠀⠀⠀⣀⣠⣴⣶⣿⣿⣿⠿⠿⠛⠋⣩⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⢿⣿⣶⣦⣄⣀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠁⠀         ▀▀▀▄ █     █▀▀▀█ █ ▀▄█ █ ▀▄█ █▀▀   █▀▀▀▄ 
⠀⠀⠀⠀⠀⠀⣀⣀⣤⣴⣶⣿⣿⣿⠿⠟⠋⠉⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠈⠉⠛⠿⢿⣿⣶⣶⣤⣄⣀⣀⣀⣀⡀⠀        ▀▀▀▀   ▀▀▀▀ ▀   ▀ ▀   ▀ ▀   ▀ ▀▀▀▀▀ ▀   ▀ 
⢰⣶⣶⣶⣾⣿⣿⣿⣿⠿⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠈⢉⣽⣿⣿⣿⣿⣿⣿⠃⠀        @xM4skByt3z - Deivid Kelven           v2.0
⢸⣿⡿⠛⠛⠻⢿⣿⣷⣦⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠀⠀⠀⠀⢀⣠⣴⣾⣿⠿⠛⠋⠁⠀⠀⠀⠀⠀        
⠘⠁⠀⠀⠀⠀⠀⠈⠛⠿⣿⣿⣿⣷⣦⣤⣄⣀⠀⠀⠀⠀⠀⠀⠈⠙⠻⠿⢿⣿⠿⠟⠛⠁⢀⣀⣤⣴⣾⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠻⠿⣿⣿⣿⣿⣷⣶⣶⣦⣤⣤⣤⣤⣤⣤⣤⣴⣶⣶⣿⣿⣿⣿⣿⠟⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠛⠛⠿⠿⠿⠿⠿⠿⠿⠿⠿⠟⠛⢋⣽⣿⡿⠏⠁⠀⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⠏⠁⠀⠀⠀⣿⣿⣧⡀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀        
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⠟⠁⠀⠀⠀⠀⠀⣿⣿⣿⣿⣷⣶⣶⣾⡟⠁⠀⠀⠀⠀        
⠀⠀⠀⠀⢀⣤⣴⣶⣶⣦⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⠋⠀⠀⠀⠀⠀⠀        
⠀⠀⠀⣴⣿⣿⠿⠛⠛⠻⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀        
⠀⠀⢰⣿⣿⠃⠀⣶⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀        
⠀⠀⢸⣿⣿⠀⠀⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        
⠀⠀⢸⣿⣿⡀⠀⠙⠿⠿⠿⠛⠁⠀⠀⠀⠀⠀⠀⢀⣤⣾⣿⡿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        
⠀⠀⠀⢿⣿⣿⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣾⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        
⠀⠀⠀⠀⠻⣿⣿⣿⣷⣶⣤⣤⣶⣶⣿⣿⣿⡿⠿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        
⠀⠀⠀⠀⠀⠀⠉⠙⠛⠛⠛⠛⠛⠛⠋⠉⠀

"""

# Exibe a arte ASCII usando lolcat
os.system(f'echo "{arte_ascii}" | lolcat')

# Inicializa o console com rich
console = Console()

# Cache para armazenar resultados da API de fabricantes de MAC
cache_fabricante_mac = {}

# Limitador de taxa para controlar o número de requisições por segundo
class LimitadorTaxa:
    def __init__(self, max_requisicoes, periodo):
        self.max_requisicoes = max_requisicoes
        self.periodo = periodo
        self.timestamps = []
        self.lock = threading.Lock()

    def __call__(self, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            with self.lock:
                agora = time.time()
                # Remove timestamps mais antigos que o período
                self.timestamps = [t for t in self.timestamps if agora - t < self.periodo]
                if len(self.timestamps) >= self.max_requisicoes:
                    # Espera até que o período expire
                    tempo_espera = self.periodo - (agora - self.timestamps[0])
                    time.sleep(tempo_espera)
                    # Atualiza a lista de timestamps
                    self.timestamps = self.timestamps[1:]
                self.timestamps.append(agora)
            return func(*args, **kwargs)
        return wrapper

# Aplica o limitador de taxa: 1 requisição a cada 2 segundos
limitador_taxa = LimitadorTaxa(max_requisicoes=1, periodo=2)

# Função para exibir um spinner de carregamento
def exibir_carregamento(mensagem):
    spinner = Spinner("dots", text=mensagem, style="bold blue")
    return console.status(spinner)

# Função para consultar o fabricante do endereço MAC com limitação de taxa
@limitador_taxa
def obter_fabricante_mac(mac):
    if mac in cache_fabricante_mac:
        return cache_fabricante_mac[mac]

    try:
        resposta = requests.get(f"https://api.macvendors.com/{mac}", timeout=5)
        if resposta.status_code == 200:
            fabricante = resposta.text
        else:
            fabricante = "Desconhecido"
    except requests.exceptions.RequestException:
        fabricante = "Desconhecido"

    cache_fabricante_mac[mac] = fabricante
    return fabricante

# Função para realizar uma varredura de rede
def varrer_rede():
    hostname = socket.gethostname()
    ip_local = socket.gethostbyname(hostname)
    interfaces = ni.interfaces()

    for interface in interfaces:
        try:
            enderecos = ni.ifaddresses(interface)
            if ni.AF_INET in enderecos:
                info_ip = enderecos[ni.AF_INET][0]
                endereco_ip = info_ip['addr']
                mascara = info_ip['netmask']

                if endereco_ip.startswith('127.'):
                    continue

                rede = ipaddress.IPv4Network(f"{endereco_ip}/{mascara}", strict=False)
                resultado = f"""
------------------ INFORMAÇÕES DA REDE ------------------

  Endereço IP      : {endereco_ip}
  Máscara          : {mascara}
  Rede             : {rede.network_address}
  Broadcast        : {rede.broadcast_address}
  HostMin          : {rede.network_address + 1}
  HostMax          : {rede.broadcast_address - 1}
  Hosts/Rede       : {rede.num_addresses - 2}  (Exclui rede e broadcast)

-----------------------------------------------------------
                """
                return resultado, rede
        except ValueError:
            continue

    return "Nenhuma interface de rede ativa encontrada.", None

# Função para identificar o sistema operacional com base no TTL
def obter_os_por_ttl(ttl):
    if ttl <= 64:
        return "[bold cyan]Linux  [/bold cyan]"
    elif ttl <= 128:
        return "[bold yellow]Windows[/bold yellow]"
    else:
        return "Desconhecido"

# Função para processar um único IP
def processar_ip(ip):
    requisicao_arp = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    requisicao_arp_broadcast = broadcast / requisicao_arp

    respostas, _ = srp(requisicao_arp_broadcast, timeout=2, verbose=False)

    if respostas:
        for enviado, recebido in respostas:
            ip = recebido.psrc
            mac = recebido.hwsrc
            fabricante = obter_fabricante_mac(mac)

            requisicao_icmp = IP(dst=ip) / ICMP()
            resposta_icmp = sr1(requisicao_icmp, timeout=2, verbose=False)

            if resposta_icmp:
                ttl = resposta_icmp.ttl
                os = obter_os_por_ttl(ttl)

                fabricante_minusculo = fabricante.lower()
                if "samsung" in fabricante_minusculo or "motorola" in fabricante_minusculo:
                    tipo_dispositivo = "Notebook"
                elif "epson" in fabricante_minusculo:
                    tipo_dispositivo = "Impressora"
                elif "huawei" in fabricante_minusculo:
                    tipo_dispositivo = "Roteador"
                elif "xiaomi" in fabricante_minusculo:
                    tipo_dispositivo = "Celular Android"
                elif "intelbras" in fabricante_minusculo:
                    tipo_dispositivo = "Câmera"
                elif "apple" in fabricante_minusculo:
                    tipo_dispositivo = "iPhone"
                elif "inpro" in fabricante_minusculo:
                    tipo_dispositivo = "Câmera IP"
                elif "intel" in fabricante_minusculo:
                    tipo_dispositivo = "Desktop"
                elif "del" in fabricante_minusculo:
                    tipo_dispositivo = "Notebook"
                elif "lenovo" in fabricante_minusculo:
                    tipo_dispositivo = "Notebook"
                else:
                    tipo_dispositivo = "Desktop"

                return ip, mac, fabricante, ttl, os, tipo_dispositivo

    return None

# Função para escanear portas abertas e serviços usando Nmap com decoy
def escanear_portas_com_nmap(ip_alvo):
    nm = nmap.PortScanner()
    decoys = "192.168.1.100,192.168.1.101"

    try:
        nm.scan(ip_alvo, arguments=f"-D {decoys} --open --top-ports=100 -T4 -sV --host-timeout 2m")

        if ip_alvo in nm.all_hosts():
            info_portas = {}
            for protocolo in nm[ip_alvo].all_protocols():
                portas = nm[ip_alvo][protocolo].keys()
                for porta in portas:
                    estado = nm[ip_alvo][protocolo][porta]['state']
                    if estado == "open":
                        servico = nm[ip_alvo][protocolo][porta]['name']
                        produto = nm[ip_alvo][protocolo][porta]['product']
                        versao = nm[ip_alvo][protocolo][porta]['version']
                        info_portas[porta] = f"{servico} {versao}".strip()
            return info_portas
        else:
            return None
    except Exception as e:
        console.print(f"[bold red]Erro ao escanear {ip_alvo}: {e}[/bold red]")
        return None

# Função para validar vulnerabilidades usando a API do Gemini
def validar_vulnerabilidade(ip, porta, servico):
    # Serviços que não devem ser considerados vulneráveis por padrão
    servicos_nao_vulneraveis = ["tcpwrapped", "unknown", "generic"]

    if any(non_vuln in servico.lower() for non_vuln in servicos_nao_vulneraveis):
        return f"""
IP: {ip}
Porta: {porta}
Status: aberta
Serviço: {servico}
Sistema Operacional: Linux
✅ O serviço {servico} não é vulnerável.
"""

    # Verifica se o serviço tem uma versão específica
    if " " not in servico:  # Se não houver versão no nome do serviço
        return f"""
IP: {ip}
Porta: {porta}
Status: aberta
Serviço: {servico}
Sistema Operacional: Linux
✅ O serviço {servico} não é vulnerável (versão não especificada).
"""

    chave_api = "SUA CHAVE API!" #ADICIONE SUA CHAVE API AQUI!!
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={chave_api}"
    headers = {'Content-Type': 'application/json'}
    dados = {
        "contents": [{
            "parts": [{
                "text": f"com base na versão do serviço {servico} na porta {porta} do IP {ip} é vulnerável. Forneça uma resposta direta: 'Sim, é vulnerável' ou 'Não, não é vulnerável'. Se for vulnerável, liste CVEs conhecidos, métodos de exploração, impacto e mitigação de forma organizada e com poucos emojis"
            }]
        }]
    }

    try:
        resposta = requests.post(url, headers=headers, json=dados, timeout=10)  # Timeout de 10 segundos
        if resposta.status_code == 200:
            resultado = resposta.json()
            if "candidates" in resultado and len(resultado["candidates"]) > 0:
                texto = resultado["candidates"][0]["content"]["parts"][0]["text"]
                if "sim, é vulnerável" in texto.lower():
                    return f"""
IP: {ip}
Porta: {porta}
Status: aberta
Serviço: {servico}
Sistema Operacional: Linux
[bold yellow]⚠ O serviço {servico} é vulnerável![/bold yellow]

🔍 **Detalhes da vulnerabilidade:**
{texto}
"""
                else:
                    return f"""
IP: {ip}
Porta: {porta}
Status: aberta
Serviço: {servico}
Sistema Operacional: Linux
✅ O serviço {servico} não é vulnerável.
"""
        return f"""
IP: {ip}
Porta: {porta}
Status: aberta
Serviço: {servico}
Sistema Operacional: Linux
❌ Não foi possível validar a vulnerabilidade.
"""
    except requests.exceptions.Timeout:
        return f"""
IP: {ip}
Porta: {porta}
Status: aberta
Serviço: {servico}
Sistema Operacional: Linux
❌ Validação de vulnerabilidade expirada.
"""
    except Exception as e:
        return f"""
IP: {ip}
Porta: {porta}
Status: aberta
Serviço: {servico}
Sistema Operacional: Linux
❌ Erro ao validar vulnerabilidade: {e}
"""

# Função para realizar uma varredura ARP e classificar dispositivos
def varrer_arp_e_classificar(ip_alvo):
    rede = ipaddress.IPv4Network(ip_alvo, strict=False)
    lista_ips = [str(ip) for ip in rede.hosts()]

    dispositivos = []

    with exibir_carregamento("Realizando varredura ARP..."):
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(processar_ip, ip) for ip in lista_ips]

            for future in as_completed(futures):
                resultado = future.result()
                if resultado:
                    ip, mac, fabricante, ttl, os, tipo_dispositivo = resultado
                    dispositivos.append(f"{'=' * 90}")
                    dispositivos.append(f" IP: {ip:<15} | MAC: {mac:<20}    | Fabricante: {fabricante}")
                    dispositivos.append(f" TTL: {ttl:<3}            | Sistema Operacional: {os:<10}    | Tipo: {tipo_dispositivo}")
                    dispositivos.append(f"{'-' * 90}")

    if dispositivos:
        console.print("\n".join(dispositivos), style="bold white")
    else:
        console.print("[bold red]Nenhum host encontrado.[/bold red]\n")

    console.print("\n[bold white]Iniciando escaneamento de portas abertas nos hosts encontrados...[/bold white]\n")

    portas_hosts = {}

    with exibir_carregamento("Escaneando portas abertas..."):
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(escanear_portas_com_nmap, ip): ip for ip in [d.split("|")[0].split(":")[1].strip() for d in dispositivos if "IP:" in d]}

            for future in as_completed(futures):
                ip = futures[future]
                try:
                    info_portas = future.result()
                    if info_portas:
                        portas_hosts[ip] = info_portas
                        console.print(f"[bold green]Escaneamento concluído para {ip}[/bold green]")
                except Exception as e:
                    console.print(f"[bold red]Erro ao escanear {ip}: {e}[/bold red]")

    return portas_hosts

# Função para verificar arquivos maliciosos usando a API do VirusTotal
def verificar_arquivo_malicioso(chave_api):
    """
    Verifica se um arquivo é malicioso usando a API do VirusTotal.

    :param chave_api: Chave da API do VirusTotal.
    """
    # Solicita ao usuário o caminho do arquivo
    caminho_arquivo = input("Digite o caminho completo do arquivo que deseja verificar: ")

    # Verifica se o arquivo existe
    try:
        with open(caminho_arquivo, 'rb') as arquivo:
            # Calcula o hash SHA-256 do arquivo
            hash_sha256 = hashlib.sha256(arquivo.read()).hexdigest()
    except FileNotFoundError:
        console.print("[bold red]Arquivo não encontrado. Verifique o caminho e tente novamente.[/bold red]")
        return
    except Exception as e:
        console.print(f"[bold red]Erro ao abrir o arquivo: {e}[/bold red]")
        return

    # Verifica se o arquivo já foi analisado anteriormente
    url_relatorio = 'https://www.virustotal.com/vtapi/v2/file/report'
    parametros = {'apikey': chave_api, 'resource': hash_sha256}

    try:
        resposta = requests.get(url_relatorio, params=parametros)
        resposta.raise_for_status()  # Lança uma exceção para códigos de status HTTP inválidos
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]Erro ao conectar ao VirusTotal: {e}[/bold red]")
        return

    if resposta.status_code == 200:
        resultado = resposta.json()
        if resultado.get('response_code') == 1:
            # O arquivo já foi analisado, exibe o resultado
            console.print(f"[bold green]Resultado da análise:[/bold green]")
            console.print(f"Arquivo: {caminho_arquivo}")
            console.print(f"Hash SHA-256: {hash_sha256}")
            console.print(f"Detecções: {resultado['positives']}/{resultado['total']}")
            if resultado['positives'] > 0:
                console.print("[bold red]Arquivo malicioso detectado![/bold red]")
                # Organiza e exibe informações detalhadas
                console.print("\n[bold yellow]🔍 Informações Detalhadas:[/bold yellow]")
                console.print(f"Primeira Submissão: {resultado.get('scan_date', 'N/A')}")
                console.print(f"Última Análise: {resultado.get('last_analysis_date', 'N/A')}")
                console.print(f"Tamanho do Arquivo: {resultado.get('size', 'N/A')} bytes")
                console.print(f"Tipo do Arquivo: {resultado.get('type', 'N/A')}")
                console.print(f"Magic: {resultado.get('magic', 'N/A')}")
                console.print("\n[bold cyan]📊 Detalhes das Detecções:[/bold cyan]")
                for scanner, scan_result in resultado.get('scans', {}).items():
                    if scan_result.get('detected'):
                        console.print(f"  - {scanner}: {scan_result.get('result', 'N/A')}")
            else:
                console.print("[bold green]Arquivo seguro.[/bold green]")
        else:
            # O arquivo não foi analisado anteriormente, submete para análise
            console.print("[bold yellow]Arquivo não analisado anteriormente. Submetendo para análise...[/bold yellow]")
            try:
                arquivos = {'file': (caminho_arquivo, open(caminho_arquivo, 'rb'))}
                parametros = {'apikey': chave_api}
                resposta = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=arquivos, params=parametros)
                resposta.raise_for_status()

                if resposta.status_code == 200:
                    console.print("[bold green]Arquivo submetido com sucesso para análise.[/bold green]")
                    console.print(f"ID da Análise: {resposta.json()['scan_id']}")
                else:
                    console.print("[bold red]Erro ao submeter o arquivo para análise.[/bold red]")
            except requests.exceptions.RequestException as e:
                console.print(f"[bold red]Erro ao submeter o arquivo para análise: {e}[/bold red]")
            except Exception as e:
                console.print(f"[bold red]Erro inesperado: {e}[/bold red]")
    else:
        console.print("[bold red]Erro ao verificar o arquivo.[/bold red]")

# Função para instalar o Snort silenciosamente
def instalar_snort():
    if not os.path.exists("/usr/local/bin/snort"):
        try:
            subprocess.run(["sudo", "apt-get", "update"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["sudo", "apt-get", "install", "-y", "snort"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # Baixa regras adicionais para malware, ransomware, DDoS, etc.
            subprocess.run(["sudo", "wget", "-O", "/etc/snort/rules/emerging-all.rules", "https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-all.rules"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["sudo", "sed", "-i", "s|^# include \\$RULE_PATH/emerging-all.rules|include \\$RULE_PATH/emerging-all.rules|", "/etc/snort/snort.conf"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            console.print("[bold red]Falha ao instalar ou configurar o Snort.[/bold red]")
            return False
    return True

# Função para iniciar o IDS do Snort com regras aprimoradas
def iniciar_ids_snort():
    if not instalar_snort():
        return

    console.print("[bold cyan]Iniciando IDS...[/bold cyan]")
    time.sleep(1)

    # Configuração básica do Snort
    config_snort = "/etc/snort/snort.conf"
    if not os.path.exists(config_snort):
        console.print(f"[bold red]Arquivo de configuração do Snort não encontrado em {config_snort}.[/bold red]")
        return

    # Adiciona regras personalizadas para detectar várias ameaças
    regras_personalizadas = """
    # Regras para detectar reverse shells em várias portas
    alert tcp any any -> any 4444 (msg:"Possível Reverse Shell Detectado na Porta 4444"; sid:1000002; rev:1;)
    alert tcp any any -> any 5555 (msg:"Possível Reverse Shell Detectado na Porta 5555"; sid:1000003; rev:1;)
    alert tcp any any -> any 6666 (msg:"Possível Reverse Shell Detectado na Porta 6666"; sid:1000004; rev:1;)

    # Regras para detectar DDoS
    alert udp any any -> any any (msg:"Possível Ataque DDoS - Tráfego UDP Alto"; threshold:type both, track by_src, count 100, seconds 10; sid:1000005; rev:1;)

    # Regras para detectar portscan
    alert tcp any any -> any any (msg:"Possível Port Scan Detectado"; detection_filter:track by_src, count 20, seconds 10; sid:1000006; rev:1;)

    # Regras para detectar ICMP ping flood
    alert icmp any any -> any any (msg:"Possível ICMP Ping Flood Detectado"; threshold:type both, track by_src, count 50, seconds 5; sid:1000007; rev:1;)

    # Regras para detectar exploits
    alert tcp any any -> any any (msg:"Possível Tentativa de Exploit"; content:"|90 90 90 90|"; sid:1000008; rev:1;)

    # Regras para detectar ransomwares
    alert tcp any any -> any any (msg:"Possível Conexão C2 de Ransomware"; content:"ransom"; nocase; sid:1000009; rev:1;)

    # Regras para detectar comandos suspeitos
    alert tcp any any -> any any (msg:"Possível Execução de Comando Suspeito"; content:"|2f 62 69 6e 2f 73 68|"; nocase; sid:1000010; rev:1;)
    """
    with open("/etc/snort/rules/local.rules", "w") as f:
        f.write(regras_personalizadas)

    # Comando para iniciar o Snort em modo de monitoramento com regras aprimoradas
    comando_snort = f"sudo snort -A console -q -c {config_snort} -i {ni.gateways()['default'][ni.AF_INET][1]}"

    try:
        console.print("[bold green]IDS está em execução. Monitorando tráfego de rede...[/bold green]")
        console.print("[bold yellow]Pressione Ctrl+C para parar o IDS.[/bold yellow]")
        os.system(comando_snort)
    except KeyboardInterrupt:
        console.print("[bold red]IDS parado.[/bold red]")
    except Exception as e:
        console.print(f"[bold red]Erro ao iniciar o IDS: {e}[/bold red]")

# Função para analisar syscalls usando auditd
def analisar_syscalls():
    console.print("[bold cyan]Iniciando análise de syscalls...[/bold cyan]")
    time.sleep(1)

    # Instala o auditd se não estiver instalado
    if not os.path.exists("/usr/sbin/auditd"):
        console.print("[bold yellow]auditd não encontrado. Instalando...[/bold yellow]")
        subprocess.run(["sudo", "apt-get", "install", "-y", "auditd"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Configura regras de auditoria para syscalls suspeitos
    regras_auditoria = """
    # Monitora a execução de comandos suspeitos
    -a always,exit -F arch=b64 -S execve -k comandos_suspeitos

    # Monitora o acesso a arquivos sensíveis
    -a always,exit -F path=/etc/passwd -F perm=rw -k arquivos_sensiveis
    """
    with open("/etc/audit/rules.d/syscall.rules", "w") as f:
        f.write(regras_auditoria)

    # Reinicia o auditd para aplicar as novas regras
    subprocess.run(["sudo", "service", "auditd", "restart"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    console.print("[bold green]Análise de syscalls em execução. Monitorando chamadas de sistema...[/bold green]")
    console.print("[bold yellow]Pressione Ctrl+C para parar a análise de syscalls.[/bold yellow]")

    try:
        # Exibe logs de auditoria em tempo real
        os.system("sudo ausearch -k comandos_suspeitos | aureport -i")
    except KeyboardInterrupt:
        console.print("[bold red]Análise de syscalls parada.[/bold red]")
    except Exception as e:
        console.print(f"[bold red]Erro ao analisar syscalls: {e}[/bold red]")

# Função para perguntar ao usuário se deseja salvar os logs
def perguntar_salvar_logs():
    salvar_logs = input("Deseja salvar os logs? (s/n): ").strip().lower()
    return salvar_logs == 's'

# Função para salvar logs em um arquivo
def salvar_logs(conteudo_log, tipo_log):
    # Cria o diretório de logs se não existir
    diretorio_logs = "logs"
    if not os.path.exists(diretorio_logs):
        os.makedirs(diretorio_logs)

    # Cria subdiretório para o tipo de log
    diretorio_tipo = os.path.join(diretorio_logs, tipo_log)
    if not os.path.exists(diretorio_tipo):
        os.makedirs(diretorio_tipo)

    # Cria um arquivo de log com timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    arquivo_log = os.path.join(diretorio_tipo, f"{timestamp}.log")

    # Escreve o conteúdo do log no arquivo
    with open(arquivo_log, "w") as f:
        f.write(conteudo_log)

    console.print(f"[bold green]Logs salvos em: {arquivo_log}[/bold green]")

# Função principal
def main():
    chave_api = 'SUA CHAVE!'  # Substitua pela sua chave da API do VirusTotal

    # Exibe o menu inicial
    console.print("1 - Varredura de Vulnerabilidades", style="bold white")
    time.sleep(0.1)
    console.print("2 - Sistema de Monitoramento (IDS)", style="bold white")
    time.sleep(0.1)
    console.print("3 - Verificador de Arquivos Maliciosos", style="bold white")
    time.sleep(0.1)
    console.print("4 - Analisar Syscalls", style="bold white")
    time.sleep(0.1)

    opcao = input("Digite uma opção: ")

    if opcao == "1":
        console.print("[bold cyan]Você selecionou a opção 1 - Varredura de Vulnerabilidades[/bold cyan]")
        time.sleep(0.5)
        console.print("\n[bold white]Coletando informações da rede...[/bold white]")
        time.sleep(1.5)
        resultado_varredura, rede = varrer_rede()
        console.print(resultado_varredura)
        time.sleep(0.5)

        if rede:
            ip_alvo = f"{rede.network_address}/{rede.prefixlen}"
            console.print(f"\n[bold white]Realizando varredura ARP para:[/bold white] {ip_alvo}\n")
            portas_hosts = varrer_arp_e_classificar(ip_alvo)

            console.print("\n[bold green]Resultado do escaneamento de portas abertas:[/bold green]")
            conteudo_log = ""
            for ip, portas in portas_hosts.items():
                console.print(f"\n[bold cyan]{ip}:[/bold cyan]")
                conteudo_log += f"\n{ip}:\n"
                for porta, servico in portas.items():
                    status_vulnerabilidade = validar_vulnerabilidade(ip, porta, servico)
                    console.print(status_vulnerabilidade)
                    conteudo_log += status_vulnerabilidade + "\n"

            if perguntar_salvar_logs():
                salvar_logs(conteudo_log, "varredura_vulnerabilidades")
        else:
            console.print("[bold red]Não foi possível determinar a rede para escaneamento.[/bold red]")
    elif opcao == "2":
        console.print("[bold cyan]Você selecionou a opção 2 - Sistema de Monitoramento (IDS)[/bold cyan]")
        iniciar_ids_snort()  # Chama a função para iniciar o IDS do Snort
    elif opcao == "3":
        console.print("[bold cyan]Você selecionou a opção 3 - Verificador de Arquivos Maliciosos[/bold cyan]")
        verificar_arquivo_malicioso(chave_api)
    elif opcao == "4":
        console.print("[bold cyan]Você selecionou a opção 4 - Analisar Syscalls[/bold cyan]")
        analisar_syscalls()
    else:
        console.print("[bold red]Opção inválida[/bold red]")

# Executa o programa
if __name__ == "__main__":
    main()
