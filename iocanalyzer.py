#!/usr/bin/env python3

import os
import sys
import subprocess
import re
import json
import time
import random
import webbrowser
from typing import Dict, List, Any, Optional
from configparser import ConfigParser
from datetime import datetime
import requests
from colorama import init, Fore, Style
from jinja2 import Template

# Inicialización de colorama
init(autoreset=True)

# Configuración global
CONFIG_FILE = 'config.ini'
config = ConfigParser()

def load_config():
    """Carga la configuración desde el archivo config.ini."""
    if os.path.exists(CONFIG_FILE):
        config.read(CONFIG_FILE)
    else:
        config['DEFAULT'] = {'vt_api_key': ''}
    
    if not config['DEFAULT'].get('vt_api_key'):
        config['DEFAULT']['vt_api_key'] = input(f"{Fore.GREEN}[?] Ingrese su API key de VirusTotal: {Style.RESET_ALL}").strip()
    
    save_config()
    print(f"{Fore.GREEN}[+] Configuración cargada y actualizada.{Style.RESET_ALL}")

def save_config():
    """Guarda la configuración en el archivo config.ini."""
    with open(CONFIG_FILE, 'w') as configfile:
        config.write(configfile)

def install_prerequisites():
    """Instala los prerrequisitos necesarios en Kali Linux."""
    print(f"\n{Fore.YELLOW}[*] Iniciando instalación de prerrequisitos...{Style.RESET_ALL}")
    
    if os.geteuid() != 0:
        print(f"{Fore.RED}[!] Este script necesita privilegios de superusuario para instalar paquetes.{Style.RESET_ALL}")
        print(f"{Fore.RED}[!] Por favor, ejecute el script con 'sudo python3 nombre_del_script.py'{Style.RESET_ALL}")
        return

    try:
        # Actualizar la lista de paquetes
        subprocess.run(["apt", "update"], check=True)

        # Lista de paquetes a instalar
        packages = [
            "python3-pip",
            "python3-colorama",
            "python3-requests",
            "python3-jinja2"
        ]

        # Instalar paquetes
        for package in packages:
            print(f"{Fore.CYAN}[*] Instalando {package}...{Style.RESET_ALL}")
            subprocess.run(["apt", "install", "-y", package], check=True)

        print(f"{Fore.GREEN}[+] Instalación de prerrequisitos completada.{Style.RESET_ALL}")

    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}[!] Error durante la instalación: {e}{Style.RESET_ALL}")
        return

    # Solicitar información adicional
    config['DEFAULT']['vt_api_key'] = input(f"{Fore.GREEN}[?] Ingrese su API key de VirusTotal: {Style.RESET_ALL}").strip()
    
    save_config()
    print(f"{Fore.GREEN}[+] Configuración guardada.{Style.RESET_ALL}")

def classify_ioc(ioc: str) -> Optional[str]:
    """Clasifica el tipo de IOC."""
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    domain_pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    md5_pattern = r'^[a-fA-F0-9]{32}$'
    sha1_pattern = r'^[a-fA-F0-9]{40}$'
    sha256_pattern = r'^[a-fA-F0-9]{64}$'

    if re.match(ip_pattern, ioc):
        return 'ip'
    elif re.match(domain_pattern, ioc):
        return 'domain'
    elif re.match(md5_pattern, ioc):
        return 'hash'
    elif re.match(sha1_pattern, ioc):
        return 'hash'
    elif re.match(sha256_pattern, ioc):
        return 'hash'
    return None

def query_virustotal(api_key: str, ioc: str, ioc_type: str) -> Dict[str, Any]:
    """Consulta VirusTotal para obtener información sobre el IOC."""
    base_url = 'https://www.virustotal.com/api/v3/'
    headers = {'x-apikey': api_key}

    if ioc_type == 'ip':
        url = f'{base_url}ip_addresses/{ioc}'
    elif ioc_type == 'domain':
        url = f'{base_url}domains/{ioc}'
    else:  # hash
        url = f'{base_url}files/{ioc}'

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json().get('data', {}).get('attributes', {})
        
        result = {
            'type': ioc_type,
            'ioc': ioc,
            'last_analysis_date': data.get('last_analysis_date'),
            'last_analysis_stats': data.get('last_analysis_stats', {}),
            'last_analysis_results': data.get('last_analysis_results', {})
        }
        
        if ioc_type in ['ip', 'domain']:
            result.update({
                'country': data.get('country', 'N/A'),
                'as_owner': data.get('as_owner', 'N/A'),
                'asn': data.get('asn', 'N/A')
            })
        elif ioc_type == 'hash':
            result.update({
                'type_description': data.get('type_description', 'N/A'),
                'magic': data.get('magic', 'N/A'),
                'size': data.get('size', 'N/A'),
                'file_type': data.get('file_type', 'N/A'),
                'mitre_attack': data.get('popular_threat_classification', {}).get('mitre_attack', []),
            })
        
        return result
    except requests.RequestException as e:
        print(f"{Fore.RED}[!] Error al consultar VirusTotal: {str(e)}{Style.RESET_ALL}")
        return {'error': str(e), 'type': ioc_type, 'ioc': ioc}

def generate_html_report(results: List[Dict[str, Any]]) -> str:
    """Genera un informe HTML interactivo con los resultados del análisis de IOCs."""
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Informe de Análisis de IOCs</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; }
            h1 { color: #2c3e50; }
            .ioc-card { border: 1px solid #ddd; border-radius: 8px; padding: 15px; margin-bottom: 20px; }
            .ioc-header { display: flex; justify-content: space-between; align-items: center; }
            .danger-level { font-weight: bold; }
            .danger-low { color: green; }
            .danger-medium { color: orange; }
            .danger-high { color: red; }
            .danger-error { color: gray; }
            .details { display: none; margin-top: 10px; }
            .show-details { cursor: pointer; color: blue; text-decoration: underline; }
            table { width: 100%; border-collapse: collapse; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
        </style>
    </head>
    <body>
        <h1>Informe de Análisis de IOCs</h1>
        {% for result in results %}
            <div class="ioc-card">
                <div class="ioc-header">
                    <h2>{{ result['ioc'] }} ({{ result['type'] }})</h2>
                    <span class="danger-level danger-{{ result['danger_level'] }}">
                        {{ result['danger_symbol'] }} {{ result['danger_level'] | capitalize }}
                    </span>
                </div>
                <p>Detectado por {{ result['detected_by'] }} de {{ result['total_engines'] }} motores</p>
                <p>Última fecha de análisis: {{ result['last_analysis_date'] }}</p>
                <span class="show-details" onclick="toggleDetails('{{ result['ioc'] }}')">Mostrar detalles</span>
                <div id="{{ result['ioc'] }}" class="details">
                    <h3>Detalles adicionales:</h3>
                    <table>
                        {% for key, value in result['additional_info'].items() %}
                            <tr>
                                <th>{{ key }}</th>
                                <td>{{ value }}</td>
                            </tr>
                        {% endfor %}
                    </table>
                    {% if result['malicious_engines'] %}
                        <h3>Motores que lo detectaron como malicioso:</h3>
                        <ul>
                            {% for engine, data in result['malicious_engines'].items() %}
                                <li>{{ engine }}: {{ data['result'] }}</li>
                            {% endfor %}
                        </ul>
                    {% endif %}
                </div>
            </div>
        {% endfor %}
        <script>
            function toggleDetails(iocId) {
                var details = document.getElementById(iocId);
                if (details.style.display === "none" || details.style.display === "") {
                    details.style.display = "block";
                } else {
                    details.style.display = "none";
                }
            }
        </script>
    </body>
    </html>
    """
    
    for result in results:
        if 'error' in result:
            result['danger_level'] = 'error'
            result['danger_symbol'] = '❌'
            result['detected_by'] = 'N/A'
            result['total_engines'] = 'N/A'
            result['last_analysis_date'] = 'N/A'
            result['additional_info'] = {'Error': result['error']}
            result['malicious_engines'] = {}
        else:
            malicious_count = result['last_analysis_stats'].get('malicious', 0)
            total_engines = sum(result['last_analysis_stats'].values())
            
            if malicious_count >= 10:
                result['danger_level'] = 'high'
                result['danger_symbol'] = '🚨'
            elif 5 <= malicious_count < 10:
                result['danger_level'] = 'medium'
                result['danger_symbol'] = '⚠️'
            else:
                result['danger_level'] = 'low'
                result['danger_symbol'] = '✅'
            
            result['detected_by'] = malicious_count
            result['total_engines'] = total_engines
            result['last_analysis_date'] = datetime.fromtimestamp(result['last_analysis_date']).strftime('%Y-%m-%d %H:%M:%S') if result.get('last_analysis_date') else 'N/A'
            
            result['additional_info'] = {}
            if result['type'] in ['ip', 'domain']:
                result['additional_info'].update({
                    'País': result.get('country', 'N/A'),
                    'AS Number': result.get('asn', 'N/A'),
                    'AS Label': result.get('as_owner', 'N/A')
                })
            elif result['type'] == 'hash':
                result['additional_info'].update({
                    'Tipo de archivo': result.get('type_description', 'N/A'),
                    'Magic': result.get('magic', 'N/A'),
                    'Tamaño del archivo': f"{result.get('size', 'N/A')} bytes",
                    'MITRE ATT&CK': ', '.join(tactic.get('technique', 'N/A') for tactic in result.get('mitre_attack', []))
                })
            
            result['malicious_engines'] = {
                engine: data for engine, data in result.get('last_analysis_results', {}).items()
                if data.get('category') == 'malicious'
            }
    
    template = Template(html_template)
    return template.render(results=results)

def analyze_iocs(config: ConfigParser) -> None:
    """Analiza IOCs (direcciones IP, dominios o hashes) utilizando VirusTotal."""
    print(f"\n{Fore.YELLOW}[*] Iniciando análisis de IOCs...{Style.RESET_ALL}")
    
    file_path = input(f"{Fore.GREEN}[?] Ingrese la ruta del archivo con los IOCs: {Style.RESET_ALL}")
    
    if not os.path.exists(file_path):
        print(f"{Fore.RED}[!] El archivo no existe.{Style.RESET_ALL}")
        return

    vt_api_key = config['DEFAULT'].get('vt_api_key')
    if not vt_api_key:
        print(f"{Fore.RED}[!] API key de VirusTotal no configurada.{Style.RESET_ALL}")
        return

    with open(file_path, 'r') as file:
        iocs = file.read().splitlines()

    results = []
    for ioc in iocs:
        ioc = ioc.strip()
        ioc_type = classify_ioc(ioc)
        if ioc_type:
            print(f"{Fore.CYAN}[*] Analizando {ioc_type}: {ioc}{Style.RESET_ALL}")
            result = query_virustotal(vt_api_key, ioc, ioc_type)
            results.append(result)
        else:
            print(f"{Fore.RED}[!] IOC no reconocido: {ioc}{Style.RESET_ALL}")

    html_report = generate_html_report(results)
    report_path = 'ioc_analysis_report.html'
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html_report)
    
    print(f"{Fore.GREEN}[*] Informe HTML generado: {report_path}{Style.RESET_ALL}")
    webbrowser.open('file://' + os.path.realpath(report_path))

def print_banner():
    banner = f"""
    {Fore.RED}
     _____         _     _     _____ _        _   _      
    |  _  |_ _ ___| |_ _| |___|   __| |_ __ _| |_|_|___  
    |     | | |   | '_| . |___|__   |  _|  _|   | |  __|   {Fore.GREEN}+--[ IOC Analyzer ]--+{Fore.RED}
    |__|__|___|_|_|_,_|___|   |_____|_| |_| |_|_|_|___|             {Fore.YELLOW}v1.0
    {Fore.CYAN}
                🛡️  VirusTotal IOC Analysis Tool 🛡️
    {Style.RESET_ALL}
    """
    print(banner)

def print_loading_bar():
    print(f"\n{Fore.YELLOW}Iniciando sistema de análisis...{Style.RESET_ALL}")
    for i in range(101):
        time.sleep(0.01)
        print(f"\r{'█' * i}{'░' * (100-i)} {i}%", end='', flush=True)
    print(f"\n{Fore.GREEN}Sistema listo para el análisis.{Style.RESET_ALL}\n")

def print_menu():
    menu = f"""
    {Fore.CYAN}+----------------------[ MENU PRINCIPAL ]----------------------+
    |                                                               |
    |  {Fore.YELLOW}[1]{Fore.CYAN} 🔧 Instalar Prerrequisitos                               |
    |  {Fore.YELLOW}[2]{Fore.CYAN} 🌐 Análisis de IOCs con VirusTotal                       |
    |  {Fore.YELLOW}[3]{Fore.CYAN} ❓ Ayuda                                                 |
    |  {Fore.YELLOW}[4]{Fore.CYAN} 🚪 Salir                                                 |
    |                                                               |
    +---------------------------------------------------------------+
    """
    print(menu)

def fake_activity():
    activities = [
        "Escaneando firmas de malware conocidas...",
        "Examinando indicadores de compromiso...",
        "Analizando reputación de IOCs...",
        "Consultando bases de datos de amenazas...",
        "Correlacionando datos de inteligencia...",
    ]
    for _ in range(5):
        activity = random.choice(activities)
        print(f"{Fore.CYAN}[*] {activity}{Style.RESET_ALL}")
        time.sleep(0.5)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def main():
    load_config()
    print_banner()
    print_loading_bar()
    
    while True:
        print_menu()
        choice = input(f"{Fore.GREEN}[?] Seleccione una opción:{Style.RESET_ALL} ")
        
        if choice == '1':
            print(f"\n{Fore.YELLOW}[*] Iniciando instalación de prerrequisitos...{Style.RESET_ALL}")
            fake_activity()
            try:
                install_prerequisites()
            except Exception as e:
                print(f"{Fore.RED}[!] Error durante la instalación: {e}{Style.RESET_ALL}")
        
        elif choice == '2':
            print(f"\n{Fore.YELLOW}[*] Iniciando análisis de IOCs con VirusTotal...{Style.RESET_ALL}")
            fake_activity()
            try:
                analyze_iocs(config)
            except Exception as e:
                print(f"{Fore.RED}[!] Error durante el análisis de IOCs: {e}{Style.RESET_ALL}")
        
        elif choice == '3':
            print(f"""
            {Fore.CYAN}+----------------------[ AYUDA ]----------------------+
            | Este es un sistema de análisis de IOCs con VirusTotal. |
            | 1: Instala los prerrequisitos necesarios.              |
            | 2: Analiza IOCs (IPs, dominios, hashes) con VirusTotal.|
            | 3: Muestra este menú de ayuda.                         |
            | 4: Salir del programa.                                 |
            | Para más información, consulta la documentación.       |
            +-------------------------------------------------------+
            {Style.RESET_ALL}""")
        
        elif choice == '4':
            print(f"\n{Fore.GREEN}[*] Gracias por usar AnubisIOCAnalyzer. ¡Hasta luego!{Style.RESET_ALL}")
            break
        
        else:
            print(f"{Fore.RED}[!] Opción no válida. Intente de nuevo.{Style.RESET_ALL}")
        
        input(f"\n{Fore.YELLOW}Presione Enter para continuar...{Style.RESET_ALL}")
        clear_screen()

if __name__ == "__main__":
    main()
