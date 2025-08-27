#!/usr/bin/env python3

import os
import sys
import subprocess
import re
import json
import time
import random
import webbrowser
import base64
from typing import Dict, List, Any, Optional, Tuple
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

class IOCAnalyzer:
    def __init__(self):
        self.config = ConfigParser()
        self.load_config()
        
    def load_config(self):
        """Carga la configuración desde el archivo config.ini."""
        if os.path.exists(CONFIG_FILE):
            self.config.read(CONFIG_FILE)
        else:
            self.config['DEFAULT'] = {
                'vt_api_key': '',
                'abuseipdb_api_key': '',
                'maltiverse_api_key': ''
            }
        
        # Verificar si las claves están configuradas
        if not self.config['DEFAULT'].get('vt_api_key'):
            print(f"{Fore.YELLOW}[!] API key de VirusTotal no configurada.{Style.RESET_ALL}")
        if not self.config['DEFAULT'].get('abuseipdb_api_key'):
            print(f"{Fore.YELLOW}[!] API key de AbuseIPDB no configurada.{Style.RESET_ALL}")
        if not self.config['DEFAULT'].get('maltiverse_api_key'):
            print(f"{Fore.YELLOW}[!] API key de Maltiverse no configurada.{Style.RESET_ALL}")
        
        self.save_config()

    def save_config(self):
        """Guarda la configuración en el archivo config.ini."""
        with open(CONFIG_FILE, 'w') as configfile:
            self.config.write(configfile)

    def configure_apis(self):
        """Configura las API keys para los diferentes servicios."""
        print(f"\n{Fore.CYAN}=== CONFIGURACIÓN DE API KEYS ==={Style.RESET_ALL}\n")
        
        # VirusTotal
        if not self.config['DEFAULT'].get('vt_api_key'):
            vt_key = input(f"{Fore.GREEN}[?] Ingrese su API key de VirusTotal (dejar vacío para omitir): {Style.RESET_ALL}").strip()
            if vt_key:
                self.config['DEFAULT']['vt_api_key'] = vt_key
        
        # AbuseIPDB
        if not self.config['DEFAULT'].get('abuseipdb_api_key'):
            abuse_key = input(f"{Fore.GREEN}[?] Ingrese su API key de AbuseIPDB (dejar vacío para omitir): {Style.RESET_ALL}").strip()
            if abuse_key:
                self.config['DEFAULT']['abuseipdb_api_key'] = abuse_key
        
        # Maltiverse
        if not self.config['DEFAULT'].get('maltiverse_api_key'):
            maltiverse_key = input(f"{Fore.GREEN}[?] Ingrese su API key de Maltiverse (dejar vacío para omitir): {Style.RESET_ALL}").strip()
            if maltiverse_key:
                self.config['DEFAULT']['maltiverse_api_key'] = maltiverse_key
        
        self.save_config()
        print(f"{Fore.GREEN}[+] Configuración guardada exitosamente.{Style.RESET_ALL}")

    def install_prerequisites(self):
        """Instala los prerrequisitos necesarios en Kali Linux."""
        print(f"\n{Fore.YELLOW}[*] Iniciando instalación de prerrequisitos...{Style.RESET_ALL}")
        
        if os.geteuid() != 0:
            print(f"{Fore.RED}[!] Este script necesita privilegios de superusuario para instalar paquetes.{Style.RESET_ALL}")
            print(f"{Fore.RED}[!] Por favor, ejecute el script con 'sudo python3 {sys.argv[0]}'{Style.RESET_ALL}")
            return False

        try:
            # Actualizar la lista de paquetes
            print(f"{Fore.CYAN}[*] Actualizando lista de paquetes...{Style.RESET_ALL}")
            result = subprocess.run(["apt", "update"], capture_output=True, text=True)
            if result.returncode != 0:
                print(f"{Fore.YELLOW}[!] Advertencia: No se pudo actualizar la lista de paquetes completamente.{Style.RESET_ALL}")

            # Lista de paquetes del sistema a instalar
            system_packages = [
                "python3-pip",
                "python3-dev", 
                "python3-setuptools",
                "python3-wheel",
                "build-essential"
            ]

            # Instalar paquetes del sistema
            for package in system_packages:
                print(f"{Fore.CYAN}[*] Instalando {package}...{Style.RESET_ALL}")
                try:
                    result = subprocess.run(["apt", "install", "-y", package], capture_output=True, text=True)
                    if result.returncode != 0:
                        print(f"{Fore.YELLOW}[!] Advertencia: Error instalando {package}, continuando...{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.YELLOW}[!] Error con {package}: {e}{Style.RESET_ALL}")

            # Actualizar pip a la última versión
            print(f"{Fore.CYAN}[*] Actualizando pip...{Style.RESET_ALL}")
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], 
                             capture_output=True, check=False)
            except:
                pass

            # Lista de paquetes de Python a instalar con pip
            python_packages = [
                "colorama",
                "requests", 
                "jinja2",
                "python-dateutil",
                "tabulate"
            ]

            # Intentar diferentes métodos de instalación
            failed_packages = []
            
            for package in python_packages:
                print(f"{Fore.CYAN}[*] Instalando {package} via pip...{Style.RESET_ALL}")
                
                # Método 1: pip install normal
                try:
                    result = subprocess.run([sys.executable, "-m", "pip", "install", package], 
                                          capture_output=True, text=True, timeout=60)
                    if result.returncode == 0:
                        print(f"{Fore.GREEN}[+] {package} instalado correctamente{Style.RESET_ALL}")
                        continue
                except:
                    pass
                
                # Método 2: pip install con --user
                try:
                    result = subprocess.run([sys.executable, "-m", "pip", "install", "--user", package], 
                                          capture_output=True, text=True, timeout=60)
                    if result.returncode == 0:
                        print(f"{Fore.GREEN}[+] {package} instalado con --user{Style.RESET_ALL}")
                        continue
                except:
                    pass
                
                # Método 3: apt install
                try:
                    apt_package = f"python3-{package.replace('_', '-')}"
                    result = subprocess.run(["apt", "install", "-y", apt_package], 
                                          capture_output=True, text=True, timeout=60)
                    if result.returncode == 0:
                        print(f"{Fore.GREEN}[+] {package} instalado via apt como {apt_package}{Style.RESET_ALL}")
                        continue
                except:
                    pass
                
                # Si todos los métodos fallan
                failed_packages.append(package)
                print(f"{Fore.RED}[!] No se pudo instalar {package}{Style.RESET_ALL}")

            # Verificar qué paquetes se pudieron importar
            successful_imports = []
            for package in python_packages:
                try:
                    if package == "python-dateutil":
                        import dateutil
                    elif package == "colorama":
                        import colorama
                    elif package == "requests":
                        import requests
                    elif package == "jinja2":
                        import jinja2
                    elif package == "tabulate":
                        import tabulate
                    successful_imports.append(package)
                except ImportError:
                    pass

            print(f"\n{Fore.CYAN}[*] Resumen de instalación:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Paquetes disponibles: {len(successful_imports)}/{len(python_packages)}{Style.RESET_ALL}")
            
            if len(successful_imports) >= 3:  # Al menos colorama, requests y jinja2
                print(f"{Fore.GREEN}[+] Instalación suficiente para ejecutar el script.{Style.RESET_ALL}")
                
                # Configurar las API keys después de la instalación
                self.configure_apis()
                return True
            else:
                print(f"{Fore.YELLOW}[!] Instalación parcial. Puede que el script no funcione completamente.{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[!] Intente instalar manualmente: pip3 install {' '.join(failed_packages)}{Style.RESET_ALL}")
                return False

        except Exception as e:
            print(f"{Fore.RED}[!] Error crítico durante la instalación: {e}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Intente ejecutar manualmente:{Style.RESET_ALL}")
            print(f"{Fore.WHITE}sudo apt update && sudo apt install python3-pip python3-dev python3-setuptools{Style.RESET_ALL}")
            print(f"{Fore.WHITE}pip3 install colorama requests jinja2 python-dateutil tabulate{Style.RESET_ALL}")
            return False

    def classify_ioc(self, ioc: str) -> Optional[str]:
        """Clasifica el tipo de IOC."""
        # Patrones de expresiones regulares para identificar IOCs
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        url_pattern = r'^https?://.*'
        md5_pattern = r'^[a-fA-F0-9]{32}$'
        sha1_pattern = r'^[a-fA-F0-9]{40}$'
        sha256_pattern = r'^[a-fA-F0-9]{64}$'

        if re.match(ip_pattern, ioc):
            return 'ip'
        elif re.match(domain_pattern, ioc):
            return 'domain'
        elif re.match(url_pattern, ioc):
            return 'url'
        elif re.match(md5_pattern, ioc):
            return 'hash'
        elif re.match(sha1_pattern, ioc):
            return 'hash'
        elif re.match(sha256_pattern, ioc):
            return 'hash'
        return None

    def format_datetime(self, timestamp):
        """Convierte timestamp a formato legible."""
        if not timestamp or timestamp == 'N/A':
            return 'N/A'
        
        try:
            # Si es timestamp unix
            if isinstance(timestamp, (int, float)):
                return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            # Si es string de fecha
            elif isinstance(timestamp, str):
                # Intentar varios formatos
                formats = [
                    '%Y-%m-%dT%H:%M:%S',
                    '%Y-%m-%d %H:%M:%S', 
                    '%Y-%m-%dT%H:%M:%SZ',
                    '%Y-%m-%dT%H:%M:%S.%f',
                    '%Y-%m-%dT%H:%M:%S.%fZ'
                ]
                
                for fmt in formats:
                    try:
                        return datetime.strptime(timestamp, fmt).strftime('%Y-%m-%d %H:%M:%S')
                    except ValueError:
                        continue
                        
                return timestamp  # Devolver original si no se puede convertir
        except:
            pass
        
        return 'N/A'

    def query_virustotal(self, ioc: str, ioc_type: str) -> Dict[str, Any]:
        """Consulta VirusTotal para obtener información sobre el IOC."""
        api_key = self.config['DEFAULT'].get('vt_api_key')
        if not api_key:
            return {'error': 'API key no configurada', 'source': 'virustotal'}
        
        base_url = 'https://www.virustotal.com/api/v3/'
        headers = {'x-apikey': api_key}

        # Determinar el endpoint según el tipo de IOC
        if ioc_type == 'ip':
            url = f'{base_url}ip_addresses/{ioc}'
        elif ioc_type == 'domain':
            url = f'{base_url}domains/{ioc}'
        elif ioc_type == 'url':
            # Para URLs, necesitamos codificarlas en base64
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            url = f'{base_url}urls/{url_id}'
        else:  # hash
            url = f'{base_url}files/{ioc}'

        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json().get('data', {}).get('attributes', {})
            
            # Obtener fecha de último análisis
            last_analysis_date = self.format_datetime(data.get('last_analysis_date'))
            
            result = {
                'source': 'virustotal',
                'success': True,
                'last_analysis_date': last_analysis_date,
                'last_analysis_stats': data.get('last_analysis_stats', {}),
                'last_analysis_results': data.get('last_analysis_results', {}),
                'reputation': data.get('reputation', 0),
                'total_votes': data.get('total_votes', {})
            }
            
            if ioc_type in ['ip', 'domain']:
                result.update({
                    'country': data.get('country', 'N/A'),
                    'as_owner': data.get('as_owner', 'N/A'),
                    'asn': data.get('asn', 'N/A'),
                    'whois': data.get('whois', 'N/A')
                })
            elif ioc_type == 'hash':
                result.update({
                    'type_description': data.get('type_description', 'N/A'),
                    'magic': data.get('magic', 'N/A'),
                    'size': data.get('size', 'N/A'),
                    'file_type': data.get('type_tag', 'N/A'),
                    'names': data.get('names', [])[:5],  # Primeros 5 nombres conocidos
                    'signature_info': data.get('signature_info', {}),
                })
            
            return result
            
        except requests.RequestException as e:
            return {'error': str(e), 'source': 'virustotal', 'success': False}

    def query_abuseipdb(self, ioc: str, ioc_type: str) -> Dict[str, Any]:
        """Consulta AbuseIPDB para obtener información sobre IPs."""
        if ioc_type != 'ip':
            return {'error': 'AbuseIPDB solo soporta IPs', 'source': 'abuseipdb', 'success': False}
        
        api_key = self.config['DEFAULT'].get('abuseipdb_api_key')
        if not api_key:
            return {'error': 'API key no configurada', 'source': 'abuseipdb', 'success': False}
        
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Accept': 'application/json',
            'Key': api_key
        }
        params = {
            'ipAddress': ioc,
            'maxAgeInDays': '90',
            'verbose': ''
        }

        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            data = response.json().get('data', {})
            
            # Obtener fecha del último reporte
            last_reported_at = self.format_datetime(data.get('lastReportedAt'))
            
            return {
                'source': 'abuseipdb',
                'success': True,
                'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                'country_code': data.get('countryCode', 'N/A'),
                'usage_type': data.get('usageType', 'N/A'),
                'isp': data.get('isp', 'N/A'),
                'domain': data.get('domain', 'N/A'),
                'total_reports': data.get('totalReports', 0),
                'num_distinct_users': data.get('numDistinctUsers', 0),
                'last_reported_at': last_reported_at,
                'reports': data.get('reports', [])[:5],  # Últimos 5 reportes
                'is_whitelisted': data.get('isWhitelisted', False)
            }
            
        except requests.RequestException as e:
            return {'error': str(e), 'source': 'abuseipdb', 'success': False}

    def query_maltiverse(self, ioc: str, ioc_type: str) -> Dict[str, Any]:
        """Consulta Maltiverse para obtener información sobre el IOC."""
        api_key = self.config['DEFAULT'].get('maltiverse_api_key')
        
        # Maltiverse permite consultas limitadas sin API key
        headers = {}
        if api_key:
            headers['Authorization'] = f'Bearer {api_key}'
        
        # Determinar el endpoint según el tipo
        if ioc_type == 'ip':
            url = f'https://api.maltiverse.com/ip/{ioc}'
        elif ioc_type == 'domain':
            url = f'https://api.maltiverse.com/hostname/{ioc}'
        elif ioc_type == 'url':
            # Para URLs, necesitamos codificarlas
            import urllib.parse
            encoded_url = urllib.parse.quote(ioc, safe='')
            url = f'https://api.maltiverse.com/url/{encoded_url}'
        elif ioc_type == 'hash':
            # Para hashes, usar el endpoint correcto
            url = f'https://api.maltiverse.com/search/hash/{ioc}'
        else:
            return {'error': 'Tipo de IOC no soportado', 'source': 'maltiverse', 'success': False}

        try:
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 404:
                return {
                    'source': 'maltiverse',
                    'success': True,
                    'found': False,
                    'classification': 'unknown',
                    'blacklists': [],
                    'blacklist_names': [],
                    'creation_time': 'N/A',
                    'modification_time': 'N/A'
                }
            
            response.raise_for_status()
            data = response.json()
            
            # Manejar respuesta según el tipo de endpoint
            if ioc_type == 'hash' and isinstance(data, list):
                # El endpoint de hash devuelve una lista
                if data:
                    data = data[0]  # Tomar el primer resultado
                else:
                    return {
                        'source': 'maltiverse',
                        'success': True,
                        'found': False,
                        'classification': 'unknown',
                        'blacklists': [],
                        'blacklist_names': [],
                        'creation_time': 'N/A',
                        'modification_time': 'N/A'
                    }
            
            # Extraer nombres de blacklists
            blacklist_info = data.get('blacklist', [])
            blacklist_names = []
            if isinstance(blacklist_info, list):
                for bl in blacklist_info:
                    if isinstance(bl, dict):
                        bl_name = bl.get('source', bl.get('name', 'Unknown'))
                        if bl_name not in blacklist_names:
                            blacklist_names.append(bl_name)
                    elif isinstance(bl, str):
                        blacklist_names.append(bl)
            
            # Formatear fechas
            creation_time = self.format_datetime(data.get('creation_time'))
            modification_time = self.format_datetime(data.get('modification_time'))
            
            result = {
                'source': 'maltiverse',
                'success': True,
                'found': True,
                'classification': data.get('classification', 'unknown'),
                'type': data.get('type', 'N/A'),
                'creation_time': creation_time,
                'modification_time': modification_time,
                'blacklists': blacklist_info,
                'blacklist_names': blacklist_names,
                'blacklist_count': len(blacklist_names),
                'tags': data.get('tag', []),
                'threat_score': len(blacklist_names) * 20  # Score basado en blacklists
            }
            
            # Información adicional según el tipo
            if ioc_type == 'ip':
                result.update({
                    'asn': data.get('as_name', 'N/A'),
                    'country': data.get('country_code', 'N/A'),
                    'city': data.get('city', 'N/A')
                })
            elif ioc_type == 'domain':
                result.update({
                    'resolved_ips': data.get('ip', [])[:5],
                    'tld': data.get('tld', 'N/A')
                })
            elif ioc_type == 'hash':
                result.update({
                    'filename': data.get('filename', 'N/A'),
                    'filetype': data.get('filetype', 'N/A'),
                    'md5': data.get('md5', 'N/A'),
                    'sha1': data.get('sha1', 'N/A'),
                    'sha256': data.get('sha256', 'N/A')
                })
            
            return result
            
        except requests.RequestException as e:
            error_msg = str(e)
            if 'BAD REQUEST' in error_msg:
                error_msg = f"IOC no encontrado o formato inválido"
            return {'error': error_msg, 'source': 'maltiverse', 'success': False}

    def aggregate_results(self, ioc: str, ioc_type: str, engines: List[str]) -> Dict[str, Any]:
        """Agrega los resultados de todos los motores seleccionados."""
        
        # Filtrar motores no aplicables según el tipo de IOC
        applicable_engines = engines.copy()
        if ioc_type != 'ip' and 'abuseipdb' in applicable_engines:
            print(f"{Fore.YELLOW}[!] AbuseIPDB solo soporta IPs, se excluirá del análisis{Style.RESET_ALL}")
            applicable_engines.remove('abuseipdb')
        
        aggregated = {
            'ioc': ioc,
            'type': ioc_type,
            'timestamp': datetime.now().isoformat(),
            'engines_results': {},
            'total_score': 0,
            'max_score': 0,
            'detection_summary': {
                'total_engines': 0,
                'detected_malicious': 0,
                'detected_suspicious': 0,
                'detected_clean': 0,
                'errors': 0,
                'not_applicable': len(engines) - len(applicable_engines)
            }
        }
        
        # Consultar cada motor aplicable
        for engine in applicable_engines:
            print(f"{Fore.CYAN}[*] Consultando {engine} para {ioc}...{Style.RESET_ALL}")
            
            if engine == 'virustotal':
                result = self.query_virustotal(ioc, ioc_type)
            elif engine == 'abuseipdb':
                result = self.query_abuseipdb(ioc, ioc_type)
            elif engine == 'maltiverse':
                result = self.query_maltiverse(ioc, ioc_type)
            else:
                continue
            
            aggregated['engines_results'][engine] = result
            
            # Actualizar el resumen de detección
            if result.get('success'):
                aggregated['detection_summary']['total_engines'] += 1
                
                # Calcular score según el motor
                if engine == 'virustotal' and 'last_analysis_stats' in result:
                    stats = result['last_analysis_stats']
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    total = sum(stats.values())
                    if total > 0:
                        score = (malicious * 100 + suspicious * 50) / total
                        aggregated['total_score'] += score
                        aggregated['max_score'] += 100
                        if malicious > 5:
                            aggregated['detection_summary']['detected_malicious'] += 1
                        elif suspicious > 3 or malicious > 0:
                            aggregated['detection_summary']['detected_suspicious'] += 1
                        else:
                            aggregated['detection_summary']['detected_clean'] += 1
                
                elif engine == 'abuseipdb' and 'abuse_confidence_score' in result:
                    score = result['abuse_confidence_score']
                    aggregated['total_score'] += score
                    aggregated['max_score'] += 100
                    if score > 75:
                        aggregated['detection_summary']['detected_malicious'] += 1
                    elif score > 25:
                        aggregated['detection_summary']['detected_suspicious'] += 1
                    else:
                        aggregated['detection_summary']['detected_clean'] += 1
                
                elif engine == 'maltiverse' and result.get('found'):
                    classification = result.get('classification', 'unknown')
                    blacklist_count = result.get('blacklist_count', 0)
                    score = min(blacklist_count * 25, 100)  # Ajustado para ser más sensible
                    aggregated['total_score'] += score
                    aggregated['max_score'] += 100
                    if classification == 'malicious' or blacklist_count > 2:
                        aggregated['detection_summary']['detected_malicious'] += 1
                    elif classification == 'suspicious' or blacklist_count > 0:
                        aggregated['detection_summary']['detected_suspicious'] += 1
                    else:
                        aggregated['detection_summary']['detected_clean'] += 1
            else:
                aggregated['detection_summary']['errors'] += 1
        
        # Agregar motores no aplicables con mensaje explicativo
        for engine in engines:
            if engine not in applicable_engines:
                aggregated['engines_results'][engine] = {
                    'source': engine,
                    'success': False,
                    'error': f'{engine.capitalize()} solo soporta IPs',
                    'not_applicable': True
                }
        
        # Calcular el score final ajustado
        if aggregated['max_score'] > 0:
            aggregated['final_score'] = round(aggregated['total_score'] / aggregated['max_score'] * 100, 2)
        else:
            aggregated['final_score'] = 0
        
        # Determinar el nivel de peligro con umbrales ajustados según el tipo
        if ioc_type == 'ip':
            # Para IPs, mantener umbrales originales
            high_threshold = 70
            medium_threshold = 40
        else:
            # Para dominios y hashes, ajustar umbrales ya que no tienen AbuseIPDB
            high_threshold = 60
            medium_threshold = 30
        
        if aggregated['final_score'] >= high_threshold:
            aggregated['danger_level'] = 'high'
            aggregated['danger_symbol'] = '🚨'
            aggregated['danger_color'] = '#dc3545'
        elif aggregated['final_score'] >= medium_threshold:
            aggregated['danger_level'] = 'medium'
            aggregated['danger_symbol'] = '⚠️'
            aggregated['danger_color'] = '#ffc107'
        else:
            aggregated['danger_level'] = 'low'
            aggregated['danger_symbol'] = '✅'
            aggregated['danger_color'] = '#28a745'
        
        return aggregated

    def generate_html_report(self, results: List[Dict[str, Any]], engines_used: List[str]) -> str:
        """Genera un informe HTML interactivo con gráficos y resultados detallados."""
        html_template = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Anubis IOC Analyzer - Informe de Análisis</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .header {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .header h1 {
            color: #2c3e50;
            font-size: 2.5em;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 15px;
        }
        
        .header .subtitle {
            color: #7f8c8d;
            font-size: 1.1em;
        }
        
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .summary-card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }
        
        .summary-card:hover {
            transform: translateY(-5px);
        }
        
        .summary-card .icon {
            font-size: 2em;
            margin-bottom: 10px;
        }
        
        .summary-card .value {
            font-size: 2em;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .summary-card .label {
            color: #7f8c8d;
            margin-top: 5px;
        }
        
        .ioc-card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 15px 40px rgba(0,0,0,0.1);
            transition: all 0.3s ease;
        }
        
        .ioc-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 20px 50px rgba(0,0,0,0.15);
        }
        
        .ioc-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid #ecf0f1;
        }
        
        .ioc-info {
            flex: 1;
        }
        
        .ioc-type {
            display: inline-block;
            background: #3498db;
            color: white;
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 0.9em;
            margin-right: 10px;
        }
        
        .ioc-value {
            font-family: 'Courier New', monospace;
            font-size: 1.1em;
            color: #2c3e50;
            margin-top: 5px;
            word-break: break-all;
        }
        
        .danger-badge {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 20px;
            border-radius: 10px;
            font-weight: bold;
            color: white;
        }
        
        .danger-high { background: linear-gradient(135deg, #f85032 0%, #e73827 100%); }
        .danger-medium { background: linear-gradient(135deg, #f7971e 0%, #ffd200 100%); }
        .danger-low { background: linear-gradient(135deg, #00d2ff 0%, #3a7bd5 100%); }
        
        .score-meter {
            display: flex;
            align-items: center;
            gap: 15px;
            margin: 20px 0;
        }
        
        .score-bar {
            flex: 1;
            height: 30px;
            background: #ecf0f1;
            border-radius: 15px;
            overflow: hidden;
            position: relative;
        }
        
        .score-fill {
            height: 100%;
            transition: width 1.5s ease;
            background: linear-gradient(90deg, #00d2ff, #3a7bd5, #f7971e, #f85032);
            background-size: 300% 100%;
            animation: shimmer 3s ease infinite;
        }
        
        @keyframes shimmer {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        
        .score-text {
            font-size: 1.5em;
            font-weight: bold;
            color: #2c3e50;
            min-width: 80px;
        }
        
        .engine-results {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .engine-card {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 15px;
            border-left: 4px solid #3498db;
        }
        
        .engine-card.error {
            border-left-color: #e74c3c;
            opacity: 0.7;
        }
        
        .engine-card.not-applicable {
            border-left-color: #95a5a6;
            background: #ecf0f1;
            opacity: 0.6;
        }
        
        .engine-name {
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .engine-details {
            font-size: 0.9em;
            color: #7f8c8d;
        }
        
        .detail-item {
            margin: 5px 0;
            display: flex;
            justify-content: space-between;
        }
        
        .detail-label {
            font-weight: 500;
        }
        
        .detail-value {
            color: #2c3e50;
            font-weight: bold;
        }
        
        .chart-container {
            background: white;
            border-radius: 10px;
            padding: 15px;
            margin: 20px 0;
            height: 300px;
            position: relative;
        }
        
        .tabs {
            display: flex;
            gap: 10px;
            margin: 20px 0;
            border-bottom: 2px solid #ecf0f1;
        }
        
        .tab {
            padding: 10px 20px;
            background: none;
            border: none;
            color: #7f8c8d;
            cursor: pointer;
            transition: all 0.3s;
            font-size: 1em;
        }
        
        .tab:hover {
            color: #3498db;
        }
        
        .tab.active {
            color: #3498db;
            border-bottom: 3px solid #3498db;
            margin-bottom: -2px;
        }
        
        .tab-content {
            display: none;
            animation: fadeIn 0.3s ease;
        }
        
        .tab-content.active {
            display: block;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .details-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        
        .detail-box {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 8px;
        }
        
        .detail-box label {
            color: #7f8c8d;
            font-size: 0.85em;
            display: block;
            margin-bottom: 5px;
        }
        
        .detail-box value {
            color: #2c3e50;
            font-weight: bold;
            word-break: break-all;
        }
        
        .date-info {
            background: #e8f4fd;
            border-left: 4px solid #3498db;
            padding: 10px 15px;
            margin: 10px 0;
            border-radius: 5px;
        }
        
        .date-info .date-label {
            font-weight: bold;
            color: #2c3e50;
            font-size: 0.9em;
        }
        
        .date-info .date-value {
            color: #34495e;
            margin-left: 5px;
        }
        
        .detection-engines {
            max-height: 120px;
            overflow-y: auto;
            border: 1px solid #e8e8e8;
            border-radius: 5px;
            padding: 8px;
            margin-top: 5px;
            background: #fafafa;
        }
        
        .detection-engines::-webkit-scrollbar {
            width: 6px;
        }
        
        .detection-engines::-webkit-scrollbar-track {
            background: #f1f1f1;
            border-radius: 3px;
        }
        
        .detection-engines::-webkit-scrollbar-thumb {
            background: #c1c1c1;
            border-radius: 3px;
        }
        
        .detection-engines::-webkit-scrollbar-thumb:hover {
            background: #a8a8a8;
        }
        
        .engine-list {
            font-size: 0.8em;
            line-height: 1.4;
        }
        
        .engine-list.malicious {
            color: #e74c3c;
        }
        
        .engine-list.suspicious {
            color: #f39c12;
        }
        
        .footer {
            text-align: center;
            margin-top: 40px;
            color: white;
            font-size: 0.9em;
        }
        
        .timestamp {
            color: #95a5a6;
            font-size: 0.85em;
        }
        
        .legend {
            display: flex;
            justify-content: center;
            gap: 20px;
            margin: 10px 0;
            flex-wrap: wrap;
        }
        
        .legend-item {
            display: flex;
            align-items: center;
            gap: 5px;
            font-size: 0.9em;
        }
        
        .legend-color {
            width: 20px;
            height: 20px;
            border-radius: 3px;
        }
        
        @media (max-width: 768px) {
            .header h1 {
                font-size: 1.8em;
            }
            
            .engine-results {
                grid-template-columns: 1fr;
            }
            
            .ioc-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>
                <i class="fas fa-shield-alt"></i>
                Anubis IOC Analyzer v2.0
            </h1>
            <p class="subtitle">
                Análisis Multi-Motor de Indicadores de Compromiso
                <br>
                <span class="timestamp">Generado: {{ timestamp }}</span>
            </p>
        </div>
        
        <div class="summary-cards">
            <div class="summary-card">
                <div class="icon">📊</div>
                <div class="value">{{ total_iocs }}</div>
                <div class="label">IOCs Analizados</div>
            </div>
            <div class="summary-card">
                <div class="icon">🔍</div>
                <div class="value">{{ engines_count }}</div>
                <div class="label">Motores Utilizados</div>
            </div>
            <div class="summary-card">
                <div class="icon">🚨</div>
                <div class="value">{{ malicious_count }}</div>
                <div class="label">IOCs Maliciosos</div>
            </div>
            <div class="summary-card">
                <div class="icon">⚠️</div>
                <div class="value">{{ suspicious_count }}</div>
                <div class="label">IOCs Sospechosos</div>
            </div>
        </div>
        
        {% for result in results %}
        <div class="ioc-card">
            <div class="ioc-header">
                <div class="ioc-info">
                    <span class="ioc-type">{{ result.type | upper }}</span>
                    <div class="ioc-value">{{ result.ioc }}</div>
                </div>
                <div class="danger-badge danger-{{ result.danger_level }}">
                    <span>{{ result.danger_symbol }}</span>
                    <span>{{ result.danger_level | upper }}</span>
                </div>
            </div>
            
            <div class="score-meter">
                <span class="score-text">{{ result.final_score }}%</span>
                <div class="score-bar">
                    <div class="score-fill" style="width: {{ result.final_score }}%"></div>
                </div>
            </div>
            
            <div class="tabs">
                <button class="tab active" onclick="switchTab(event, '{{ result.ioc }}_overview')">
                    <i class="fas fa-chart-line"></i> Resumen
                </button>
                <button class="tab" onclick="switchTab(event, '{{ result.ioc }}_engines')">
                    <i class="fas fa-cogs"></i> Motores
                </button>
                <button class="tab" onclick="switchTab(event, '{{ result.ioc }}_details')">
                    <i class="fas fa-info-circle"></i> Detalles
                </button>
            </div>
            
            <div id="{{ result.ioc }}_overview" class="tab-content active">
                <div class="chart-container">
                    <canvas id="chart_{{ loop.index }}"></canvas>
                </div>
                <div class="legend">
                    <div class="legend-item">
                        <div class="legend-color" style="background: #e74c3c;"></div>
                        <span>Malicioso ({{ result.detection_summary.detected_malicious }})</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background: #f39c12;"></div>
                        <span>Sospechoso ({{ result.detection_summary.detected_suspicious }})</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background: #27ae60;"></div>
                        <span>Limpio ({{ result.detection_summary.detected_clean }})</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background: #95a5a6;"></div>
                        <span>Errores ({{ result.detection_summary.errors }})</span>
                    </div>
                </div>
            </div>
            
            <div id="{{ result.ioc }}_engines" class="tab-content">
                <div class="engine-results">
                    {% for engine, data in result.engines_results.items() %}
                    <div class="engine-card {% if data.not_applicable %}not-applicable{% elif not data.success %}error{% endif %}">
                        <div class="engine-name">
                            {% if engine == 'virustotal' %}
                                <i class="fas fa-virus"></i> VirusTotal
                            {% elif engine == 'abuseipdb' %}
                                <i class="fas fa-ban"></i> AbuseIPDB
                            {% elif engine == 'maltiverse' %}
                                <i class="fas fa-globe"></i> Maltiverse
                            {% endif %}
                            {% if data.not_applicable %}
                                <span style="color: #95a5a6;">(No Aplicable)</span>
                            {% elif not data.success %}
                                <span style="color: #e74c3c;">(Error)</span>
                            {% endif %}
                        </div>
                        
                        <!-- Información de fecha para cada motor -->
                        {% if data.success and not data.not_applicable %}
                            {% if engine == 'virustotal' and data.last_analysis_date and data.last_analysis_date != 'N/A' %}
                                <div class="date-info">
                                    <span class="date-label">Último Análisis:</span>
                                    <span class="date-value">{{ data.last_analysis_date }}</span>
                                </div>
                            {% elif engine == 'abuseipdb' and data.last_reported_at and data.last_reported_at != 'N/A' %}
                                <div class="date-info">
                                    <span class="date-label">Último Reporte:</span>
                                    <span class="date-value">{{ data.last_reported_at }}</span>
                                </div>
                            {% elif engine == 'maltiverse' %}
                                {% if data.creation_time and data.creation_time != 'N/A' %}
                                <div class="date-info">
                                    <span class="date-label">Creación:</span>
                                    <span class="date-value">{{ data.creation_time }}</span>
                                </div>
                                {% endif %}
                                {% if data.modification_time and data.modification_time != 'N/A' %}
                                <div class="date-info">
                                    <span class="date-label">Modificación:</span>
                                    <span class="date-value">{{ data.modification_time }}</span>
                                </div>
                                {% endif %}
                            {% endif %}
                        {% endif %}
                        
                        <div class="engine-details">
                            {% if data.success %}
                                {% if engine == 'virustotal' and data.last_analysis_stats %}
                                    <div class="detail-item">
                                        <span class="detail-label">Detecciones:</span>
                                        <span class="detail-value" style="color: {% if data.last_analysis_stats.malicious > 5 %}#e74c3c{% else %}#27ae60{% endif %};">
                                            {{ data.last_analysis_stats.malicious }}/{{ data.last_analysis_stats.malicious + data.last_analysis_stats.undetected + data.last_analysis_stats.suspicious }}
                                        </span>
                                    </div>
                                    <div class="detail-item">
                                        <span class="detail-label">Reputación:</span>
                                        <span class="detail-value">{{ data.reputation | default(0) }}</span>
                                    </div>
                                    
                                    <!-- Mostrar motores que detectaron como malicioso/sospechoso -->
                                    {% if data.last_analysis_results %}
                                        {% set malicious_engines = [] %}
                                        {% set suspicious_engines = [] %}
                                        {% for engine_name, result in data.last_analysis_results.items() %}
                                            {% if result.category == 'malicious' %}
                                                {% set _ = malicious_engines.append(engine_name) %}
                                            {% elif result.category == 'suspicious' %}
                                                {% set _ = suspicious_engines.append(engine_name) %}
                                            {% endif %}
                                        {% endfor %}
                                        
                                        {% if malicious_engines %}
                                        <div class="detail-item" style="margin-top: 10px; border-top: 1px solid #eee; padding-top: 8px;">
                                            <span class="detail-label" style="color: #e74c3c;">Malicioso ({{ malicious_engines|length }}):</span>
                                        </div>
                                        <div style="margin-left: 10px; font-size: 0.8em; color: #e74c3c; max-height: 80px; overflow-y: auto;">
                                            {% for engine_name in malicious_engines[:10] %}
                                                • {{ engine_name }}<br>
                                            {% endfor %}
                                            {% if malicious_engines|length > 10 %}
                                                <span style="color: #95a5a6;">... y {{ malicious_engines|length - 10 }} más</span>
                                            {% endif %}
                                        </div>
                                        {% endif %}
                                        
                                        {% if suspicious_engines %}
                                        <div class="detail-item" style="margin-top: 8px;">
                                            <span class="detail-label" style="color: #f39c12;">Sospechoso ({{ suspicious_engines|length }}):</span>
                                        </div>
                                        <div style="margin-left: 10px; font-size: 0.8em; color: #f39c12; max-height: 60px; overflow-y: auto;">
                                            {% for engine_name in suspicious_engines[:8] %}
                                                • {{ engine_name }}<br>
                                            {% endfor %}
                                            {% if suspicious_engines|length > 8 %}
                                                <span style="color: #95a5a6;">... y {{ suspicious_engines|length - 8 }} más</span>
                                            {% endif %}
                                        </div>
                                        {% endif %}
                                    {% endif %}
                                {% elif engine == 'abuseipdb' and not data.not_applicable %}
                                    <div class="detail-item">
                                        <span class="detail-label">Confianza de Abuso:</span>
                                        <span class="detail-value" style="color: {% if data.abuse_confidence_score > 75 %}#e74c3c{% elif data.abuse_confidence_score > 25 %}#f39c12{% else %}#27ae60{% endif %};">
                                            {{ data.abuse_confidence_score }}%
                                        </span>
                                    </div>
                                    <div class="detail-item">
                                        <span class="detail-label">Total Reportes:</span>
                                        <span class="detail-value">{{ data.total_reports }}</span>
                                    </div>
                                    <div class="detail-item">
                                        <span class="detail-label">País:</span>
                                        <span class="detail-value">{{ data.country_code }}</span>
                                    </div>
                                {% elif engine == 'maltiverse' %}
                                    <div class="detail-item">
                                        <span class="detail-label">Clasificación:</span>
                                        <span class="detail-value" style="color: {% if data.classification == 'malicious' %}#e74c3c{% elif data.classification == 'suspicious' %}#f39c12{% else %}#27ae60{% endif %};">
                                            {{ data.classification | upper }}
                                        </span>
                                    </div>
                                    <div class="detail-item">
                                        <span class="detail-label">Blacklists:</span>
                                        <span class="detail-value">{{ data.blacklist_count | default(0) }}</span>
                                    </div>
                                    {% if data.blacklist_names %}
                                    <div class="detail-item" style="margin-top: 10px;">
                                        <span class="detail-label">En listas:</span>
                                    </div>
                                    <div style="margin-left: 10px; font-size: 0.85em; color: #e74c3c;">
                                        {% for bl_name in data.blacklist_names[:3] %}
                                            • {{ bl_name }}<br>
                                        {% endfor %}
                                        {% if data.blacklist_names | length > 3 %}
                                            <span style="color: #95a5a6;">... y {{ data.blacklist_names | length - 3 }} más</span>
                                        {% endif %}
                                    </div>
                                    {% endif %}
                                {% endif %}
                            {% else %}
                                <div class="detail-item">
                                    <span class="detail-label">{% if data.not_applicable %}No Aplicable{% else %}Error{% endif %}:</span>
                                    <span class="detail-value">{{ data.error }}</span>
                                </div>
                            {% endif %}
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </div>
            
            <div id="{{ result.ioc }}_details" class="tab-content">
                <div class="details-grid">
                    {% for engine, data in result.engines_results.items() %}
                        {% if data.success and not data.not_applicable %}
                            {% if engine == 'virustotal' %}
                                {% if result.type in ['ip', 'domain'] %}
                                    <div class="detail-box">
                                        <label>País</label>
                                        <value>{{ data.country | default('N/A') }}</value>
                                    </div>
                                    <div class="detail-box">
                                        <label>ASN</label>
                                        <value>{{ data.asn | default('N/A') }}</value>
                                    </div>
                                    <div class="detail-box">
                                        <label>AS Owner</label>
                                        <value>{{ data.as_owner | default('N/A') }}</value>
                                    </div>
                                {% elif result.type == 'hash' %}
                                    <div class="detail-box">
                                        <label>Tipo de Archivo</label>
                                        <value>{{ data.type_description | default('N/A') }}</value>
                                    </div>
                                    <div class="detail-box">
                                        <label>Tamaño</label>
                                        <value>{{ data.size | default('N/A') }} bytes</value>
                                    </div>
                                    <div class="detail-box">
                                        <label>Magic</label>
                                        <value>{{ data.magic | default('N/A') }}</value>
                                    </div>
                                    {% if data.names %}
                                    <div class="detail-box">
                                        <label>Nombres Conocidos</label>
                                        <value>{{ data.names[:3] | join(', ') }}</value>
                                    </div>
                                    {% endif %}
                                {% endif %}
                            {% elif engine == 'abuseipdb' %}
                                <div class="detail-box">
                                    <label>ISP</label>
                                    <value>{{ data.isp | default('N/A') }}</value>
                                </div>
                                <div class="detail-box">
                                    <label>Tipo de Uso</label>
                                    <value>{{ data.usage_type | default('N/A') }}</value>
                                </div>
                                <div class="detail-box">
                                    <label>Dominio</label>
                                    <value>{{ data.domain | default('N/A') }}</value>
                                </div>
                            {% elif engine == 'maltiverse' %}
                                {% if data.tags %}
                                <div class="detail-box">
                                    <label>Tags</label>
                                    <value>{{ data.tags | join(', ') }}</value>
                                </div>
                                {% endif %}
                                {% if data.blacklist_names %}
                                <div class="detail-box" style="grid-column: span 2;">
                                    <label>Detectado en Blacklists ({{ data.blacklist_count }})</label>
                                    <value style="color: #e74c3c; margin-top: 5px;">
                                        {% for bl_name in data.blacklist_names %}
                                            • {{ bl_name }}<br>
                                        {% endfor %}
                                    </value>
                                </div>
                                {% endif %}
                                {% if result.type == 'hash' %}
                                    {% if data.filename and data.filename != 'N/A' %}
                                    <div class="detail-box">
                                        <label>Nombre de Archivo</label>
                                        <value>{{ data.filename }}</value>
                                    </div>
                                    {% endif %}
                                    {% if data.filetype and data.filetype != 'N/A' %}
                                    <div class="detail-box">
                                        <label>Tipo de Archivo</label>
                                        <value>{{ data.filetype }}</value>
                                    </div>
                                    {% endif %}
                                {% endif %}
                            {% endif %}
                        {% endif %}
                    {% endfor %}
                </div>
            </div>
        </div>
        {% endfor %}
        
        <div class="footer">
            <p>Anubis IOC Analyzer v2.0 - Análisis Multi-Motor</p>
            <p>© 2024 - Desarrollado con ❤️ para la comunidad de ciberseguridad</p>
        </div>
    </div>
    
    <script>
        // Función para cambiar de pestañas
        function switchTab(event, tabId) {
            const button = event.currentTarget;
            const card = button.closest('.ioc-card');
            
            // Remover clase active de todos los tabs y contenidos
            card.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
            card.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
            
            // Agregar clase active al tab clickeado y su contenido
            button.classList.add('active');
            document.getElementById(tabId).classList.add('active');
        }
        
        // Crear gráficos para cada IOC
        {% for result in results %}
        (function() {
            const ctx = document.getElementById('chart_{{ loop.index }}').getContext('2d');
            
            {% if result.engines_results.get('virustotal', {}).get('success') and result.engines_results.virustotal.get('last_analysis_stats') %}
            const vtStats = {{ result.engines_results.virustotal.last_analysis_stats | tojson }};
            new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['Malicioso', 'Sospechoso', 'No detectado', 'Timeout', 'Error'],
                    datasets: [{
                        data: [
                            vtStats.malicious || 0,
                            vtStats.suspicious || 0,
                            vtStats.undetected || 0,
                            vtStats.timeout || 0,
                            vtStats.failure || 0
                        ],
                        backgroundColor: [
                            '#e74c3c',
                            '#f39c12',
                            '#27ae60',
                            '#3498db',
                            '#95a5a6'
                        ],
                        borderWidth: 2,
                        borderColor: '#fff'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: {
                                padding: 15,
                                font: {
                                    size: 12
                                }
                            }
                        },
                        title: {
                            display: true,
                            text: 'Análisis de VirusTotal',
                            font: {
                                size: 16,
                                weight: 'bold'
                            }
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const label = context.label || '';
                                    const value = context.parsed || 0;
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = ((value / total) * 100).toFixed(1);
                                    return label + ': ' + value + ' (' + percentage + '%)';
                                }
                            }
                        }
                    }
                }
            });
            {% else %}
            // Gráfico de resumen general para cualquier combinación de motores
            const engines = {{ result.engines_results.keys() | list | tojson }};
            const scores = [];
            const colors = [];
            const borderColors = [];
            
            {% for engine, data in result.engines_results.items() %}
                {% if engine == 'virustotal' and data.get('success') and data.get('last_analysis_stats') %}
                    scores.push({{ ((data.last_analysis_stats.malicious | default(0)) / ((data.last_analysis_stats.malicious | default(0)) + (data.last_analysis_stats.undetected | default(1)) + (data.last_analysis_stats.suspicious | default(0)))) * 100 if data.last_analysis_stats else 0 }});
                    colors.push('rgba(52, 152, 219, 0.8)');
                    borderColors.push('rgb(52, 152, 219)');
                {% elif engine == 'abuseipdb' and data.get('success') and not data.get('not_applicable') %}
                    scores.push({{ data.abuse_confidence_score | default(0) }});
                    colors.push('rgba(231, 76, 60, 0.8)');
                    borderColors.push('rgb(231, 76, 60)');
                {% elif engine == 'maltiverse' and data.get('success') and data.get('found') %}
                    scores.push({{ data.threat_score | default(0) }});
                    colors.push('rgba(46, 204, 113, 0.8)');
                    borderColors.push('rgb(46, 204, 113)');
                {% else %}
                    scores.push(0);
                    colors.push('rgba(149, 165, 166, 0.8)');
                    borderColors.push('rgb(149, 165, 166)');
                {% endif %}
            {% endfor %}
            
            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: engines,
                    datasets: [{
                        label: 'Score de Detección',
                        data: scores,
                        backgroundColor: colors,
                        borderColor: borderColors,
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            max: 100,
                            ticks: {
                                callback: function(value) {
                                    return value + '%';
                                }
                            }
                        }
                    },
                    plugins: {
                        legend: {
                            display: false
                        },
                        title: {
                            display: true,
                            text: 'Comparación de Detección por Motor',
                            font: {
                                size: 16,
                                weight: 'bold'
                            }
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    return context.parsed.y.toFixed(1) + '% de confianza';
                                }
                            }
                        }
                    }
                }
            });
            {% endif %}
        })();
        {% endfor %}
    </script>
</body>
</html>
"""
        
        # Preparar datos para el template
        template_data = {
            'results': results,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_iocs': len(results),
            'engines_count': len(engines_used),
            'malicious_count': sum(1 for r in results if r['danger_level'] == 'high'),
            'suspicious_count': sum(1 for r in results if r['danger_level'] == 'medium')
        }
        
        template = Template(html_template)
        return template.render(**template_data)

    def analyze_iocs_from_file(self, file_path: str, engines: List[str]) -> List[Dict[str, Any]]:
        """Analiza IOCs desde un archivo."""
        results = []
        
        if not os.path.exists(file_path):
            print(f"{Fore.RED}[!] El archivo {file_path} no existe.{Style.RESET_ALL}")
            return results
        
        with open(file_path, 'r') as file:
            iocs = [line.strip() for line in file if line.strip()]
        
        total = len(iocs)
        print(f"\n{Fore.CYAN}[*] Se encontraron {total} IOCs para analizar{Style.RESET_ALL}")
        
        for i, ioc in enumerate(iocs, 1):
            print(f"\n{Fore.YELLOW}[{i}/{total}] Analizando: {ioc}{Style.RESET_ALL}")
            
            ioc_type = self.classify_ioc(ioc)
            if not ioc_type:
                print(f"{Fore.RED}[!] Tipo de IOC no reconocido: {ioc}{Style.RESET_ALL}")
                continue
            
            print(f"{Fore.CYAN}[*] Tipo detectado: {ioc_type}{Style.RESET_ALL}")
            
            result = self.aggregate_results(ioc, ioc_type, engines)
            results.append(result)
            
            # Pequeña pausa para no sobrecargar las APIs
            if i < total:
                time.sleep(1)
        
        return results


def print_banner():
    banner = f"""
    {Fore.RED}
     _____             _     _       _____ _____ _____    {Fore.CYAN}2.0{Fore.RED}
    |  _  |___ _ _ ___| |___|_|___  |     |     |     |  {Fore.YELLOW}Multi-Engine{Fore.RED}
    |     |   | | | . | | . | |_ -| |-   -|  |  |   --|   {Fore.GREEN}Analyzer{Fore.RED}
    |__|__|_|_|___|___|_|___|_|___| |_____|_____|_____|
    {Fore.CYAN}
    ╔══════════════════════════════════════════════════════════╗
    ║        🛡️  Advanced IOC Multi-Engine Analysis Tool 🛡️        ║
    ║                                                          ║
    ║  Engines: VirusTotal | AbuseIPDB | Maltiverse          ║
    ╚══════════════════════════════════════════════════════════╝
    {Style.RESET_ALL}
    """
    print(banner)


def print_loading_animation():
    """Muestra una animación de carga mejorada."""
    print(f"\n{Fore.YELLOW}Inicializando sistema de análisis multi-motor...{Style.RESET_ALL}\n")
    
    stages = [
        "Cargando módulos de análisis",
        "Verificando conectividad con APIs",
        "Preparando motores de detección",
        "Inicializando base de datos local",
        "Sistema listo"
    ]
    
    for stage in stages:
        print(f"{Fore.CYAN}[*] {stage}...{Style.RESET_ALL}", end='')
        for _ in range(3):
            time.sleep(0.2)
            print('.', end='', flush=True)
        print(f" {Fore.GREEN}✓{Style.RESET_ALL}")
    
    print(f"\n{Fore.GREEN}[+] Sistema completamente inicializado.{Style.RESET_ALL}\n")


def print_menu():
    menu = f"""
    {Fore.CYAN}╔═══════════════════════[ MENÚ PRINCIPAL ]═══════════════════════╗
    ║                                                           ║
    ║  {Fore.YELLOW}[1]{Fore.CYAN} 🔧 Instalar Prerrequisitos                           ║
    ║  {Fore.YELLOW}[2]{Fore.CYAN} 🔑 Configurar API Keys                               ║
    ║  {Fore.YELLOW}[3]{Fore.CYAN} 🌐 Análisis Completo (Todos los motores)            ║
    ║  {Fore.YELLOW}[4]{Fore.CYAN} 🦠 Análisis con VirusTotal                          ║
    ║  {Fore.YELLOW}[5]{Fore.CYAN} 🚫 Análisis con AbuseIPDB                           ║
    ║  {Fore.YELLOW}[6]{Fore.CYAN} 🌍 Análisis con Maltiverse                          ║
    ║  {Fore.YELLOW}[7]{Fore.CYAN} 📊 Análisis Personalizado (Seleccionar motores)    ║
    ║  {Fore.YELLOW}[8]{Fore.CYAN} ❓ Ayuda                                             ║
    ║  {Fore.YELLOW}[9]{Fore.CYAN} 🚪 Salir                                             ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    print(menu)


def show_help():
    help_text = f"""
    {Fore.CYAN}╔══════════════════════[ AYUDA ]══════════════════════╗
    ║                                                  ║
    ║  {Fore.YELLOW}Anubis IOC Analyzer v2.0{Fore.CYAN}                       ║
    ║                                                  ║
    ║  Sistema avanzado de análisis de IOCs con       ║
    ║  múltiples motores de detección.                ║
    ║                                                  ║
    ║  {Fore.GREEN}Características:{Fore.CYAN}                               ║
    ║  • Análisis con VirusTotal, AbuseIPDB y         ║
    ║    Maltiverse                                    ║
    ║  • Detección de IPs, dominios, URLs y hashes    ║
    ║  • Informes HTML interactivos con gráficos      ║
    ║  • Sistema de puntuación unificado              ║
    ║                                                  ║
    ║  {Fore.GREEN}Formato de archivo de IOCs:{Fore.CYAN}                    ║
    ║  Un IOC por línea, ejemplo:                     ║
    ║  192.168.1.1                                    ║
    ║  malicious-domain.com                           ║
    ║  d41d8cd98f00b204e9800998ecf8427e              ║
    ║                                                  ║
    ║  {Fore.GREEN}API Keys necesarias:{Fore.CYAN}                           ║
    ║  • VirusTotal: https://virustotal.com/gui/      ║
    ║  • AbuseIPDB: https://www.abuseipdb.com/        ║
    ║  • Maltiverse: https://maltiverse.com/          ║
    ║                                                  ║
    ╚══════════════════════════════════════════════════╝
    {Style.RESET_ALL}"""
    print(help_text)


def select_engines():
    """Permite al usuario seleccionar qué motores usar."""
    print(f"\n{Fore.CYAN}=== SELECCIÓN DE MOTORES ==={Style.RESET_ALL}\n")
    
    engines = []
    
    use_vt = input(f"{Fore.GREEN}[?] ¿Usar VirusTotal? (s/n): {Style.RESET_ALL}").lower() == 's'
    if use_vt:
        engines.append('virustotal')
    
    use_abuse = input(f"{Fore.GREEN}[?] ¿Usar AbuseIPDB? (s/n): {Style.RESET_ALL}").lower() == 's'
    if use_abuse:
        engines.append('abuseipdb')
    
    use_malti = input(f"{Fore.GREEN}[?] ¿Usar Maltiverse? (s/n): {Style.RESET_ALL}").lower() == 's'
    if use_malti:
        engines.append('maltiverse')
    
    if not engines:
        print(f"{Fore.YELLOW}[!] No se seleccionó ningún motor. Usando todos por defecto.{Style.RESET_ALL}")
        engines = ['virustotal', 'abuseipdb', 'maltiverse']
    
    return engines


def clear_screen():
    """Limpia la pantalla."""
    os.system('cls' if os.name == 'nt' else 'clear')


def main():
    analyzer = IOCAnalyzer()
    
    clear_screen()
    print_banner()
    print_loading_animation()
    
    while True:
        print_menu()
        choice = input(f"{Fore.GREEN}[?] Seleccione una opción: {Style.RESET_ALL}")
        
        if choice == '1':
            print(f"\n{Fore.YELLOW}[*] Instalando prerrequisitos...{Style.RESET_ALL}")
            if analyzer.install_prerequisites():
                print(f"{Fore.GREEN}[+] Instalación completada.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] Error en la instalación.{Style.RESET_ALL}")
        
        elif choice == '2':
            analyzer.configure_apis()
        
        elif choice in ['3', '4', '5', '6', '7']:
            # Determinar qué motores usar
            if choice == '3':
                engines = ['virustotal', 'abuseipdb', 'maltiverse']
                print(f"\n{Fore.CYAN}[*] Usando todos los motores disponibles{Style.RESET_ALL}")
            elif choice == '4':
                engines = ['virustotal']
                print(f"\n{Fore.CYAN}[*] Usando solo VirusTotal{Style.RESET_ALL}")
            elif choice == '5':
                engines = ['abuseipdb']
                print(f"\n{Fore.CYAN}[*] Usando solo AbuseIPDB{Style.RESET_ALL}")
            elif choice == '6':
                engines = ['maltiverse']
                print(f"\n{Fore.CYAN}[*] Usando solo Maltiverse{Style.RESET_ALL}")
            else:  # choice == '7'
                engines = select_engines()
            
            # Solicitar archivo de IOCs
            file_path = input(f"\n{Fore.GREEN}[?] Ingrese la ruta del archivo con IOCs: {Style.RESET_ALL}").strip()
            
            if file_path:
                print(f"\n{Fore.YELLOW}[*] Iniciando análisis con motores: {', '.join(engines)}{Style.RESET_ALL}")
                results = analyzer.analyze_iocs_from_file(file_path, engines)
                
                if results:
                    # Generar informe HTML
                    html_report = analyzer.generate_html_report(results, engines)
                    report_name = f"anubis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                    
                    with open(report_name, 'w', encoding='utf-8') as f:
                        f.write(html_report)
                    
                    print(f"\n{Fore.GREEN}[+] Informe generado: {report_name}{Style.RESET_ALL}")
                    
                    # Preguntar si abrir el informe
                    if input(f"{Fore.GREEN}[?] ¿Abrir informe en el navegador? (s/n): {Style.RESET_ALL}").lower() == 's':
                        webbrowser.open('file://' + os.path.realpath(report_name))
                else:
                    print(f"{Fore.YELLOW}[!] No se encontraron IOCs válidos para analizar.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] No se especificó archivo.{Style.RESET_ALL}")
        
        elif choice == '8':
            show_help()
        
        elif choice == '9':
            print(f"\n{Fore.GREEN}[*] Gracias por usar Anubis IOC Analyzer v2.0{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] ¡Hasta pronto!{Style.RESET_ALL}\n")
            break
        
        else:
            print(f"{Fore.RED}[!] Opción no válida. Por favor, seleccione una opción del menú.{Style.RESET_ALL}")
        
        input(f"\n{Fore.YELLOW}Presione Enter para continuar...{Style.RESET_ALL}")
        clear_screen()
        print_banner()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Programa interrumpido por el usuario.{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Cerrando Anubis IOC Analyzer...{Style.RESET_ALL}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error crítico: {e}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Por favor, reporte este error si persiste.{Style.RESET_ALL}\n")
        sys.exit(1)
        