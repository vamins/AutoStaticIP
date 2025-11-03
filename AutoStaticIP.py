# requiere Npcap para Scapy
# -*- coding: utf-8 -*-
import os
import sys
import ctypes
import subprocess
import platform
import time
import json 

try:
    from scapy.all import srp, Ether, ARP, conf
except ImportError:
    print("[!] ERROR: La librería 'scapy' no está instalada.")
    print("    Por favor, instálala ejecutando: pip install scapy")
    sys.exit(1)

# --- ARCHIVO DE CONFIGURACIÓN ---
CONFIG_FILE = "config.json"

# --- VALORES PREDETERMINADOS para usar como sugerencia en la primera ejecución si el usuario no introduce nada ---
# Estos valores ahora son "internos" a la función get_user_config
# y no están expuestos globalmente como un diccionario CONFIG.
#--------------------------------------------------------------------------------------------------

def check_and_request_privileges():
    """Verifica si el script tiene privilegios de Administrador en Windows.
       Si no los tiene, intenta reiniciarse con ellos."""
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        is_admin = False 

    if not is_admin:
        print("[!] Se requieren privilegios de Administrador. Reiniciando...")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)

def load_config():
    """Carga la configuración desde el archivo JSON.
       Devuelve un diccionario vacío si el archivo no existe o es inválido."""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                loaded_config = json.load(f)
                # Opcional: Validar que las claves mínimas estén presentes
                required_keys = ["interface_name", "scan_start", "scan_end", "gateway", "subnet_mask", "dns_primary", "dns_secondary", "temp_ip"]
                if all(key in loaded_config for key in required_keys):
                    print(f"[+] Configuración cargada desde '{CONFIG_FILE}'.")
                    return loaded_config
                else:
                    print(f"[!] Archivo de configuración '{CONFIG_FILE}' incompleto o inválido. Se solicitará la configuración.")
                    return {}
        except json.JSONDecodeError:
            print(f"[!] Error al leer '{CONFIG_FILE}'. El archivo está corrupto. Se solicitará la configuración.")
            return {}
        except Exception as e:
            print(f"[!] Error inesperado al cargar la configuración: {e}. Se solicitará la configuración.")
            return {}
    print(f"[*] No se encontró el archivo de configuración '{CONFIG_FILE}'. Se solicitará la configuración.")
    return {}

def save_config(config_data):
    """Guarda la configuración en el archivo JSON."""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config_data, f, indent=4)
        print(f"[+] Configuración guardada en '{CONFIG_FILE}'.")
    except IOError as e:
        print(f"[!] ERROR: No se pudo guardar la configuración en '{CONFIG_FILE}'. Detalles: {e}")

def get_user_config(existing_config=None):
    """
    Guía al usuario para introducir la configuración, utilizando valores existentes
    como sugerencia o valores predeterminados internos si no hay configuración existente.
    """
    if existing_config is None:
        existing_config = {}

    # Valores predeterminados internos a esta función para la primera ejecución
    default_values = {
        "interface_name": "Ethernet", 
        "scan_start": 30,
        "scan_end": 254,
        "gateway": "192.168.1.1",
        "subnet_mask": "255.255.255.0",
        "dns_primary": "8.8.8.8",
        "dns_secondary": "192.168.1.1",
        "temp_ip": "192.168.1.27"
    }

    print("\n--- CONFIGURACIÓN DE RED REQUERIDA ---")
    print("Por favor, introduce los datos de tu red. Presiona Enter para usar el valor sugerido.")

    # Función auxiliar para obtener la entrada del usuario con un valor por defecto
    def get_input_with_default(prompt, key, validation_func=None):
        while True:
            default_val = str(existing_config.get(key, default_values[key]))
            user_input = input(f"{prompt} [{default_val}]: ").strip()
            if not user_input:
                user_input = default_val
            
            if validation_func:
                if validation_func(user_input):
                    return user_input
                else:
                    print(f"    [!] Entrada inválida para {key}. Intenta de nuevo.")
            else:
                return user_input

    # Validadores
    def is_valid_ip(ip_str):
        parts = ip_str.split('.')
        return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) < 256 for part in parts)
    
    def is_valid_int_range(val_str, min_val, max_val):
        try:
            val = int(val_str)
            return min_val <= val <= max_val
        except ValueError:
            return False

    def is_valid_interface(interface_name_str):
        try:
            output = subprocess.check_output(f'netsh interface show interface name="{interface_name_str}"', shell=True, text=True, encoding='latin-1', stderr=subprocess.DEVNULL)
            return "Conectado" in output or "Desconectado" in output
        except subprocess.CalledProcessError:
            return False

    # 1. Nombre de la interfaz
    interface_name = get_input_with_default(
        "Nombre de la interfaz de red (ej. 'Ethernet', 'Wi-Fi')", 
        "interface_name", 
        is_valid_interface
    )

    # 2. Gateway
    gateway = get_input_with_default(
        "Puerta de enlace (Gateway, ej. 192.168.1.1)", 
        "gateway", 
        is_valid_ip
    )

    # 3. Máscara de subred
    subnet_mask = get_input_with_default(
        "Máscara de subred (ej. 255.255.255.0)", 
        "subnet_mask", 
        is_valid_ip
    )

    # 4. Rango de inicio
    scan_start_str = get_input_with_default(
        "Inicio del rango de IPs a escanear (ej. 30)", 
        "scan_start", 
        lambda x: is_valid_int_range(x, 1, 254)
    )
    scan_start = int(scan_start_str)

    # 5. Rango de fin
    # La validación de scan_end depende de scan_start, así que la hacemos aparte
    while True:
        scan_end_str = get_input_with_default(
            "Fin del rango de IPs a escanear (ej. 254)", 
            "scan_end"
        )
        if is_valid_int_range(scan_end_str, 1, 254):
            scan_end = int(scan_end_str)
            if scan_end > scan_start:
                break
            else:
                print(f"    [!] El valor de fin debe ser mayor que el de inicio ({scan_start}).")
        else:
            print("    [!] Entrada inválida. Por favor, introduce un número entre 1 y 254.")

    # Los DNS y la IP temporal se usarán de los valores predeterminados internos si no están en existing_config
    # Opcional: podrías añadir get_input_with_default para estos también si quieres que sean editables.
    dns_primary = existing_config.get("dns_primary", default_values["dns_primary"])
    dns_secondary = existing_config.get("dns_secondary", default_values["dns_secondary"])
    temp_ip = existing_config.get("temp_ip", default_values["temp_ip"])

    new_config = {
        "interface_name": interface_name,
        "scan_start": scan_start,
        "scan_end": scan_end,
        "gateway": gateway,
        "subnet_mask": subnet_mask,
        "dns_primary": dns_primary,
        "dns_secondary": dns_secondary,
        "temp_ip": temp_ip
    }
    return new_config

def set_static_ip(ip_address, config):
    """Ejecuta los comandos netsh para configurar la IP estática y los DNS en Windows."""
    interface = config["interface_name"]
    mask = config["subnet_mask"]
    gateway = config["gateway"]
    dns1 = config["dns_primary"]
    dns2 = config["dns_secondary"]
    
    print(f"\n[+] Asignando la IP estática {ip_address} a la interfaz '{interface}'...")
    
    commands = [
        f'netsh interface ip set address name="{interface}" static {ip_address} {mask} {gateway}',
        f'netsh interface ip set dns name="{interface}" static {dns1}',
        f'netsh interface ip add dns name="{interface}" {dns2} index=2'
    ]

    try:
        for cmd in commands:
            subprocess.run(cmd, check=True, shell=True, capture_output=True, text=True, encoding='latin-1')
        print("    - Asignación completada.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] ERROR: Falló la ejecución de un comando netsh.")
        print(f"    Comando: {e.cmd}")
        print(f"    Salida: {e.stderr.decode('latin-1', errors='ignore')}")
        return False

def find_all_potential_free_ips(config):
    """Escanea todo el rango usando Scapy y devuelve una LISTA de todas las IPs que parecen libres."""
    print(f"\n[2] Escaneando la red para encontrar IPs candidatas (Scapy)...")
    conf.verb = 0 
    ip_prefix = ".".join(config["gateway"].split('.')[:-1]) 
    
    ips_to_scan = [f"{ip_prefix}.{i}" for i in range(config['scan_start'], config['scan_end'] + 1)]
    
    packets = [Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip) for ip in ips_to_scan]
    
    ans, _ = srp(packets, timeout=2) 
    
    occupied_ips = {received.psrc for sent, received in ans}
    
    potential_free_ips = [ip for ip in ips_to_scan if ip not in occupied_ips]
    
    print(f"    - Se encontraron {len(occupied_ips)} dispositivos activos.")
    print(f"    - Se encontraron {len(potential_free_ips)} IPs potencialmente libres.")
    return potential_free_ips

def verify_connectivity(gateway_ip):
    """Hace ping a la puerta de enlace en Windows para verificar la conexión de red."""
    print("    - Verificando conectividad con la puerta de enlace", end="", flush=True)
    for _ in range(3):
        time.sleep(0.5)
        print(".", end="", flush=True)
    print() 
    
    command = ["ping", "-n", "2", "-w", "1000", gateway_ip]
        
    try:
        result = subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode == 0:
            print("    - ¡Verificación exitosa! La conexión funciona.")
            return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
        
    print("    - Verificación fallida. La IP podría estar en conflicto.")
    return False

def main():
    print("==================================================")
    print("  Asistente de Asignación de IP Estática (Windows)")
    print("==================================================")
    
    if platform.system() != "Windows":
        print("[!] Este script está diseñado exclusivamente para Windows y no puede ejecutarse en este sistema operativo.")
        input("Presiona Enter para salir.")
        sys.exit(1)

    check_and_request_privileges()
    
    # --- Lógica de carga/petición de configuración ---
    final_config = load_config() # Intenta cargar la configuración
    
    if not final_config: # Si no se cargó una configuración válida, la pedimos
        final_config = get_user_config()
        save_config(final_config) # Guardamos la configuración que el usuario acaba de introducir
    # -------------------------------------------------

    print(f"\n[1] Asignando IP temporal ({final_config['temp_ip']})...")
    if not set_static_ip(final_config['temp_ip'], final_config):
        input("\nPresiona Enter para salir.")
        sys.exit(1)
    
    print("    - Esperando a que la red se estabilice...")
    time.sleep(2)

    potential_free_ips = find_all_potential_free_ips(final_config)

    if not potential_free_ips:
        print("\n[!] No se encontraron direcciones IP libres en el rango especificado.")
        print(f"    Se mantendrá la IP temporal ({final_config['temp_ip']}).")
        input("\nEl proceso ha finalizado. Presiona Enter para salir.")
        sys.exit(0)

    print("\n[3] Iniciando proceso de asignación y verificación...")
    success = False
    last_tried_ip = ""
    
    for candidate_ip in potential_free_ips:
        last_tried_ip = candidate_ip
        if set_static_ip(candidate_ip, final_config):
            print("    - Esperando a que la red se estabilice...")
            time.sleep(2)
            
            if verify_connectivity(final_config["gateway"]):
                success = True
                print(f"\n¡Configuración final exitosa con la IP {candidate_ip}!")
                break
            else:
                print(f"    - Descartando IP {candidate_ip} y probando la siguiente...")
        else:
            print(f"    - No se pudo asignar la IP {candidate_ip}. Saltando a la siguiente.")

    if not success:
        print("\n[!] Se agotaron todas las IPs candidatas sin lograr una conexión estable.")
        print("    Puede que haya un problema con la red o todas las IPs detectadas como libres están en conflicto.")
        print(f"    Se ha dejado la última IP probada: {last_tried_ip}.")

    input("\nEl proceso ha finalizado. Presiona Enter para salir.")

if __name__ == "__main__":
    main()
