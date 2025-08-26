# Script final para compilar con PyInstaller (requiere Npcap instalado manualmente)
# -*- coding: utf-8 -*-
import os
import sys
import ctypes
import subprocess
import platform
import time # <--- IMPORTANTE: Importamos la librería time

try:
    from scapy.all import srp, Ether, ARP, conf
except ImportError:
    print("[!] ERROR: La librería 'scapy' no está instalada.")
    print("    Por favor, instálala ejecutando: pip install scapy")
    sys.exit(1)

# --- CONFIGURACIÓN ---
CONFIG = {
    "interface_name": "Ethernet", 
    "ip_range": "192.168.1.0/24", # --- CONFIGURACIÓN --- Rango del pool.
    "scan_start": 30, # --- CONFIGURACIÓN --- donde inicia a escanear
    "scan_end": 254,
    "gateway": "192.168.1.1", # --- CONFIGURACIÓN --- puerta de enlace
    "subnet_mask": "255.255.255.0", 
    "dns_primary": "8.8.8.8",
    "dns_secondary": "192.168.1.1",
    "temp_ip": "192.168.1.27" # --- CONFIGURACIÓN --- IP temporal.
}
# --------------------

def check_and_request_privileges():
    os_type = platform.system()
    if os_type == "Windows":
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except: is_admin = False
        if not is_admin:
            print("[!] Se requieren privilegios de Administrador. Reiniciando...")
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit(0)
    elif os_type in ["Darwin", "Linux"]:
        if os.geteuid() != 0:
            print("[!] Se requieren privilegios de superusuario (sudo).")
            print(f"    Por favor, ejecuta el script así: sudo python3 {os.path.basename(__file__)}")
            sys.exit(1)

def set_static_ip(ip_address, config):
    os_type = platform.system()
    interface, mask, gateway, dns1, dns2 = config["interface_name"], config["subnet_mask"], config["gateway"], config["dns_primary"], config["dns_secondary"]
    print(f"\n[+] Asignando la IP estática {ip_address} a la interfaz '{interface}'...")
    commands = []
    if os_type == "Windows":
        commands.extend([
            f'netsh interface ip set address name="{interface}" static {ip_address} {mask} {gateway}',
            f'netsh interface ip set dns name="{interface}" static {dns1}',
            f'netsh interface ip add dns name="{interface}" {dns2} index=2'
        ])
    elif os_type == "Darwin":
        commands.extend([
            f'networksetup -setmanual "{interface}" {ip_address} {mask} {gateway}',
            f'networksetup -setdnsservers "{interface}" {dns1} {dns2}'
        ])
    else:
        print(f"[!] Sistema Operativo '{os_type}' no soportado.")
        return False
    try:
        for cmd in commands:
            subprocess.run(cmd, check=True, shell=True, capture_output=True, text=True, encoding='latin-1')
        print("    - Asignación completada.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] ERROR: Falló la ejecución de un comando.\n    Comando: {e.cmd}\n    Salida: {e.stderr}")
        return False

def find_all_potential_free_ips(config):
    """Escanea todo el rango y devuelve una LISTA de todas las IPs que parecen libres."""
    print(f"\n[2] Escaneando la red para encontrar IPs candidatas...")
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
    """Hace ping a la puerta de enlace para verificar la conexión de red."""
    print("    - Verificando conectividad con la puerta de enlace...")
    os_type = platform.system()
    
    if os_type == "Windows":
        command = ["ping", "-n", "2", "-w", "1500", gateway_ip]
    else: # macOS y Linux
        command = ["ping", "-c", "2", "-t", "2", gateway_ip]
        
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
    print("  Asistente de Asignación de IP Estática (Win/Mac)")
    print("==================================================")
    
    print(f"\n[1] Asignando IP temporal ({CONFIG['temp_ip']})...")
    if not set_static_ip(CONFIG['temp_ip'], CONFIG):
        input("\nPresiona Enter para salir.")
        sys.exit(1)
    
    # --- AÑADIMOS UNA PAUSA AQUÍ TAMBIÉN, PARA LA IP TEMPORAL ---
    print("    - Esperando a que la red se estabilice...")
    time.sleep(2)

    potential_free_ips = find_all_potential_free_ips(CONFIG)

    if not potential_free_ips:
        print("\n[!] No se encontraron direcciones IP libres en el rango especificado.")
        print(f"    Se mantendrá la IP temporal ({CONFIG['temp_ip']}).")
        input("\nEl proceso ha finalizado. Presiona Enter para salir.")
        sys.exit(0)

    print("\n[3] Iniciando proceso de asignación y verificación...")
    success = False
    last_tried_ip = ""
    for candidate_ip in potential_free_ips:
        last_tried_ip = candidate_ip
        if set_static_ip(candidate_ip, CONFIG):
            # --- LA PAUSA CLAVE ESTÁ AQUÍ ---
            print("    - Esperando a que la red se estabilice...")
            time.sleep(2) # Pausa de 2 segundos
            
            if verify_connectivity(CONFIG["gateway"]):
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
    check_and_request_privileges()
    main()