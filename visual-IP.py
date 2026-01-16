#!/usr/bin/env python3
# =================================================================
# PROGRAMA: Network Intelligence Dashboard Pro v1.0
# AUTOR: Matias Jofre Figueroa (vamins)
# COPYRIGHT: © 2026 Matias Jofre Figueroa (vamins)
# =================================================================

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import json
import os
import threading
import subprocess
import time
import ctypes
import sys

# Bandera para ocultar ventanas de terminal en Windows
CREATE_NO_WINDOW = 0x08000000

# --- Elevación de Privilegios (Modo Administrador) ---
def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

if not is_admin():
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    except: pass
    sys.exit()

# --- Gestión de Scapy y Npcap ---
try:
    from scapy.all import srp, Ether, ARP, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class NetDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Intelligence Dashboard Pro v1.0")
        self.root.geometry("600x780")
        self.root.configure(bg="#f5f5f5")
        self.root.resizable(False, False)

        self.config_file = "config.json"
        self.default_data = {
            "interface_name": "", "gateway": "192.168.1.1", "subnet_mask": "255.255.255.0",
            "dns_primary": "8.8.8.8", "dns_secondary": "1.1.1.1", "temp_ip": "192.168.1.200",
            "scan_start": "30", "scan_end": "254"
        }
        
        # Cache de interfaces para apertura instantánea
        self.cached_interfaces = ["Cargando..."]
        self.config_data = self.cargar_config_inicial()
        
        self.setup_ui()
        self.check_conexion_loop()
        
        # Iniciar detección de interfaces en segundo plano
        threading.Thread(target=self.precargar_interfaces, daemon=True).start()

    def cargar_config_inicial(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    return {**self.default_data, **json.load(f)}
            except: return self.default_data
        return self.default_data

    def precargar_interfaces(self):
        """Busca las interfaces al inicio para que el Pop-up sea instantáneo"""
        try:
            if os.name == 'nt':
                cmd = ["powershell", "-Command", "Get-NetAdapter | Select-Object -ExpandProperty Name"]
                res = subprocess.run(cmd, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
                self.cached_interfaces = [line.strip() for line in res.stdout.splitlines() if line.strip()]
            else:
                res = subprocess.run(["ip", "-br", "link"], capture_output=True, text=True)
                self.cached_interfaces = [line.split()[0] for line in res.stdout.splitlines() if line.split()[0] != "lo"]
        except:
            self.cached_interfaces = ["Ethernet", "Wi-Fi"]
        
        if not self.cached_interfaces:
            self.cached_interfaces = ["Ethernet", "Wi-Fi"]

    def setup_ui(self):
        # --- 1. BARRA DE ESTADO (TOP) ---
        self.status_bar = tk.Label(self.root, text="VERIFICANDO...", fg="white", bg="#7f8c8d", font=("Segoe UI", 11, "bold"), height=2)
        self.status_bar.pack(fill=tk.X)

        # --- 2. ZONA DE BOTONES ---
        mid_frame = tk.Frame(self.root, bg="#f5f5f5", pady=25)
        mid_frame.pack(fill=tk.X)

        self.btn_config = tk.Button(mid_frame, text="⚙ CONFIGURACIÓN", command=self.abrir_popup_config, bg="#34495e", fg="white", font=("Segoe UI", 10, "bold"), width=18, height=2, relief=tk.FLAT, cursor="hand2")
        self.btn_config.pack(side=tk.LEFT, padx=45)

        self.btn_start = tk.Button(mid_frame, text="▶ INICIAR", command=self.iniciar_hilo_proceso, bg="#2980b9", fg="white", font=("Segoe UI", 10, "bold"), width=18, height=2, relief=tk.FLAT, cursor="hand2")
        self.btn_start.pack(side=tk.RIGHT, padx=45)

        # --- 3. BARRA DE PROGRESO ---
        progress_frame = tk.Frame(self.root, bg="#f5f5f5", padx=25)
        progress_frame.pack(fill=tk.X, pady=(0, 10))
        self.progress = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, length=100, mode='determinate')
        self.progress.pack(fill=tk.X)

        # --- 4. CONSOLA DE LOGS ---
        tk.Label(self.root, text="DETALLES DE OPERACIÓN", bg="#f5f5f5", fg="#95a5a6", font=("Segoe UI", 8, "bold")).pack(anchor=tk.W, padx=25)
        self.console = scrolledtext.ScrolledText(self.root, bg="#1e1e1e", fg="#00ff00", font=("Consolas", 10), padx=10, pady=10, borderwidth=0)
        self.console.pack(fill=tk.BOTH, expand=True, padx=25, pady=(0, 5))
        
        # --- 5. FIRMA DE COPYRIGHT (CENTRO ABAJO) ---
        self.footer = tk.Label(
            self.root, 
            text="Desarrollado por Matias Jofre Figueroa (vamins) © 2026", 
            bg="#f5f5f5", 
            fg="#95a5a6", 
            font=("Segoe UI", 8, "bold italic")
        )
        self.footer.pack(pady=10)

        self.log(">>> Sistema listo.")

    def log(self, mensaje):
        self.console.config(state=tk.NORMAL)
        self.console.insert(tk.END, f"{mensaje}\n")
        self.console.config(state=tk.DISABLED); self.console.see(tk.END)

    def abrir_popup_config(self):
        """Apertura instantánea de ajustes"""
        popup = tk.Toplevel(self.root); popup.title("Configuración de Red"); popup.geometry("400x620"); popup.grab_set()
        
        tk.Label(popup, text="Interfaz de Red:", font=("Segoe UI", 9, "bold")).pack(anchor=tk.W, padx=30, pady=(15,0))
        self.combo_int = ttk.Combobox(popup, values=self.cached_interfaces, state="readonly")
        
        if self.cached_interfaces == ["Cargando..."]:
            self.precargar_interfaces()
            self.combo_int.config(values=self.cached_interfaces)

        self.combo_int.set(self.config_data.get("interface_name", "Seleccione...")); self.combo_int.pack(fill=tk.X, padx=30)

        fields = [("Gateway:", "gateway"), ("Máscara:", "subnet_mask"), ("DNS Primario:", "dns_primary"), 
                  ("DNS Secundario:", "dns_secondary"), ("IP Temporal:", "temp_ip"), 
                  ("Inicio Rango:", "scan_start"), ("Fin Rango:", "scan_end")]

        entries = {}
        for label, key in fields:
            tk.Label(popup, text=label).pack(anchor=tk.W, padx=30, pady=(5,0))
            ent = ttk.Entry(popup); ent.insert(0, str(self.config_data.get(key, ""))); ent.pack(fill=tk.X, padx=30); entries[key] = ent

        def guardar():
            self.config_data["interface_name"] = self.combo_int.get()
            for key, ent in entries.items(): self.config_data[key] = ent.get()
            with open(self.config_file, 'w', encoding='utf-8') as f: json.dump(self.config_data, f, indent=4)
            self.log("[✓] Ajustes guardados."); popup.destroy()

        tk.Button(popup, text="GUARDAR CAMBIOS", command=guardar, bg="#27ae60", fg="white", font=("Segoe UI", 10, "bold"), height=2).pack(pady=25, fill=tk.X, padx=30)

    def check_conexion_loop(self):
        def ping():
            res = subprocess.run(['ping', '-n', '1', '-w', '1000', '8.8.8.8'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW)
            color = "#27ae60" if res.returncode == 0 else "#e74c3c"
            text = "● ESTADO: CONECTADO" if res.returncode == 0 else "● ESTADO: DESCONECTADO"
            self.status_bar.config(text=text, bg=color)
            self.root.after(5000, self.check_conexion_loop)
        threading.Thread(target=ping, daemon=True).start()

    def set_ip(self, ip):
        try:
            cmd = f'netsh interface ip set address name="{self.config_data["interface_name"]}" static {ip} {self.config_data["subnet_mask"]} {self.config_data["gateway"]}'
            subprocess.run(cmd, shell=True, creationflags=CREATE_NO_WINDOW)
            dns = f'netsh interface ip set dns name="{self.config_data["interface_name"]}" static {self.config_data["dns_primary"]}'
            subprocess.run(dns, shell=True, creationflags=CREATE_NO_WINDOW)
            return True
        except: return False

    def iniciar_hilo_proceso(self):
        if not self.config_data["interface_name"] or self.config_data["interface_name"] in ["Seleccione...", "Cargando..."]:
            messagebox.showwarning("Error", "Seleccione una interfaz válida."); return
        self.btn_start.config(state=tk.DISABLED); self.progress['value'] = 0
        threading.Thread(target=self.proceso_real, daemon=True).start()

    def proceso_real(self):
        try:
            self.log("\n[1] Aplicando IP Temporal..."); self.progress['value'] = 10
            self.set_ip(self.config_data["temp_ip"]); time.sleep(3)
            
            if not SCAPY_AVAILABLE: 
                self.log("[!] Error: Npcap o Scapy no detectados."); 
                messagebox.showerror("Driver Faltante", "Por favor instale Npcap para habilitar el escaneo.")
                return
            
            prefix = ".".join(self.config_data["gateway"].split(".")[:-1])
            start, end = int(self.config_data["scan_start"]), int(self.config_data["scan_end"])
            ips = [f"{prefix}.{i}" for i in range(start, end + 1)]
            
            self.log(f"[*] Escaneando {len(ips)} IPs..."); self.progress['value'] = 30
            conf.verb = 0
            ans, _ = srp([Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip) for ip in ips], timeout=2, verbose=0)
            
            libres = [ip for ip in ips if ip not in {r.psrc for s, r in ans} and ip != self.config_data["gateway"]]
            self.progress['value'] = 60
            
            if not libres: self.log("[-] Sin IPs libres."); return

            step = 40 / len(libres) if libres else 0
            for ip in libres:
                self.log(f"[*] Probando IP: {ip}")
                self.set_ip(ip); time.sleep(4)
                check = subprocess.run(['ping', '-n', '1', '-w', '1500', self.config_data["gateway"]], stdout=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW)
                if check.returncode == 0:
                    self.log(f"\n[★] ¡ÉXITO! {ip} operativa."); self.progress['value'] = 100
                    messagebox.showinfo("Completado", f"IP {ip} asignada con éxito."); break
                self.progress['value'] += step
        except Exception as e: self.log(f"[-] Error: {str(e)}")
        finally: self.btn_start.config(state=tk.NORMAL)

if __name__ == "__main__":
    root = tk.Tk(); app = NetDashboard(root); root.mainloop()
