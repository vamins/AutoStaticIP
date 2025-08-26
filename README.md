# AutoStaticIP
 script multiplataforma (Windows y macOS) diseñado para encontrar y configurar automáticamente una dirección IP estática libre dentro de una red local
## Requisitos
### Para Usuarios Finales (usando el `.exe` compilado)

- **Windows:**
    
    - **Npcap:** Es **obligatorio** tener Npcap instalado para que el escaneo de red funcione. Se puede descargar desde la [página oficial de Npcap](https://www.google.com/search?q=https://npcap.com/%23download&authuser=1).
        
        - **Importante:** Durante la instalación de Npcap, asegurarse de marcar la casilla **"Install Npcap in WinPcap API-compatible Mode"**.
            
    - **Permisos de Administrador:** El programa debe ser ejecutado como Administrador para poder modificar la configuración de red.
        
- **macOS:**
    
    - **Permisos de Superusuario:** El script debe ser ejecutado con `sudo`.
       

### Para Desarrolladores (ejecutando el script `.py`)

- **Python 3.7+**
    
- **Librerías de Python:**
    
    - `scapy`: `pip install scapy`
        
- **(Opcional) Para compilar el `.exe`:**
    
    - `pyinstaller`: `pip install pyinstaller`
        
Cómo Compilar? (Guía para Desarrolladores)

Si has modificado el script y quieres generar un nuevo archivo `.exe` para distribuirlo:

1. Asegúrate de tener Python y PyInstaller instalados.
    
2. Crea un archivo de icono (`.ico`) si deseas personalizar el ejecutable. Nómbralo `icono.ico` y colócalo en la misma carpeta que el script.
    
3. Abre una terminal (CMD o PowerShell) en la carpeta del proyecto.
    
4. Ejecuta el siguiente comando:
    
    Bash
    
    ```
    pyinstaller --onefile --name "AsignadorDeIP" --icon="icono.ico" tu_script.py
    ```
    
5. El archivo `AsignadorDeIP.exe` final estará en la subcarpeta `dist`.
