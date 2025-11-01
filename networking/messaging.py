from __future__ import annotations

import platform
import subprocess
import socket
from contextlib import closing
from typing import Tuple, Optional


# Métodos de envío disponibles
METODO_MSG = "msg"  # Comando msg de Windows (RPC)
METODO_NET_SEND = "net_send"  # Net send (obsoleto en Windows moderno)
METODO_POWERSHELL = "powershell"  # PowerShell remoting
METODO_SSH_LINUX = "ssh_linux"  # SSH para sistemas Linux/Unix
METODO_SAMBA_LINUX = "samba_linux"  # Mensajes NetBIOS a Linux con Samba
METODO_NETCAT = "netcat"  # Socket TCP directo (sin autenticación)
METODO_WRITE_UNIX = "write_unix"  # Protocolo write de Unix (puerto 513)

# Puertos comunes para mensajería
PUERTO_SMB = 445  # SMB/CIFS
PUERTO_RPC = 135  # RPC Endpoint Mapper
PUERTO_NETBIOS = 139  # NetBIOS Session Service
PUERTO_WINRM = 5985  # Windows Remote Management (PowerShell)
PUERTO_SSH = 22  # SSH para Linux/Unix
PUERTO_WRITE = 513  # Write/rlogin
PUERTO_TALK = 517  # Talk (mensajería Unix antigua)
PUERTO_NTALK = 518  # New Talk


def enviar_mensaje(ip: str, mensaje: str, metodo: str = METODO_MSG, puerto: Optional[int] = None) -> Tuple[bool, str]:
    """
    Envía un mensaje a un dispositivo Windows o Linux.
    
    Args:
        ip: Dirección IP del dispositivo destino
        mensaje: Texto del mensaje a enviar
        metodo: Método de envío (msg, net_send, powershell, ssh_linux, samba_linux, netcat, write_unix)
        puerto: Puerto específico a usar (None = puerto por defecto del método)
    
    Returns:
        Tupla (éxito: bool, mensaje_error: str)
    """
    if not mensaje.strip():
        return False, "El mensaje no puede estar vacío."
    
    if metodo == METODO_MSG:
        return _enviar_via_msg(ip, mensaje)
    elif metodo == METODO_NET_SEND:
        return _enviar_via_net_send(ip, mensaje)
    elif metodo == METODO_POWERSHELL:
        return _enviar_via_powershell(ip, mensaje)
    elif metodo == METODO_SSH_LINUX:
        return _enviar_via_ssh_linux(ip, mensaje)
    elif metodo == METODO_SAMBA_LINUX:
        return _enviar_via_samba_linux(ip, mensaje)
    elif metodo == METODO_NETCAT:
        return _enviar_via_netcat(ip, mensaje, puerto or 9999)
    elif metodo == METODO_WRITE_UNIX:
        return _enviar_via_write_unix(ip, mensaje)
    else:
        return False, f"Método desconocido: {metodo}"


def enviar_mensaje_multiple(ips: list[str], mensaje: str, metodo: str = METODO_MSG) -> dict[str, Tuple[bool, str]]:
    """
    Envía un mensaje a múltiples destinatarios.
    
    Args:
        ips: Lista de direcciones IP destino
        mensaje: Texto del mensaje a enviar
        metodo: Método de envío a usar para todos
    
    Returns:
        Diccionario {ip: (éxito, mensaje_resultado)}
    """
    resultados = {}
    for ip in ips:
        exito, msg = enviar_mensaje(ip, mensaje, metodo)
        resultados[ip] = (exito, msg)
    return resultados


def _enviar_via_msg(ip: str, mensaje: str) -> Tuple[bool, str]:
    """
    Envía mensaje usando el comando 'msg' de Windows.
    Usa RPC (puerto 135) y SMB (puerto 445).
    """
    # Verificar que estamos en Windows
    if platform.system() != "Windows":
        return False, "El comando 'msg' solo está disponible en Windows. Use SSH para Linux."
    
    # Primero intentar con el método estándar (requiere sesión activa)
    comando = ["msg", f"/SERVER:{ip}", "*", mensaje]
    
    try:
        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            encoding="cp850",
            errors="ignore",
            check=False,
            timeout=10,
        )
        
        if resultado.returncode == 0:
            return True, "Mensaje enviado correctamente."
        
        # Capturar error
        error = resultado.stderr or resultado.stdout or "Error desconocido"
        error_lower = error.lower()
        
        # Error 1722 = RPC Server unavailable
        if "1722" in error or "error 1722" in error_lower:
            return False, (
                "El servicio RPC no está disponible en el dispositivo.\n\n"
                "Posibles causas:\n"
                "• El dispositivo tiene el firewall bloqueando RPC (puerto 135)\n"
                "• El servicio 'Llamada a procedimiento remoto (RPC)' está deshabilitado\n"
                "• El dispositivo no es Windows o no soporta mensajería remota\n\n"
                "Soluciones:\n"
                "1. Intente usar el método 'PowerShell Remoting' en Preferencias\n"
                "2. En el dispositivo destino, habilite el servicio RPC\n"
                "3. Configure el firewall para permitir RPC (puerto 135)"
            )
        
        if "no se encontró" in error_lower or "cannot find" in error_lower or "no session" in error_lower:
            return False, "No hay sesiones de usuario activas en el dispositivo remoto."
        elif "acceso denegado" in error_lower or "access denied" in error_lower:
            return False, "Acceso denegado. Verifique permisos administrativos y credenciales de red."
        elif "no se puede establecer" in error_lower or "cannot establish" in error_lower:
            return False, "No se puede conectar con el dispositivo. Verifique la conectividad de red."
        elif "5" == str(resultado.returncode):
            return False, "Acceso denegado. El dispositivo requiere autenticación administrativa."
        else:
            return False, f"Error al enviar mensaje: {error.strip()}"
    
    except subprocess.TimeoutExpired:
        return False, "Timeout al intentar enviar el mensaje."
    except Exception as e:
        return False, f"Error inesperado: {str(e)}"


def _enviar_via_net_send(ip: str, mensaje: str) -> Tuple[bool, str]:
    """
    Envía mensaje usando 'net send' (obsoleto, no funciona en Windows Vista+).
    Incluido solo por compatibilidad histórica.
    """
    # Verificar que estamos en Windows
    if platform.system() != "Windows":
        return False, "El comando 'net send' solo está disponible en Windows."
    
    comando = ["net", "send", ip, mensaje]
    
    try:
        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            encoding="cp850",
            errors="ignore",
            check=False,
            timeout=10,
        )
        
        if resultado.returncode == 0:
            return True, "Mensaje enviado correctamente."
        else:
            return False, "Net send no está disponible en este sistema (obsoleto desde Windows Vista)."
    
    except Exception as e:
        return False, f"Error: {str(e)}"


def _enviar_via_powershell(ip: str, mensaje: str) -> Tuple[bool, str]:
    """
    Envía mensaje usando PowerShell remoting.
    Requiere WinRM habilitado en el destino (puerto 5985).
    """
    # Script PowerShell para mostrar mensaje remoto
    script = f'''
    Invoke-Command -ComputerName {ip} -ScriptBlock {{
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show("{mensaje}", "Mensaje de red", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }}
    '''
    
    comando = ["powershell", "-NoProfile", "-Command", script]
    
    try:
        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            check=False,
            timeout=15,
        )
        
        if resultado.returncode == 0:
            return True, "Mensaje enviado correctamente."
        else:
            error = resultado.stderr or resultado.stdout or "Error desconocido"
            if "WinRM" in error or "remoting" in error.lower():
                return False, "PowerShell remoting no está habilitado en el dispositivo destino."
            elif "access denied" in error.lower() or "acceso denegado" in error.lower():
                return False, "Acceso denegado. Verifique credenciales y permisos."
            else:
                return False, f"Error: {error.strip()[:200]}"
    
    except subprocess.TimeoutExpired:
        return False, "Timeout al intentar enviar el mensaje."
    except Exception as e:
        return False, f"Error inesperado: {str(e)}"


def _enviar_via_ssh_linux(ip: str, mensaje: str) -> Tuple[bool, str]:
    """
    Envía mensaje a un sistema Linux/Unix usando SSH y notify-send o wall.
    Requiere SSH habilitado (puerto 22) y acceso configurado.
    """
    # Escapar comillas en el mensaje
    mensaje_escapado = mensaje.replace('"', '\\"').replace("'", "\\'")
    
    # Intentar primero con notify-send (muestra notificación gráfica)
    # Si falla, usar wall (broadcast a todas las terminales)
    script = f'''
    if command -v notify-send >/dev/null 2>&1; then
        DISPLAY=:0 notify-send "Mensaje de red" "{mensaje_escapado}" -u critical -t 10000
    elif command -v wall >/dev/null 2>&1; then
        echo "{mensaje_escapado}" | wall
    else
        echo "No hay herramientas de notificación disponibles"
        exit 1
    fi
    '''
    
    # Intentar con ssh usando clave (sin contraseña)
    comando = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=5",
        "-o", "BatchMode=yes",  # No pedir contraseña
        f"root@{ip}",  # Intentar con root primero
        script
    ]
    
    try:
        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            check=False,
            timeout=10,
        )
        
        if resultado.returncode == 0:
            return True, "Mensaje enviado correctamente al sistema Linux."
        else:
            # Intentar con usuario actual del sistema
            comando[5] = f"{ip}"  # Sin especificar usuario
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                check=False,
                timeout=10,
            )
            
            if resultado.returncode == 0:
                return True, "Mensaje enviado correctamente al sistema Linux."
            else:
                error = resultado.stderr or resultado.stdout or "Error desconocido"
                if "Permission denied" in error or "denied" in error.lower():
                    return False, "Acceso SSH denegado. Configure autenticación por clave SSH."
                elif "Connection refused" in error or "No route to host" in error:
                    return False, "No se puede conectar al servidor SSH (puerto 22)."
                elif "Host key verification failed" in error:
                    return False, "Verificación de clave del host falló."
                else:
                    return False, f"Error SSH: {error.strip()[:150]}"
    
    except subprocess.TimeoutExpired:
        return False, "Timeout al conectar por SSH."
    except FileNotFoundError:
        return False, "SSH no está disponible en este sistema. Instale un cliente SSH."
    except Exception as e:
        return False, f"Error inesperado: {str(e)}"


def _enviar_via_samba_linux(ip: str, mensaje: str) -> Tuple[bool, str]:
    """
    Envía mensaje a un sistema Linux/Unix con Samba usando net send de smbclient.
    Funciona sin SSH si el sistema tiene Samba instalado y configurado.
    No requiere autenticación.
    """
    # Verificar que smbclient esté disponible
    try:
        subprocess.run(
            ["which", "smbclient"],
            capture_output=True,
            check=True,
            timeout=2
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False, (
            "smbclient no está instalado en este sistema.\n\n"
            "Para instalar:\n"
            "• Ubuntu/Debian: sudo apt install smbclient\n"
            "• Fedora/RHEL: sudo dnf install samba-client\n"
            "• Arch: sudo pacman -S smbclient"
        )
    
    # Intentar enviar mensaje usando net send de samba
    # Nota: net send de samba es diferente del net send de Windows
    comando = [
        "smbclient",
        "-M", ip,  # Modo mensaje
        "-N",  # Sin contraseña
        "-I", ip  # IP específica
    ]
    
    try:
        resultado = subprocess.run(
            comando,
            input=mensaje,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            check=False,
            timeout=10,
        )
        
        if resultado.returncode == 0:
            return True, "Mensaje enviado a través de Samba/NetBIOS."
        else:
            error = resultado.stderr or resultado.stdout or "Error desconocido"
            if "Connection refused" in error or "No route to host" in error:
                return False, "No se puede conectar al servicio Samba (puerto 139/445)."
            elif "not listening" in error.lower() or "not running" in error.lower():
                return False, "El servicio Samba no está en ejecución en el dispositivo destino."
            else:
                return False, f"Error Samba: {error.strip()[:200]}\n\nNota: La mensajería NetBIOS puede estar deshabilitada en el destino."
    
    except subprocess.TimeoutExpired:
        return False, "Timeout al enviar mensaje por Samba."
    except Exception as e:
        return False, f"Error inesperado: {str(e)}"


def _enviar_via_netcat(ip: str, mensaje: str, puerto: int = 9999) -> Tuple[bool, str]:
    """
    Envía mensaje usando netcat (nc) a un puerto TCP específico.
    Requiere que el destino tenga un listener en ese puerto.
    
    Útil para sistemas Linux sin SSH donde se puede configurar un listener:
    En el destino ejecutar: nc -l -p 9999 | xargs -I {} notify-send "Mensaje" "{}"
    """
    # Verificar que netcat esté disponible
    nc_cmd = None
    for cmd in ["nc", "netcat", "ncat"]:
        try:
            subprocess.run(
                ["which", cmd],
                capture_output=True,
                check=True,
                timeout=2
            )
            nc_cmd = cmd
            break
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
    
    if not nc_cmd:
        return False, (
            "netcat no está instalado en este sistema.\n\n"
            "Para instalar:\n"
            "• Ubuntu/Debian: sudo apt install netcat\n"
            "• Fedora/RHEL: sudo dnf install nmap-ncat\n"
            "• Arch: sudo pacman -S openbsd-netcat\n\n"
            "Nota: En el destino debe haber un listener configurado:\n"
            "nc -l -p 9999 | while read msg; do notify-send 'Red' \"$msg\"; done"
        )
    
    # Enviar mensaje por netcat
    comando = [nc_cmd, "-w", "3", ip, str(puerto)]
    
    try:
        resultado = subprocess.run(
            comando,
            input=mensaje,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            check=False,
            timeout=5,
        )
        
        # Netcat no siempre indica error claramente
        if "Connection refused" in (resultado.stderr or ""):
            return False, f"No hay listener en el puerto {puerto} del dispositivo destino.\n\nEn el destino ejecutar:\nnc -l -p {puerto} | xargs -I {{}} notify-send 'Mensaje' '{{}}'"
        
        # Si no hubo error de conexión, asumimos éxito
        return True, f"Mensaje enviado al puerto {puerto}.\n\nNota: Verifique que el destino tenga un listener configurado."
    
    except subprocess.TimeoutExpired:
        return False, f"Timeout al conectar al puerto {puerto}."
    except Exception as e:
        return False, f"Error inesperado: {str(e)}"


def _enviar_via_write_unix(ip: str, mensaje: str) -> Tuple[bool, str]:
    """
    Intenta usar el protocolo 'write' de Unix (puerto 513).
    Protocolo antiguo, generalmente deshabilitado por seguridad.
    """
    return False, (
        "El protocolo 'write' (puerto 513) está obsoleto y deshabilitado en sistemas modernos por seguridad.\n\n"
        "Alternativas recomendadas:\n"
        "• SSH: Más seguro, requiere autenticación\n"
        "• Netcat: Requiere configurar listener en destino\n"
        "• Samba: Si el sistema tiene Samba instalado\n\n"
        "Para habilitar write (NO RECOMENDADO):\n"
        "En el destino: sudo systemctl enable rlogin.socket"
    )


def verificar_disponibilidad_mensajeria(ip: str, puertos: Optional[list[int]] = None) -> Tuple[bool, list[int]]:
    """
    Verifica si el dispositivo puede recibir mensajes comprobando puertos comunes.
    
    Args:
        ip: Dirección IP del dispositivo
        puertos: Lista de puertos a verificar (None = verificar todos los comunes)
    
    Returns:
        Tupla (tiene_algún_puerto_abierto: bool, lista_puertos_abiertos: list[int])
    """
    if puertos is None:
        puertos = [PUERTO_SMB, PUERTO_RPC, PUERTO_NETBIOS, PUERTO_WINRM, PUERTO_SSH, PUERTO_WRITE, PUERTO_TALK, PUERTO_NTALK]
    
    puertos_abiertos = []
    
    for puerto in puertos:
        if _verificar_puerto(ip, puerto):
            puertos_abiertos.append(puerto)
    
    return len(puertos_abiertos) > 0, puertos_abiertos


def detectar_sistema_operativo_por_puertos(puertos_abiertos: list[int]) -> str:
    """
    Intenta detectar el tipo de sistema operativo basándose en puertos abiertos.
    
    Args:
        puertos_abiertos: Lista de puertos abiertos detectados
    
    Returns:
        Tipo de sistema: "windows", "linux", "unknown"
    """
    puertos_set = set(puertos_abiertos)
    
    # Puertos típicos de Windows
    windows_ports = {PUERTO_SMB, PUERTO_RPC, PUERTO_NETBIOS, PUERTO_WINRM}
    # Puertos típicos de Linux
    linux_ports = {PUERTO_SSH}
    
    windows_count = len(puertos_set & windows_ports)
    linux_only = PUERTO_SSH in puertos_set and not any(p in puertos_set for p in windows_ports)
    
    if windows_count >= 2:
        return "windows"
    elif linux_only:
        return "linux"
    elif PUERTO_SSH in puertos_set:
        return "linux"  # SSH es más común en Linux
    elif any(p in puertos_set for p in windows_ports):
        return "windows"
    else:
        return "unknown"


def _verificar_puerto(ip: str, puerto: int, timeout: float = 0.5) -> bool:
    """Verifica si un puerto específico está abierto."""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((ip, puerto))
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False


def obtener_info_mensajeria() -> str:
    """
    Devuelve información sobre el sistema de mensajería.
    
    Returns:
        Texto explicativo sobre requisitos y limitaciones
    """
    return """
Sistema de Mensajería de Red

MÉTODOS DISPONIBLES PARA WINDOWS:
• msg (RPC): Servicio nativo de Windows (requiere RPC activo)
• PowerShell: Remoting de PowerShell (requiere WinRM)
• Net Send: Obsoleto en Windows modernos

MÉTODOS DISPONIBLES PARA LINUX:
• SSH: Más seguro y común (requiere autenticación por clave)
  - Usa notify-send o wall para mostrar mensajes
  - Puerto 22 debe estar abierto
  
• Samba/NetBIOS: Sin autenticación (si Samba está instalado)
  - Funciona si el sistema tiene Samba configurado
  - Puertos 139/445 deben estar abiertos
  - Comando: smbclient -M <ip>
  
• Netcat: Socket TCP directo (requiere listener en destino)
  - Muy flexible, cualquier puerto
  - Destino debe ejecutar: nc -l -p 9999 | xargs notify-send 'Msg'
  - NO requiere autenticación pero SÍ configuración previa

REQUISITOS GENERALES:
• Ambos equipos deben estar en la misma red local
• El firewall no debe bloquear los puertos necesarios
• Para Linux: El destino debe tener herramientas de notificación

RECOMENDACIONES DE SEGURIDAD:
• SSH: Más seguro, usar autenticación por clave
• Samba: Sin autenticación, solo en redes confiables
• Netcat: Sin cifrado, solo para pruebas/desarrollo

CONFIGURACIÓN EN DESTINO LINUX:

Para SSH (recomendado):
  1. sudo systemctl enable ssh
  2. Copiar clave pública: ssh-copy-id user@destino
  3. Instalar notify-send: sudo apt install libnotify-bin

Para Samba:
  1. sudo apt install samba
  2. Habilitar mensajería en /etc/samba/smb.conf:
     [global]
     message command = /usr/bin/notify-send "%f" "%s"

Para Netcat:
  1. Crear servicio systemd o ejecutar manualmente:
     nc -l -p 9999 | while read msg; do 
       notify-send "Mensaje de red" "$msg"
     done
"""
