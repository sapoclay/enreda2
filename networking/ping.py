from __future__ import annotations

import ipaddress
import platform
import socket
import subprocess
from functools import lru_cache
from typing import Optional, Tuple


TIEMPO_ESPERA_MS = 400

# Caché para resultados de DNS (mejora rendimiento)
@lru_cache(maxsize=256)
def _resolver_dns_cached(direccion_ip: str) -> Optional[str]:
    """Versión cacheada de resolución DNS."""
    try:
        nombre, _, _ = socket.gethostbyaddr(direccion_ip)
        return nombre
    except (socket.herror, socket.gaierror, TimeoutError):
        return None


def ping_host(direccion_ip: str) -> Tuple[bool, Optional[int]]:
    """Ejecuta un ping rápido y devuelve una tupla (activo, ttl)."""

    # Detectar sistema operativo para usar los parámetros correctos
    sistema = platform.system()
    
    if sistema == "Windows":
        # Windows: -n (count), -w (timeout en ms)
        comando = ["ping", "-n", "1", "-w", str(TIEMPO_ESPERA_MS), direccion_ip]
    else:
        # Linux/Unix/macOS: -c (count), -W (timeout en segundos)
        timeout_segundos = max(1, TIEMPO_ESPERA_MS // 1000)
        comando = ["ping", "-c", "1", "-W", str(timeout_segundos), direccion_ip]
    
    try:
        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            errors="ignore",
            check=False,
        )
    except OSError:
        return False, None

    salida = resultado.stdout or ""
    ttl = _extraer_ttl(salida)

    if resultado.returncode == 0:
        return True, ttl

    salida_upper = salida.upper()
    if "TTL" in salida_upper:
        return True, ttl

    return False, ttl


def resolver_nombre(direccion_ip: str) -> Optional[str]:
    """Intenta obtener el nombre del host usando varias estrategias."""

    for estrategia in (
        _resolver_por_dns,
        _resolver_por_fqdn,
        _resolver_por_nslookup,
        _resolver_por_nbtstat,
    ):
        nombre = estrategia(direccion_ip)
        if nombre:
            return nombre
    return None


def _resolver_por_dns(direccion_ip: str) -> Optional[str]:
    """Resuelve nombre usando DNS (con caché)."""
    nombre = _resolver_dns_cached(direccion_ip)
    if nombre:
        return _normalizar_nombre(nombre)
    return None


def _resolver_por_fqdn(direccion_ip: str) -> Optional[str]:
    nombre = socket.getfqdn(direccion_ip)
    return _normalizar_nombre(nombre)


def _resolver_por_nslookup(direccion_ip: str) -> Optional[str]:
    comando = ["nslookup", direccion_ip]
    
    # Determinar encoding según el sistema operativo
    sistema = platform.system()
    encoding = "cp850" if sistema == "Windows" else "utf-8"
    
    try:
        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            encoding=encoding,
            errors="ignore",
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    if resultado.returncode != 0:
        return None

    for linea in (resultado.stdout or "").splitlines():
        linea = linea.strip()
        if not linea:
            continue
        if linea.lower().startswith("nombre") or linea.lower().startswith("name"):
            partes = linea.split(":", 1)
            if len(partes) == 2:
                posible = partes[1].strip()
                nombre = _normalizar_nombre(posible)
                if nombre:
                    return nombre
    return None


def _resolver_por_nbtstat(direccion_ip: str) -> Optional[str]:
    # nbtstat es específico de Windows, en Linux se puede usar nmblookup
    sistema = platform.system()
    
    if sistema == "Windows":
        comando = ["nbtstat", "-A", direccion_ip]
        encoding = "cp850"
    else:
        # En Linux, usar nmblookup (parte de samba-common-bin)
        # Si no está instalado, simplemente retornará None
        comando = ["nmblookup", "-A", direccion_ip]
        encoding = "utf-8"
    
    try:
        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            encoding=encoding,
            errors="ignore",
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    if resultado.returncode != 0:
        return None

    for linea in (resultado.stdout or "").splitlines():
        linea_limpia = linea.strip()
        if not linea_limpia or "<" not in linea_limpia:
            continue
        linea_min = linea_limpia.lower()
        if linea_min.startswith("nombre") or linea_min.startswith("name"):
            continue
        if "<00>" not in linea_min and "<20>" not in linea_min:
            continue
        partes = linea_limpia.split()
        if not partes:
            continue
        posible_nombre = partes[0].strip(" *\t")
        nombre_normalizado = _normalizar_nombre(posible_nombre)
        if nombre_normalizado:
            return nombre_normalizado

    return None


def _normalizar_nombre(nombre: str) -> Optional[str]:
    if not nombre:
        return None
    limpio = nombre.strip().rstrip(".")
    if not limpio:
        return None
    if _es_direccion_ip(limpio):
        return None
    return limpio


def _es_direccion_ip(valor: str) -> bool:
    try:
        ipaddress.ip_address(valor)
        return True
    except ValueError:
        return False


def _extraer_ttl(salida: str) -> Optional[int]:
    salida_upper = salida.upper()
    if "TTL=" not in salida_upper:
        return None
    for linea in salida.splitlines():
        linea_upper = linea.upper()
        if "TTL=" not in linea_upper:
            continue
        fragmentos = linea_upper.split("TTL=")
        if len(fragmentos) < 2:
            continue
        resto = fragmentos[1].strip()
        numero = ""
        for caracter in resto:
            if caracter.isdigit():
                numero += caracter
            else:
                break
        if numero:
            try:
                return int(numero)
            except ValueError:
                continue
    return None
