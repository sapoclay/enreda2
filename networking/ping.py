from __future__ import annotations

import ipaddress
import socket
import subprocess
from typing import Optional, Tuple


TIEMPO_ESPERA_MS = 400


def ping_host(direccion_ip: str) -> Tuple[bool, Optional[int]]:
    """Ejecuta un ping rápido y devuelve una tupla (activo, ttl)."""

    comando = ["ping", "-n", "1", "-w", str(TIEMPO_ESPERA_MS), direccion_ip]
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
    try:
        nombre, _, _ = socket.gethostbyaddr(direccion_ip)
    except (socket.herror, socket.gaierror, TimeoutError):
        return None
    return _normalizar_nombre(nombre)


def _resolver_por_fqdn(direccion_ip: str) -> Optional[str]:
    nombre = socket.getfqdn(direccion_ip)
    return _normalizar_nombre(nombre)


def _resolver_por_nslookup(direccion_ip: str) -> Optional[str]:
    comando = ["nslookup", direccion_ip]
    try:
        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            encoding="cp850",
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
    comando = ["nbtstat", "-A", direccion_ip]
    try:
        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            encoding="cp850",
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
        if linea_min.startswith("nombre"):
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
