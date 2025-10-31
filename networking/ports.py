from __future__ import annotations

import socket
from contextlib import closing
from typing import Iterable, List

PUERTOS_COMUNES: List[int] = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    135,
    139,
    143,
    443,
    445,
    587,
    993,
    995,
    3306,
    3389,
    5900,
]

PUERTOS_EXTENDIDOS: List[int] = sorted(
    set(
        PUERTOS_COMUNES
        + [
            7,
            19,
            37,
            42,
            67,
            68,
            69,
            79,
            88,
            102,
            111,
            113,
            119,
            135,
            137,
            138,
            161,
            162,
            179,
            389,
            427,
            445,
            500,
            512,
            513,
            514,
            873,
            902,
            912,
            1080,
            1433,
            1521,
            1723,
            2049,
            2082,
            2083,
            2483,
            2484,
            3268,
            3690,
            5060,
            5432,
            5901,
            5985,
            5986,
            6379,
            8080,
            8443,
            9000,
        ]
    )
)

TIEMPO_ESPERA_SEGUNDOS = 0.4


def escanear_puertos(direccion_ip: str, puertos: Iterable[int] | None = None) -> List[int]:
    """Devuelve una lista de puertos accesibles mediante TCP en la IP dada."""

    lista = list(puertos) if puertos is not None else PUERTOS_COMUNES
    abiertos: List[int] = []

    for puerto in lista:
        if _esta_abierto(direccion_ip, puerto):
            abiertos.append(puerto)

    return abiertos


def escanear_puertos_extenso(direccion_ip: str) -> List[int]:
    """Realiza un escaneo más amplio sobre una lista extendida de puertos comunes."""

    return escanear_puertos(direccion_ip, PUERTOS_EXTENDIDOS)


def _esta_abierto(direccion_ip: str, puerto: int) -> bool:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(TIEMPO_ESPERA_SEGUNDOS)
        try:
            sock.connect((direccion_ip, puerto))
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False
    return True
