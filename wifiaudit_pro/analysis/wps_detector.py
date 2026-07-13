"""Detector de WPS — identifica puntos de acceso con WPS habilitado."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass
class WPSResult:
    """Resultado de la detección WPS para un punto de acceso."""
    bssid: str              # Dirección MAC del AP
    wps_locked: bool        # ¿WPS está bloqueado por intentos fallidos?
    wps_version: str        # Versión de WPS (ej. "1.0", "2.0" o "Unknown")


def detect_wps_wash(interface: str = "wlan0mon", timeout: int = 30) -> list[WPSResult]:
    """Ejecuta ``wash`` para detectar APs con WPS habilitado.

    Devuelve una lista de objetos ``WPSResult``. Requiere el binario ``wash``
    de la suite aircrack-ng instalado en el sistema.
    """
    try:
        proc = subprocess.run(
            ["wash", "-i", interface],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "Binario wash no encontrado. Instalar aircrack-ng: sudo apt install aircrack-ng"
        )
    except subprocess.TimeoutExpired:
        # Si el comando tarda demasiado, devolver lista vacía
        return []

    results: list[WPSResult] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        # Ignorar líneas vacías, cabeceras y separadores
        if not line or line.startswith("BSSID") or line.startswith("---"):
            continue
        parts = line.split()
        if len(parts) >= 4:
            results.append(
                WPSResult(
                    bssid=parts[0],
                    wps_locked=parts[1].upper() == "YES",
                    wps_version=parts[3] if len(parts) > 3 else "Unknown",
                )
            )
    return results


def detect_wps_from_csv(csv_content: str) -> list[WPSResult]:
    """Analiza la salida CSV de airodump-ng para encontrar APs con WPS habilitado.

    Es una alternativa a ``wash`` que parsea la salida CSV de
    ``airodump-ng --write-interval 1``.
    """
    results: list[WPSResult] = []
    for line in csv_content.splitlines():
        lower = line.lower()
        # Buscar líneas que contengan referencias a WPS
        if "wps" in lower or "wps_version" in lower:
            parts = line.split(",")
            if len(parts) >= 14:
                bssid = parts[0].strip()
                # Evitar cabeceras y líneas vacías
                if bssid and bssid != "BSSID":
                    results.append(
                        WPSResult(
                            bssid=bssid,
                            wps_locked=False,
                            wps_version="Unknown",
                        )
                    )
    return results
