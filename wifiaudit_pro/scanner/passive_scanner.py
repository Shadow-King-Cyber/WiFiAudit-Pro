"""Escáner pasivo — wrapper de airodump-ng para descubrimiento de redes."""

from __future__ import annotations

import csv
import io
import subprocess
from dataclasses import dataclass


@dataclass
class ScanResult:
    """Resultado del escaneo de una red WiFi individual."""
    bssid: str          # Dirección MAC del punto de acceso
    ssid: str           # Nombre de la red
    channel: int        # Canal de radio
    encryption: str     # Tipo de cifrado (cadena cruda de airodump-ng)
    signal_dbm: int     # Fuerza de señal en dBm
    packets: int        # Paquetes capturados


def scan_networks(
    interface: str = "wlan0mon",
    duration: int = 60,
    output_prefix: str = "/tmp/wifiaudit_scan",
) -> list[ScanResult]:
    """Ejecuta airodump-ng en modo pasivo y devuelve las redes descubiertas.

    Requiere el binario ``airodump-ng`` de la suite aircrack-ng y un
    adaptador inalámbrico en modo monitor.

    Args:
        interface: Nombre de la interfaz en modo monitor.
        duration: Duración del escaneo en segundos.
        output_prefix: Prefijo para los archivos de salida de airodump-ng.

    Returns:
        Lista de objetos ``ScanResult``.
    """
    csv_path = f"{output_prefix}-01.csv"

    # Construir comando de airodump-ng
    cmd = [
        "airodump-ng",
        "--write-interval", "1",
        "--output-format", "csv",
        "-w", output_prefix,
        interface,
    ]

    try:
        # Ejecutar airodump-ng en segundo plano
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        import time
        # Esperar la duración especificada
        time.sleep(duration)
        # Terminar el proceso limpiamente
        proc.terminate()
        proc.wait(timeout=10)
    except FileNotFoundError:
        raise RuntimeError(
            "airodump-ng no encontrado. Instalar: sudo apt install aircrack-ng"
        )

    return _parse_csv(csv_path)


def scan_networks_mock() -> list[ScanResult]:
    """Devuelve resultados de escaneo simulados para pruebas sin hardware."""
    return [
        ScanResult(
            bssid="AA:BB:CC:DD:EE:01",
            ssid="HomeNetwork_2G",
            channel=1,
            encryption="WPA2",
            signal_dbm=-45,
            packets=1200,
        ),
        ScanResult(
            bssid="AA:BB:CC:DD:EE:02",
            ssid="OfficeWiFi",
            channel=6,
            encryption="WPA2",
            signal_dbm=-52,
            packets=800,
        ),
        ScanResult(
            bssid="AA:BB:CC:DD:EE:03",
            ssid="CoffeeShop_Free",
            channel=11,
            encryption="OPN",
            signal_dbm=-60,
            packets=3000,
        ),
        ScanResult(
            bssid="AA:BB:CC:DD:EE:04",
            ssid="TP-LINK_WR841N",
            channel=3,
            encryption="WPA",
            signal_dbm=-38,
            packets=500,
        ),
        ScanResult(
            bssid="AA:BB:CC:DD:EE:05",
            ssid="GuestNetwork",
            channel=1,
            encryption="WPA3",
            signal_dbm=-55,
            packets=900,
        ),
    ]


def _parse_csv(csv_path: str) -> list[ScanResult]:
    """Parsea un archivo CSV de salida de airodump-ng."""
    results: list[ScanResult] = []
    try:
        with open(csv_path, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except FileNotFoundError:
        return results

    # El CSV de airodump-ng tiene dos secciones separadas por una línea vacía
    sections = content.split("\n\n")
    if not sections:
        return results

    # La primera sección contiene información de los APs
    reader = csv.reader(io.StringIO(sections[0]))
    for row in reader:
        # Cada fila debe tener al menos 14 columnas
        if len(row) < 14:
            continue
        bssid = row[0].strip()
        # Ignorar cabeceras, líneas vacías y separadores
        if not bssid or bssid == "BSSID" or bssid.startswith("---"):
            continue
        try:
            channel = int(row[3].strip()) if row[3].strip() else 0
        except ValueError:
            channel = 0
        try:
            signal = int(row[8].strip()) if row[8].strip() else 0
        except ValueError:
            signal = 0
        try:
            packets = int(row[10].strip()) if row[10].strip() else 0
        except ValueError:
            packets = 0

        results.append(
            ScanResult(
                bssid=bssid,
                ssid=row[13].strip() if len(row) > 13 else "",
                channel=channel,
                encryption=row[5].strip() if len(row) > 5 else "",
                signal_dbm=signal,
                packets=packets,
            )
        )
    return results
