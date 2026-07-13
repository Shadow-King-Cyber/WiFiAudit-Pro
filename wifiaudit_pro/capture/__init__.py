"""Módulo de captura de handshakes WPA/WPA2."""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass

from ..core.scope_manager import ScopeManager
from ..core.audit_logger import AuditLogger


@dataclass
class CaptureResult:
    """Resultado de una operación de captura de handshake."""
    bssid: str          # BSSID objetivo
    file_path: str      # Ruta al archivo .cap resultante
    success: bool       # ¿La captura fue exitosa?
    message: str        # Mensaje descriptivo del resultado


def capture_handshake(
    bssid: str,
    scope: ScopeManager,
    logger: AuditLogger,
    interface: str = "wlan0mon",
    channel: int | None = None,
    deauth_count: int = 5,
    timeout: int = 120,
    output_prefix: str = "/tmp/wifiaudit_capture",
) -> CaptureResult:
    """Captura un handshake de 4 vías WPA/WPA2.

    Este es un módulo ACTIVO — valida el BSSID contra el alcance antes
    de realizar cualquier acción.

    Args:
        bssid: BSSID objetivo.
        scope: Instancia de ScopeManager para verificación de autorización.
        logger: Instancia de AuditLogger.
        interface: Interfaz en modo monitor.
        channel: Canal a fijar (opcional, mejora velocidad de captura).
        deauth_count: Número de tramas de deautenticación a enviar.
        timeout: Segundos máximos de espera para el handshake.
        output_prefix: Prefijo de ruta para los archivos capturados.

    Returns:
        ``CaptureResult`` con estado de éxito y detalles.
    """
    # GATE: Validar que el BSSID esté en el alcance autorizado
    if not scope.is_authorized(bssid):
        logger.log_denied("HANDSHAKE_CAPTURE", bssid)
        return CaptureResult(
            bssid=bssid,
            file_path="",
            success=False,
            message=f"El BSSID {bssid} NO está en el alcance autorizado.",
        )

    logger.log("HANDSHAKE_CAPTURE", bssid, "STARTED")

    cap_file = f"{output_prefix}-01.cap"

    # Construir comando de airodump-ng para captura dirigida
    cmd = [
        "airodump-ng",
        "--bssid", bssid,
        "--write", output_prefix,
        "--output-format", "cap",
    ]
    # Fijar canal si se especifica (mejora la velocidad de captura)
    if channel:
        cmd.extend(["--channel", str(channel)])
    cmd.append(interface)

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Enviar tramas de deauth para forzar la reconexión y capturar handshake
        if deauth_count > 0:
            _send_deauth(bssid, interface, deauth_count)

        # Esperar a que se capture el handshake
        time.sleep(timeout)
        proc.terminate()
        proc.wait(timeout=10)
    except FileNotFoundError:
        logger.log("HANDSHAKE_CAPTURE", bssid, "ERROR_BINARY_NOT_FOUND")
        return CaptureResult(
            bssid=bssid,
            file_path="",
            success=False,
            message="airodump-ng no encontrado. Instalar suite aircrack-ng.",
        )

    logger.log("HANDSHAKE_CAPTURE", bssid, "COMPLETED")
    return CaptureResult(
        bssid=bssid,
        file_path=cap_file,
        success=True,
        message=f"Captura completada. Salida: {cap_file}",
    )


def capture_handshake_mock(bssid: str) -> CaptureResult:
    """Devuelve un resultado de captura simulado para pruebas."""
    return CaptureResult(
        bssid=bssid,
        file_path="/tmp/mock_capture-01.cap",
        success=True,
        message="Captura simulada completada.",
    )


def _send_deauth(bssid: str, interface: str, count: int) -> None:
    """Envía tramas de deautenticación usando aireplay-ng."""
    cmd = [
        "aireplay-ng",
        "--deauth", str(count),
        "-a", bssid,
        interface,
    ]
    try:
        subprocess.run(
            cmd,
            capture_output=True,
            timeout=30,
        )
    except FileNotFoundError:
        # aireplay-ng no instalado; omitir silenciosamente
        pass
