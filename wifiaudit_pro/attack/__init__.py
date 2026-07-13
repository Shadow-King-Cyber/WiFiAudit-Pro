"""Módulo de ataque — ataque de diccionario offline contra handshakes capturados."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

from ..core.scope_manager import ScopeManager
from ..core.audit_logger import AuditLogger


@dataclass
class CrackResult:
    """Resultado de un intento de cracking de contraseña."""
    bssid: str              # BSSID objetivo
    password_found: str | None  # Contraseña encontrada (o None)
    time_seconds: float     # Tiempo invertido en segundos
    keys_tested: int        # Número de claves probadas
    success: bool           # ¿Se encontró la contraseña?
    message: str            # Mensaje descriptivo del resultado


def dictionary_attack(
    handshake_path: str,
    wordlist_path: str,
    bssid: str,
    scope: ScopeManager,
    logger: AuditLogger,
    timeout: int = 3600,
) -> CrackResult:
    """Ejecuta un ataque de diccionario offline usando aircrack-ng.

    Este es un módulo ACTIVO — valida el BSSID contra el alcance antes
    de realizar cualquier acción.

    Args:
        handshake_path: Ruta al archivo .cap capturado.
        wordlist_path: Ruta al archivo de diccionario.
        bssid: BSSID objetivo.
        scope: Instancia de ScopeManager para verificación de autorización.
        logger: Instancia de AuditLogger.
        timeout: Segundos máximos para el ataque.

    Returns:
        ``CrackResult`` con detalles del resultado.
    """
    # GATE: Validar que el BSSID esté en el alcance autorizado
    if not scope.is_authorized(bssid):
        logger.log_denied("DICTIONARY_ATTACK", bssid)
        return CrackResult(
            bssid=bssid,
            password_found=None,
            time_seconds=0,
            keys_tested=0,
            success=False,
            message=f"El BSSID {bssid} NO está en el alcance autorizado.",
        )

    logger.log("DICTIONARY_ATTACK", bssid, "STARTED")

    # Construir comando de aircrack-ng
    cmd = [
        "aircrack-ng",
        "-w", wordlist_path,
        "-b", bssid,
        "--stdout",
        handshake_path,
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        logger.log("DICTIONARY_ATTACK", bssid, "ERROR_BINARY_NOT_FOUND")
        return CrackResult(
            bssid=bssid,
            password_found=None,
            time_seconds=0,
            keys_tested=0,
            success=False,
            message="aircrack-ng no encontrado. Instalar suite aircrack-ng.",
        )
    except subprocess.TimeoutExpired:
        logger.log("DICTIONARY_ATTACK", bssid, "TIMEOUT")
        return CrackResult(
            bssid=bssid,
            password_found=None,
            time_seconds=timeout,
            keys_tested=0,
            success=False,
            message="El ataque excedió el tiempo límite.",
        )

    # Combinar stdout y stderr para parsear resultados
    output = proc.stdout + proc.stderr
    password = _parse_password(output)
    keys_tested = _parse_keys_tested(output)

    if password:
        logger.log("DICTIONARY_ATTACK", bssid, "SUCCESS", extra={"password_length": len(password)})
        return CrackResult(
            bssid=bssid,
            password_found=password,
            time_seconds=0,
            keys_tested=keys_tested,
            success=True,
            message="¡Contraseña encontrada!",
        )

    logger.log("DICTIONARY_ATTACK", bssid, "NOT_FOUND")
    return CrackResult(
        bssid=bssid,
        password_found=None,
        time_seconds=0,
        keys_tested=keys_tested,
        success=False,
        message="Contraseña no encontrada en el diccionario.",
    )


def dictionary_attack_mock(bssid: str, password: str = "password123") -> CrackResult:
    """Devuelve un resultado de cracking simulado para pruebas."""
    return CrackResult(
        bssid=bssid,
        password_found=password,
        time_seconds=2.5,
        keys_tested=1000,
        success=True,
        message="Simulación: contraseña encontrada.",
    )


def _parse_password(output: str) -> str | None:
    """Extrae la contraseña encontrada de la salida de aircrack-ng."""
    for line in output.splitlines():
        if "KEY FOUND!" in line:
            # Formato esperado: KEY FOUND! [ password ]
            start = line.find("[") + 1
            end = line.find("]")
            if start > 0 and end > start:
                return line[start:end].strip()
    return None


def _parse_keys_tested(output: str) -> int:
    """Extrae el número de claves probadas de la salida de aircrack-ng."""
    for line in output.splitlines():
        if "keys tested" in line.lower():
            parts = line.split()
            for part in parts:
                try:
                    return int(part.replace(",", ""))
                except ValueError:
                    continue
    return 0
