"""Motor de scoring de riesgo — asigna un nivel de riesgo a cada hallazgo de red."""

from __future__ import annotations

from dataclasses import dataclass

# -- constantes de puntuación (documentadas, reproducibles) -----------------

# Puntuación por tipo de cifrado
SCORE_WEP = 40           # WEP es roto, riesgo muy alto
SCORE_OPEN = 50          # Red abierta, sin cifrado alguno
SCORE_WPA = 25           # WPA legacy con TKIP, débil
SCORE_WPA2_PENALTY = 5   # WPA2 sin WPA3 disponible

# Puntuación por hallazgos adicionales
SCORE_WPS_ENABLED = 20       # WPS habilitado es vector de ataque conocido
SCORE_DEFAULT_CREDS = 30     # Credenciales por defecto sospechadas
SCORE_CHANNEL_OVERLAP = 5    # Solapamiento severo de canales

# Umbrales de riesgo
RANGE_CRITICAL = 61  # Crítico
RANGE_HIGH = 36       # Alto
RANGE_MEDIUM = 16     # Medio
# 0-15 → Bajo


@dataclass
class ScoringFactors:
    """Entradas para la función de scoring."""

    encryption: str                # Tipo de cifrado (WEP, WPA, WPA2, WPA3, Open)
    wps_enabled: bool = False      # ¿WPS está habilitado?
    default_creds_suspected: bool = False  # ¿Se sospechan credenciales por defecto?
    # Cuántas OTRAS redes comparten el mismo canal
    channel_overlap_count: int = 0


def calculate_score(factors: ScoringFactors) -> int:
    """Calcula el puntaje de riesgo bruto (entero)."""
    score = 0

    # Sumar puntos según el tipo de cifrado
    enc = factors.encryption.upper()
    if enc == "WEP":
        score += SCORE_WEP
    elif enc == "OPEN":
        score += SCORE_OPEN
    elif enc == "WPA":
        score += SCORE_WPA
    elif enc == "WPA2":
        score += SCORE_WPA2_PENALTY

    # Sumar puntos por hallazgos adicionales
    if factors.wps_enabled:
        score += SCORE_WPS_ENABLED

    if factors.default_creds_suspected:
        score += SCORE_DEFAULT_CREDS

    # Solo sumar si hay solapamiento severo (2 o más redes en el mismo canal)
    if factors.channel_overlap_count >= 2:
        score += SCORE_CHANNEL_OVERLAP

    return score


def risk_level(score: int) -> str:
    """Mapea un puntaje numérico a una etiqueta de nivel de riesgo."""
    if score >= RANGE_CRITICAL:
        return "Critico"
    if score >= RANGE_HIGH:
        return "Alto"
    if score >= RANGE_MEDIUM:
        return "Medio"
    return "Bajo"


def score_network(factors: ScoringFactors) -> tuple[int, str]:
    """Devuelve ``(score, risk_level)`` para los factores dados."""
    s = calculate_score(factors)
    return s, risk_level(s)
