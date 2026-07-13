"""Analizador de cifrado — clasifica los tipos de cifrado WiFi."""

from __future__ import annotations


# Tipos de cifrado soportados
ENCRYPTION_TYPES = ("WEP", "WPA", "WPA2", "WPA3", "Open")


def classify_encryption(enc_string: str) -> str:
    """Clasifica una cadena de cifrado cruda (de airodump-ng) en un tipo canónico.

    Entradas aceptadas (sin distinción de mayúsculas): cadenas que contengan
    'WPA3', 'WPA2', 'WPA', 'WEP', o 'OPN'/'OPEN'/'ESS' (sin cifrado).

    Devuelve uno de: ``"WPA3"``, ``"WPA2"``, ``"WPA"``, ``"WEP"``, ``"Open"``.
    """
    upper = enc_string.upper()

    # Verificar en orden de mayor a menor seguridad para priorizar WPA3/WPA2
    if "WPA3" in upper:
        return "WPA3"
    if "WPA2" in upper:
        return "WPA2"
    if "WPA" in upper:
        return "WPA"
    if "WEP" in upper:
        return "WEP"
    # Si no coincide con ninguno, se asume red abierta
    return "Open"


def encryption_summary(encryption: str) -> str:
    """Devuelve un resumen legible para el tipo de cifrado."""
    summaries = {
        "WPA3": "WPA3 — Último estándar, protección robusta.",
        "WPA2": "WPA2 — Uso generalizado, vulnerable a KRACK sin parches.",
        "WPA": "WPA — TKIP heredado, débil; reemplazar con WPA2/3.",
        "WEP": "WEP — RC4 roto, descifrable en minutos.",
        "Open": "Open — Sin cifrado, todo el tráfico en texto plano.",
    }
    return summaries.get(encryption, f"Cifrado desconocido: {encryption}")
