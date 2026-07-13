"""Utilidades de canal — detecta solapamiento y congestión de canales."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

# Canales 2.4 GHz y sus frecuencias centrales (MHz)
CHANNEL_FREQ_24GHZ: dict[int, int] = {
    1: 2412, 2: 2417, 3: 2422, 4: 2427, 5: 2432,
    6: 2437, 7: 2442, 8: 2447, 9: 2452, 10: 2457,
    11: 2462, 12: 2467, 13: 2472, 14: 2484,
}

# Canales que NO se solapan en 2.4 GHz (los estándar)
NON_OVERLAPPING_24GHZ = {1, 6, 11}


@dataclass
class ChannelOverlap:
    """Resultado del análisis de solapamiento para un canal específico."""
    channel: int            # Número de canal
    network_count: int      # Cantidad de redes en este canal
    severity: str           # "clean" (limpio) | "moderate" (moderado) | "severe" (severo)


def analyze_overlap(channels: list[int]) -> list[ChannelOverlap]:
    """Analiza la distribución de canales e identifica solapamientos.

    Args:
        channels: Lista de números de canal de las redes escaneadas.

    Returns:
        Lista de objetos ``ChannelOverlap`` por canal.
    """
    counts = Counter(channels)
    results: list[ChannelOverlap] = []

    for ch, count in sorted(counts.items()):
        # Clasificar severidad según cantidad de redes por canal
        if count >= 3:
            severity = "severe"    # 3+ redes = congestión severa
        elif count == 2:
            severity = "moderate"  # 2 redes = solapamiento moderado
        else:
            severity = "clean"    # 1 red = canal limpio
        results.append(
            ChannelOverlap(channel=ch, network_count=count, severity=severity)
        )
    return results


def overlap_score(channels: list[int]) -> int:
    """Devuelve el número total de pares de redes solapadas (métrica de congestión)."""
    counts = Counter(channels)
    total = 0
    for count in counts.values():
        # Calcular combinaciones de pares: n*(n-1)/2
        if count >= 2:
            total += count * (count - 1) // 2
    return total
