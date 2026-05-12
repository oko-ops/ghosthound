"""
Analyzer module for GhostHound.

Provides independent, modular security analyzers that run against normalized AD data.
"""

from .base import Analyzer, AnalysisContext
from .kerberoastable import KerberoastableAnalyzer
from .asrep import ASREPAnalyzer
from .domain_admin import DomainAdminAnalyzer
from .delegation import UncstrainedDelegationAnalyzer

__all__ = [
    "Analyzer",
    "AnalysisContext",
    "KerberoastableAnalyzer",
    "ASREPAnalyzer",
    "DomainAdminAnalyzer",
    "UncstrainedDelegationAnalyzer",
]

# Registry of all available analyzers
DEFAULT_ANALYZERS = [
    KerberoastableAnalyzer(),
    ASREPAnalyzer(),
    DomainAdminAnalyzer(),
    UncstrainedDelegationAnalyzer(),
]
