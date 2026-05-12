"""
Parser module for GhostHound.

Provides parsers for different data sources (BloodHound, NetExec, etc).
"""

from .bloodhound import BloodHoundParser

__all__ = ["BloodHoundParser"]
