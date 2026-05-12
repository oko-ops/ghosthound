"""
Base analyzer class and context.

All analyzers inherit from Analyzer and implement the run() method.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Dict
from ..models import Finding, User, Computer, Group, Domain


@dataclass
class AnalysisContext:
    """Context passed to analyzers containing all parsed objects."""
    
    domains: Dict[str, Domain]
    users: List[User]
    computers: List[Computer]
    groups: List[Group]


class Analyzer(ABC):
    """Base class for all security analyzers."""
    
    @property
    def name(self) -> str:
        """Human-readable analyzer name."""
        raise NotImplementedError
    
    @abstractmethod
    def run(self, context: AnalysisContext) -> List[Finding]:
        """
        Run the analyzer and return findings.
        
        Args:
            context: AnalysisContext containing all parsed objects
            
        Returns:
            List of Finding objects
        """
        pass
