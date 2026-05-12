"""
Unconstrained Delegation Analyzer

Detects users and computers with unconstrained delegation enabled.
"""

from typing import List
from ..models import Finding
from .base import Analyzer, AnalysisContext


class UncstrainedDelegationAnalyzer(Analyzer):
    """Analyzes for unconstrained delegation."""
    
    @property
    def name(self) -> str:
        return "Unconstrained Delegation"
    
    def run(self, context: AnalysisContext) -> List[Finding]:
        """
        Identify accounts with unconstrained delegation enabled.
        
        Unconstrained delegation allows the account to impersonate any other
        user when requested by a client. This is a significant security risk
        as compromise of such an account enables impersonation attacks.
        """
        findings = []
        computers_with_unconstrained = []
        users_with_unconstrained = []
        
        # Check computers
        for computer in context.computers:
            if computer.has_unconstrained_delegation:
                computers_with_unconstrained.append(computer.name)
        
        # Check users
        for user in context.users:
            # Users can also have unconstrained delegation in some cases
            # This is determined by the "Trusted For Delegation" UAC flag
            if user.properties.get("unconstraineddelegation", False):
                users_with_unconstrained.append(user.name)
        
        all_affected = computers_with_unconstrained + users_with_unconstrained
        
        if all_affected:
            findings.append(Finding(
                severity="HIGH",
                title=f"{len(all_affected)} Accounts with Unconstrained Delegation",
                description=(
                    "Accounts with unconstrained delegation can impersonate any "
                    "user in the domain when requested. This is a critical "
                    "security risk. Compromise of such an account enables "
                    "attackers to impersonate domain users and escalate privileges. "
                    "Domain controllers should never have unrestricted delegation."
                ),
                affected_objects=sorted(all_affected),
                details=[
                    f"Computer: {name}"
                    for name in sorted(computers_with_unconstrained)
                ] + [
                    f"User: {name}"
                    for name in sorted(users_with_unconstrained)
                ]
            ))
        
        return findings
