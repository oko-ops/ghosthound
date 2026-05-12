"""
Kerberoastable Users Analyzer

Detects users with SPNs that can be targeted for Kerberoasting attacks.
"""

from typing import List
from ..models import Finding
from .base import Analyzer, AnalysisContext


class KerberoastableAnalyzer(Analyzer):
    """Analyzes for Kerberoastable users."""
    
    @property
    def name(self) -> str:
        return "Kerberoastable Users"
    
    def run(self, context: AnalysisContext) -> List[Finding]:
        """
        Identify users with SPNs that can be kerberoasted.
        
        Kerberoastable users are:
        - Enabled
        - Have Service Principal Names (SPNs)
        - Are not Domain Admins (admin_count == 0)
        """
        findings = []
        kerberoastable_users = []
        
        for user in context.users:
            if user.kerberoastable:
                kerberoastable_users.append(user.name)
        
        if kerberoastable_users:
            findings.append(Finding(
                severity="HIGH",
                title=f"{len(kerberoastable_users)} Kerberoastable Users Found",
                description=(
                    "Users with Service Principal Names (SPNs) can be targeted "
                    "for offline Kerberoasting attacks. An attacker can request "
                    "a Kerberos service ticket (TGS) and perform offline password "
                    "cracking against the encrypted ticket."
                ),
                affected_objects=kerberoastable_users,
                details=[
                    f"User: {name}" 
                    for name in sorted(kerberoastable_users)
                ]
            ))
        
        return findings
