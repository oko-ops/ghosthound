"""
AS-REP Roastable Users Analyzer

Detects users that don't require pre-authentication for Kerberos.
"""

from typing import List
from ..models import Finding
from .base import Analyzer, AnalysisContext


class ASREPAnalyzer(Analyzer):
    """Analyzes for AS-REP roastable users."""
    
    @property
    def name(self) -> str:
        return "AS-REP Roastable Users"
    
    def run(self, context: AnalysisContext) -> List[Finding]:
        """
        Identify users vulnerable to AS-REP roasting.
        
        AS-REP roastable users are:
        - Enabled
        - Have DONT_REQUIRE_PREAUTH flag set
        - OR have password not required flag
        """
        findings = []
        asrep_roastable_users = []
        
        for user in context.users:
            if user.asrep_roastable:
                asrep_roastable_users.append(user.name)
        
        if asrep_roastable_users:
            findings.append(Finding(
                severity="HIGH",
                title=f"{len(asrep_roastable_users)} AS-REP Roastable Users Found",
                description=(
                    "Users with DONT_REQUIRE_PREAUTH flag enabled or password "
                    "not required setting can be targeted for AS-REP roasting. "
                    "An attacker can request pre-authentication for these users "
                    "and perform offline password cracking against the KRB5-ASREP "
                    "encrypted response without having valid credentials."
                ),
                affected_objects=asrep_roastable_users,
                details=[
                    f"User: {name}"
                    for name in sorted(asrep_roastable_users)
                ]
            ))
        
        return findings
