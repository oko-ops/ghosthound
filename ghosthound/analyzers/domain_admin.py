"""
Domain Admin Members Analyzer

Detects users and computers that are members of Domain Admin groups.
"""

from typing import List, Set
from ..models import Finding
from .base import Analyzer, AnalysisContext


class DomainAdminAnalyzer(Analyzer):
    """Analyzes for Domain Admin members."""
    
    @property
    def name(self) -> str:
        return "Domain Admin Members"
    
    def run(self, context: AnalysisContext) -> List[Finding]:
        """
        Identify members of Domain Admins group.
        
        Domain Admins are the highest privilege group in Active Directory.
        Finding all members is critical for understanding the attack surface.
        """
        findings = []
        domain_admin_members = set()
        
        # Find Domain Admins group in each domain
        for domain in context.domains.values():
            domain_admin_group = None
            
            for group in domain.groups:
                # Look for "Domain Admins" group
                if group.name.upper().startswith("DOMAIN ADMINS@"):
                    domain_admin_group = group
                    break
            
            if domain_admin_group:
                # Collect members (stored as dicts with ObjectIdentifier in BloodHound)
                for member in domain_admin_group.members:
                    # Handle both dict format (nested objects) and string format
                    if isinstance(member, dict):
                        member_id = member.get("ObjectIdentifier", "")
                    else:
                        member_id = member
                    
                    if not member_id:
                        continue
                    
                    # Try to find matching user or computer
                    found = False
                    for user in domain.users:
                        if user.object_id == member_id:
                            domain_admin_members.add(user.name)
                            found = True
                            break
                    
                    if not found:
                        # Not found in users, try computers
                        for computer in domain.computers:
                            if computer.object_id == member_id:
                                domain_admin_members.add(computer.name)
                                break
        
        if domain_admin_members:
            findings.append(Finding(
                severity="CRITICAL",
                title=f"{len(domain_admin_members)} Domain Admin Members",
                description=(
                    "Users and computers that are members of the Domain Admins "
                    "group. Members of this group have full administrative "
                    "privileges across the entire domain and should be protected "
                    "with strong security controls and monitoring."
                ),
                affected_objects=sorted(domain_admin_members),
                details=[
                    f"Member: {name}"
                    for name in sorted(domain_admin_members)
                ]
            ))
        
        return findings
