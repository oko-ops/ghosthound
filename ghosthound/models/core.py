"""
Core normalized data models for GhostHound.

These models represent normalized Active Directory objects,
independent of the data source (BloodHound, NetExec, LDAP, etc).
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class User:
    """Represents an Active Directory user."""
    
    name: str
    domain: str
    object_id: str
    enabled: bool = True
    kerberoastable: bool = False
    asrep_roastable: bool = False
    admin_count: int = 0
    sensitive_to_delegation: bool = False
    password_not_required: bool = False
    has_spn: bool = False
    service_principal_names: List[str] = field(default_factory=list)
    member_of_groups: List[str] = field(default_factory=list)
    properties: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_risky(self) -> bool:
        """Check if user has high-risk properties."""
        return (
            self.kerberoastable
            or self.asrep_roastable
            or self.admin_count > 0
            or not self.sensitive_to_delegation
        )


@dataclass
class Computer:
    """Represents an Active Directory computer."""
    
    name: str
    domain: str
    object_id: str
    enabled: bool = True
    operating_system: str = ""
    dns_hostname: str = ""
    has_unconstrained_delegation: bool = False
    has_constrained_delegation: bool = False
    constrained_delegation_targets: List[str] = field(default_factory=list)
    local_admins: List[str] = field(default_factory=list)
    member_of_groups: List[str] = field(default_factory=list)
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Group:
    """Represents an Active Directory group."""
    
    name: str
    domain: str
    object_id: str
    members: List[str] = field(default_factory=list)
    member_count: int = 0
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Domain:
    """Represents an Active Directory domain."""
    
    name: str
    domain_sid: str
    object_id: str
    users: List[User] = field(default_factory=list)
    computers: List[Computer] = field(default_factory=list)
    groups: List[Group] = field(default_factory=list)
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """Represents a security finding."""
    
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str
    affected_objects: List[str] = field(default_factory=list)
    details: List[str] = field(default_factory=list)
    source: str = "analyzer"


@dataclass
class AttackPath:
    """Represents a potential attack path."""
    
    source: str
    target: str
    relationships: List[str] = field(default_factory=list)
    severity: str = "MEDIUM"
    description: str = ""
