"""
BloodHound data parser.

Handles loading and parsing BloodHound ZIP and JSON exports.
Normalizes BloodHound data into internal models.
"""

import json
import zipfile
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Any
from ..models import User, Computer, Group, Domain


class BloodHoundParser:
    """Parser for BloodHound ZIP and JSON exports."""
    
    # BloodHound JSON file names
    USERS_FILE = "users.json"
    COMPUTERS_FILE = "computers.json"
    GROUPS_FILE = "groups.json"
    DOMAINS_FILE = "domains.json"
    
    def __init__(self):
        self.raw_data: Dict[str, List[Dict[str, Any]]] = {}
        self.domains: Dict[str, Domain] = {}
        self.user_id_map: Dict[str, User] = {}
        self.computer_id_map: Dict[str, Computer] = {}
        self.group_id_map: Dict[str, Group] = {}
    
    def load(self, path: str) -> Dict[str, Domain]:
        """
        Load BloodHound data from ZIP or JSON files.
        
        Args:
            path: Path to ZIP file or directory containing JSON files
            
        Returns:
            Dictionary mapping domain names to Domain objects
        """
        path_obj = Path(path)
        
        if path_obj.suffix.lower() == ".zip":
            self._load_from_zip(path)
        elif path_obj.is_dir():
            self._load_from_directory(path_obj)
        else:
            raise ValueError(f"Invalid path: {path}. Must be a ZIP file or directory.")
        
        self._parse_data()
        return self.domains
    
    def _load_from_zip(self, zip_path: str) -> None:
        """Extract and load JSON files from BloodHound ZIP."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(tmpdir)
            
            tmpdir_path = Path(tmpdir)
            self._load_from_directory(tmpdir_path)
    
    def _load_from_directory(self, directory: Path) -> None:
        """Load JSON files from directory."""
        # Look for JSON files in the directory, including nested ones
        for json_type in [self.USERS_FILE, self.COMPUTERS_FILE, 
                          self.GROUPS_FILE, self.DOMAINS_FILE]:
            # Try direct path first
            json_path = directory / json_type
            if json_path.exists():
                self._load_json_file(json_path, json_type)
                continue
            
            # Search recursively for files matching the type
            # This handles files with timestamp prefixes like 20220210132706_users.json
            found = False
            pattern = f"*{json_type}"
            for potential_file in directory.rglob(pattern):
                self._load_json_file(potential_file, json_type)
                found = True
                break
            
            if not found and json_type != self.DOMAINS_FILE:
                # Domains file is optional
                raise FileNotFoundError(
                    f"Required file not found: {json_type} in {directory}"
                )
    
    def _load_json_file(self, file_path: Path, file_type: str) -> None:
        """Load a single JSON file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Handle both direct array and wrapped format
            if isinstance(data, list):
                self.raw_data[file_type] = data
            elif isinstance(data, dict) and "data" in data:
                self.raw_data[file_type] = data["data"]
            else:
                self.raw_data[file_type] = []
                
        except json.JSONDecodeError as e:
            print(f"Warning: Failed to parse {file_path}: {e}")
            self.raw_data[file_type] = []
    
    def _parse_data(self) -> None:
        """Parse loaded JSON data into normalized models."""
        # Parse domains first
        self._parse_domains()
        
        # Parse objects
        self._parse_users()
        self._parse_computers()
        self._parse_groups()
        
        # Link objects to domains
        self._link_objects_to_domains()
    
    def _parse_domains(self) -> None:
        """Parse domains from BloodHound data."""
        domains_data = self.raw_data.get(self.DOMAINS_FILE, [])
        
        for domain_data in domains_data:
            domain = self._parse_domain_object(domain_data)
            self.domains[domain.name] = domain
    
    def _parse_domain_object(self, data: Dict[str, Any]) -> Domain:
        """Parse a single domain object."""
        # BloodHound JSON uses PascalCase keys
        name = self._get_property(data, "Properties.name", "")
        object_id = self._get_property(data, "ObjectIdentifier", "")
        sid = self._get_property(data, "Properties.domainsid", "")
        
        return Domain(
            name=name,
            domain_sid=sid,
            object_id=object_id,
            properties=self._extract_properties(data)
        )
    
    def _parse_users(self) -> None:
        """Parse users from BloodHound data."""
        users_data = self.raw_data.get(self.USERS_FILE, [])
        
        for user_data in users_data:
            user = self._parse_user_object(user_data)
            self.user_id_map[user.object_id] = user
    
    def _parse_user_object(self, data: Dict[str, Any]) -> User:
        """Parse a single user object."""
        # BloodHound JSON uses PascalCase keys
        name = self._get_property(data, "Properties.name", "")
        object_id = self._get_property(data, "ObjectIdentifier", "")
        
        # Extract domain from name (format: USER@DOMAIN.COM or from Properties.domain)
        domain = self._get_property(data, "Properties.domain", "")
        if not domain and "@" in name:
            domain = name.split("@")[1]
        
        # Parse properties
        props = self._get_property(data, "Properties", {})
        enabled = self._get_property(props, "enabled", True)
        admin_count = self._get_property(props, "admincount", 0)
        # Handle both boolean and int values for admincount
        if isinstance(admin_count, bool):
            admin_count = 1 if admin_count else 0
        
        sensitive_to_delegation = not self._get_property(
            props, "sensitive", False
        )
        password_not_required = self._get_property(
            props, "passwordnotreqd", False
        )
        spns = self._get_property(props, "serviceprincipalnames", [])
        dontreqpreauth = self._get_property(props, "dontreqpreauth", False)
        
        # Check for kerberoastable
        kerberoastable = (
            len(spns) > 0 
            and enabled
            and not admin_count
        )
        
        # Check for AS-REP roastable
        asrep_roastable = (
            password_not_required
            and enabled
        ) or dontreqpreauth
        
        # Get group memberships (stored as GroupMembership in BloodHound)
        groups = self._get_property(data, "GroupMembership", [])
        
        return User(
            name=name,
            domain=domain,
            object_id=object_id,
            enabled=enabled,
            kerberoastable=kerberoastable,
            asrep_roastable=asrep_roastable,
            admin_count=admin_count,
            sensitive_to_delegation=sensitive_to_delegation,
            password_not_required=password_not_required,
            has_spn=len(spns) > 0,
            service_principal_names=spns,
            member_of_groups=groups,
            properties=self._extract_properties(data)
        )
    
    def _parse_computers(self) -> None:
        """Parse computers from BloodHound data."""
        computers_data = self.raw_data.get(self.COMPUTERS_FILE, [])
        
        for computer_data in computers_data:
            computer = self._parse_computer_object(computer_data)
            self.computer_id_map[computer.object_id] = computer
    
    def _parse_computer_object(self, data: Dict[str, Any]) -> Computer:
        """Parse a single computer object."""
        # BloodHound JSON uses PascalCase keys
        name = self._get_property(data, "Properties.name", "")
        object_id = self._get_property(data, "ObjectIdentifier", "")
        
        # Extract domain from Properties.domain field (preferred) or from name
        domain = self._get_property(data, "Properties.domain", "")
        if not domain:
            # Try extracting from name format: COMPUTER.DOMAIN or COMPUTER@DOMAIN
            if "@" in name:
                domain = name.split("@")[1]
            elif "." in name:
                # For FQDN format, take everything after first dot
                parts = name.split(".")
                if len(parts) > 1:
                    domain = ".".join(parts[1:])
        
        # Parse properties
        props = self._get_property(data, "Properties", {})
        enabled = self._get_property(props, "enabled", True)
        os = self._get_property(props, "operatingsystem", "")
        dns_hostname = self._get_property(props, "dnshostname", "")
        
        # Check for delegation
        user_account_control = self._get_property(
            props, "useraccountcontrol", 0
        )
        has_unconstrained = self._has_unconstrained_delegation(
            user_account_control
        )
        has_constrained = self._has_constrained_delegation(props)
        
        constrained_targets = self._get_property(
            props, "allowedtodelegate", []
        )
        
        # Get local admin information (stored as AdminRights in BloodHound)
        local_admins = self._get_property(data, "AdminRights", [])
        groups = self._get_property(data, "GroupMembership", [])
        
        return Computer(
            name=name,
            domain=domain,
            object_id=object_id,
            enabled=enabled,
            operating_system=os,
            dns_hostname=dns_hostname,
            has_unconstrained_delegation=has_unconstrained,
            has_constrained_delegation=has_constrained,
            constrained_delegation_targets=constrained_targets,
            local_admins=local_admins,
            member_of_groups=groups,
            properties=self._extract_properties(data)
        )
    
    def _parse_groups(self) -> None:
        """Parse groups from BloodHound data."""
        groups_data = self.raw_data.get(self.GROUPS_FILE, [])
        
        for group_data in groups_data:
            group = self._parse_group_object(group_data)
            self.group_id_map[group.object_id] = group
    
    def _parse_group_object(self, data: Dict[str, Any]) -> Group:
        """Parse a single group object."""
        # BloodHound JSON uses PascalCase keys
        name = self._get_property(data, "Properties.name", "")
        object_id = self._get_property(data, "ObjectIdentifier", "")
        
        # Extract domain from Properties.domain field (preferred) or from name
        domain = self._get_property(data, "Properties.domain", "")
        if not domain:
            # Try extracting from name format: GROUP@DOMAIN or GROUP.DOMAIN
            if "@" in name:
                domain = name.split("@")[1]
            elif "." in name:
                parts = name.split(".")
                if len(parts) > 1:
                    domain = ".".join(parts[1:])
        
        # Get members (stored as Members in BloodHound)
        members = self._get_property(data, "Members", [])
        member_count = len(members)
        
        return Group(
            name=name,
            domain=domain,
            object_id=object_id,
            members=members,
            member_count=member_count,
            properties=self._extract_properties(data)
        )
    
    def _link_objects_to_domains(self) -> None:
        """Link parsed objects to their respective domains."""
        for user in self.user_id_map.values():
            if user.domain in self.domains:
                self.domains[user.domain].users.append(user)
        
        for computer in self.computer_id_map.values():
            if computer.domain in self.domains:
                self.domains[computer.domain].computers.append(computer)
        
        for group in self.group_id_map.values():
            if group.domain in self.domains:
                self.domains[group.domain].groups.append(group)
        
        # If no domains were parsed, create one from the data
        if not self.domains and (self.user_id_map or self.computer_id_map or self.group_id_map):
            # Infer domain from first object
            sample_domain = None
            if self.user_id_map:
                sample_domain = next(iter(self.user_id_map.values())).domain
            elif self.computer_id_map:
                sample_domain = next(iter(self.computer_id_map.values())).domain
            elif self.group_id_map:
                sample_domain = next(iter(self.group_id_map.values())).domain
            
            if sample_domain:
                self.domains[sample_domain] = Domain(
                    name=sample_domain,
                    domain_sid="",
                    object_id=""
                )
                
                for user in self.user_id_map.values():
                    if user.domain == sample_domain:
                        self.domains[sample_domain].users.append(user)
                
                for computer in self.computer_id_map.values():
                    if computer.domain == sample_domain:
                        self.domains[sample_domain].computers.append(computer)
                
                for group in self.group_id_map.values():
                    if group.domain == sample_domain:
                        self.domains[sample_domain].groups.append(group)
    
    @staticmethod
    def _get_property(data: Dict[str, Any], path: str, default: Any = None) -> Any:
        """
        Get a nested property from a dictionary using dot notation.
        
        Args:
            data: Dictionary to search
            path: Property path (e.g., "properties.name")
            default: Default value if property not found
            
        Returns:
            Property value or default
        """
        keys = path.split(".")
        current = data
        
        for key in keys:
            if isinstance(current, dict):
                current = current.get(key)
                if current is None:
                    return default
            else:
                return default
        
        return current if current is not None else default
    
    @staticmethod
    def _has_unconstrained_delegation(user_account_control: int) -> bool:
        """Check if UAC flags indicate unconstrained delegation."""
        # TRUSTED_FOR_DELEGATION = 0x80000 (524288)
        TRUSTED_FOR_DELEGATION = 0x80000
        return bool(user_account_control & TRUSTED_FOR_DELEGATION)
    
    @staticmethod
    def _has_constrained_delegation(properties: Dict[str, Any]) -> bool:
        """Check if computer has constrained delegation enabled."""
        allowed_to_delegate = properties.get("allowedtodelegate", [])
        return len(allowed_to_delegate) > 0
    
    @staticmethod
    def _extract_properties(data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract all properties from a BloodHound object for storage."""
        return data.get("properties", {})
