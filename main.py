#!/usr/bin/env python3
"""
GhostHound - Lightweight Active Directory Attack Surface Analyzer

Main entry point for the CLI.
"""

import argparse
import sys
from pathlib import Path
from ghosthound.parsers import BloodHoundParser
from ghosthound.analyzers import AnalysisContext, DEFAULT_ANALYZERS
from ghosthound.models import Finding


def print_summary(domains: dict) -> None:
    """Print a summary of loaded data."""
    total_users = 0
    total_computers = 0
    total_groups = 0
    
    for domain_name, domain in domains.items():
        total_users += len(domain.users)
        total_computers += len(domain.computers)
        total_groups += len(domain.groups)
    
    print("\n" + "=" * 60)
    print("BloodHound Data Loaded Successfully")
    print("=" * 60)
    print(f"Domains:  {len(domains)}")
    for domain_name in sorted(domains.keys()):
        print(f"  - {domain_name}")
    print()
    print(f"Total Users:     {total_users}")
    print(f"Total Computers: {total_computers}")
    print(f"Total Groups:    {total_groups}")
    print("=" * 60 + "\n")


def run_analysis(domains: dict) -> list:
    """
    Run all analyzers against parsed data.
    
    Returns:
        List of Finding objects
    """
    # Collect all objects for context
    all_users = []
    all_computers = []
    all_groups = []
    
    for domain in domains.values():
        all_users.extend(domain.users)
        all_computers.extend(domain.computers)
        all_groups.extend(domain.groups)
    
    # Create analysis context
    context = AnalysisContext(
        domains=domains,
        users=all_users,
        computers=all_computers,
        groups=all_groups
    )
    
    # Run all analyzers
    all_findings = []
    for analyzer in DEFAULT_ANALYZERS:
        findings = analyzer.run(context)
        all_findings.extend(findings)
    
    return all_findings


def print_findings(findings: list) -> None:
    """Print security findings in a human-readable format."""
    if not findings:
        print("\n" + "=" * 60)
        print("Analysis Complete - No Findings")
        print("=" * 60 + "\n")
        return
    
    # Sort findings by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: (severity_order.get(f.severity, 4), f.title))
    
    print("\n" + "=" * 60)
    print("Security Findings")
    print("=" * 60 + "\n")
    
    for finding in findings:
        # Print finding header
        print(f"[{finding.severity}] {finding.title}")
        print(f"  Description: {finding.description}")
        
        if finding.affected_objects:
            print(f"  Affected ({len(finding.affected_objects)}):")
            # Show first 10, then count remaining
            affected_list = finding.affected_objects[:10]
            for obj in affected_list:
                print(f"    - {obj}")
            
            if len(finding.affected_objects) > 10:
                remaining = len(finding.affected_objects) - 10
                print(f"    ... and {remaining} more")
        
        print()
    
    print("=" * 60 + "\n")


def command_analyze(args) -> int:
    """Execute the analyze command."""
    try:
        parser = BloodHoundParser()
        domains = parser.load(args.input)
        print_summary(domains)
        
        # Run analysis
        findings = run_analysis(domains)
        print_findings(findings)
        
        return 0
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: Failed to parse BloodHound data: {e}", file=sys.stderr)
        return 1


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="GhostHound - Lightweight Active Directory Attack Surface Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ghosthound analyze input/bloodhound.zip
  ghosthound analyze input/
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Analyze command
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze BloodHound data"
    )
    analyze_parser.add_argument(
        "input",
        help="Path to BloodHound ZIP file or directory containing JSON files"
    )
    analyze_parser.set_defaults(func=command_analyze)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
