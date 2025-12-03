#!/usr/bin/env python3
"""
DomainTools Batch Analyzer
Analyze multiple domains from a file and generate consolidated threat intelligence report
"""

import sys
import os
import json
from datetime import datetime
from typing import List, Dict
import argparse
from domaintools_analyzer import DomainToolsAnalyzer, print_results

def load_domains(file_path: str) -> List[str]:
    """Load domains from text file (one per line)"""
    domains = []
    with open(file_path, 'r') as f:
        for line in f:
            domain = line.strip()
            if domain and not domain.startswith('#'):
                domains.append(domain)
    return domains

def analyze_batch(analyzer: DomainToolsAnalyzer, domains: List[str], quick: bool = False) -> List[Dict]:
    """Analyze multiple domains and return all results"""
    all_results = []
    
    print(f"\n{'='*70}")
    print(f"BATCH ANALYSIS: {len(domains)} domains")
    print(f"{'='*70}\n")
    
    for i, domain in enumerate(domains, 1):
        print(f"\n[{i}/{len(domains)}] Processing: {domain}")
        try:
            result = analyzer.analyze_domain(domain, deep_analysis=not quick)
            all_results.append(result)
            print(f"✓ Completed: {domain}")
        except Exception as e:
            print(f"❌ Error analyzing {domain}: {str(e)}")
            all_results.append({
                'domain': domain,
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            })
    
    return all_results

def generate_consolidated_report(all_results: List[Dict]) -> Dict:
    """Generate consolidated threat intelligence report"""
    report = {
        'summary': {
            'total_domains': len(all_results),
            'high_risk_domains': 0,
            'medium_risk_domains': 0,
            'low_risk_domains': 0,
            'errors': 0
        },
        'threat_clusters': {
            'by_registrant_email': {},
            'by_registrant_org': {},
            'by_ip_address': {},
            'by_name_server': {}
        },
        'high_priority_targets': [],
        'detailed_results': all_results
    }
    
    # Analyze results for clustering and prioritization
    for result in all_results:
        if 'error' in result:
            report['summary']['errors'] += 1
            continue
        
        domain = result['domain']
        
        # Risk categorization
        risk_data = result['analysis'].get('risk_score', {}).get('response', {})
        if isinstance(risk_data, dict):
            score = risk_data.get('risk_score', 0)
            
            if score >= 70:
                report['summary']['high_risk_domains'] += 1
                report['high_priority_targets'].append({
                    'domain': domain,
                    'risk_score': score,
                    'reason': 'HIGH risk score'
                })
            elif score >= 40:
                report['summary']['medium_risk_domains'] += 1
            else:
                report['summary']['low_risk_domains'] += 1
        
        # Cluster by registrant email
        emails = result['iocs'].get('registrant_emails', [])
        for email in emails:
            if email not in report['threat_clusters']['by_registrant_email']:
                report['threat_clusters']['by_registrant_email'][email] = []
            report['threat_clusters']['by_registrant_email'][email].append(domain)
        
        # Cluster by registrant org
        orgs = result['iocs'].get('registrant_orgs', [])
        for org in orgs:
            if org not in report['threat_clusters']['by_registrant_org']:
                report['threat_clusters']['by_registrant_org'][org] = []
            report['threat_clusters']['by_registrant_org'][org].append(domain)
        
        # Cluster by IP
        ips = result['iocs'].get('ip_addresses', [])
        for ip_entry in ips:
            ip = ip_entry['ip']
            if ip not in report['threat_clusters']['by_ip_address']:
                report['threat_clusters']['by_ip_address'][ip] = []
            report['threat_clusters']['by_ip_address'][ip].append(domain)
        
        # Cluster by name server
        name_servers = result['iocs'].get('name_servers', [])
        for ns in name_servers:
            if ns not in report['threat_clusters']['by_name_server']:
                report['threat_clusters']['by_name_server'][ns] = []
            report['threat_clusters']['by_name_server'][ns].append(domain)
    
    # Identify significant clusters (2+ domains)
    for cluster_type in ['by_registrant_email', 'by_registrant_org', 'by_ip_address']:
        clusters = report['threat_clusters'][cluster_type]
        for key, domains in list(clusters.items()):
            if len(domains) >= 2:
                report['high_priority_targets'].append({
                    'cluster_type': cluster_type,
                    'cluster_key': key,
                    'domain_count': len(domains),
                    'domains': domains,
                    'reason': f'Infrastructure cluster - {len(domains)} domains share {cluster_type.replace("by_", "")}'
                })
    
    return report

def print_consolidated_report(report: Dict):
    """Print consolidated threat intelligence report"""
    print(f"\n{'='*70}")
    print("CONSOLIDATED THREAT INTELLIGENCE REPORT")
    print(f"{'='*70}\n")
    
    # Summary
    summary = report['summary']
    print("📊 SUMMARY:")
    print(f"   Total domains analyzed: {summary['total_domains']}")
    print(f"   High risk: {summary['high_risk_domains']}")
    print(f"   Medium risk: {summary['medium_risk_domains']}")
    print(f"   Low risk: {summary['low_risk_domains']}")
    if summary['errors'] > 0:
        print(f"   Errors: {summary['errors']}")
    
    # High Priority Targets
    if report['high_priority_targets']:
        print(f"\n{'='*70}")
        print("🎯 HIGH PRIORITY FINDINGS:")
        print(f"{'='*70}")
        
        for i, target in enumerate(report['high_priority_targets'], 1):
            print(f"\n{i}. {target.get('cluster_type', 'risk_score').upper()}")
            print(f"   Reason: {target['reason']}")
            
            if 'domain' in target:
                print(f"   Domain: {target['domain']}")
                if 'risk_score' in target:
                    print(f"   Risk Score: {target['risk_score']}/100")
            
            if 'cluster_key' in target:
                print(f"   Cluster Key: {target['cluster_key']}")
                print(f"   Associated Domains ({target['domain_count']}):")
                for domain in target['domains'][:10]:
                    print(f"      • {domain}")
                if target['domain_count'] > 10:
                    print(f"      ... and {target['domain_count'] - 10} more")
    
    # Infrastructure Clusters
    print(f"\n{'='*70}")
    print("🔗 INFRASTRUCTURE CLUSTERS:")
    print(f"{'='*70}")
    
    clusters = report['threat_clusters']
    
    # Registrant email clusters
    email_clusters = {k: v for k, v in clusters['by_registrant_email'].items() if len(v) >= 2}
    if email_clusters:
        print(f"\nBy Registrant Email ({len(email_clusters)} clusters):")
        for email, domains in list(email_clusters.items())[:5]:
            print(f"   {email}: {len(domains)} domains")
    
    # Registrant org clusters
    org_clusters = {k: v for k, v in clusters['by_registrant_org'].items() if len(v) >= 2}
    if org_clusters:
        print(f"\nBy Registrant Organization ({len(org_clusters)} clusters):")
        for org, domains in list(org_clusters.items())[:5]:
            print(f"   {org}: {len(domains)} domains")
    
    # IP clusters
    ip_clusters = {k: v for k, v in clusters['by_ip_address'].items() if len(v) >= 2}
    if ip_clusters:
        print(f"\nBy IP Address ({len(ip_clusters)} clusters):")
        for ip, domains in list(ip_clusters.items())[:5]:
            print(f"   {ip}: {len(domains)} domains")
    
    print(f"\n{'='*70}\n")

def main():
    parser = argparse.ArgumentParser(
        description='DomainTools Batch Analyzer - Analyze multiple domains and identify threat clusters'
    )
    parser.add_argument('domain_file', help='Text file with domains (one per line)')
    parser.add_argument('--quick', action='store_true', 
                       help='Quick analysis (skip reverse WHOIS and typosquatting)')
    parser.add_argument('--output', '-o', help='Output JSON file path')
    parser.add_argument('--api-user', help='DomainTools API username (or set DOMAINTOOLS_USER env var)')
    parser.add_argument('--api-key', help='DomainTools API key (or set DOMAINTOOLS_KEY env var)')
    
    args = parser.parse_args()
    
    # Get API credentials
    api_user = args.api_user or os.getenv('DOMAINTOOLS_USER')
    api_key = args.api_key or os.getenv('DOMAINTOOLS_KEY')
    
    if not api_user or not api_key:
        print("❌ Error: DomainTools API credentials required")
        print("   Set via --api-user/--api-key flags or DOMAINTOOLS_USER/DOMAINTOOLS_KEY env vars")
        sys.exit(1)
    
    # Load domains
    if not os.path.exists(args.domain_file):
        print(f"❌ Error: Domain file not found: {args.domain_file}")
        sys.exit(1)
    
    domains = load_domains(args.domain_file)
    print(f"✓ Loaded {len(domains)} domains from {args.domain_file}")
    
    # Initialize analyzer
    analyzer = DomainToolsAnalyzer(api_user, api_key)
    
    # Run batch analysis
    all_results = analyze_batch(analyzer, domains, quick=args.quick)
    
    # Generate consolidated report
    report = generate_consolidated_report(all_results)
    
    # Print report
    print_consolidated_report(report)
    
    # Save to file
    if args.output:
        output_file = args.output
    else:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = f"domaintools_batch_report_{timestamp}.json"
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"✓ Full report saved to: {output_file}")

if __name__ == '__main__':
    main()
