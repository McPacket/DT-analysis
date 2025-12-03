#!/usr/bin/env python3
"""
DomainTools Domain Analysis Tool
Automated domain investigation with IOC discovery and threat intelligence
"""

import requests
import json
import sys
import os
from datetime import datetime
from typing import Dict, List, Optional
import argparse
from collections import defaultdict

class DomainToolsAnalyzer:
    """Main analyzer class for DomainTools API integration"""
    
    def __init__(self, api_username: str, api_key: str):
        self.api_username = api_username
        self.api_key = api_key
        self.base_url = "https://api.domaintools.com/v1"
        self.session = requests.Session()
        self.session.auth = (api_username, api_key)
        
    def analyze_domain(self, domain: str, deep_analysis: bool = True) -> Dict:
        """
        Comprehensive domain analysis with IOC discovery
        
        Args:
            domain: Domain to analyze
            deep_analysis: Perform extended pivoting and related domain discovery
            
        Returns:
            Dictionary containing all analysis results and discovered IOCs
        """
        print(f"\n{'='*70}")
        print(f"ANALYZING DOMAIN: {domain}")
        print(f"{'='*70}\n")
        
        results = {
            'domain': domain,
            'timestamp': datetime.utcnow().isoformat(),
            'analysis': {},
            'iocs': defaultdict(list),
            'risk_indicators': [],
            'pivot_opportunities': []
        }
        
        # Core domain intelligence
        print("[1/8] Fetching WHOIS data...")
        results['analysis']['whois'] = self.get_whois(domain)
        
        print("[2/8] Calculating risk score...")
        results['analysis']['risk_score'] = self.get_risk_score(domain)
        
        print("[3/8] Checking domain reputation...")
        results['analysis']['reputation'] = self.get_reputation(domain)
        
        print("[4/8] Retrieving DNS history...")
        results['analysis']['dns_history'] = self.get_hosting_history(domain)
        
        print("[5/8] Analyzing domain profile...")
        results['analysis']['domain_profile'] = self.get_domain_profile(domain)
        
        if deep_analysis:
            print("[6/8] Performing reverse WHOIS (related domains)...")
            results['analysis']['related_domains'] = self.reverse_whois(domain)
            
            print("[7/8] Checking for typosquatting variants...")
            results['analysis']['typosquatting'] = self.check_typosquatting(domain)
            
            print("[8/8] Finding reverse IP neighbors...")
            results['analysis']['reverse_ip'] = self.reverse_ip(domain)
        
        # Extract IOCs from results
        self._extract_iocs(results)
        
        # Identify pivot opportunities
        self._identify_pivots(results)
        
        return results
    
    def get_whois(self, domain: str) -> Dict:
        """Fetch comprehensive WHOIS data"""
        try:
            url = f"{self.base_url}/{domain}/whois"
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {'error': str(e)}
    
    def get_risk_score(self, domain: str) -> Dict:
        """Get DomainTools risk score (0-100)"""
        try:
            url = f"{self.base_url}/risk/{domain}"
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {'error': str(e)}
    
    def get_reputation(self, domain: str) -> Dict:
        """Get domain reputation data"""
        try:
            url = f"{self.base_url}/reputation/{domain}"
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {'error': str(e)}
    
    def get_hosting_history(self, domain: str) -> Dict:
        """Get historical hosting/IP information"""
        try:
            url = f"{self.base_url}/{domain}/hosting-history"
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {'error': str(e)}
    
    def get_domain_profile(self, domain: str) -> Dict:
        """Get comprehensive domain profile"""
        try:
            url = f"{self.base_url}/{domain}"
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {'error': str(e)}
    
    def reverse_whois(self, domain: str) -> Dict:
        """Find related domains by registrant information"""
        try:
            # First get WHOIS to extract registrant details
            whois_data = self.get_whois(domain)
            
            if 'error' in whois_data:
                return whois_data
            
            results = {'related_domains': []}
            
            # Extract registrant email for pivoting
            registrant = whois_data.get('response', {}).get('registrant', {})
            registrant_email = registrant.get('email', '')
            registrant_org = registrant.get('org', '')
            
            if registrant_email and registrant_email != 'REDACTED FOR PRIVACY':
                url = f"{self.base_url}/reverse-whois"
                params = {'terms': registrant_email, 'mode': 'purchase'}
                response = self.session.get(url, params=params)
                if response.status_code == 200:
                    results['by_email'] = response.json()
            
            if registrant_org and registrant_org != 'REDACTED FOR PRIVACY':
                url = f"{self.base_url}/reverse-whois"
                params = {'terms': registrant_org, 'mode': 'purchase'}
                response = self.session.get(url, params=params)
                if response.status_code == 200:
                    results['by_org'] = response.json()
            
            return results
        except Exception as e:
            return {'error': str(e)}
    
    def check_typosquatting(self, domain: str) -> Dict:
        """Check for typosquatting/brand monitoring alerts"""
        try:
            url = f"{self.base_url}/brand-monitor/{domain}"
            response = self.session.get(url)
            if response.status_code == 200:
                return response.json()
            return {'note': 'Brand monitoring requires specific API tier'}
        except Exception as e:
            return {'error': str(e)}
    
    def reverse_ip(self, domain: str) -> Dict:
        """Find other domains hosted on same IP"""
        try:
            url = f"{self.base_url}/{domain}/reverse-ip"
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {'error': str(e)}
    
    def _extract_iocs(self, results: Dict):
        """Extract IOCs from analysis results"""
        analysis = results['analysis']
        iocs = results['iocs']
        
        # Extract IPs from hosting history
        hosting = analysis.get('dns_history', {}).get('response', {})
        if isinstance(hosting, dict):
            ip_history = hosting.get('ip_history', [])
            for entry in ip_history:
                if 'ip' in entry:
                    iocs['ip_addresses'].append({
                        'ip': entry['ip'],
                        'first_seen': entry.get('action_date'),
                        'source': 'hosting_history'
                    })
        
        # Extract name servers
        whois = analysis.get('whois', {}).get('response', {})
        if isinstance(whois, dict):
            name_servers = whois.get('name_servers', [])
            for ns in name_servers:
                iocs['name_servers'].append(ns)
            
            # Extract registrant details (if not redacted)
            registrant = whois.get('registrant', {})
            if registrant:
                email = registrant.get('email')
                if email and 'PRIVACY' not in email.upper():
                    iocs['registrant_emails'].append(email)
                
                org = registrant.get('org')
                if org and 'PRIVACY' not in org.upper():
                    iocs['registrant_orgs'].append(org)
        
        # Extract related domains
        related = analysis.get('related_domains', {})
        if related.get('by_email'):
            domains = related['by_email'].get('response', {}).get('domains', [])
            iocs['related_domains_by_email'].extend(domains)
        
        if related.get('by_org'):
            domains = related['by_org'].get('response', {}).get('domains', [])
            iocs['related_domains_by_org'].extend(domains)
        
        # Extract reverse IP neighbors
        reverse_ip = analysis.get('reverse_ip', {}).get('response', {})
        if isinstance(reverse_ip, dict):
            neighbors = reverse_ip.get('ip_addresses', [])
            for neighbor in neighbors:
                domains = neighbor.get('domain_names', [])
                iocs['reverse_ip_neighbors'].extend(domains)
    
    def _identify_pivots(self, results: Dict):
        """Identify high-value pivot opportunities for further hunting"""
        analysis = results['analysis']
        pivots = results['pivot_opportunities']
        risk_indicators = results['risk_indicators']
        
        # Risk score analysis
        risk_data = analysis.get('risk_score', {}).get('response', {})
        if isinstance(risk_data, dict):
            risk_score = risk_data.get('risk_score', 0)
            
            if risk_score >= 70:
                risk_indicators.append(f"HIGH RISK SCORE: {risk_score}/100")
                pivots.append({
                    'type': 'high_risk_domain',
                    'confidence': 'HIGH',
                    'action': 'Investigate all related infrastructure immediately'
                })
        
        # Domain age analysis
        whois = analysis.get('whois', {}).get('response', {})
        if isinstance(whois, dict):
            created_date = whois.get('created')
            if created_date:
                # Check if domain is newly registered (< 30 days)
                risk_indicators.append(f"Domain creation date: {created_date}")
                pivots.append({
                    'type': 'domain_age',
                    'confidence': 'MEDIUM',
                    'action': 'Check for other domains registered around same time by same entity'
                })
        
        # Related domains pivot
        iocs = results['iocs']
        if iocs['related_domains_by_email'] or iocs['related_domains_by_org']:
            pivots.append({
                'type': 'registrant_infrastructure',
                'confidence': 'HIGH',
                'action': 'Analyze all related domains - same threat actor infrastructure',
                'domains': (iocs['related_domains_by_email'][:5] if iocs['related_domains_by_email'] 
                           else iocs['related_domains_by_org'][:5])
            })
        
        # Reverse IP pivot
        if len(iocs['reverse_ip_neighbors']) > 10:
            risk_indicators.append(f"Shared hosting: {len(iocs['reverse_ip_neighbors'])} domains on same IP")
            pivots.append({
                'type': 'shared_hosting',
                'confidence': 'MEDIUM',
                'action': 'Analyze reverse IP neighbors for additional malicious domains'
            })
        
        # Name server clustering
        if len(iocs['name_servers']) > 0:
            pivots.append({
                'type': 'name_server_pivot',
                'confidence': 'MEDIUM',
                'action': f"Query Shodan/Censys for other domains using nameservers: {', '.join(iocs['name_servers'][:3])}"
            })

def print_results(results: Dict):
    """Pretty print analysis results"""
    print(f"\n{'='*70}")
    print(f"ANALYSIS RESULTS: {results['domain']}")
    print(f"Timestamp: {results['timestamp']}")
    print(f"{'='*70}\n")
    
    # Risk Assessment
    risk_data = results['analysis'].get('risk_score', {}).get('response', {})
    if isinstance(risk_data, dict) and 'risk_score' in risk_data:
        score = risk_data['risk_score']
        print(f"🎯 RISK SCORE: {score}/100")
        if score >= 70:
            print("   ⚠️  HIGH RISK - Likely malicious")
        elif score >= 40:
            print("   ⚠️  MEDIUM RISK - Suspicious activity")
        else:
            print("   ✓ LOW RISK")
        print()
    
    # Risk Indicators
    if results['risk_indicators']:
        print("📊 RISK INDICATORS:")
        for indicator in results['risk_indicators']:
            print(f"   • {indicator}")
        print()
    
    # Discovered IOCs
    print("🔍 DISCOVERED IOCs:")
    iocs = results['iocs']
    
    if iocs['ip_addresses']:
        print(f"\n   IP Addresses ({len(iocs['ip_addresses'])}):")
        for ip in iocs['ip_addresses'][:5]:
            print(f"      • {ip['ip']} (first seen: {ip['first_seen']})")
    
    if iocs['name_servers']:
        print(f"\n   Name Servers ({len(iocs['name_servers'])}):")
        for ns in iocs['name_servers']:
            print(f"      • {ns}")
    
    if iocs['registrant_emails']:
        print(f"\n   Registrant Emails ({len(iocs['registrant_emails'])}):")
        for email in iocs['registrant_emails']:
            print(f"      • {email}")
    
    if iocs['related_domains_by_email']:
        print(f"\n   Related Domains (by email) ({len(iocs['related_domains_by_email'])}):")
        for domain in iocs['related_domains_by_email'][:10]:
            print(f"      • {domain}")
    
    if iocs['reverse_ip_neighbors']:
        print(f"\n   Reverse IP Neighbors ({len(iocs['reverse_ip_neighbors'])}):")
        for domain in iocs['reverse_ip_neighbors'][:10]:
            print(f"      • {domain}")
    
    # Pivot Opportunities
    if results['pivot_opportunities']:
        print(f"\n{'='*70}")
        print("🎯 RECOMMENDED PIVOT ACTIONS:")
        print(f"{'='*70}")
        for i, pivot in enumerate(results['pivot_opportunities'], 1):
            print(f"\n{i}. {pivot['type'].upper()} [Confidence: {pivot['confidence']}]")
            print(f"   Action: {pivot['action']}")
            if 'domains' in pivot:
                print(f"   Sample domains: {', '.join(pivot['domains'][:3])}")
    
    print(f"\n{'='*70}\n")

def save_results(results: Dict, output_file: str):
    """Save results to JSON file"""
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"✓ Results saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description='DomainTools Domain Analysis Tool - Automated threat intelligence gathering'
    )
    parser.add_argument('domain', help='Domain to analyze')
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
    
    # Initialize analyzer
    analyzer = DomainToolsAnalyzer(api_user, api_key)
    
    # Run analysis
    deep_analysis = not args.quick
    results = analyzer.analyze_domain(args.domain, deep_analysis=deep_analysis)
    
    # Print results
    print_results(results)
    
    # Save to file if requested
    if args.output:
        save_results(results, args.output)
    else:
        default_output = f"domaintools_{args.domain.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        save_results(results, default_output)

if __name__ == '__main__':
    main()
