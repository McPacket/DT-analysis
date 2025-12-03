#!/usr/bin/env python3
"""
DomainTools Analysis Script for Amazon Q
Simple wrapper that takes a domain parameter and returns analysis results
"""

import sys
import json
import os
from domaintools_analyzer import DomainToolsAnalyzer

def main():
    """Main function - takes domain as argument, returns JSON analysis"""
    
    # Check for domain argument
    if len(sys.argv) < 2:
        error_response = {
            "error": "Missing domain parameter",
            "usage": "python3 domaintools_query.py <domain> [--quick]"
        }
        print(json.dumps(error_response, indent=2))
        sys.exit(1)
    
    domain = sys.argv[1]
    quick = '--quick' in sys.argv
    
    # Get API credentials from environment
    api_user = os.getenv('DOMAINTOOLS_USER')
    api_key = os.getenv('DOMAINTOOLS_KEY')
    
    if not api_user or not api_key:
        error_response = {
            "error": "DomainTools API credentials not found",
            "message": "Set DOMAINTOOLS_USER and DOMAINTOOLS_KEY environment variables"
        }
        print(json.dumps(error_response, indent=2))
        sys.exit(1)
    
    # Initialize analyzer
    analyzer = DomainToolsAnalyzer(api_user, api_key)
    
    # Perform analysis
    deep_analysis = not quick
    results = analyzer.analyze_domain(domain, deep_analysis=deep_analysis)
    
    # Output JSON to stdout (Amazon Q will capture this)
    print(json.dumps(results, indent=2))

if __name__ == '__main__':
    main()
