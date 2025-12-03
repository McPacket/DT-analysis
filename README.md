# DomainTools Domain Analysis Configuration

## API Credentials Setup

### Option 1: Environment Variables (Recommended)
```bash
export DOMAINTOOLS_USER="your_api_username"
export DOMAINTOOLS_KEY="your_api_key"
```

Add to your ~/.bashrc or ~/.zshrc for persistence:
```bash
echo 'export DOMAINTOOLS_USER="your_api_username"' >> ~/.bashrc
echo 'export DOMAINTOOLS_KEY="your_api_key"' >> ~/.bashrc
source ~/.bashrc
```

### Option 2: Command Line Arguments
```bash
python3 domaintools_analyzer.py example.com --api-user your_username --api-key your_key
```

## Installation

### Prerequisites
```bash
# Install Python 3.8+
sudo apt-get update
sudo apt-get install python3 python3-pip

# Install required packages
pip3 install requests
```

### Make Scripts Executable
```bash
chmod +x domaintools_analyzer.py
chmod +x domaintools_batch_analyzer.py
```

## Usage Examples

### Single Domain Analysis

**Full Analysis (includes reverse WHOIS, typosquatting, etc.)**
```bash
python3 domaintools_analyzer.py malicious-domain.com
```

**Quick Analysis (core intelligence only)**
```bash
python3 domaintools_analyzer.py malicious-domain.com --quick
```

**Specify Output File**
```bash
python3 domaintools_analyzer.py malicious-domain.com --output my_analysis.json
```

### Batch Domain Analysis

**Create a domain list file (domains.txt)**
```
malicious-domain1.com
malicious-domain2.com
phishing-site.net
# Comments are ignored
suspicious-login.com
```

**Run Batch Analysis**
```bash
python3 domaintools_batch_analyzer.py domains.txt
```

**Quick Batch Analysis with Custom Output**
```bash
python3 domaintools_batch_analyzer.py domains.txt --quick --output threat_report.json
```

## Output Structure

### Single Domain Analysis Output

```json
{
  "domain": "example.com",
  "timestamp": "2025-12-03T10:30:00.000000",
  "analysis": {
    "whois": { /* Full WHOIS data */ },
    "risk_score": { /* DomainTools risk scoring */ },
    "reputation": { /* Domain reputation data */ },
    "dns_history": { /* Historical DNS/IP data */ },
    "domain_profile": { /* Comprehensive profile */ },
    "related_domains": { /* Related infrastructure */ },
    "typosquatting": { /* Brand monitoring alerts */ },
    "reverse_ip": { /* Co-hosted domains */ }
  },
  "iocs": {
    "ip_addresses": [
      {"ip": "1.2.3.4", "first_seen": "2025-01-01", "source": "hosting_history"}
    ],
    "name_servers": ["ns1.example.com", "ns2.example.com"],
    "registrant_emails": ["contact@example.com"],
    "registrant_orgs": ["Example Corp"],
    "related_domains_by_email": ["domain1.com", "domain2.com"],
    "reverse_ip_neighbors": ["neighbor1.com", "neighbor2.com"]
  },
  "risk_indicators": [
    "HIGH RISK SCORE: 85/100",
    "Domain creation date: 2025-11-01"
  ],
  "pivot_opportunities": [
    {
      "type": "high_risk_domain",
      "confidence": "HIGH",
      "action": "Investigate all related infrastructure immediately"
    },
    {
      "type": "registrant_infrastructure",
      "confidence": "HIGH",
      "action": "Analyze all related domains - same threat actor infrastructure",
      "domains": ["related1.com", "related2.com"]
    }
  ]
}
```

### Batch Analysis Report Structure

```json
{
  "summary": {
    "total_domains": 10,
    "high_risk_domains": 3,
    "medium_risk_domains": 5,
    "low_risk_domains": 2,
    "errors": 0
  },
  "threat_clusters": {
    "by_registrant_email": {
      "attacker@example.com": ["domain1.com", "domain2.com", "domain3.com"]
    },
    "by_registrant_org": { /* Organization clusters */ },
    "by_ip_address": { /* IP-based clusters */ },
    "by_name_server": { /* DNS infrastructure clusters */ }
  },
  "high_priority_targets": [
    {
      "cluster_type": "by_registrant_email",
      "cluster_key": "attacker@example.com",
      "domain_count": 3,
      "domains": ["domain1.com", "domain2.com", "domain3.com"],
      "reason": "Infrastructure cluster - 3 domains share registrant_email"
    }
  ],
  "detailed_results": [ /* Full individual domain results */ ]
}
```

## Threat Hunting Workflow

### 1. Initial IOC Discovery
```bash
# Analyze suspected malicious domain
python3 domaintools_analyzer.py suspicious-domain.com
```

### 2. Review Pivot Opportunities
The tool automatically identifies:
- Related domains by registrant (HIGH confidence pivot)
- Shared IP infrastructure (MEDIUM confidence pivot)
- Name server clustering (MEDIUM confidence pivot)
- Risk score indicators (immediate threat assessment)

### 3. Expand Investigation
Extract related domains from output and create new domain list:
```bash
# From JSON output, extract related_domains_by_email
jq -r '.iocs.related_domains_by_email[]' domaintools_*.json > expanded_domains.txt

# Analyze expanded infrastructure
python3 domaintools_batch_analyzer.py expanded_domains.txt
```

### 4. Cross-Reference with Other Tools
Use discovered IOCs with your infrastructure hunting tools:

**IP Addresses → Shodan/Censys**
```bash
# Extract IPs
jq -r '.iocs.ip_addresses[].ip' domaintools_*.json

# Query in Shodan
shodan host 1.2.3.4
```

**Name Servers → DNS Intelligence**
```bash
# Extract name servers
jq -r '.iocs.name_servers[]' domaintools_*.json

# Query other platforms for domains using same NS
```

**Registrant Info → Reverse WHOIS**
```bash
# Already included in analysis, but can pivot further on other platforms
```

## Integration with Amazon Q

To integrate this with Amazon Q, create a custom action:

1. **Create AWS Lambda function** with this Python code
2. **Configure Lambda Layer** with `requests` package
3. **Set environment variables** in Lambda for API credentials
4. **Create Amazon Q Custom Action** pointing to Lambda
5. **Prompt Amazon Q**: "Analyze domain malicious-site.com for threat intelligence"

Amazon Q will:
- Invoke the Lambda function
- Receive structured JSON response
- Perform AI analysis on the results
- Provide contextualized threat intelligence

## API Rate Limits & Cost Considerations

DomainTools API has different tiers with varying rate limits:

- **Personal**: ~5 API calls/month (very limited)
- **Professional**: ~100-500 API calls/month
- **Enterprise**: Custom limits

### Optimizing API Usage

**Use Quick Mode for Initial Triage**
```bash
python3 domaintools_analyzer.py domain.com --quick
```
This reduces API calls by ~40% by skipping:
- Reverse WHOIS lookups
- Typosquatting checks
- Some extended profiling

**Batch Similar Domains**
Group analysis sessions to stay within monthly quotas.

## Troubleshooting

### Authentication Errors
```
❌ Error: 401 Unauthorized
```
**Solution**: Verify API credentials are correct

### Rate Limit Errors
```
❌ Error: 429 Too Many Requests
```
**Solution**: You've exceeded API quota. Wait for reset or upgrade tier.

### API Endpoint Not Available
```
❌ Note: Brand monitoring requires specific API tier
```
**Solution**: Some features require higher API tiers. Contact DomainTools sales.

## Security Best Practices

1. **Never commit API credentials to git**
2. **Use environment variables or AWS Secrets Manager**
3. **Restrict API key permissions** to read-only if possible
4. **Rotate API keys** regularly
5. **Monitor API usage** for unauthorized access

## Next Steps: Enhanced Features

Consider adding:
- **VirusTotal Integration**: Cross-reference domains with VT intelligence
- **Shodan Integration**: Pivot from IPs to service fingerprints
- **MISP Integration**: Export IOCs to MISP threat sharing platform
- **Slack/Discord Notifications**: Alert on high-risk findings
- **Automated Blocking**: Feed results to firewall/proxy for automatic blocking
