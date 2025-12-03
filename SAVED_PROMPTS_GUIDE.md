# Using Saved Prompts with Amazon Q - Complete Guide

## Overview

Instead of configuring complex custom actions, use **saved prompt templates** (`.md` files) that Amazon Q can reference. This is simpler and more flexible.

## Setup

### 1. Save Prompt Templates

I've created three prompt templates for you:

**For comprehensive analysis:**
- **File**: `domain-threat-analysis.md`
- **Use when**: Full investigation of suspicious domain
- **Output**: Detailed threat report with IOCs and pivot recommendations

**For quick checks:**
- **File**: `quick-domain-check.md`  
- **Use when**: Rapid triage, need quick verdict
- **Output**: Brief assessment (5-10 lines)

**For multiple domains:**
- **File**: `batch-domain-analysis.md`
- **Use when**: Analyzing multiple domains, looking for patterns
- **Output**: Cluster analysis and consolidated IOC list

### 2. Update Script Paths

**Edit each `.md` file** and replace `/path/to/` with your actual paths:

```bash
# Find your current directory
pwd

# Example: If you're in /home/mitch/domaintools/
# Update this line in the .md files:
python3 /path/to/domaintools_query.py {domain}

# To this:
python3 /home/mitch/domaintools/domaintools_query.py {domain}
```

### 3. Make Amazon Q Aware of Prompts

**Option A: Upload to Amazon Q Project** (Recommended)

1. In Amazon Q, create or open your project
2. Upload the `.md` files as knowledge sources
3. Amazon Q will be able to reference them with `@`

**Option B: Use File Path Reference**

Tell Amazon Q where the files are:
```
The domain analysis prompt is at /home/mitch/domaintools/domain-threat-analysis.md
```

Amazon Q will remember this in the conversation.

## Usage Examples

### Comprehensive Analysis

```
@domain-threat-analysis malicious-site.com
```

or more naturally:

```
Follow the domain-threat-analysis prompt to analyze suspicious-login.net
```

Amazon Q will:
1. Read the `domain-threat-analysis.md` instructions
2. Execute: `python3 domaintools_query.py suspicious-login.net`
3. Receive JSON results
4. Follow the analysis framework in the prompt
5. Provide comprehensive threat intelligence report

### Quick Check

```
@quick-domain-check urgent-security-update.com
```

Amazon Q will:
1. Read `quick-domain-check.md`
2. Run script with `--quick` flag
3. Provide brief verdict (SAFE/SUSPICIOUS/MALICIOUS)
4. List top 3 risk indicators
5. Give one-line recommendation

### Batch Analysis

```
@batch-domain-analysis

Analyze these domains:
phishing1.com
phishing2.com
malware-c2.net
```

Amazon Q will:
1. Read `batch-domain-analysis.md`
2. Run script for each domain
3. Look for infrastructure clusters
4. Provide consolidated threat report

## Real-World Workflow Examples

### Example 1: Phishing Email Investigation

**Scenario**: Security alert about phishing email with domain `secure-verify-account.com`

**Your prompt:**
```
@domain-threat-analysis secure-verify-account.com

Context: Received in phishing email claiming to be from IT department
```

**Amazon Q Response:**
```
🎯 EXECUTIVE SUMMARY
Domain secure-verify-account.com is MALICIOUS (HIGH confidence)
Risk Score: 87/100 - Confirmed phishing infrastructure

⚠️ KEY FINDINGS
• Domain registered 2 days ago (2025-12-01)
• High risk score of 87 indicates active threat
• Part of larger phishing campaign (12 related domains)
• Registrant: tempmail123@proton.me (disposable email)

🔍 DISCOVERED IOCs - BLOCK IMMEDIATELY
• secure-verify-account.com
• secure-login-portal.com (related)
• verify-account-now.net (related)
• IPs: 185.220.101.45, 198.54.117.200
• Name servers: ns1.malicious-host.ru

📋 RECOMMENDED ACTIONS
1. BLOCK all 3 domains in web proxy NOW
2. BLOCK IPs: 185.220.101.45, 198.54.117.200
3. Search email logs for other domains by same registrant
4. Hunt proxy logs for connections to ns1.malicious-host.ru
5. Create detection rule for future domains from this registrant
```

### Example 2: Quick Triage During Incident

**Scenario**: User clicked on link, need quick assessment

**Your prompt:**
```
@quick-domain-check user-clicked-on-this-domain.com
```

**Amazon Q Response:**
```
🚨 MALICIOUS

Top 3 indicators:
• Risk score: 92/100
• Registered yesterday
• 8 related phishing domains

BLOCK immediately. Check user's machine for compromise.
```

### Example 3: Campaign Analysis

**Scenario**: Multiple suspicious domains in proxy logs

**Your prompt:**
```
@batch-domain-analysis

Found these in proxy logs today:
secure-microsoft-sso.com
microsoft-auth-portal.net
ms-office-verify.com
microsoft-support-help.net
```

**Amazon Q Response:**
```
📊 SUMMARY
Total domains: 4
High risk: 4 | Medium risk: 0 | Low risk: 0
Clusters identified: 1 MAJOR CAMPAIGN

🎯 THREAT CLUSTER DETECTED
**Type**: Registrant Infrastructure
**Indicator**: attacker@tempmail.xyz
**Domains**: All 4 domains
**Assessment**: Coordinated Microsoft impersonation campaign

All domains:
• Registered same day (2025-11-29)
• Same registrant email
• Same name servers
• Risk scores 85-95/100

🚨 HIGH PRIORITY
This is an active, coordinated phishing campaign.
BLOCK all 4 domains immediately.

📋 CONSOLIDATED IOC LIST
Block these NOW:
• All 4 domains above
• Registrant email: attacker@tempmail.xyz
• IP: 203.0.113.45
• Name servers: ns1.badhost.ru, ns2.badhost.ru

Next: Hunt for any user connections to these domains in last 7 days
```

## Advanced Usage

### Combining with Web Search

```
@domain-threat-analysis suspicious-domain.com

Also search for any recent security reports about this domain
```

Amazon Q will run domain analysis AND search for additional context.

### Custom Context

```
@domain-threat-analysis phishing-site.com

Context: 
- Found in email from "IT Support <support@phishing-site.com>"
- Subject: "Urgent: Password Expiration"
- 15 users clicked the link
```

Amazon Q will factor in this context when providing recommendations.

### Follow-up Analysis

```
@domain-threat-analysis found 12 related domains. 
Run batch analysis on those domains to map full infrastructure.
```

## Tips for Best Results

1. **Be specific about what you need:**
   - Quick verdict vs comprehensive analysis
   - Single domain vs batch
   - Investigation context

2. **Provide context when relevant:**
   - How the domain was discovered
   - What users may have been affected
   - Urgency level

3. **Use follow-up prompts:**
   ```
   Now query Shodan for those IPs
   ```
   ```
   Create a blocking rule for all related domains
   ```

4. **Chain analyses:**
   ```
   @domain-threat-analysis domain1.com
   
   [After results]
   
   @batch-domain-analysis Now analyze all the related domains you found
   ```

## Customizing Prompts

You can edit the `.md` files to match your environment:

### Add Your Specific Tools

In `domain-threat-analysis.md`, update the "Cross-Tool Analysis" section:
```markdown
3. **Cross-Tool Analysis**:
   - Query our Splunk index=proxy for connections
   - Check our ThreatConnect instance for known IOCs
   - Search our SIEM for alert correlations
```

### Add Your Response Procedures

```markdown
#### 📋 RECOMMENDED ACTIONS

**Immediate Actions:**
1. Block domain in Palo Alto firewall
2. Create Jira ticket: "Phishing Infrastructure Detected"
3. Alert #security-team Slack channel
4. Notify SOC manager if high risk
```

### Adjust Output Format

Prefer tables? Add to prompt:
```markdown
## Output Format
Present IOCs in table format:
| IOC Type | Value | Risk | Action |
|----------|-------|------|--------|
```

## Troubleshooting

### Amazon Q doesn't recognize `@` reference

Try these alternatives:
```
Use the domain-threat-analysis prompt to analyze domain.com
```
```
Follow the instructions in domain-threat-analysis.md for domain.com
```

### Script execution fails

Amazon Q will show the error. Common fixes:
```bash
# Check script path is correct
ls -la /path/to/domaintools_query.py

# Check credentials
echo $DOMAINTOOLS_USER
echo $DOMAINTOOLS_KEY

# Check permissions
chmod +x domaintools_query.py
```

### Want different analysis depth

Create a custom prompt:
```markdown
# Fast Domain Check
## Purpose
Ultra-quick verdict only
## Execution
python3 domaintools_query.py {domain} --quick
## Output
One line: SAFE / SUSPICIOUS / MALICIOUS
```

## Summary

**This approach gives you:**
- ✅ No complex Amazon Q action configuration needed
- ✅ Easy to customize and update prompts
- ✅ Flexible analysis depth (quick/full/batch)
- ✅ Consistent structured output
- ✅ Natural language interaction with Amazon Q
- ✅ Version control friendly (`.md` files in git)

**Your workflow:**
1. Save `.md` prompt files
2. Update script paths in prompts
3. Reference with `@prompt-name` in Amazon Q
4. Get structured threat intelligence
5. Take action based on recommendations
