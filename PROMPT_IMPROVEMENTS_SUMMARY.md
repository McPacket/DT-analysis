# Prompt Engineering Improvements - Before & After

## Summary of Changes

All prompts have been revised following prompt engineering best practices. Here's how the new versions (v2) improve upon the originals:

---

## ✅ Best Practice 1: Start with Simplicity

### Before
```markdown
## Purpose
Analyze domains for malicious activity using DomainTools API and provide 
comprehensive threat intelligence assessment with actionable recommendations.
```

### After
```markdown
**Role**: You are a senior threat intelligence analyst specializing in 
adversary infrastructure hunting with expertise in domain analysis, IOC 
pivoting, and threat actor attribution.

**Goal**: Analyze domains for malicious activity using DomainTools API, 
identify infrastructure patterns, extract actionable IOCs, and provide 
clear recommendations for threat hunting and incident response.
```

**Improvement**: Added clear role prompting and broke goal into specific, actionable components using simple language.

---

## ✅ Best Practice 2: Use Action Verbs

### Before
```markdown
### 3. Threat Assessment Analysis
Perform comprehensive threat assessment based on the data:
```

### After
```markdown
## Step 2: Assess Threat Level
**Action**: Interpret the risk score and identify primary threat indicators.
```

**Improvement**: Every section now starts with a clear action verb (Execute, Assess, Extract, Identify, Generate, Match).

---

## ✅ Best Practice 3: Provide Examples (Critical)

### Before
- No concrete examples in original prompts

### After (Added Multiple Examples)
```markdown
### Example 1: High-Risk Phishing Domain
**User Input**: @domain-threat-analysis urgent-security-verify.com

**Expected Output**:
🎯 EXECUTIVE SUMMARY
urgent-security-verify.com is MALICIOUS (HIGH confidence). This is an 
active phishing domain targeting users with fake security alerts.
[... full example continues ...]

### Example 2: Benign Domain
**User Input**: @domain-threat-analysis google.com
[... full example ...]
```

**Improvement**: Added 2-3 complete input/output examples for each prompt showing both malicious and benign cases. Examples demonstrate exact format expected.

---

## ✅ Best Practice 4: Specify Output Format

### Before
```markdown
## Output Format
Present findings in clear, structured format:
- Use emojis for visual clarity
- Bold key findings
- Bullet points for IOCs
```

### After
```markdown
### 🎯 EXECUTIVE SUMMARY
[One sentence: Is this domain malicious? HIGH/MEDIUM/LOW risk]

**Verdict**: [MALICIOUS / SUSPICIOUS / BENIGN]
**Confidence**: [HIGH / MEDIUM / LOW]
**Primary Threat**: [e.g., "Phishing campaign targeting financial sector"]

### ⚠️ KEY FINDINGS
- Risk Score: [X/100]
- Domain Age: [X days old, registered YYYY-MM-DD]
[... exact structure continues ...]
```

**Improvement**: Specified EXACT format with placeholders showing what goes where. No ambiguity about structure.

---

## ✅ Best Practice 5: Use Instructions Over Constraints

### Before
```markdown
## Notes
- Always run the script first before providing analysis
- Base assessment on data returned, don't speculate
- If script fails, clearly state the error
```

### After
```markdown
**Always**:
✓ Run the script before analyzing (never speculate without data)
✓ Base assessment only on returned data
✓ Provide specific, actionable recommendations

**Never**:
✗ Speculate beyond the data
✗ Make definitive claims with LOW confidence
✗ Provide generic advice
```

**Improvement**: Reframed as positive instructions (Always/Never) with specific checkboxes. Tells model what TO do, not just what to avoid.

---

## ✅ Best Practice 6: Use Variables for Reusability

### Before
- Hardcoded paths in examples

### After
```markdown
## Variables Reference
Replace these in actual use:
- `{domain}`: Target domain to analyze
- `/path/to/`: Full path to script location

**Temperature Setting**: 0.2 (Low creativity, factual analysis)
**Max Tokens**: 2000 (Comprehensive report)
```

**Improvement**: Added dedicated variables section and included model configuration parameters.

---

## ✅ Best Practice 7: Role Prompting

### Before
- No role definition

### After
```markdown
**Role**: You are a senior threat intelligence analyst specializing in 
adversary infrastructure hunting with expertise in domain analysis, IOC 
pivoting, and threat actor attribution.
```

**Improvement**: Explicitly defined expert role to set appropriate tone and expertise level.

---

## ✅ Best Practice 8: Contextual Prompting

### Before
```markdown
### 5. Threat Actor Pattern Recognition
If patterns match known threat actors, provide context:
```

### After
```markdown
## Step 5: Match Threat Actor Patterns
**Action**: Compare domain characteristics against known threat actor TTPs.

### DPRK Actors (Lazarus, Bluenoroff, APT43)
**Look for**: Dynamic DNS (linkpc.net, publicvm.com, ddns.net), 
cryptocurrency themes, job recruitment lures
**Examples**: jobdescription.linkpc.net, bitscrunch.ddns.net
**Confidence**: HIGH if 3+ patterns match
```

**Improvement**: Added specific context with actual examples, confidence thresholds, and clear matching criteria.

---

## ✅ Best Practice 9: Specify Length Requirements

### Before
- No length guidance

### After
```markdown
## Output Requirements
- **Length**: 15-30 lines for quick analysis, 40-60 lines for comprehensive
- **Format**: Use emojis, bold, bullets, and code blocks as shown in examples
- **Tone**: Direct, professional, actionable
```

**Quick Check Prompt**:
```markdown
**Always**:
- Keep response under 10 lines
```

**Improvement**: Explicit length constraints for different prompt types.

---

## ✅ Best Practice 10: Documentation Template

### Before
- No model configuration specified

### After
```markdown
---
**Temperature Setting**: 0.2 (Low creativity, factual analysis)
**Max Tokens**: 2000 (Comprehensive report)
---

Quick Check:
**Temperature**: 0 (Deterministic, factual)
**Max Tokens**: 200 (Brief output)

Batch Analysis:
**Temperature**: 0.2 (Factual with some analytical flexibility)
**Max Tokens**: 3000 (Comprehensive batch report)
```

**Improvement**: Added model configuration parameters appropriate for each task type.

---

## Detailed Improvements by Prompt

### Domain Threat Analysis (Comprehensive)

| Aspect | Before | After |
|--------|--------|-------|
| **Structure** | Numbered steps | Step-by-step with Action verbs |
| **Examples** | 0 examples | 2 complete examples (malicious + benign) |
| **Output Format** | Vague guidance | Exact template with placeholders |
| **Role** | Not defined | Senior threat intelligence analyst |
| **Length** | Unspecified | 40-60 lines specified |
| **Temperature** | Not specified | 0.2 (factual analysis) |
| **Instructions** | Mixed positive/negative | Clear Always/Never lists |

### Quick Domain Check

| Aspect | Before | After |
|--------|--------|-------|
| **Structure** | Loose format | Exact 4-line output format |
| **Examples** | 0 examples | 3 examples (malicious, suspicious, safe) |
| **Output Format** | "Brief" | "Under 10 lines" with exact structure |
| **Role** | Not defined | SOC analyst (rapid triage) |
| **Length** | "5-10 lines max" | "Under 10 lines" (more direct) |
| **Temperature** | Not specified | 0 (deterministic) |
| **Action Verbs** | Minimal | Check, Identify, Recommend (all specific) |

### Batch Domain Analysis

| Aspect | Before | After |
|--------|--------|-------|
| **Structure** | Analysis approach | Workflow with 3 clear steps |
| **Examples** | 0 examples | 1 comprehensive example (full workflow) |
| **Output Format** | General sections | Exact template for clusters and IOCs |
| **Role** | Not defined | Threat intelligence analyst (campaign attribution) |
| **Cluster Definition** | Vague | Specific format for each cluster type |
| **Temperature** | Not specified | 0.2 (analytical flexibility) |
| **Action Verbs** | Analyze, Look for | Analyze, Identify, Generate, Consolidate |

---

## Key Improvements Summary

### ✅ Completeness
- **Before**: Missing examples, role definitions, and model configs
- **After**: Complete prompts with examples, roles, and temperature settings

### ✅ Clarity
- **Before**: Vague output descriptions
- **After**: Exact templates with placeholders and length requirements

### ✅ Actionability
- **Before**: General guidance
- **After**: Specific action verbs, commands, and tool queries

### ✅ Reusability
- **Before**: Hardcoded values
- **After**: Variables clearly marked ({domain}, {file_path}, /path/to/)

### ✅ Consistency
- **Before**: Inconsistent structure across prompts
- **After**: Standardized format (Role → Goal → Steps → Output → Examples → Rules)

---

## Before/After Comparison: Quick Example

### Original Quick Check
```markdown
# Quick Domain Check
## Purpose
Rapid domain threat assessment using DomainTools API.

## Output
- ✅ SAFE / ⚠️ SUSPICIOUS / 🚨 MALICIOUS
- Top 3 risk indicators
- Critical IOCs to block
- Next step recommendation

Keep it brief - 5-10 lines max.
```

### Improved Quick Check v2
```markdown
# Quick Domain Threat Check

**Role**: You are a SOC analyst performing rapid domain triage during 
active incidents.

**Goal**: Provide immediate verdict (SAFE/SUSPICIOUS/MALICIOUS) with 
top 3 risk indicators and one-line next action in under 10 lines.

---

## Output Format (EXACTLY)
[EMOJI] [VERDICT]

Top 3 Indicators:
• [Indicator 1 with metric]
• [Indicator 2 with metric]
• [Indicator 3 with metric]

Action: [One specific action to take now]

---

### Example 1: Malicious Domain
**Input**: @quick-domain-check phishing-urgent-verify.com

**Output**:
🚨 MALICIOUS

Top 3 Indicators:
• Risk score: 92/100 (DomainTools HIGH)
• Domain age: 2 days (registered yesterday)
• Clustering: 12 related domains by same registrant

Action: Block immediately in web proxy. Check logs for user 
connections in last 24 hours.
```

**Difference**: v2 is 5x more specific with exact format, example, and clear role.

---

## Files Updated

### New V2 Prompts (Improved)
1. **[domain-threat-analysis-v2.md](computer:///mnt/user-data/outputs/domain-threat-analysis-v2.md)**
   - Added role prompting
   - 2 complete examples
   - Exact output template
   - Temperature: 0.2

2. **[quick-domain-check-v2.md](computer:///mnt/user-data/outputs/quick-domain-check-v2.md)**
   - Added SOC analyst role
   - 3 complete examples
   - 10-line limit enforced
   - Temperature: 0

3. **[batch-domain-analysis-v2.md](computer:///mnt/user-data/outputs/batch-domain-analysis-v2.md)**
   - Added TI analyst role
   - 1 comprehensive example
   - Cluster template format
   - Temperature: 0.2

### Original Prompts (For Reference)
1. domain-threat-analysis.md (v1)
2. quick-domain-check.md (v1)
3. batch-domain-analysis.md (v1)

---

## Recommendation

**Use the V2 prompts** for production. They follow all best practices:
- ✅ Simple, clear language with action verbs
- ✅ Role prompting for appropriate expertise
- ✅ Multiple examples (critical for quality)
- ✅ Exact output format specifications
- ✅ Length requirements enforced
- ✅ Variables for reusability
- ✅ Model configuration specified
- ✅ Instructions over constraints
- ✅ Appropriate temperature settings

The V2 prompts will produce more consistent, higher-quality outputs from Amazon Q.
