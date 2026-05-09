# ISO 27001:2022 Policies - Quick Reference

## 📋 Policy Files Overview

### 1. azure_mfa_policy.rego
**Controls:** A.5.15 (User Management), A.5.16 (Identity Management)  
**Enforces:** MFA, password management, account lifecycle

```bash
opa eval -d data/examples/azure_users.json \
  -b policies/ \
  'data.iso27001_2022.authentication.deny'
```

**Key Rules:**
- ✅ MFA mandatory for all users
- ✅ Password minimum 12 characters
- ✅ Complexity required
- ✅ Password change every 90 days
- ✅ Inactive accounts disabled (60+ days)
- ✅ PIM for privileged accounts
- ✅ Conditional Access for cloud users

---

### 2. azure_encryption_policy.rego
**Controls:** A.5.10 (Cryptography), A.5.23 (Cloud Security)  
**Enforces:** Encryption at rest & in transit, key management

```bash
opa eval -d data/examples/cloud_resources.json \
  -b policies/ \
  'data.iso27001_2022.cryptography.deny'
```

**Key Rules:**
- ✅ AES-256 encryption at rest only
- ✅ TLS 1.2+ for all transfers (no downgrade)
- ✅ HTTPS only (no HTTP)
- ✅ Encryption key rotation ≤12 months
- ✅ Transparent Data Encryption (TDE) for SQL
- ✅ Data residency enforcement for sensitive data
- ✅ Cloud key management assessment

---

### 3. monitoring_policy.rego
**Controls:** A.5.18 (Monitoring - NEW EMPHASIS), A.5.23.1 (Cloud Monitoring)  
**Enforces:** Continuous monitoring, metrics, incident response

```bash
opa eval -d data/examples/cloud_resources.json \
  -b policies/ \
  'data.iso27001_2022.monitoring.deny'
```

**Key Rules (2022 NEW EMPHASIS):**
- ✅ Monitoring enabled on all resources
- ✅ Audit logging mandatory (60+ day retention)
- ✅ Real-time alerting for sensitive data
- ✅ MTTR tracking (≤4 hours target)
- ✅ MTPD tracking (≤1 hour target)
- ✅ Cloud security monitoring (NEW 2022)
- ✅ Automated log analysis
- ✅ Metrics & KPIs tracked

---

### 4. m365_data_protection_policy.rego
**Controls:** A.5.19 (Asset Management), A.5.23 (Cloud), A.5.9 (Supply Chain)  
**Enforces:** Data classification, DLP, supplier management

```bash
opa eval -d data/examples/m365_resources.json \
  -b policies/ \
  'data.iso27001_2022.m365_data_protection.deny'
```

**Key Rules:**
- ✅ Data classification mandatory (Public/Internal/Confidential/Restricted)
- ✅ Retention labels for sensitive data
- ✅ DLP policies on sensitive data
- ✅ External sharing restrictions with MFA
- ✅ Cloud provider security assessments (NEW 2022)
- ✅ Data Processing Agreements (DPA) required (NEW 2022)
- ✅ Incident response procedures for cloud (NEW 2022)
- ✅ Vendor security reviews (ENHANCED 2022)

---

## 🔍 Violation Types

### By Severity

**CRITICAL - Fix Immediately:**
- MFA not enabled
- Encryption disabled
- Monitoring missing
- Cloud provider not assessed

**HIGH - Fix Within 30 Days:**
- Weak encryption algorithm
- Short log retention
- No DLP policy
- No data classification

**MEDIUM - Fix Within 90 Days:**
- Inactive users not disabled
- SIEM not integrated
- Vendor reviews overdue
- Passwordless auth not enabled

---

## 📊 Common Commands

### View All Violations
```bash
opa eval -d data/examples/*.json \
  -b policies/ \
  'data.iso27001_2022.*.deny[msg]' | jq .
```

### Count Violations by Type
```bash
opa eval -d data/examples/azure_users.json \
  -b policies/ \
  'data.iso27001_2022.authentication.deny | length'
```

### Get Just the Messages
```bash
opa eval -d data/examples/*.json \
  -b policies/ \
  'data.iso27001_2022.*.deny[_].msg' | jq -r .[]
```

### Export to CSV
```bash
opa eval -d data/examples/*.json \
  -b policies/ \
  'data.iso27001_2022.*.deny' | \
  jq -r '.[] | [.msg] | @csv' > violations.csv
```

### Get Recommendations
```bash
opa eval -d data/examples/*.json \
  -b policies/ \
  'data.iso27001_2022.*.audit[msg]' | jq -r .[]
```

---

## 🎯 Control Checklist

### Phase 1: Foundation (Weeks 1-4)
- [ ] Audit azure_mfa_policy violations
- [ ] Audit azure_encryption_policy violations
- [ ] Identify all users without MFA
- [ ] Identify all unencrypted resources
- [ ] Baseline established

### Phase 2: Remediation (Weeks 5-12)
- [ ] Enable MFA for all users
- [ ] Apply AES-256 encryption
- [ ] Enable monitoring on all resources
- [ ] Implement Conditional Access policies
- [ ] Update password policies

### Phase 3: Cloud Controls (Weeks 13-16) *NEW 2022*
- [ ] Complete cloud provider assessments
- [ ] Implement data residency controls
- [ ] Set up incident response procedures
- [ ] Deploy DLP policies
- [ ] Establish vendor security reviews

### Phase 4: Measurement (Weeks 17-20) *NEW 2022 EMPHASIS*
- [ ] Set up metrics dashboards (MTTR, MTPD)
- [ ] Implement SIEM integration
- [ ] Establish KPI tracking
- [ ] Configure continuous monitoring
- [ ] Build compliance reporting

---

## 🚨 Critical Controls

### Must Have Immediately:
1. **MFA on all accounts** (A.5.15)
   - High risk if missing
   - Simple to implement
   - Major audit finding

2. **Encryption at rest** (A.5.10)
   - Regulatory requirement
   - Data breach risk
   - Cloud mandate

3. **Audit logging** (A.5.18)
   - Required for incident response
   - Forensics requirement
   - Audit requirement

4. **Cloud assessment** (A.5.23) **NEW 2022**
   - All cloud services require assessment
   - New requirement in 2022
   - Fundamental for cloud governance

---

## 🔄 Data Export Automation

### PowerShell - Azure Users
```powershell
$users = Get-AzADUser -All
$users | ConvertTo-Json | Out-File data/examples/azure_users.json
```

### Azure CLI - Cloud Resources
```bash
az resource list --output json > data/examples/cloud_resources.json
az storage account list --output json >> data/examples/cloud_resources.json
```

### Microsoft Graph - M365 Resources
```powershell
Connect-MgGraph
Get-MgUser -All -Filter "createdDateTime gt 2020-01-01" | ConvertTo-Json | Out-File data/examples/m365_resources.json
```

---

## 📈 Metrics & KPIs

### Track These (NEW in 2022):
```
MTPD (Mean Time to Detect):     Target ≤ 1 hour
MTTR (Mean Time to Respond):    Target ≤ 4 hours
Control Coverage:               Target ≥ 90%
Policy Violations:              Target 0 (critical), <5 (high)
Remediation Rate:               Target ≥ 80% per month
```

---

## 🎓 Learning Path

1. **Start Here:** README.md
2. **Understand Controls:** ISO27001_2022_IMPLEMENTATION_GUIDE.md
3. **Run Tests:** `opa test -v policies/`
4. **Evaluate Your Data:** Use provided example data
5. **Export Real Data:** Follow export automation scripts
6. **Build Dashboards:** Create compliance reports
7. **Automate:** Integrate with CI/CD

---

## ❓ FAQ

**Q: Which control is most critical?**  
A: A.5.15 (Authentication) - it's the foundation of all security.

**Q: What's new in the 2022 policies?**  
A: A.5.23 (Cloud Controls) is entirely new. A.5.18 (Measurement) is heavily emphasized.

**Q: How often should I run these policies?**  
A: Minimum weekly; daily recommended for critical controls.

**Q: Can I customize the thresholds?**  
A: Yes - edit the `.rego` files to adjust limits (e.g., password age, log retention).

**Q: Do these policies work with non-Azure clouds?**  
A: These are Azure/M365 specific. Extend policies for AWS/GCP.

**Q: What does "deny" vs "audit" mean?**  
A: **Deny** = violation (must fix). **Audit** = recommendation (should fix).

---

**Last Updated:** 2026-05-09  
**Policy Version:** 1.0  
**Status:** Production Ready ✅
