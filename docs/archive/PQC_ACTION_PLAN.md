# PQC Migration Action Plan - ITL Security

**Created:** February 10, 2026  
**Status:** READY FOR EXECUTION  
**Governance:** Security Leadership Review Required

---

## EXECUTIVE SUMMARY

Your organization has a **4-year window** to transition cryptographic systems from vulnerable RSA/ECDSA to quantum-safe post-quantum cryptography (PQC). Delaying this transition exposes:

- ✅ All HTTPS traffic being captured for future decryption (Harvest-Now-Decrypt-Later)
- ✅ SSH sessions vulnerable to authentication compromise  
- ✅ Database backups at risk (7-10 year retention = decryption timeline)
- ✅ API security degradation

**Recommended Action:** BEGIN PHASE 1 IMMEDIATELY

---

## QUICK REFERENCE: WHAT NEEDS TO CHANGE

```
┌─────────────────────────────────────────────────────────────┐
│ ASSET TYPE              │ ACTION          │ TIMELINE        │
├─────────────────────────────────────────────────────────────┤
│ HTTPS/TLS Certificates  │ Deploy hybrid   │ IMMEDIATE (6ws) │
│ API Tokens (JWT)        │ Add ML-DSA sig  │ HIGH (8-12ws)   │
│ SSH Keys                │ Wait→Rotate     │ MEDIUM (6-12mo) │
│ Database Encryption     │ PQC key wrap    │ HIGH (10-14ws)  │
│ Vault/Secrets Mgmt      │ Hybrid backup   │ HIGH (6-10ws)   │
│ Legacy Systems          │ Identify EOL    │ MEDIUM (8-18mo) │
│                                                              │
│ BLOCKER: OpenSSH needs PQC support (vendor timeline)       │
└─────────────────────────────────────────────────────────────┘
```

---

## THE 6 PHASES: SIMPLIFIED VERSION

### ✅ PHASE 1: DISCOVERY (NOW - 8 weeks)
```
Objective: Know what we have to protect
Duration: 4-8 weeks
Effort: 1 FTE security engineer + 1 FTE ops

TASKS:
  □ Run pqc_asset_scanner.py on all systems
  □ Catalog all cryptographic assets (attached JSON template)
  □ Identify data retention periods (harvest risk window)
  □ Document vendor PQC support status
  
DELIVERABLES:
  ✓ Complete crypto asset inventory
  ✓ Risk heat map with prioritization
  ✓ Executive brief on quantum threat
  
BUDGET: Staff time only
BLOCKER: None
```

### 🔴 PHASE 2: RISK & STRATEGY (Weeks 8-10)
```
Objective: Decide where to focus and secure funding
Duration: 2-4 weeks
Effort: Security lead + Finance + Vendor contacts

TASKS:
  □ Rank assets by risk score (see inventory.json)
  □ Design TLS hybrid certificate strategy
  □ Plan OpenSSH migration timeline (vendor wait)
  □ Calculate ROI (cost of migration vs breach cost)
  □ Get budget approval
  
BUDGET: Consulting/assessment $20K-$40K (optional)
BLOCKER: Budget approval
```

### 🟡 PHASE 3: PROOF OF CONCEPT (Weeks 10-18)
```
Objective: Validate PQC in YOUR environment
Duration: 4-8 weeks
Effort: 2-3 dev/ops engineers

TASKS:
  □ Create lab environment with liboqs
  □ Generate hybrid test certificates
  □ Load test PQC performance
  □ Document interoperability findings
  □ Create runbooks for Phase 4
  
BUDGET: Lab infrastructure only
DELIVERABLES: Working PQC lab + performance report
BLOCKER: None (parallel to Phase 2)
```

### 🟢 PHASE 4: HYBRID ROLLOUT (Weeks 18-34)
```
Objective: Deploy hybrid crypto to production (NO BREAKING CHANGES)
Duration: 16 weeks
Effort: 4-5 engineers across multiple teams

4A: TLS CERTIFICATES (6 weeks)
  □ Request hybrid certificates from CA
  □ Test on staging
  □ Deploy to load balancers (zero-downtime)
  □ Monitor error logs
  ✓ RESULT: All HTTPS now hybrid (RSA + ML-KEM)

4B: API TOKENS (2-4 weeks)
  □ Update authorization server to issue ML-DSA JWT
  □ Clients accept both RSA + ML-DSA
  □ Gradual rollout (canary 10% → 50% → 100%)
  ✓ RESULT: New API tokens use PQC

4C: VAULT ENCRYPTION (4 weeks)
  □ Enable hybrid encryption in Vault
  □ New secrets encrypted with ML-KEM
  □ Rotate old secrets gradually
  ✓ RESULT: Future secrets use PQC

4D: SSH KEYS (WAITING)
  □ Monitor OpenSSH 9.1 release
  □ Cannot proceed until vendor support
  
BUDGET: $150K-$250K (staff + licensing)
TIMELINE: Parallel with Phase 5 activities
CRITICAL SUCCESS FACTOR: No production outages
```

### 🟣 PHASE 5: NATIVE PQC (Weeks 34-50)
```
Objective: Phase out classic-only algorithms
Duration: 16 weeks (ongoing)
Effort: Continuous integration with Phase 4

TASKS:
  □ New TLS certificates are PQC-native
  □ SSH key rotation to PQC hybrid (when OpenSSH ready)
  □ Documentation updates
  □ Compliance validation
  □ Legacy system sunset plans
  
BUDGET: $200K-$400K (major replacements)
TIMELINE: 12-24 months for full phaseout
CRITICAL: Maintain backward compatibility
```

### ♾️ PHASE 6: CONTINUOUS COMPLIANCE (ONGOING)
```
Objective: Stay quantum-safe permanently
Duration: Ongoing
Effort: 0.5 FTE ongoing

TASKS:
  ✓ Annual PQC readiness audits
  ✓ Monitor NIST/vendor updates
  ✓ Track key rotation metrics
  ✓ Vendor compliance tracking
  
DELIVERABLES: Annual PQC health report
BUDGET: Staff time (included in security operations)
```

---

## IMMEDIATE NEXT STEPS (This Week)

### For Security Leadership
- [ ] Review this assessment document
- [ ] Schedule 30-min decision meeting
- [ ] Approve Phase 1 (discovery) resource allocation
- [ ] Communicate board-level quantum risk awareness

### For Security Engineering
- [ ] Run `python pqc_asset_scanner.py --export` on critical systems
- [ ] Populate `crypto_asset_inventory_pqc.json` with findings
- [ ] Identify TLS certificate renewal schedule
- [ ] Contact certificate authority about hybrid cert support

### For Operations
- [ ] Audit SSH key management processes
- [ ] Document all TLS termination points
- [ ] Identify legacy systems (firmware, IoT)
- [ ] Prepare disaster recovery test (for Phase 4)

### For Vendor Management
- [ ] Schedule calls with OpenSSH maintainers (status update)
- [ ] Contact cloud providers (AWS, Azure, GCP) about PQC timeline
- [ ] Ask internal vendors for PQC roadmaps
- [ ] Request hybrid certificate support timeline

### For Finance
- [ ] Review PQC budget estimate ($600K-$1.1M over 3 years)
- [ ] Compare to regulatory/breach costs
- [ ] Approve Phase 1 & 2 budgets ($70K-$100K)

---

## SUCCESS METRICS

### Phase 1 Completion
- ✓ 100% asset inventory completed
- ✓ Risk scores calculated for all assets
- ✓ Executive brief delivered

### Phase 2 Completion  
- ✓ Migration roadmap approved
- ✓ Budget allocated
- ✓ Vendor timelines documented

### Phase 4 Completion (TLS Hybrid)
- ✓ All HTTPS endpoints using hybrid certs
- ✓ Zero production outages
- ✓ Client error rate <0.01%
- ✓ Performance impact <5%

### Phase 5 Completion
- ✓ 80% of new crypto assets are PQC-ready
- ✓ SSH keys rotated to PQC hybrid
- ✓ Legacy system phaseout plan executed

### Phase 6 Ongoing
- ✓ Annual audit: 100% quantum-ready critical assets
- ✓ Vendor status tracked quarterly
- ✓ Key rotation success rate >99%

---

## GOVERNANCE & ACCOUNTABILITY

| Role | Responsibility | Timeline |
|------|---|---|
| **CISO/Security Lead** | Approve phases, secure resources, executive reporting | Start of each phase |
| **Security Engineering** | Technical execution, testing, vendor coordination | Ongoing |
| **Infrastructure/DevOps** | Certificate deployment, key rotation, systems testing | Phase 4-6 |
| **Development** | Application updates (JWT, API changes), testing | Phase 4 |
| **Compliance** | Regulatory alignment, audit support, policy updates | Phase 2-6 |
| **Finance** | Budget allocation, cost tracking, ROI reporting | Ongoing |

---

## RISK MITIGATION IF DELAYED

**If starting Phase 1 is delayed:**

```
Delay Cost Formula:
  Years of delay × Risk escalation × Cost multiplier

Example:
  - 2-year delay = Implementation emergency by 2028
  - 3-year delay = CRQC threat becomes existential
  - 4-year delay = Potential $50M-$500M breach cost
```

**Regulatory pressure will increase:**
- 2026: Voluntary best practices
- 2027: Customer expectations increase  
- 2028: Compliance requirements likely
- 2029: Mandatory for government contracts
- 2030: General compliance expectation

---

## DEPENDENCY: OPENSSH PQC SUPPORT

⚠️ **CRITICAL BLOCKER:** SSH key migration depends on OpenSSH vendor support

```
Current Status (Feb 2026):
  OpenSSH version: 8.9-9.7 (classic only)
  PQC support: PLANNED for 9.1+ (expected mid-2026)
  RFC 8308 implementation: IN PROGRESS
  
Action:
  □ Engage OpenSSH maintainers for timeline confirmation
  □ Subscribe to openssh-unix-dev mailing list  
  □ Plan SSH key lab testing immediately after 9.1 release
  □ Prepare hybrid SSH key generation procedures
  
Interim Mitigation:
  □ Rotate SSH keys quarterly (reduce harvest window)
  □ Use certificate-based SSH auth (vs key-based)
  □ Implement strict logging/monitoring of SSH access
  □ Network segmentation (limit SSH exposure)
```

---

## VENDOR PQC READINESS

**READY or PRODUCTION:**
- ✅ OpenSSL 3.0+ (FIPS 203/204 in 3.4+)
- ✅ Python cryptography (liboqs integration)
- ✅ Hybrid TLS certificates (major CAs)
- ✅ Hardware tokens (with firmware updates)

**PARTIAL/PLANNED:**
- 🟡 AWS KMS - hybrid key support
- 🟡 Azure Key Vault - trial PQC support
- 🟡 Google Cloud KMS - planning support
- 🟡 Kubernetes - planning 2027

**NOT YET READY:**
- 🔴 OpenSSH < 9.1
- 🔴 Go crypto standard library
- 🔴 Java crypto (partial via liboqs JNI)

---

## COST SUMMARY

| Phase | Duration | Cost | Notes |
|-------|----------|------|-------|
| 1: Discovery | 8 weeks | $20K | Staff time only |
| 2: Risk & Strategy | 2 weeks | $20K | Consulting (optional) |
| 3: PoC | 8 weeks | $50K | Lab infrastructure |
| 4: Hybrid Rollout | 16 weeks | $200K | Certificates, staff |
| 5: Native PQC | 16 weeks | $300K | Legacy replacements |
| 6: Compliance | Ongoing | $10K/year | Audits, training |
| **TOTAL (36 mo)** | | **$600K-$1.1M** | All-in cost |

**Comparison:** Single breach from harvest-attack = $10M-$500M

---

## KEY CONTACTS & RESOURCES

- **NIST PQC Standards:** https://csrc.nist.gov/publications/detail/fips/203/final
- **liboqs Library:** https://github.com/open-quantum-safe/liboqs  
- **OpenSSH Development:** https://www.openbsd.org/openssh/
- **Dutch BIO (Compliance):** https://www.cibsecurity.org/
- **EU Cyber Security Act:** https://digital-strategy.ec.europa.eu/en/policies/cybersecurity-act

---

## APPENDICES

### A. Asset Inventory Template
→ See: `crypto_asset_inventory_pqc.json`

### B. Full Risk Assessment  
→ See: `PQC_RISK_ASSESSMENT.md`

### C. Automated Scanner
→ See: `pqc_asset_scanner.py`

### D. Example Implementation
```bash
# Generate hybrid TLS certificate (once CA support available)
openssl req -new -keyout hybrid_key.key -out hybrid.csr \
  -addext "keyUsage=digitalSignature,keyEncapsulation" \
  -subj "/CN=example.com"

# Test with liboqs-openssl
/opt/oqs-openssl/bin/openssl req -in hybrid.csr -text -noout

# Generate PQC-ready JWT token
python -c "
import jwt
from liboqs import Signature
sig = Signature('ML-DSA-65')
pubkey, seckey = sig.generate_keypair()
token = jwt.encode({'data': 'test'}, seckey, algorithm='ML-DSA-65')
print(f'PQC JWT: {token}')
"
```

---

## APPROVAL & SIGN-OFF

| Role | Name | Date | Approval |
|------|------|------|----------|
| **CISO** | ________________ | _____ | ☐ Approved |
| **Security Lead** | ________________ | _____ | ☐ Approved |
| **CTO/Technical Lead** | ________________ | _____ | ☐ Approved |
| **Finance Director** | ________________ | _____ | ☐ Budget OK |
| **Compliance Officer** | ________________ | _____ | ☐ Compliant |

---

**Document Version:** 1.0  
**Last Updated:** February 10, 2026  
**Next Review:** February 10, 2027 (annual)

