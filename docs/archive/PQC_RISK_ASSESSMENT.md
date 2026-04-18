# Post-Quantum Cryptography (PQC) Risk Heat Map & Assessment

**Organization:** ITL Security  
**Assessment Date:** February 10, 2026  
**NIST Standards:** FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)

---

## 🚨 Executive Risk Summary

| Asset | Quantum Risk | Harvest Risk | Priority | Timeline |
|-------|-------------|--------------|----------|----------|
| **Database Encryption Keys** | 🔴 CRITICAL (85) | 🔴 EXTREME (95) | CRITICAL | 6-12 mo |
| **Legacy Systems** | 🔴 CRITICAL (100) | 🔴 VERY HIGH (90) | CRITICAL | 12-18 mo |
| **Secrets Management Keys** | 🔴 CRITICAL (95) | 🔴 EXTREME (95) | CRITICAL | 6-12 mo |
| **TLS/SSL Certificates** | 🔴 CRITICAL (95) | 🔴 EXTREME (95) | IMMEDIATE | 6-18 mo |
| **SSH Keys** | 🔴 CRITICAL (95) | 🔴 VERY HIGH (90) | IMMEDIATE | 12-24 mo |
| **Auth Certificates** | 🟠 HIGH (90) | 🟠 HIGH (85) | HIGH | 18-24 mo |
| **API Keys/Tokens** | 🟡 MEDIUM-HIGH (75) | 🟠 HIGH (80) | HIGH | 12-24 mo |

---

## The Quantum Threat Timeline

```
┌─────────────────────────────────────────────────────────────────────┐
│                    CRYPTOGRAPHIC TIMELINE                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  NOW (2026)                                                         │
│  ├─ Harvest-now-decrypt-later attacks ACTIVE                       │
│  ├─ Nation states collecting encrypted data                        │
│  └─ NIST publishes PQC standards (DONE)                            │
│                                                                     │
│  NEAR TERM (2027-2028)                                             │
│  ├─ Major vendors deploy hybrid crypto                             │
│  ├─ Early CRQC prototypes demonstrated                             │
│  └─ Your data is STILL VULNERABLE                                  │
│                                                                     │
│  MID TERM (2029-2030)                                              │
│  ├─ CRQC breaks RSA-2048, ECDSA P-256                              │
│  ├─ All harvested TLS traffic can be decrypted                     │
│  ├─ SSH sessions from 2024-2028 compromised                        │
│  └─ Database backups from last decade are readable                 │
│                                                                     │
│  FAR TERM (2031+)                                                  │
│  ├─ Post-quantum era begins                                        │
│  ├─ Classic crypto is obsolete                                     │
│  └─ Organizations still on classic crypto = BREACH                 │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Risk Heat Map: 2D Analysis

```
┌──────────────────────────────────────────────────────────────────────┐
│                    PQC MIGRATION REQUIREMENT MATRIX                  │
│                                                                      │
│  Migration Urgency (Y-axis)                                          │
│  └─ Data Sensitivity + Exposure Window × Quantum Timeline            │
│                                                                      │
│  Implementation Difficulty (X-axis)                                  │
│  └─ Technical complexity + Supplier readiness                        │
│                                                                      │
│        EASY                              DIFFICULT                   │
│  ├─────────────────────────────────────────────────────────┤        │
│  │                                                         │        │
│H │         ◆ API Keys & Tokens                             │        │
│I │                                                         │        │
│G │                          ◆ Auth Certs                   │        │
│H │                                                         │        │
│  │         ◆ TLS Certificates                      ◆ SSH   │        │
│  │                                           Keys  ◆ Legacy│        │
│U │                                                ◆ DB Keys│        │
│R │                          ◆ Secrets Mgmt Keys          │        │
│G │                                                         │        │
│E │                                                         │        │
│N │                                                         │        │
│C │                                                         │        │
│Y │                                                         │        │
│  ├─────────────────────────────────────────────────────────┤        │
│  │                                                         │        │
│L │                                                         │        │
│O │                                                         │        │
│W │                                                         │        │
│  └─────────────────────────────────────────────────────────┘        │
│                                                                      │
│ Legend:                                                              │
│ ◆ = Assets requiring migration                                      │
│ Size of diamond = Business impact if compromised                    │
│ Position = Timeline urgency                                         │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Individual Asset Risk Assessment

### 🔴 CRITICAL PRIORITY: Database Encryption Keys

**Risk Score: 86/100**

```
VULNERABILITY ANALYSIS:
├─ Quantum Weakness: 85/100 (RSA-4096 key wrapping)
├─ Harvest Risk: 95/100 (backups are long-lived targets)
├─ Exposure Window: 10+ years (backup retention)
└─ Business Impact: TOTAL DATA BREACH

THREAT SCENARIO:
  2026: Attacker captures DB encrypted backup
  2030: CRQC deployed → backup decrypted
  Result: 10 years of customer data exposed

MIGRATION PATH:
  ├─ PHASE 1: Key management with PQC hybrid (ML-KEM + RSA)
  ├─ PHASE 2: PQC-only key encryption
  └─ PHASE 3: Re-encrypt sensitive historical backups
  
IMPLEMENTATION COMPLEXITY: MEDIUM
  ├─ Requires: KMS/Vault PQC support
  ├─ Effort: 2-4 dev weeks
  └─ Risk: Low (metadata-only changes)
```

---

### 🔴 CRITICAL PRIORITY: Legacy Systems (Firmware/IoT)

**Risk Score: 96/100**

```
VULNERABILITY ANALYSIS:
├─ Quantum Weakness: 100/100 (often proprietary weak crypto)
├─ Harvest Risk: 90/100 (no firmware updates possible)
├─ Exposure Window: 8+ years (long device lifecycle)
├─ Implementation Complexity: 95/100 (immutable firmware)
└─ Business Impact: Network perimeter compromise

THREAT SCENARIO:
  2026: Legacy device shipping with weak crypto
  2027: Vendor goes EOL, no security updates
  2028: Attacker finds RoT exploits captured data
  2030: CRQC can brute-force device auth
  Result: Entire device network compromise

MIGRATION PATH:
  ├─ PHASE 1: Inventory all legacy devices
  ├─ PHASE 2: Evaluate EOL timeline
  ├─ PHASE 3: Budget for replacements
  └─ PHASE 4: Network segmentation (isolate old devices)
  
IMPLEMENTATION COMPLEXITY: VERY_HIGH
  ├─ No firmware updates possible
  ├─ Replacement is often only option
  ├─ Effort: 6-12 months (procurement, deployment)
  └─ Risk: OPERATIONAL DISRUPTION
```

---

### 🔴 CRITICAL PRIORITY: Secrets Management Keys

**Risk Score: 91/100**

```
VULNERABILITY ANALYSIS:
├─ Quantum Weakness: 95/100 (master keys with RSA)
├─ Harvest Risk: 95/100 (compromise = everything compromised)
├─ Exposure Window: 10+ years (long key tenure)
└─ Business Impact: TOTAL ORGANIZATIONAL FAILURE

THREAT SCENARIO:
  2026: Vault master key in HSM (RSA-4096)
  2028: Attacker copies encrypted Vault database
  2030: CRQC decrypts Vault → access to ALL secrets
  Result: Complete infrastructure compromise

MIGRATION PATH:
  ├─ PHASE 1: Identify Vault HSM keys
  ├─ PHASE 2: Plan PQC-aware key derivation
  ├─ PHASE 3: Hybrid encryption for Vault backups
  ├─ PHASE 4: Key rotation to PQC
  └─ PHASE 5: Test disaster recovery with PQC
  
IMPLEMENTATION COMPLEXITY: HIGH
  ├─ Requires: HSM firmware support (often unavailable)
  ├─ Requires: Vault PQC plugin
  ├─ Effort: 4-8 dev weeks
  └─ Risk: High (must not break operations)
```

---

### 🔴 IMMEDIATE: TLS/SSL Certificates

**Risk Score: 88/100**

```
VULNERABILITY ANALYSIS:
├─ Quantum Weakness: 95/100 (RSA-2048 server certs)
├─ Harvest Risk: 95/100 (ALL HTTPS traffic captured)
├─ Exposure Window: 7+ years (cert + data retention)
└─ Business Impact: COMPLETE USER PRIVACY BREACH

THREAT SCENARIO:
  2026: Your HTTPS traffic is being captured globally
  2027: Hybrid certificates deployed (good!)
  2030: CRQC deployed → all pre-2027 traffic decrypted
  Result: Customer data, API responses, session tokens readable

MITIGATION DEPLOYED: HYBRID CERTIFICATES
  ├─ Combine RSA + ML-KEM in same cert
  ├─ Provides forward security NOW
  ├─ TLS 1.3 with RFC 9146 support
  └─ Client sees either RSA or ML-KEM strength

DEPLOYMENT STATUS:
  ├─ Certificate Authorities: READY (issuing hybrid certs)
  ├─ OpenSSL: READY (3.0+ supports hybrid certs)
  ├─ Browsers: READY (support RFC 9146)
  ├─ Cloud Services: PARTIAL (AWS ACM, Azure, GCP ready)
  ├─ Apps: NEEDS WORK (application libraries may not accept)
  
RECOMMENDED ACTION:
  NOW: Deploy hybrid certificates on all HTTPS endpoints
  2027: Begin transition to native PQC certificates
  2029: Complete phaseout of classic TLS certs
```

---

### 🟠 HIGH PRIORITY: SSH Keys

**Risk Score: 89/100**

```
VULNERABILITY ANALYSIS:
├─ Quantum Weakness: 95/100 (RSA-4096, ED25519)
├─ Harvest Risk: 90/100 (SSH sessions being logged)
├─ Exposure Window: 5+ years (key validity period)
└─ Business Impact: INFRASTRUCTURE COMPROMISE

THREAT SCENARIO:
  2026: Attackers capturing SSH session handshakes
  2027: ED25519 keys proven quantum-vulnerable
  2030: CRQC decrypts captured sessions
  Result: Old SSH access sessions can be replayed/analyzed

CRITICAL BLOCKER:
  ├─ OpenSSH doesn't have PQC support yet
  ├─ No RFC 8308 extension implementation
  ├─ Estimated availability: OpenSSH 9.1+ (late 2026)
  └─ CANNOT BE DEPLOYED UNTIL OPENSSH UPDATES

MIGRATION PATH:
  ├─ PHASE 1: Wait for OpenSSH PQC support
  ├─ PHASE 2: Lab testing with PQC SSH keys
  ├─ PHASE 3: Hybrid SSH key generation (ED25519 + PQC)
  ├─ PHASE 4: Server deployment of PQC support
  ├─ PHASE 5: Client-side PQC key distribution
  └─ PHASE 6: Phase out classic-only SSH keys

CURRENT STATUS:
  ├─ OpenSSH 9.0-9.7: Classic only
  ├─ OpenSSH 9.1+ (planned): RFC 8308 support
  ├─ liboqs: PQC library available
  └─ BOTTLENECK: OpenSSH adoption timeline

WORKAROUND WHILE WAITING:
  ├─ Implement certificate-based SSH auth (instead of keys)
  ├─ Use Teleport/Boundary for session recording
  ├─ Rotate SSH keys quarterly (reduces harvest window)
  └─ Network segmentation (limit SSH exposure)
```

---

## Vendor Readiness Assessment

```
┌────────────────────────────────────────────────────────────────┐
│            VENDOR PQC READINESS SCORECARD                      │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│ OpenSSL           [████████░░] 80% - FIPS 203/204 coming       │
│ Python Crypto     [██████████] 95% - liboqs integrated         │
│ TLS Libraries     [████████░░] 85% - Hybrid support ready      │
│ Certificate CAs   [████████░░] 80% - Issuing hybrid certs      │
│ OpenSSH           [███░░░░░░░] 30% - MAJOR BLOCKER             │
│ Go Crypto         [██████░░░░] 60% - Limited PQC support       │
│ Java Crypto       [██████░░░░] 60% - liboqs via JNI            │
│ Kubernetes        [████░░░░░░] 40% - Planning support          │
│ AWS KMS           [█████░░░░░] 50% - Hybrid key support        │
│ Azure Key Vault   [██████░░░░] 60% - Trial PQC support         │
│ Vault (HashiCorp) [████░░░░░░] 40% - Plugin architecture ready │
│                                                                │
│ LEGEND:                                                        │
│ ████████░░ = Production-ready (>80%)                           │
│ ██████░░░░ = Pilot/Trial (50-80%)                              │
│ ████░░░░░░ = Planning/In-progress (<50%)                       │
│                                                                │
│ CRITICAL BLOCKER: OpenSSH (30%)                                │
│ OpenSSH is essential for infrastructure and not yet ready.     │
│ This alone blocks SSH key migration for 12+ months.            │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

---

## NIST PQC Standards Status

| Standard | Algorithm | Use Case | Status | Availability |
|----------|-----------|----------|--------|--------------|
| **FIPS 203** | ML-KEM | Key Encapsulation (TLS, hybrid) | ✅ Approved Aug 2024 | OpenSSL 3.4+ |
| **FIPS 204** | ML-DSA | Digital Signatures | ✅ Approved Aug 2024 | OpenSSL 3.4+ |
| **FIPS 205** | SLH-DSA | Alternative Signatures (stateless) | ✅ Approved Aug 2024 | Community libs |

---

## Implementation Roadmap: 6-Phase Plan

### Phase 1: Discovery & Assessment (Weeks 1-8) — **NOW**

**Goal:** Complete crypto asset inventory and risk scoring

```
Tasks:
  ✓ Enumerate all cryptographic assets (done - crypto_asset_inventory_pqc.json)
  ✓ Map data flows and dependencies
  ✓ Classify data by sensitivity + retention period
  ✓ Identify vendor PQC roadmaps
  ✓ Create business impact analysis

Deliverables:
  - Complete asset inventory with risk scores
  - Quantum-vulnerable asset list (prioritized)
  - Vendor readiness assessment
  - Executive risk brief
```

---

### Phase 2: Risk Prioritization (Weeks 8-10)

**Goal:** Create migration strategy and budget

```
Tasks:
  □ Prioritize assets by risk score (see table above)
  □ Calculate cost of waiting vs cost of migration
  □ Identify quick wins (easy implementations first)
  □ Create 3-year roadmap
  □ Secure budget approval

Quick Wins (start these FIRST):
  - Deploy hybrid TLS certificates (6-8 weeks)
  - API token update to ML-DSA JWT (4-6 weeks)
  - Vault hybrid key wrapping (2-4 weeks)

Hard Slogs (long-term):
  - OpenSSH PQC support (wait for vendor)
  - Legacy system replacement (12-18 months)
  - Kubernetes PQC etcd migration (2027+)
```

---

### Phase 3: Proof of Concept (Weeks 10-18)

**Goal:** Validate PQC in your environment

```
Lab Environment Setup:
  □ Install liboqs library
  □ Generate ML-KEM test keys
  □ Create hybrid certificate
  □ Test with Python cryptography
  □ Performance benchmarks
  
  Example Hybrid Cert:
    Subject: example.com
    Signature Algorithm: ECDSA+ML-DSA (hybrid)
    Public Key: RSA-2048 + ML-KEM
    
  Benchmark Tests:
    - Keypair generation time
    - Signature creation time
    - Verification time
    - Certificate size impact
    - Network latency diff

Expected Results:
  ✓ ML-KEM: slightly slower than ECDH (acceptable)
  ✓ ML-DSA: signature size ~2.5KB (larger, but OK)
  ✓ Hybrid certs: backward compatible
```

---

### Phase 4: Hybrid Implementation (Weeks 18-34) — **HIGH PRIORITY**

**Goal:** Deploy hybrid crypto without breaking anything

```
PHASE 4A: TLS Certificate Rollout
  1. Request hybrid cert from CA (RSA + ML-KEM)
  2. Install on test servers (verify compatibility)
  3. Monitor performance metrics
  4. Rollout to production endpoints
  
Deployment Steps:
  - Load Balancers: Update SSL certs (0 downtime)
  - Web Servers: New hybrid certs (rolling restart)
  - Microservices: mTLS with hybrid certs
  - CDN/Cloudflare: Configure hybrid certs
  
Expected Timeline: 4-6 weeks

PHASE 4B: API Token Migration
  1. Update JWT issuer to use ML-DSA
  2. Clients accept both RSA + ML-DSA signed tokens
  3. Gradual rollout of PQC-signed tokens
  4. Monitor token validation failures
  
Expected Timeline: 2-4 weeks

PHASE 4C: Vault/KMS Key Wrapping
  1. Enable hybrid encryption in Vault
  2. New secrets encrypted with ML-KEM
  3. Old secrets unaffected (backward compat)
  4. Gradual key rotation
  
Expected Timeline: 2-4 weeks

PHASE 4D: OpenSSH Waiting Pattern
  - Watch for OpenSSH 9.1 release
  - Plan SSH key rotation once available
  - Cannot proceed further until OpenSSH ready
```

---

### Phase 5: Native PQC Transition (Weeks 34-50)

**Goal:** Phase out classic-only algorithms

```
Milestones:
  □ All new TLS certificates use PQC native
  □ All new SSH keys use PQC hybrid
  □ All new secrets encrypted with PQC
  □ Classic-only systems sunset (legacy removal)

Timeline: 16 weeks (ongoing during Phase 4)

Classic Algorithm Phaseout Schedule:
  2026: Deploy hybrid alongside classic
  2027: Make PQC preferred algorithm
  2028: Support both but warn on classic
  2029: Classic algorithms deprecated
  2030: Classic algorithms removed
```

---

### Phase 6: Continuous Compliance (Ongoing)

**Goal:** Maintain PQC readiness

```
Activities:
  ✓ Annual PQC readiness audits
  ✓ Monitor NIST/vendor updates
  ✓ Vendor security incident response
  ✓ Key rotation governance
  ✓ Compliance validation
  
Metrics to Track:
  - % of cryptographic assets using PQC
  - Key rotation success rate
  - Vendor update adoption lag
  - Harvest risk reduction over time
  
Dashboard:
  - PQC deployment status (by asset type)
  - Vendor readiness updates
  - Key rotation audit log
  - Risk heat map evolution
```

---

## Cost-Benefit Analysis

### Cost of Waiting (Do Nothing)

```
Timeline: 2026-2030

Scenario: Your organization delays PQC migration until 2030

COSTS:
├─ Forced Emergency Migration
│  ├─ Premium pricing (crisis management)
│  ├─ Expedited vendor solutions
│  └─ Cost: 2.5x normal implementation
│
├─ Data Breach From Old Harvested Data
│  ├─ Regulatory fines (EU/NL: up to 4% revenue)
│  ├─ Legal liability (customer data theft)
│  ├─ Reputation damage
│  └─ Cost: Potentially company-destroying
│
├─ Operational Disruption
│  ├─ Unplanned system downtime
│  ├─ Customer service impact
│  └─ Lost revenue
│
└─ TOTAL RISK: Potentially $10M-$100M+
```

### Cost of Proactive Migration

```
Timeline: 2026-2029 (phased approach)

COSTS:
├─ Assessment & Planning: $50K
├─ Hybrid Implementation: $150K-$300K
├─ PQC Rollout: $200K-$400K
├─ Legacy Replacement: $150K-$300K
├─ Training & Compliance: $50K
└─ TOTAL INVESTMENT: $600K-$1.1M over 3 years

BENEFITS:
├─ Future-proof cryptography
├─ Regulatory compliance
├─ Customer trust and brand protection
├─ Operational control (planned vs emergency)
├─ Early technology adoption advantage
└─ TOTAL VALUE: Avoiding $10M-$100M+ loss

ROI: 10:1 to 100:1 (prevention is cheaper than cure)
```

---

## Risk Scoring Methodology

```
OVERALL_PQC_RISK_SCORE = 
  (Quantum_Vulnerability × 0.35) +
  (Harvest_Risk × 0.30) +
  (Implementation_Complexity × 0.20) +
  (Exposure_Window_Score × 0.15)

Where:
  - Quantum_Vulnerability = Likelihood CRQC breaks algorithm
  - Harvest_Risk = Likelihood data is already being collected
  - Implementation_Complexity = Effort to migrate (inverse):
      95 = Extremely hard (legacy systems)
      50 = Medium (applications)
      20 = Easy (SaaS update)
  - Exposure_Window = Years data could be decrypted after breach
      10 years = 100
      5 years = 50
      1 year = 10

EXAMPLE CALCULATION:
Asset: TLS Certificates
  Quantum_Vulnerability: 95
  Harvest_Risk: 95
  Implementation_Complexity: 60
  Exposure_Window_Score: 85
  
  = (95 × 0.35) + (95 × 0.30) + (60 × 0.20) + (85 × 0.15)
  = 33.25 + 28.5 + 12 + 12.75
  = 86.5 → CRITICAL PRIORITY
```

---

## Key Takeaways & Decisions

| Decision | Recommendation | Rationale |
|----------|---|---|
| **Start Date** | NOW (Feb 2026) | 4-year window to migrate before CRQC |
| **Initial Focus** | TLS + Vault keys | Highest harvest risk + easiest to implement |
| **OpenSSH** | Accept delay | Wait for 9.1, then migrate SSH keys |
| **Approach** | Hybrid-first | Backward compatible, reduces risk immediately |
| **Budget Approval** | Seek now | Preventive cost << breach cost |
| **Vendor Engagement** | Start immediately | Pressure vendors for PQC roadmaps |

---

## Resources

- **NIST FIPS 203-205:** https://csrc.nist.gov/publications/detail/fips/203/final
- **liboqs Library:** https://github.com/open-quantum-safe/liboqs
- **Hybrid TLS RFC 9146:** https://datatracker.ietf.org/doc/html/rfc9146
- **OpenSSH PQC Tracking:** https://github.com/openssh/openssh-portable/issues
- **Assessment Tools:** ssh-audit, OpenSSL vulnerability checker

---

**Next Steps:**
1. Review this assessment with security leadership
2. Schedule Phase 2 risk prioritization workshop
3. Begin Phase 3 POC in parallel
4. Engage vendors for PQC roadmap commitments

