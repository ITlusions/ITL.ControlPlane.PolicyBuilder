# PQC Transitie Begeleiding - Stappenplan voor Bedrijven

## Executive Summary

Dit stappenplan helpt organisaties bij de transitie naar Post-Quantum Cryptography (PQC). Met de komst van cryptografisch relevante quantumcomputers worden huidige versleutelingsmethoden (RSA, ECDSA) kwetsbaar. De NIST heeft in 2024 de eerste PQC standaarden gepubliceerd (FIPS 203, 204, 205). Organisaties moeten nu beginnen met voorbereidingen.

---

## Fase 1: Inventarisatie (4-8 weken)

### Doel
Volledig overzicht van cryptografische assets en afhankelijkheden.

### Activiteiten

#### 1.1 Crypto Asset Discovery
- [ ] Inventariseer alle systemen die cryptografie gebruiken
- [ ] Documenteer gebruikte algoritmes (RSA, ECDSA, AES, etc.)
- [ ] Identificeer key sizes en configuraties
- [ ] Map certificaat-afhankelijkheden

#### 1.2 Data Classificatie
- [ ] Classificeer data op gevoeligheid (openbaar, vertrouwelijk, geheim)
- [ ] Bepaal "harvest now, decrypt later" risico per dataset
- [ ] Identificeer data met lange levensduur (>10 jaar relevant)

#### 1.3 Supply Chain Analyse
- [ ] Inventariseer crypto-afhankelijkheden van leveranciers
- [ ] Documenteer third-party certificaten en keys
- [ ] Evalueer SaaS/cloud provider PQC roadmaps

### Deliverables
- Crypto Asset Register
- Data Classification Matrix
- Risk Assessment Report

### ITL PolicyBuilder Ondersteuning
```python
from itl_policy_builder import get_pqc_policy

# Verplicht crypto inventarisatie tags
policy = get_pqc_policy("pqc-require-crypto-inventory")

# Audit klassieke cryptografie
policy = get_pqc_policy("pqc-audit-classical")

# Verplicht PQC readiness tags
policy = get_pqc_policy("pqc-require-readiness-tag")
```

---

## Fase 2: Risicobeoordeling (2-4 weken)

### Doel
Prioriteer systemen op basis van quantum-risico.

### Activiteiten

#### 2.1 Risico Scoring
Voor elk systeem, bepaal:
- **Data Sensitivity**: Hoe gevoelig is de data?
- **Cryptographic Relevance**: Welke crypto wordt gebruikt?
- **Exposure Window**: Hoe lang moet data beschermd blijven?
- **Attack Surface**: Is het systeem internet-facing?

#### 2.2 Prioritering
| Prioriteit | Criteria |
|------------|----------|
| Kritiek | Geheime data + lange levensduur + internet-facing |
| Hoog | Vertrouwelijke data + RSA/ECDSA key exchange |
| Medium | Interne systemen met standaard encryptie |
| Laag | Tijdelijke data, korte levensduur |

#### 2.3 Timeline Planning
- **2025-2026**: Inventarisatie en planning
- **2026-2028**: Hybrid implementatie (kritieke systemen)
- **2028-2030**: Volledige PQC transitie
- **2030+**: Deprecatie klassieke algoritmes

### Deliverables
- Prioritized Migration Roadmap
- Risk Register met quantum-specifieke entries
- Budget en resource planning

---

## Fase 3: Proof of Concept (4-8 weken)

### Doel
Valideer PQC implementatie in gecontroleerde omgeving.

### Activiteiten

#### 3.1 Lab Environment Setup
- [ ] Configureer test Key Vault met PQC ondersteuning
- [ ] Deploy test applicaties met hybrid TLS
- [ ] Setup monitoring voor crypto operations

#### 3.2 Algorithm Testing
- [ ] Test ML-KEM (Kyber) voor key exchange
- [ ] Test ML-DSA (Dilithium) voor signatures
- [ ] Benchmark performance impact
- [ ] Valideer interoperabiliteit

#### 3.3 Certificate Testing
- [ ] Genereer hybrid certificaten (RSA + Dilithium)
- [ ] Test certificate chain validation
- [ ] Valideer revocation flows

### Deliverables
- PoC Environment Documentation
- Performance Benchmark Report
- Interoperability Test Results

### ITL PolicyBuilder Ondersteuning
```python
from itl_policy_builder import get_pqc_policy

# Vereist hybrid mode in PoC
policy = get_pqc_policy("pqc-require-hybrid")

# Minimum security level (NIST Level 3)
policy = get_pqc_policy("pqc-minimum-security-level", minimum_level=3)
```

---

## Fase 4: Hybrid Implementatie (8-16 weken)

### Doel
Implementeer hybrid cryptografie (klassiek + PQC) in productie.

### Activiteiten

#### 4.1 Infrastructure Updates
- [ ] Upgrade Key Management Systems
- [ ] Update TLS configuraties (TLS 1.3 met PQC KeyShare)
- [ ] Deploy nieuwe CA infrastructuur (hybrid certs)

#### 4.2 Application Updates
- [ ] Update crypto libraries (OpenSSL 3.x, BoringSSL, etc.)
- [ ] Refactor hardcoded algorithm choices
- [ ] Implement crypto-agility patterns

#### 4.3 Key Rotation
- [ ] Roteer naar hybrid keys
- [ ] Update key escrow en backup procedures
- [ ] Test disaster recovery met nieuwe keys

### Deliverables
- Updated Architecture Documentation
- Crypto-Agility Implementation Guide
- Operational Runbooks

### ITL PolicyBuilder Ondersteuning
```python
from itl_policy_builder import get_pqc_policy

# Vereist TLS 1.3
policy = get_pqc_policy("pqc-require-tls13")

# Vereist PQC-enabled TLS
policy = get_pqc_policy("pqc-require-tls")

# Key rotation policy (max 90 dagen)
policy = get_pqc_policy("pqc-require-key-rotation", max_key_age_days=90)
```

---

## Fase 5: Native PQC Transitie (8-16 weken)

### Doel
Migreer naar pure PQC (geen klassieke fallback).

### Activiteiten

#### 5.1 Deprecate Classical Crypto
- [ ] Disable RSA/ECDSA fallback in kritieke systemen
- [ ] Update firewall rules voor PQC-only traffic
- [ ] Remove klassieke keys uit production

#### 5.2 Compliance Validation
- [ ] Audit alle systemen op PQC compliance
- [ ] Genereer compliance reports
- [ ] Externe audit door certified party

#### 5.3 Documentation
- [ ] Update security policies
- [ ] Train personeel op nieuwe procedures
- [ ] Update incident response playbooks

### Deliverables
- PQC Compliance Certification
- Updated Security Policies
- Training Materials

### ITL PolicyBuilder Ondersteuning
```python
from itl_policy_builder import get_pqc_policy, get_pqc_initiative

# Blokkeer klassieke crypto
policy = get_pqc_policy("pqc-deny-deprecated")

# Blokkeer nieuwe resources met klassieke crypto
policy = get_pqc_policy("pqc-deny-new-classical")

# Complete PQC initiative voor compliance audit
initiative = get_pqc_initiative()
```

---

## Fase 6: Continuous Compliance (Ongoing)

### Doel
Behoud PQC compliance en reageer op nieuwe ontwikkelingen.

### Activiteiten

#### 6.1 Monitoring
- [ ] Continue crypto asset scanning
- [ ] Automated compliance checks
- [ ] Alerting op non-compliant resources

#### 6.2 Governance
- [ ] Regelmatige policy reviews
- [ ] Update roadmap bij nieuwe NIST guidance
- [ ] Vendor management voor PQC updates

### ITL PolicyBuilder Ondersteuning
```python
from itl_policy_builder import PolicyEvaluator, get_all_pqc_policies

# Setup continuous compliance monitoring
evaluator = PolicyEvaluator()
for policy in get_all_pqc_policies():
    evaluator.register_policy(policy)

# Evaluate resources in CI/CD pipeline
result = evaluator.evaluate(resource)
if result.denied:
    raise Exception(f"PQC compliance violation: {result.deny_reasons}")
```

---

## Tijdlijn Samenvatting

```
2025 Q1-Q2: Fase 1 - Inventarisatie
2025 Q3-Q4: Fase 2 - Risicobeoordeling
2026 Q1-Q2: Fase 3 - Proof of Concept
2026 Q3-Q4: Fase 4 - Hybrid Implementatie (kritieke systemen)
2027 Q1-Q4: Fase 4 - Hybrid Implementatie (overige systemen)
2028 Q1-Q2: Fase 5 - Native PQC (kritieke systemen)
2028 Q3-Q4: Fase 5 - Native PQC (overige systemen)
2029+:      Fase 6 - Continuous Compliance
```

---

## Budget Indicaties

| Organisatiegrootte | Inventarisatie | PoC | Implementatie | Totaal |
|--------------------|----------------|-----|---------------|--------|
| Klein (< 50 FTE) | EUR 15.000 | EUR 25.000 | EUR 50.000 | EUR 90.000 |
| Middel (50-500 FTE) | EUR 40.000 | EUR 75.000 | EUR 200.000 | EUR 315.000 |
| Groot (> 500 FTE) | EUR 100.000+ | EUR 200.000+ | EUR 500.000+ | EUR 800.000+ |

*Exclusief software licenties en hardware upgrades*

---

## Veelgestelde Vragen

### Wanneer zijn quantumcomputers een bedreiging?
Cryptografisch relevante quantumcomputers (CRQC) worden verwacht tussen 2030-2035. Echter, "harvest now, decrypt later" aanvallen vinden nu al plaats.

### Moet ik wachten op meer NIST standaarden?
Nee. FIPS 203 (ML-KEM), 204 (ML-DSA) en 205 (SLH-DSA) zijn definitief. Begin nu met planning en hybrid implementatie.

### Is hybrid mode veilig?
Ja. Hybrid mode combineert klassieke en PQC algoritmes. Als een van beide wordt gebroken, blijft de ander beschermen.

### Wat is crypto-agility?
Het vermogen om snel van cryptografisch algoritme te wisselen zonder grote codewijzigingen. Essentieel voor toekomstbestendigheid.

---

## Contact

Voor begeleiding bij uw PQC transitie:

- **ITL Platform Team**
- Email: pqc-transitie@itl-platform.nl
- Website: https://itl-platform.nl/pqc

---

*Document versie 1.0 - Februari 2026*
*Gebaseerd op NIST PQC standaarden en AIVD/NCSC richtlijnen*
