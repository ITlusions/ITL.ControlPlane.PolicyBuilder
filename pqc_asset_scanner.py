#!/usr/bin/env python3
"""
PQC Crypto Asset Discovery & Risk Assessment Tool
Scans infrastructure for cryptographic assets and evaluates quantum readiness
"""

import json
import subprocess
import os
import re
from typing import Dict, List, Any
from datetime import datetime

class PQCAssessment:
    def __init__(self):
        self.assessment = {
            "timestamp": datetime.now().isoformat(),
            "assets": [],
            "risks": [],
            "recommendations": []
        }
    
    # ============================================================
    # 1. SSH KEY SCANNING
    # ============================================================
    
    def scan_ssh_keys(self, paths: List[str] = None) -> List[Dict]:
        """Scan for SSH keys and analyze their cryptographic algorithms"""
        if not paths:
            paths = [
                os.path.expanduser("~/.ssh"),
                "/etc/ssh",
                "/home/*/.ssh",
                "/root/.ssh"
            ]
        
        ssh_keys = []
        
        for path in paths:
            if not os.path.exists(path):
                continue
                
            if os.path.isdir(path):
                for file in os.listdir(path):
                    if os.path.isfile(os.path.join(path, file)):
                        filepath = os.path.join(path, file)
                        key_info = self._analyze_ssh_key(filepath)
                        if key_info:
                            ssh_keys.append(key_info)
        
        return ssh_keys
    
    def _analyze_ssh_key(self, filepath: str) -> Dict:
        """Analyze a single SSH key"""
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            
            if 'PRIVATE KEY' not in content and 'public key' not in content.lower():
                return None
            
            # Determine algorithm
            algorithm = "UNKNOWN"
            if 'RSA' in content:
                algorithm = "RSA"
                quantum_safe = False
                size = self._extract_rsa_bits(filepath)
            elif 'OPENSSH PRIVATE KEY' in content and 'ed25519' in content.lower():
                algorithm = "ED25519"
                quantum_safe = False
                size = 256
            elif 'ECDSA' in content:
                algorithm = "ECDSA"
                quantum_safe = False
                size = self._extract_ecdsa_bits(content)
            else:
                return None  # Unknown algorithm
            
            return {
                "type": "SSH_KEY",
                "path": filepath,
                "algorithm": algorithm,
                "key_size": size,
                "quantum_safe": quantum_safe,
                "risk_level": "CRITICAL" if not quantum_safe else "LOW",
                "recommendations": [
                    "Track OpenSSH 9.1+ for PQC support",
                    "Rotate keys annually (reduce harvest window)",
                    "Consider certificate-based auth as interim"
                ]
            }
        except Exception as e:
            return None
    
    def _extract_rsa_bits(self, filepath: str) -> int:
        """Extract RSA key size"""
        try:
            result = subprocess.run(
                ['openssl', 'rsa', '-in', filepath, '-noout', '-text'],
                capture_output=True, text=True, timeout=5
            )
            match = re.search(r'Public-Key: \((\d+) bit', result.stdout)
            return int(match.group(1)) if match else 2048
        except:
            return 2048
    
    def _extract_ecdsa_bits(self, content: str) -> int:
        """Extract ECDSA key size"""
        if 'P-256' in content or 'prime256v1' in content:
            return 256
        elif 'P-384' in content or 'secp384r1' in content:
            return 384
        elif 'P-521' in content or 'secp521r1' in content:
            return 521
        return 256
    
    # ============================================================
    # 2. TLS/SSL CERTIFICATE SCANNING
    # ============================================================
    
    def scan_tls_certificates(self, paths: List[str] = None) -> List[Dict]:
        """Scan for TLS certificates"""
        if not paths:
            paths = [
                "/etc/ssl/certs",
                "/etc/pki/tls/certs",
                "/etc/letsencrypt/live",
                "/etc/nginx/ssl",
                "/etc/apache2/ssl",
                "/etc/ssl/private"
            ]
        
        certs = []
        for path in paths:
            if not os.path.isdir(path):
                continue
            
            for file in os.listdir(path):
                if file.endswith(('.crt', '.pem', '.cert', '.cer')):
                    filepath = os.path.join(path, file)
                    cert_info = self._analyze_certificate(filepath)
                    if cert_info:
                        certs.append(cert_info)
        
        return certs
    
    def _analyze_certificate(self, filepath: str) -> Dict:
        """Analyze a single certificate"""
        try:
            result = subprocess.run(
                ['openssl', 'x509', '-in', filepath, '-noout', '-text'],
                capture_output=True, text=True, timeout=5
            )
            
            if result.returncode != 0:
                return None
            
            text = result.stdout
            
            # Extract key information
            cert_info = {
                "type": "TLS_CERTIFICATE",
                "path": filepath,
                "quantum_safe": False
            }
            
            # Extract subject
            match = re.search(r'Subject:.*CN\s*=\s*([^\n,]+)', text)
            if match:
                cert_info["subject"] = match.group(1).strip()
            
            # Extract issuer
            match = re.search(r'Issuer:.*CN\s*=\s*([^\n,]+)', text)
            if match:
                cert_info["issuer"] = match.group(1).strip()
            
            # Determine signature algorithm
            if 'sha256WithRSAEncryption' in text:
                cert_info["signature_algorithm"] = "RSA"
                cert_info["risk_level"] = "CRITICAL"
            elif 'ecdsa-with-SHA' in text:
                cert_info["signature_algorithm"] = "ECDSA"
                cert_info["risk_level"] = "CRITICAL"
            else:
                cert_info["signature_algorithm"] = "UNKNOWN"
                cert_info["risk_level"] = "UNKNOWN"
            
            # Check validity
            match = re.search(r'Not Valid Before: (.+?)\n', result.stdout)
            if match:
                cert_info["valid_from"] = match.group(1)
            
            match = re.search(r'Not Valid After : (.+?)\n', result.stdout)
            if match:
                cert_info["valid_until"] = match.group(1)
            
            # Check for hybrid PQC support
            if 'ML-KEM' in text or 'ML-DSA' in text or 'kyber' in text.lower():
                cert_info["hybrid_pqc"] = True
                cert_info["risk_level"] = "MEDIUM"
            
            cert_info["recommendations"] = [
                "Request hybrid TLS certificate (RSA + ML-KEM)",
                "Deploy hybrid certificate when renewed",
                "Monitor CA PQC support timeline",
                "Test certificate with RFC 9146 clients"
            ]
            
            return cert_info
            
        except Exception as e:
            return None
    
    # ============================================================
    # 3. DATABASE ENCRYPTION SCANNING
    # ============================================================
    
    def scan_database_encryption(self) -> List[Dict]:
        """Scan for database encryption keys (limited by permissions)"""
        db_findings = []
        
        # Check for common key storage locations
        key_locations = [
            "/var/lib/mysql/.tokudb-recovery-key",
            "/etc/mysql/encryption_key",
            "/var/lib/postgresql/",
            "/etc/postgresql/",
            "/var/lib/mongodb/encryption.key"
        ]
        
        for location in key_locations:
            if os.path.exists(location):
                db_findings.append({
                    "type": "DATABASE_ENCRYPTION_KEY",
                    "location": location,
                    "status": "FOUND",
                    "risk_level": "CRITICAL",
                    "recommendations": [
                        "Audit encryption key algorithm",
                        "Plan for PQC-aware key management",
                        "Register with HSM/KMS for hybrid encryption"
                    ]
                })
        
        return db_findings
    
    # ============================================================
    # 4. VAULT/KMS ASSESSMENT
    # ============================================================
    
    def scan_vault_secrets(self) -> Dict:
        """Assess Vault/KMS encryption status"""
        vault_info = {
            "type": "VAULT_SECRETS",
            "risk_level": "CRITICAL",
            "findings": []
        }
        
        # Check if Vault is accessible
        try:
            result = subprocess.run(
                ['vault', 'status'],
                capture_output=True, text=True, timeout=5
            )
            
            vault_info["vault_accessible"] = result.returncode == 0
            vault_info["findings"].append({
                "issue": "Vault key encryption algorithm unknown",
                "severity": "CRITICAL",
                "action": "Audit HSM-backed key encryption in Vault"
            })
        except:
            vault_info["vault_accessible"] = False
        
        vault_info["recommendations"] = [
            "Enable Vault backup encryption with hybrid keys",
            "Plan for ML-KEM key wrapping support",
            "Test PQC key derivation with Vault"
        ]
        
        return vault_info
    
    # ============================================================
    # 5. OPENSSL VULNERABILITY SCAN
    # ============================================================
    
    def scan_openssl_version(self) -> Dict:
        """Check OpenSSL version and PQC support"""
        try:
            result = subprocess.run(
                ['openssl', 'version'],
                capture_output=True, text=True, timeout=5
            )
            
            version_string = result.stdout.strip()
            
            # Parse version
            match = re.match(r'OpenSSL\s+([\d.]+)', version_string)
            version = match.group(1) if match else "UNKNOWN"
            
            # Check PQC support
            pqc_ready = False
            if version.startswith('3.0') or version.startswith('3.1') or version.startswith('3.2'):
                pqc_ready = True  # OpenSSL 3.0+ will have FIPS 203/204
            
            return {
                "type": "OPENSSL_VERSION",
                "version": version,
                "pqc_ready": pqc_ready,
                "risk_level": "MEDIUM" if not pqc_ready else "LOW",
                "recommendations": [
                    f"Current: {version_string}",
                    "OpenSSL 3.4+ will have FIPS 203/204 (ML-KEM, ML-DSA)",
                    "Plan upgrade timeline for PQC support"
                ]
            }
        except:
            return {"error": "OpenSSL not found or unable to check"}
    
    # ============================================================
    # 6. RISK SCORING
    # ============================================================
    
    def calculate_risk_score(self, asset: Dict) -> int:
        """Calculate PQC risk score for any asset"""
        quantum_vulnerability = 85 if not asset.get('quantum_safe') else 10
        
        risk_mapping = {
            "SSH_KEY": 90,
            "TLS_CERTIFICATE": 95,
            "DATABASE_ENCRYPTION_KEY": 85,
            "VAULT_SECRETS": 95,
            "API_KEY": 75
        }
        
        base_risk = risk_mapping.get(asset.get('type'), 50)
        
        # Normalize complexity (higher complexity = harder to fix = higher risk)
        complexity_multiplier = 1.0 + (asset.get('implementation_complexity', 50) / 100)
        
        score = min(100, int(base_risk * complexity_multiplier))
        return score
    
    # ============================================================
    # 7. ASSESSMENT REPORT
    # ============================================================
    
    def generate_risk_matrix(self) -> str:
        """Generate ASCII risk heat matrix"""
        report = """
╔══════════════════════════════════════════════════════════════════════╗
║           PQC QUANTUM RISK HEAT MAP (PRIORITY MATRIX)                ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║   MIGRATION URGENCY (Quantum Risk)                                   ║
║          │                                                          ║
║  CRITICAL│  DATABASE KEYS                                           ║
║          │  VAULT KEYS                                              ║
║          │  TLS CERTS        SSH KEYS                               ║
║          │                   API TOKENS                             ║
║   HIGH   │                   AUTH CERTS                             ║
║          │                                                          ║
║  MEDIUM  │                                                          ║
║          │                                                          ║
║   LOW    ├──────┬──────────┬──────────┬──────┐                      ║
║          │ EASY │ MODERATE │  HARD    │ VERY │                      ║
║          │      │          │          │ HARD │                      ║
║          └──────┴──────────┴──────────┴──────┘                      ║
║             IMPLEMENTATION COMPLEXITY →                            ║
║                                                                      ║
║  ACTION ITEMS:                                                      ║
║  1. TLS Certs: Deploy hybrid immediately (6-8 weeks)               ║
║  2. API Tokens: Update to ML-DSA JWT (2-4 weeks)                   ║
║  3. SSH Keys: Wait for OpenSSH 9.1 (6-12 months)                   ║
║  4. Database: Plan key wrapping update (8-12 weeks)                ║
║  5. Vault: Enable backup encryption hybrid (4-8 weeks)             ║
║  6. Legacy: Begin EOL planning NOW                                  ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
"""
        return report
    
    def scan_all(self) -> Dict:
        """Run complete assessment"""
        print("[*] Starting PQC Crypto Asset Scan...")
        
        # Scan all asset types
        ssh_keys = self.scan_ssh_keys()
        tls_certs = self.scan_tls_certificates()
        db_encryption = self.scan_database_encryption()
        vault_secrets = self.scan_vault_secrets()
        openssl_version = self.scan_openssl_version()
        
        # Compile all assets
        all_assets = ssh_keys + tls_certs + db_encryption + [vault_secrets, openssl_version]
        
        # Score and sort
        for asset in all_assets:
            asset['risk_score'] = self.calculate_risk_score(asset)
        
        all_assets.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
        
        # Create summary
        summary = {
            "timestamp": datetime.now().isoformat(),
            "total_assets_scanned": len(all_assets),
            "critical_risk_count": len([a for a in all_assets if a.get('risk_score', 0) >= 85]),
            "high_risk_count": len([a for a in all_assets if 70 <= a.get('risk_score', 0) < 85]),
            "assets": all_assets,
            "heat_map": self.generate_risk_matrix()
        }
        
        return summary
    
    def export_json(self, output_path: str = "pqc_assessment.json"):
        """Export assessment to JSON"""
        assessment = self.scan_all()
        with open(output_path, 'w') as f:
            json.dump(assessment, f, indent=2, default=str)
        print(f"[+] Assessment exported to {output_path}")
        return output_path
    
    def print_summary(self):
        """Print assessment summary"""
        assessment = self.scan_all()
        
        print("\n" + assessment['heat_map'])
        print(f"\n[ASSESSMENT SUMMARY]")
        print(f"  Total Assets Scanned: {assessment['total_assets_scanned']}")
        print(f"  Critical Risk Assets: {assessment['critical_risk_count']}")
        print(f"  High Risk Assets: {assessment['high_risk_count']}")
        print(f"\n[TOP PRIORITY ASSETS]")
        
        for asset in assessment['assets'][:5]:
            print(f"\n  {asset.get('type', 'UNKNOWN')} (Risk Score: {asset.get('risk_score', 'N/A')})")
            if 'path' in asset:
                print(f"    Location: {asset['path']}")
            if 'subject' in asset:
                print(f"    Subject: {asset['subject']}")
            if 'recommendations' in asset:
                print(f"    Action: {asset['recommendations'][0]}")


if __name__ == "__main__":
    import sys
    
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║  PQC CRYPTOGRAPHIC ASSET INVENTORY & RISK ASSESSMENT TOOL    ║")
    print("║  Version 1.0 | For Post-Quantum Cryptography Readiness       ║")
    print("╚═══════════════════════════════════════════════════════════════╝")
    print()
    
    assessor = PQCAssessment()
    
    if len(sys.argv) > 1 and sys.argv[1] == "--export":
        assessor.export_json()
    else:
        assessor.print_summary()
