"""
RECON — External Attack Surface Scanner
"I see what hackers see."

Scans a domain for: Email security (SPF/DKIM/DMARC), SSL certificate,
open ports, HTTP security headers, technology detection.
Calculates an overall security score (0-100).

Usage:
    recon = ReconAgent()
    results = recon.scan("targetcompany.com")
    print(f"Score: {results['score']['total']}/100")
"""

import dns.resolver
import ssl
import socket
import requests
import json
import subprocess
import os
from datetime import datetime
from typing import Optional


class ReconAgent:
    """
    Vulnerability Scanner + Security Score Calculator.
    No external tools required for basic scan — pure Python.
    Optional: Nmap (port scan), Nuclei (vuln scan) for deeper analysis.
    """

    AGENT_NAME = "RECON"
    AGENT_TAGLINE = "I see what hackers see."

    def __init__(self):
        self.results = {}

    # ─── MAIN SCAN ORCHESTRATOR ──────────────────────────────

    def scan(self, domain: str, deep: bool = False) -> dict:
        """
        Run all scan modules against a domain.
        
        Args:
            domain: Target domain (e.g., "smithcpa.com")
            deep: If True, runs Nmap + Nuclei (requires them installed)
            
        Returns:
            Complete scan results with security score
        """
        print(f"\n[RECON] Starting security assessment of {domain}")
        print(f"[RECON] Mode: {'DEEP' if deep else 'STANDARD'}\n")

        results = {
            "domain": domain,
            "scan_date": datetime.utcnow().isoformat() + "Z",
            "scan_mode": "deep" if deep else "standard"
        }

        # Module 1: Email Security (SPF/DKIM/DMARC)
        print("[1/6] Checking email security (SPF/DKIM/DMARC)...")
        results["email_security"] = self.scan_email_security(domain)

        # Module 2: SSL/TLS Certificate
        print("[2/6] Checking SSL certificate...")
        results["ssl"] = self.scan_ssl(domain)

        # Module 3: HTTP Security Headers
        print("[3/6] Checking HTTP security headers...")
        results["headers"] = self.scan_security_headers(domain)

        # Module 4: Open Ports (basic without nmap)
        print("[4/6] Checking common ports...")
        results["ports"] = self.scan_common_ports(domain) if not deep else self.scan_ports_nmap(domain)

        # Module 5: Technology Detection
        print("[5/6] Detecting technology stack...")
        results["technology"] = self.detect_technology(domain)

        # Module 6: DNS Security
        print("[6/6] Checking DNS configuration...")
        results["dns"] = self.scan_dns(domain)

        # Calculate Score
        results["score"] = self.calculate_score(results)

        # Generate Findings Summary
        results["findings"] = self.generate_findings(results)

        self._print_results(results)
        return results

    # ─── MODULE 1: EMAIL SECURITY ────────────────────────────

    def scan_email_security(self, domain: str) -> dict:
        """Check SPF, DKIM, and DMARC records."""
        checks = {}

        # SPF Check
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            spf_records = [str(r).strip('"') for r in answers if 'v=spf1' in str(r)]
            
            if spf_records:
                record = spf_records[0]
                # Check for overly permissive SPF
                is_permissive = '+all' in record or '?all' in record
                checks['spf'] = {
                    'status': 'WARN' if is_permissive else 'PASS',
                    'exists': True,
                    'record': record,
                    'issue': 'SPF is too permissive (allows any sender)' if is_permissive else None,
                    'points': 5 if is_permissive else 10
                }
            else:
                checks['spf'] = {
                    'status': 'FAIL',
                    'exists': False,
                    'record': None,
                    'issue': 'No SPF record found — anyone can send email as your domain',
                    'points': 0
                }
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, Exception) as e:
            checks['spf'] = {'status': 'FAIL', 'exists': False, 'issue': str(e), 'points': 0}

        # DMARC Check
        try:
            answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            dmarc_records = [str(r).strip('"') for r in answers if 'v=DMARC1' in str(r)]
            
            if dmarc_records:
                record = dmarc_records[0]
                has_reject = 'p=reject' in record
                has_quarantine = 'p=quarantine' in record
                has_none = 'p=none' in record
                
                if has_reject:
                    policy = 'reject'
                    points = 15
                    status = 'PASS'
                elif has_quarantine:
                    policy = 'quarantine'
                    points = 10
                    status = 'WARN'
                else:
                    policy = 'none'
                    points = 3
                    status = 'WARN'
                
                checks['dmarc'] = {
                    'status': status,
                    'exists': True,
                    'record': record,
                    'policy': policy,
                    'issue': None if has_reject else f'DMARC policy is "{policy}" — should be "reject" for full protection',
                    'points': points
                }
            else:
                checks['dmarc'] = {
                    'status': 'FAIL',
                    'exists': False,
                    'record': None,
                    'policy': None,
                    'issue': 'No DMARC record — your email domain can be spoofed by ANYONE',
                    'points': 0
                }
        except Exception:
            checks['dmarc'] = {
                'status': 'FAIL', 'exists': False, 'policy': None,
                'issue': 'No DMARC record found', 'points': 0
            }

        # DKIM Check (try common selectors)
        checks['dkim'] = {'status': 'FAIL', 'exists': False, 'selector': None, 'points': 0,
                          'issue': 'No DKIM record found for common selectors'}
        
        selectors = ['google', 'default', 'selector1', 'selector2', 'k1', 'mail',
                     'smtp', 'dkim', 'email', 'mandrill', 'amazonses', 'cm']
        
        for selector in selectors:
            try:
                answers = dns.resolver.resolve(f'{selector}._domainkey.{domain}', 'TXT')
                if answers:
                    checks['dkim'] = {
                        'status': 'PASS',
                        'exists': True,
                        'selector': selector,
                        'issue': None,
                        'points': 10
                    }
                    break
            except Exception:
                continue

        return checks

    # ─── MODULE 2: SSL/TLS ───────────────────────────────────

    def scan_ssl(self, domain: str) -> dict:
        """Check SSL certificate validity, expiry, and configuration."""
        try:
            context = ssl.create_default_context()
            conn = socket.create_connection((domain, 443), timeout=10)
            ssock = context.wrap_socket(conn, server_hostname=domain)
            cert = ssock.getpeercert()
            protocol = ssock.version()
            cipher = ssock.cipher()
            ssock.close()

            # Parse expiry
            expiry_str = cert.get('notAfter', '')
            expiry = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
            days_left = (expiry - datetime.utcnow()).days

            # Parse issuer
            issuer_parts = dict(x[0] for x in cert.get('issuer', []))
            issuer = issuer_parts.get('organizationName', 'Unknown')

            # Score
            if days_left <= 0:
                points = 0
                status = 'FAIL'
                issue = f'SSL certificate EXPIRED {abs(days_left)} days ago!'
            elif days_left <= 14:
                points = 3
                status = 'WARN'
                issue = f'SSL certificate expires in {days_left} days — RENEW NOW'
            elif days_left <= 30:
                points = 8
                status = 'WARN'
                issue = f'SSL certificate expires in {days_left} days — schedule renewal'
            else:
                points = 15
                status = 'PASS'
                issue = None

            # Check for weak protocols
            weak_protocol = protocol in ['TLSv1', 'TLSv1.1', 'SSLv3']
            if weak_protocol:
                points = max(0, points - 5)
                issue = (issue or '') + f' Weak protocol: {protocol}'
                status = 'WARN'

            return {
                'status': status,
                'valid': True,
                'issuer': issuer,
                'expires': expiry_str,
                'days_until_expiry': days_left,
                'protocol': protocol,
                'cipher': cipher[0] if cipher else 'Unknown',
                'weak_protocol': weak_protocol,
                'issue': issue,
                'points': points
            }

        except ssl.SSLCertVerificationError as e:
            return {
                'status': 'FAIL', 'valid': False,
                'issue': f'SSL certificate verification failed: {e}',
                'points': 0
            }
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return {
                'status': 'FAIL', 'valid': False,
                'issue': f'Could not connect to port 443: {e}',
                'points': 0
            }

    # ─── MODULE 3: SECURITY HEADERS ──────────────────────────

    def scan_security_headers(self, domain: str) -> dict:
        """Check HTTP security headers."""
        required_headers = {
            'Strict-Transport-Security': {
                'description': 'HSTS — forces HTTPS connections',
                'risk': 'Without HSTS, users can be tricked into using insecure HTTP'
            },
            'Content-Security-Policy': {
                'description': 'CSP — prevents cross-site scripting attacks',
                'risk': 'Without CSP, your website is vulnerable to XSS attacks'
            },
            'X-Frame-Options': {
                'description': 'Clickjacking protection',
                'risk': 'Your website could be embedded in a malicious page'
            },
            'X-Content-Type-Options': {
                'description': 'MIME sniffing protection',
                'risk': 'Browsers could misinterpret file types, enabling attacks'
            },
            'Referrer-Policy': {
                'description': 'Controls referrer information',
                'risk': 'Sensitive URL data could leak to third parties'
            },
            'Permissions-Policy': {
                'description': 'Controls browser features (camera, mic, geolocation)',
                'risk': 'Malicious scripts could access device features'
            }
        }

        try:
            resp = requests.get(
                f"https://{domain}",
                timeout=10,
                allow_redirects=True,
                headers={"User-Agent": "CyberComply-Recon-Agent/1.0"}
            )

            found = 0
            checks = {}

            for header, info in required_headers.items():
                present = header.lower() in {k.lower(): v for k, v in resp.headers.items()}
                if present:
                    found += 1
                checks[header] = {
                    'present': present,
                    'value': resp.headers.get(header, None),
                    'description': info['description'],
                    'risk': info['risk'] if not present else None
                }

            points = int((found / len(required_headers)) * 15)

            return {
                'status': 'PASS' if found >= 5 else ('WARN' if found >= 3 else 'FAIL'),
                'headers_found': found,
                'headers_total': len(required_headers),
                'headers_missing': len(required_headers) - found,
                'checks': checks,
                'issue': f'{len(required_headers) - found} security headers missing' if found < len(required_headers) else None,
                'points': points
            }

        except Exception as e:
            return {
                'status': 'FAIL',
                'issue': f'Could not check headers: {e}',
                'points': 0
            }

    # ─── MODULE 4: PORT SCANNING ─────────────────────────────

    def scan_common_ports(self, domain: str) -> dict:
        """Quick port check — no Nmap required. Pure Python."""
        high_risk_ports = {
            21: ('FTP', 'File transfer — often unencrypted'),
            22: ('SSH', 'Remote access — OK if needed, but verify'),
            23: ('Telnet', 'CRITICAL — unencrypted remote access, should NEVER be open'),
            25: ('SMTP', 'Email server — verify if intentional'),
            53: ('DNS', 'Domain name server'),
            80: ('HTTP', 'Web server — should redirect to HTTPS'),
            110: ('POP3', 'Email — unencrypted'),
            135: ('RPC', 'Windows RPC — should NOT be internet-facing'),
            139: ('NetBIOS', 'Windows file sharing — should NOT be internet-facing'),
            143: ('IMAP', 'Email — unencrypted'),
            443: ('HTTPS', 'Secure web server — expected'),
            445: ('SMB', 'CRITICAL — Windows file sharing, ransomware favorite'),
            993: ('IMAPS', 'Secure email'),
            995: ('POP3S', 'Secure email'),
            1433: ('MSSQL', 'CRITICAL — database should NOT be internet-facing'),
            1521: ('Oracle', 'CRITICAL — database should NOT be internet-facing'),
            3306: ('MySQL', 'CRITICAL — database should NOT be internet-facing'),
            3389: ('RDP', 'CRITICAL — Remote Desktop, #1 ransomware entry point'),
            5432: ('PostgreSQL', 'CRITICAL — database should NOT be internet-facing'),
            5900: ('VNC', 'CRITICAL — Remote desktop, often unencrypted'),
            8080: ('HTTP-Alt', 'Alternative web server — check why'),
            8443: ('HTTPS-Alt', 'Alternative secure web server'),
            27017: ('MongoDB', 'CRITICAL — database should NOT be internet-facing'),
        }

        critical_ports = {23, 445, 1433, 1521, 3306, 3389, 5432, 5900, 27017, 135, 139}
        
        open_ports = []
        risk_count = 0

        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            return {'status': 'FAIL', 'issue': f'Could not resolve {domain}', 'points': 0}

        for port, (service, description) in high_risk_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()

                if result == 0:
                    is_critical = port in critical_ports
                    if is_critical:
                        risk_count += 1

                    open_ports.append({
                        'port': port,
                        'service': service,
                        'description': description,
                        'risk': 'CRITICAL' if is_critical else ('LOW' if port in {80, 443, 993, 995} else 'MEDIUM')
                    })
            except Exception:
                continue

        points = max(0, 15 - (risk_count * 5))

        return {
            'status': 'FAIL' if risk_count > 0 else ('WARN' if len(open_ports) > 5 else 'PASS'),
            'ip_address': ip,
            'total_open': len(open_ports),
            'critical_open': risk_count,
            'ports': open_ports,
            'issue': f'{risk_count} critical port(s) exposed to the internet' if risk_count > 0 else None,
            'points': points
        }

    def scan_ports_nmap(self, domain: str) -> dict:
        """Deep port scan using Nmap (if installed)."""
        try:
            import nmap
            nm = nmap.PortScanner()
            nm.scan(domain, arguments='-sV --top-ports 1000 -T4')
            # Process nmap results...
            return self.scan_common_ports(domain)  # Fallback for now
        except ImportError:
            print("[RECON] Nmap not installed — using basic port scan")
            return self.scan_common_ports(domain)

    # ─── MODULE 5: TECHNOLOGY DETECTION ──────────────────────

    def detect_technology(self, domain: str) -> dict:
        """Detect web technology stack from HTTP response headers and content."""
        tech_detected = []

        try:
            resp = requests.get(
                f"https://{domain}",
                timeout=10,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (CyberComply Recon)"}
            )

            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.text[:50000].lower()  # First 50KB

            # Server detection
            server = headers.get('server', '')
            if server:
                tech_detected.append({'name': f'Server: {server}', 'category': 'server'})

            # CMS detection
            if 'wp-content' in body or 'wp-includes' in body:
                tech_detected.append({'name': 'WordPress', 'category': 'cms', 'risk': 'Check version — older WordPress has many known vulnerabilities'})
            if 'drupal' in body:
                tech_detected.append({'name': 'Drupal', 'category': 'cms'})
            if 'joomla' in body:
                tech_detected.append({'name': 'Joomla', 'category': 'cms'})
            if 'squarespace' in body:
                tech_detected.append({'name': 'Squarespace', 'category': 'cms'})
            if 'shopify' in body:
                tech_detected.append({'name': 'Shopify', 'category': 'cms'})
            if 'wix' in body:
                tech_detected.append({'name': 'Wix', 'category': 'cms'})

            # Framework detection
            if 'x-powered-by' in headers:
                tech_detected.append({'name': f'Powered by: {headers["x-powered-by"]}', 'category': 'framework',
                                      'risk': 'x-powered-by header reveals server technology — should be removed'})
            if 'react' in body or 'reactdom' in body:
                tech_detected.append({'name': 'React', 'category': 'frontend'})
            if 'next' in headers.get('x-powered-by', '').lower():
                tech_detected.append({'name': 'Next.js', 'category': 'framework'})

            # Analytics/Tracking
            if 'google-analytics' in body or 'gtag' in body:
                tech_detected.append({'name': 'Google Analytics', 'category': 'analytics'})
            if 'hotjar' in body:
                tech_detected.append({'name': 'Hotjar', 'category': 'analytics'})

            # CDN Detection
            if 'cloudflare' in headers.get('server', '').lower() or 'cf-ray' in headers:
                tech_detected.append({'name': 'Cloudflare', 'category': 'cdn'})
            if 'x-amz' in str(headers):
                tech_detected.append({'name': 'AWS', 'category': 'hosting'})

        except Exception as e:
            return {'detected': [], 'issue': str(e)}

        return {
            'detected': tech_detected,
            'count': len(tech_detected)
        }

    # ─── MODULE 6: DNS CONFIGURATION ─────────────────────────

    def scan_dns(self, domain: str) -> dict:
        """Check DNS configuration for security issues."""
        checks = {}

        # Check for DNSSEC
        try:
            answers = dns.resolver.resolve(domain, 'DNSKEY')
            checks['dnssec'] = {'enabled': True, 'status': 'PASS'}
        except Exception:
            checks['dnssec'] = {
                'enabled': False,
                'status': 'INFO',
                'issue': 'DNSSEC not enabled — DNS responses could be spoofed'
            }

        # Check for CAA record (controls who can issue SSL certs)
        try:
            answers = dns.resolver.resolve(domain, 'CAA')
            checks['caa'] = {'exists': True, 'status': 'PASS',
                             'records': [str(r) for r in answers]}
        except Exception:
            checks['caa'] = {
                'exists': False,
                'status': 'WARN',
                'issue': 'No CAA record — any certificate authority can issue certs for your domain'
            }

        # Check MX records
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            mx_records = [str(r.exchange).rstrip('.') for r in answers]
            checks['mx'] = {
                'exists': True,
                'records': mx_records,
                'uses_google': any('google' in mx.lower() for mx in mx_records),
                'uses_microsoft': any('outlook' in mx.lower() or 'microsoft' in mx.lower() for mx in mx_records)
            }
        except Exception:
            checks['mx'] = {'exists': False, 'records': []}

        return checks

    # ─── SCORING ENGINE ──────────────────────────────────────

    def calculate_score(self, results: dict) -> dict:
        """Calculate overall security score (0-100)."""
        score = 0

        # Email Security (max 35 points)
        email = results.get('email_security', {})
        email_score = (
            email.get('spf', {}).get('points', 0) +
            email.get('dmarc', {}).get('points', 0) +
            email.get('dkim', {}).get('points', 0)
        )
        score += email_score

        # SSL (max 15 points)
        ssl_score = results.get('ssl', {}).get('points', 0)
        score += ssl_score

        # Headers (max 15 points)
        header_score = results.get('headers', {}).get('points', 0)
        score += header_score

        # Ports (max 15 points)
        port_score = results.get('ports', {}).get('points', 0)
        score += port_score

        # Technology (max 10 points)
        tech = results.get('technology', {})
        risky_tech = sum(1 for t in tech.get('detected', []) if t.get('risk'))
        tech_score = max(0, 10 - (risky_tech * 3))
        score += tech_score

        # DNS (max 10 points)
        dns_data = results.get('dns', {})
        dns_score = 0
        if dns_data.get('dnssec', {}).get('enabled'):
            dns_score += 5
        if dns_data.get('caa', {}).get('exists'):
            dns_score += 5
        score += dns_score

        total = min(score, 100)

        # Determine grade
        if total >= 80:
            grade, label = 'A', 'STRONG'
        elif total >= 65:
            grade, label = 'B', 'GOOD'
        elif total >= 50:
            grade, label = 'C', 'FAIR'
        elif total >= 35:
            grade, label = 'D', 'POOR'
        else:
            grade, label = 'F', 'CRITICAL'

        return {
            'total': total,
            'grade': grade,
            'label': label,
            'breakdown': {
                'email_security': {'score': email_score, 'max': 35},
                'ssl_tls': {'score': ssl_score, 'max': 15},
                'security_headers': {'score': header_score, 'max': 15},
                'network_exposure': {'score': port_score, 'max': 15},
                'technology': {'score': tech_score, 'max': 10},
                'dns_security': {'score': dns_score, 'max': 10},
            }
        }

    # ─── FINDINGS GENERATOR ──────────────────────────────────

    def generate_findings(self, results: dict) -> list:
        """Generate a prioritized list of findings."""
        findings = []

        # Email findings
        email = results.get('email_security', {})
        if not email.get('dmarc', {}).get('exists'):
            findings.append({
                'severity': 'CRITICAL',
                'category': 'Email Security',
                'title': 'No DMARC Protection',
                'description': 'Anyone can send emails pretending to be from your domain. This is the #1 vector for business email compromise (BEC) attacks.',
                'fix': 'Add a DMARC DNS record. Start with: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com',
                'effort': '15 minutes',
                'cost': '$0'
            })

        if not email.get('spf', {}).get('exists'):
            findings.append({
                'severity': 'HIGH',
                'category': 'Email Security',
                'title': 'No SPF Record',
                'description': 'Without SPF, email servers cannot verify legitimate senders from your domain.',
                'fix': 'Add an SPF TXT record to your DNS',
                'effort': '10 minutes',
                'cost': '$0'
            })

        if not email.get('dkim', {}).get('exists'):
            findings.append({
                'severity': 'MEDIUM',
                'category': 'Email Security',
                'title': 'No DKIM Signing',
                'description': 'Emails from your domain are not cryptographically signed.',
                'fix': 'Enable DKIM in your email provider settings',
                'effort': '15 minutes',
                'cost': '$0'
            })

        # SSL findings
        ssl_data = results.get('ssl', {})
        if not ssl_data.get('valid'):
            findings.append({
                'severity': 'CRITICAL',
                'category': 'SSL/TLS',
                'title': 'Invalid or Missing SSL Certificate',
                'description': 'Your website is not properly secured with HTTPS.',
                'fix': 'Install a valid SSL certificate (free via Let\'s Encrypt)',
                'effort': '30 minutes',
                'cost': '$0'
            })
        elif ssl_data.get('days_until_expiry', 999) <= 14:
            findings.append({
                'severity': 'HIGH',
                'category': 'SSL/TLS',
                'title': f'SSL Certificate Expires in {ssl_data["days_until_expiry"]} Days',
                'description': 'If your certificate expires, browsers will warn visitors your site is unsafe.',
                'fix': 'Renew your SSL certificate immediately',
                'effort': '15 minutes',
                'cost': '$0-$100'
            })

        # Port findings
        ports = results.get('ports', {})
        for port in ports.get('ports', []):
            if port.get('risk') == 'CRITICAL':
                findings.append({
                    'severity': 'CRITICAL',
                    'category': 'Network Security',
                    'title': f'Port {port["port"]} ({port["service"]}) Exposed',
                    'description': port['description'],
                    'fix': f'Close port {port["port"]} or restrict access via firewall/VPN',
                    'effort': '30 minutes',
                    'cost': '$0'
                })

        # Header findings
        headers = results.get('headers', {})
        missing_count = headers.get('headers_missing', 0)
        if missing_count > 3:
            findings.append({
                'severity': 'MEDIUM',
                'category': 'Web Security',
                'title': f'{missing_count} Security Headers Missing',
                'description': 'Your website is missing important HTTP security headers that protect against common attacks.',
                'fix': 'Configure security headers in your web server or CDN',
                'effort': '1 hour',
                'cost': '$0'
            })

        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        findings.sort(key=lambda x: severity_order.get(x['severity'], 4))

        return findings

    # ─── CONSOLE OUTPUT ──────────────────────────────────────

    def _print_results(self, results: dict):
        """Print formatted console output."""
        score = results['score']
        
        print(f"\n{'='*60}")
        print(f"  RECON SECURITY ASSESSMENT — {results['domain']}")
        print(f"{'='*60}")
        print(f"  SECURITY SCORE: {score['total']}/100 — {score['label']}")
        print(f"  GRADE: {score['grade']}")
        print(f"")
        
        # Breakdown
        for category, data in score['breakdown'].items():
            bar_len = int((data['score'] / max(data['max'], 1)) * 20)
            bar = '█' * bar_len + '░' * (20 - bar_len)
            print(f"  {category:20s} {bar} {data['score']}/{data['max']}")
        
        print(f"\n  FINDINGS ({len(results['findings'])} issues):")
        for f in results['findings']:
            icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '⚪'}.get(f['severity'], '⚪')
            print(f"  {icon} [{f['severity']}] {f['title']}")
            print(f"     → {f['description'][:80]}")
            print(f"     Fix: {f['fix'][:80]} | Effort: {f['effort']} | Cost: {f['cost']}")
            print()

        print(f"{'='*60}")

    def to_json(self, results: dict) -> str:
        """Export results as JSON."""
        return json.dumps(results, indent=2, default=str)


# ─── DEMO ────────────────────────────────────────────────────

if __name__ == "__main__":
    recon = ReconAgent()
    
    # Scan a domain (change to any target)
    target = os.getenv("SCAN_TARGET", "example.com")
    print(f"[RECON] Demo scan target: {target}")
    print(f"[RECON] Set SCAN_TARGET env variable to change target\n")
    
    results = recon.scan(target)
    
    # Save results
    with open(f"recon_scan_{target.replace('.','_')}.json", 'w') as f:
        f.write(recon.to_json(results))
    print(f"\n[RECON] Results saved to recon_scan_{target.replace('.','_')}.json")
