"""
CSRF (Cross-Site Request Forgery) Scanner Module
"""
import asyncio
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse
import aiohttp
from bs4 import BeautifulSoup
import hashlib

class CSRFScanner:
    """CSRF vulnerability scanner"""
    
    def __init__(self):
        self.name = "CSRF Scanner"
        self.severity = "medium"
        
        # Forms that should be protected
        self.protected_form_TYPES = [
            'login',
            'register', 
            'password',
            'email',
            'delete',
            'update',
            'edit',
            'admin',
            'banking',
            'payment',
            'transfer',
        ]
        
        # HTTP methods that modify data
        self.modifying_methods = ['POST', 'PUT', 'DELETE', 'PATCH']
    
    async def scan(self, target_url: str) -> List[Dict[str, Any]]:
        """
        Perform CSRF scan on target URL
        
        Args:
            target_url: Target URL to scan
            
        Returns:
            List of found vulnerabilities
        """
        vulnerabilities = []
        
        try:
            async with aiohttp.ClientSession() as session:
                # Get the page
                async with session.get(
                    target_url,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status != 200:
                        return vulnerabilities
                    
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    # Find all forms
                    forms = soup.find_all('form')
                    
                    for form in forms:
                        result = await self.analyze_form(form, target_url, session)
                        if result:
                            vulnerabilities.append(result)
                    
                    # Check for state-changing links
                    links = soup.find_all('a', href=True)
                    for link in links:
                        href = link.get('href', '')
                        if self.is_state_changing_link(href):
                            vulnerabilities.append({
                                "type": "csrf",
                                "severity": "medium",
                                "title": "State-Changing Link Without CSRF Protection",
                                "description": "A link that modifies state was found without apparent CSRF protection",
                                "url": urljoin(target_url, href),
                                "method": "GET",
                                "param": None,
                                "payload": href,
                                "evidence": f"State-changing link: {href}",
                                "remediation": "Implement anti-CSRF tokens for state-changing operations",
                                "cwe_id": "CWE-352",
                                "cvss_score": 6.5,
                                "ml_confidence": 0.70,
                                "ml_prediction": False
                            })
        
        except Exception:
            pass
        
        return vulnerabilities
    
    async def analyze_form(
        self,
        form: BeautifulSoup,
        target_url: str,
        session: aiohttp.ClientSession
    ) -> Optional[Dict[str, Any]]:
        """Analyze a form for CSRF vulnerabilities"""
        
        # Check form method
        method = form.get('method', 'get').upper()
        
        # Only check forms that modify data
        if method not in self.modifying_methods:
            return None
        
        # Get form action
        action = form.get('action', '')
        form_url = urljoin(target_url, action)
        
        # Check for CSRF token
        has_csrf_token = False
        csrf_token_field = None
        
        # Common CSRF token field names
        csrf_token_names = [
            'csrf_token',
            'csrfmiddlewaretoken',
            '_csrf',
            'csrf',
            'authenticity_token',
            'xsrf_token',
            'xsrf',
            '__RequestVerificationToken',
            'token',
        ]
        
        # Check hidden fields for CSRF tokens
        hidden_fields = form.find_all('input', {'type': 'hidden'})
        for hidden in hidden_fields:
            name = hidden.get('name', '').lower()
            if any(csrf_name in name for csrf_name in csrf_token_names):
                has_csrf_token = True
                csrf_token_field = hidden.get('name')
                break
        
        # Check for custom CSRF headers in JavaScript
        form_parent = form.parent
        if form_parent:
            scripts = form_parent.find_all('script')
            for script in scripts:
                script_content = script.string or ''
                if 'csrf' in script_content.lower() or 'xsrf' in script_content.lower():
                    has_csrf_token = True
                    break
        
        # Check SameSite cookie attribute
        cookies = []
        try:
            async with session.get(
                form_url,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                # Check Set-Cookie headers
                for header in response.headers.getall('Set-Cookie', []):
                    if 'samesite' in header.lower():
                        has_csrf_token = True
                        break
        except Exception:
            pass
        
        # Determine if form is vulnerable
        if not has_csrf_token:
            # Check if form is for sensitive action
            form_html = str(form).lower()
            is_sensitive = any(
                keyword in form_html 
                for keyword in self.protected_form_TYPES
            )
            
            if is_sensitive:
                return {
                    "type": "csrf",
                    "severity": "high",
                    "title": "CSRF Vulnerability in Sensitive Form",
                    "description": f"Form with sensitive action lacks CSRF protection",
                    "url": form_url,
                    "method": method,
                    "param": None,
                    "payload": str(form)[:200],
                    "evidence": f"No CSRF token found in {method} form",
                    "remediation": "Add anti-CSRF token to the form and validate it on the server",
                    "cwe_id": "CWE-352",
                    "cvss_score": 8.1,
                    "ml_confidence": 0.85,
                    "ml_prediction": True
                }
            else:
                return {
                    "type": "csrf",
                    "severity": "medium",
                    "title": "Missing CSRF Protection",
                    "description": f"Form lacks CSRF protection tokens",
                    "url": form_url,
                    "method": method,
                    "param": None,
                    "payload": str(form)[:200],
                    "evidence": f"No CSRF token found in {method} form",
                    "remediation": "Implement anti-CSRF tokens for all state-changing forms",
                    "cwe_id": "CWE-352",
                    "cvss_score": 6.5,
                    "ml_confidence": 0.75,
                    "ml_prediction": False
                }
        
        return None
    
    def is_state_changing_link(self, href: str) -> bool:
        """Check if a link triggers state-changing actions"""
        state_changing_patterns = [
            r'/delete/',
            r'/remove/',
            r'/update/',
            r'/edit/',
            r'/modify/',
            r'/add/',
            r'/create/',
            r'/subscribe',
            r'/unsubscribe',
            r'/confirm',
            r'/approve',
            r'/reject',
            r'/transfer',
            r'/payment',
        ]
        
        href_lower = href.lower()
        return any(
            re.search(pattern, href_lower) 
            for pattern in state_changing_patterns
        )
    
    async def check_cors_misconfiguration(
        self,
        session: aiohttp.ClientSession,
        target_url: str
    ) -> List[Dict[str, Any]]:
        """Check for CORS misconfiguration"""
        vulnerabilities = []
        
        try:
            # Check if server returns CORS headers
            async with session.options(
                target_url,
                timeout=aiohttp.ClientTimeout(total=10),
                headers={
                    'Origin': 'http://evil.com',
                    'Access-Control-Request-Method': 'GET'
                }
            ) as response:
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                # Check for insecure CORS configuration
                if acao == '*':
                    vulnerabilities.append({
                        "type": "csrf",
                        "severity": "medium",
                        "title": "Insecure CORS Configuration",
                        "description": "Server allows all origins (*), potentially exposing APIs to CSRF",
                        "url": target_url,
                        "method": "N/A",
                        "param": None,
                        "payload": None,
                        "evidence": f"Access-Control-Allow-Origin: {acao}",
                        "remediation": "Restrict CORS to specific trusted origins",
                        "cwe_id": "CWE-346",
                        "cvss_score": 5.3,
                        "ml_confidence": 0.80,
                        "ml_prediction": False
                    })
                
                elif acao and acac == 'true':
                    vulnerabilities.append({
                        "type": "csrf",
                        "severity": "high",
                        "title": "CORS with Credentials",
                        "description": "CORS allows credentials from arbitrary origins",
                        "url": target_url,
                        "method": "N/A",
                        "param": None,
                        "payload": None,
                        "evidence": f"ACAO: {acao}, ACAC: {acac}",
                        "remediation": "Do not use Access-Control-Allow-Credentials with wildcard origins",
                        "cwe_id": "CWE-346",
                        "cvss_score": 8.1,
                        "ml_confidence": 0.85,
                        "ml_prediction": True
                    })
        
        except Exception:
            pass
        
        return vulnerabilities

