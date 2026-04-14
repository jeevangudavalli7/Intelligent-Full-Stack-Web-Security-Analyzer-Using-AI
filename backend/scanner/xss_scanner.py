"""
Cross-Site Scripting (XSS) Scanner Module
"""
import asyncio
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunsplit
import aiohttp
from bs4 import BeautifulSoup
import hashlib

class XSSScanner:
    """Cross-Site Scripting vulnerability scanner"""
    
    def __init__(self):
        self.name = "XSS Scanner"
        self.severity = "high"
        
        # XSS payloads - various techniques
        self.payloads = [
            # Basic payloads
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            
            # Event handlers
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video onloadstart=alert('XSS')><source src='x'>",
            "<audio onloadstart=alert('XSS')><source src='x'>",
            
            # Attribute injection
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "><script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            
            # Encoding variations
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=\"x\" onerror=\"alert('XSS')\">",
            "<svg><script>alert('XSS')</script></svg>",
            
            # DOM-based
            "#<img src=x onerror=alert('XSS')>",
            "#<script>alert('XSS')</script>",
            
            # jQuery
            "<script>$(alert('XSS'))</script>",
            "<img src=\"x\" onerror=\"$(alert('XSS'))\">",
        ]
        
        # Patterns that indicate XSS vulnerability
        self.reflection_patterns = [
            r"<script.*?>.*?alert.*?</script>",
            r"onerror\s*=\s*['\"]?.*?alert",
            r"onload\s*=\s*['\"]?.*?alert",
            r"javascript:\s*alert",
        ]
        
        self.compiled_reflection = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.reflection_patterns]
        
        # Marker to detect reflection
        self.marker = "XSS_TEST_MARKER"
    
    async def scan(self, target_url: str) -> List[Dict[str, Any]]:
        """
        Perform XSS scan on target URL
        
        Args:
            target_url: Target URL to scan
            
        Returns:
            List of found vulnerabilities
        """
        vulnerabilities = []
        
        try:
            async with aiohttp.ClientSession() as session:
                # Test URL parameters
                parsed = urlparse(target_url)
                if parsed.query:
                    vulnerabilities.extend(await self.test_url_params(session, target_url, parsed))
                
                # Test forms
                vulnerabilities.extend(await self.test_forms(session, target_url))
                
                # Test DOM-based XSS
                vulnerabilities.extend(await test_dom_xss(session, target_url))
        
        except Exception:
            pass
        
        return vulnerabilities
    
    async def test_url_params(
        self,
        session: aiohttp.ClientSession,
        url: str,
        parsed: urlparse
    ) -> List[Dict[str, Any]]:
        """Test URL parameters for XSS vulnerabilities"""
        vulnerabilities = []
        params = parse_qs(parsed.query)
        
        for param_name in params.keys():
            # Test with each payload
            for payload in self.payloads[:5]:
                try:
                    # Inject marker + payload
                    test_params = params.copy()
                    test_params[param_name] = [self.marker + payload]
                    
                    new_query = urlencode(test_params, doseq=True)
                    test_url = urlunsplit((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        new_query,
                        parsed.fragment
                    ))
                    
                    async with session.get(
                        test_url,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as response:
                        if response.status == 200:
                            text = await response.text()
                            
                            # Check if our payload is reflected
                            if self.marker + payload in text:
                                # Check if it's being executed (simplified check)
                                for pattern in self.compiled_reflection:
                                    if pattern.search(text):
                                        vulnerabilities.append({
                                            "type": "xss",
                                            "severity": "high",
                                            "title": "Reflected Cross-Site Scripting (XSS)",
                                            "description": f"XSS vulnerability found in parameter '{param_name}'",
                                            "url": url,
                                            "method": "GET",
                                            "param": param_name,
                                            "payload": payload,
                                            "evidence": f"Reflected: {payload[:50]}...",
                                            "remediation": "Implement input validation, output encoding, and Content Security Policy",
                                            "cwe_id": "CWE-79",
                                            "cvss_score": 7.3,
                                            "ml_confidence": 0.90,
                                            "ml_prediction": True
                                        })
                                        break
                
                except Exception:
                    continue
        
        return vulnerabilities
    
    async def test_forms(
        self,
        session: aiohttp.ClientSession,
        target_url: str
    ) -> List[Dict[str, Any]]:
        """Test forms for XSS vulnerabilities"""
        vulnerabilities = []
        
        try:
            async with session.get(
                target_url,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status != 200:
                    return vulnerabilities
                
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                forms = soup.find_all('form')
                
                for form in forms:
                    form_action = form.get('action', '')
                    form_method = form.get('method', 'get').lower()
                    full_url = urljoin(target_url, form_action)
                    
                    # Get all input fields
                    inputs = form.find_all('input')
                    for input_elem in inputs:
                        input_name = input_elem.get('name')
                        input_type = input_elem.get('type', 'text').lower()
                        
                        # Skip hidden and submit fields
                        if input_type in ['hidden', 'submit', 'image', 'button']:
                            continue
                        
                        # Test each input field
                        for payload in self.payloads[:3]:
                            try:
                                if form_method == 'post':
                                    data = {input_name: self.marker + payload}
                                    for inp in inputs:
                                        if inp.get('name') and inp.get('name') != input_name:
                                            data[inp.get('name')] = inp.get('value', '')
                                    
                                    async with session.post(
                                        full_url,
                                        data=data,
                                        timeout=aiohttp.ClientTimeout(total=10)
                                    ) as resp:
                                        if resp.status == 200:
                                            text = await resp.text()
                                            if self.marker + payload in text:
                                                vulnerabilities.append({
                                                    "type": "xss",
                                                    "severity": "high",
                                                    "title": "Cross-Site Scripting (XSS) in Form",
                                                    "description": f"XSS vulnerability found in form field '{input_name}'",
                                                    "url": full_url,
                                                    "method": "POST",
                                                    "param": input_name,
                                                    "payload": payload,
                                                    "evidence": f"Reflected in form: {payload[:50]}...",
                                                    "remediation": "Implement input validation and output encoding",
                                                    "cwe_id": "CWE-79",
                                                    "cvss_score": 7.3,
                                                    "ml_confidence": 0.88,
                                                    "ml_prediction": True
                                                })
                                                break
                                else:
                                    # GET request
                                    parsed = urlparse(full_url)
                                    params = parse_qs(parsed.query) if parsed.query else {}
                                    params[input_name] = [self.marker + payload]
                                    new_query = urlencode(params, doseq=True)
                                    test_url = urlunsplit((
                                        parsed.scheme,
                                        parsed.netloc,
                                        parsed.path,
                                        new_query,
                                        parsed.fragment
                                    ))
                                    
                                    async with session.get(
                                        test_url,
                                        timeout=aiohttp.ClientTimeout(total=10)
                                    ) as resp:
                                        if resp.status == 200:
                                            text = await resp.text()
                                            if self.marker + payload in text:
                                                vulnerabilities.append({
                                                    "type": "xss",
                                                    "severity": "high",
                                                    "title": "Cross-Site Scripting (XSS) in Form",
                                                    "description": f"XSS vulnerability found in form field '{input_name}'",
                                                    "url": full_url,
                                                    "method": "GET",
                                                    "param": input_name,
                                                    "payload": payload,
                                                    "evidence": f"Reflected in form: {payload[:50]}...",
                                                    "remediation": "Implement input validation and output encoding",
                                                    "cwe_id": "CWE-79",
                                                    "cvss_score": 7.3,
                                                    "ml_confidence": 0.88,
                                                    "ml_prediction": True
                                                })
                                                break
                            
                            except Exception:
                                continue
        
        except Exception:
            pass
        
        return vulnerabilities


async def test_dom_xss(
    session: aiohttp.ClientSession,
    target_url: str
) -> List[Dict[str, Any]]:
    """Test for DOM-based XSS vulnerabilities"""
    vulnerabilities = []
    
    # DOM XSS sinks to look for
    dom_sinks = [
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "setTimeout(",
        "setInterval(",
        "location.href",
        "location.assign",
        "location.replace",
    ]
    
    try:
        async with session.get(
            target_url,
            timeout=aiohttp.ClientTimeout(total=30)
        ) as response:
            if response.status != 200:
                return vulnerabilities
            
            html = await response.text()
            
            # Check for potential DOM XSS in scripts
            soup = BeautifulSoup(html, 'html.parser')
            scripts = soup.find_all('script')
            
            for script in scripts:
                script_content = script.string or ""
                
                # Check for source that could be controlled
                for sink in dom_sinks:
                    if sink in script_content:
                        # Check for potentially dangerous source usage
                        sources = [
                            "location.hash",
                            "location.href",
                            "document.URL",
                            "document.referrer",
                            "window.name",
                        ]
                        
                        for source in sources:
                            if source in script_content:
                                vulnerabilities.append({
                                    "type": "xss",
                                    "severity": "medium",
                                    "title": "Potential DOM-based XSS",
                                    "description": f"Potential DOM XSS: '{sink}' may use user-controlled source",
                                    "url": target_url,
                                    "method": "GET",
                                    "param": "N/A (Client-side)",
                                    "payload": f"Source: {source}, Sink: {sink}",
                                    "evidence": f"Sink '{sink}' with source '{source}' found",
                                    "remediation": "Use safe DOM APIs and sanitize user input",
                                    "cwe_id": "CWE-79",
                                    "cvss_score": 6.1,
                                    "ml_confidence": 0.75,
                                    "ml_prediction": False
                                })
                                break
    
    except Exception:
        pass
    
    return vulnerabilities

