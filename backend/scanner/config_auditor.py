"""
Configuration Security Auditor Module (IaC Scanner)
"""
import re
from typing import List, Dict, Any

class ConfigAuditor:
    """Audits configurations such as Dockerfiles, K8s manifests, and package.json"""

    def audit_dockerfile(self, filename: str, content: str) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        
        has_user = False
        has_healthcheck = False
        
        for idx, line in enumerate(lines):
            line_strip = line.strip()
            # Ignore comments
            if line_strip.startswith("#"):
                continue
                
            # Check for latest base image tag
            if line_strip.upper().startswith("FROM "):
                if ":latest" in line_strip or (":" not in line_strip and " as " not in line_strip.lower() and len(line_strip.split()) == 2):
                    findings.append({
                        "type": "Insecure Dockerfile Base Image",
                        "severity": "MEDIUM",
                        "title": "Base image pinned to 'latest' or untagged",
                        "description": "Using 'latest' or untagged base images risks unpredictable build-time changes and vulnerabilities.",
                        "url": filename,
                        "method": "CONFIG",
                        "parameter": f"Line {idx+1}",
                        "payload": line_strip,
                        "evidence": line_strip,
                        "remediation": "Pin the base image to a specific version or SHA hash: FROM node:18-alpine",
                        "cwe_id": "CWE-1104",
                        "cvss_score": 5.3,
                        "ml_confidence": 0.9,
                        "location": f"{filename}:{idx+1}"
                    })
            
            # Check for USER command
            if line_strip.upper().startswith("USER "):
                has_user = True
                if "root" in line_strip.lower():
                    findings.append({
                        "type": "Insecure Dockerfile User",
                        "severity": "HIGH",
                        "title": "Container explicitly configured to run as root",
                        "description": "Running container processes as root increases threat impact if a container breakout occurs.",
                        "url": filename,
                        "method": "CONFIG",
                        "parameter": f"Line {idx+1}",
                        "payload": line_strip,
                        "evidence": line_strip,
                        "remediation": "Create a non-privileged user and switch to it: USER appuser",
                        "cwe_id": "CWE-250",
                        "cvss_score": 7.8,
                        "ml_confidence": 0.95,
                        "location": f"{filename}:{idx+1}"
                    })
                    
            # Check for HEALTHCHECK
            if line_strip.upper().startswith("HEALTHCHECK "):
                has_healthcheck = True
                
            # Check for hardcoded secrets in ENV/RUN
            if any(cmd in line_strip.upper() for cmd in ["ENV ", "RUN "]):
                if any(sec in line_strip.lower() for sec in ["password=", "secret=", "key=", "token="]) and not any(env in line_strip for env in ["$ENV", "$SECRET", "$KEY"]):
                    findings.append({
                        "type": "Hardcoded Secret in Build Config",
                        "severity": "CRITICAL",
                        "title": "Potential hardcoded credential or secret in build arguments",
                        "description": "Storing secrets in Dockerfile ENV or RUN directives leaks them into container layers and history.",
                        "url": filename,
                        "method": "CONFIG",
                        "parameter": f"Line {idx+1}",
                        "payload": "Redacted credential",
                        "evidence": line_strip,
                        "remediation": "Inject secrets at runtime using docker secret or environment variables, or use build-time secret mounts.",
                        "cwe_id": "CWE-522",
                        "cvss_score": 9.1,
                        "ml_confidence": 0.88,
                        "location": f"{filename}:{idx+1}"
                    })

        # Missing USER configuration
        if not has_user:
            findings.append({
                "type": "Missing Dockerfile USER Configuration",
                "severity": "HIGH",
                "title": "No USER instruction configured",
                "description": "Containers default to running as root when no USER instruction is defined in the Dockerfile.",
                "url": filename,
                "method": "CONFIG",
                "parameter": "File-level",
                "payload": "N/A",
                "evidence": "Missing USER directive",
                "remediation": "Add a non-privileged USER declaration to the Dockerfile (e.g. USER node or USER 10001).",
                "cwe_id": "CWE-250",
                "cvss_score": 7.5,
                "ml_confidence": 0.9,
                "location": f"{filename}:1"
            })
            
        # Missing HEALTHCHECK
        if not has_healthcheck:
            findings.append({
                "type": "Missing Dockerfile HEALTHCHECK",
                "severity": "LOW",
                "title": "No health check configured",
                "description": "Missing HEALTHCHECK prevents the container runtime from detecting unhealthy application states.",
                "url": filename,
                "method": "CONFIG",
                "parameter": "File-level",
                "payload": "N/A",
                "evidence": "Missing HEALTHCHECK directive",
                "remediation": "Add a HEALTHCHECK instruction to monitor the health status of the application.",
                "cwe_id": "CWE-1008",
                "cvss_score": 2.5,
                "ml_confidence": 0.92,
                "location": f"{filename}:1"
            })
            
        return findings

    def audit_kubernetes(self, filename: str, content: str) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        
        for idx, line in enumerate(lines):
            line_strip = line.strip()
            
            # Check privileged container
            if "privileged: true" in line_strip:
                findings.append({
                    "type": "Privileged Kubernetes Container",
                    "severity": "CRITICAL",
                    "title": "Privileged container execution allowed",
                    "description": "Running containers with privileged flags gives them root capabilities on the host node, defeating isolation.",
                    "url": filename,
                    "method": "CONFIG",
                    "parameter": f"Line {idx+1}",
                    "payload": line_strip,
                    "evidence": line_strip,
                    "remediation": "Remove privileged: true from the deployment container securityContext.",
                    "cwe_id": "CWE-250",
                    "cvss_score": 9.5,
                    "ml_confidence": 0.95,
                    "location": f"{filename}:{idx+1}"
                })
                
            # AllowPrivilegeEscalation check
            if "allowPrivilegeEscalation: true" in line_strip:
                findings.append({
                    "type": "Kubernetes Privilege Escalation",
                    "severity": "HIGH",
                    "title": "Container allowPrivilegeEscalation enabled",
                    "description": "Allowing privilege escalation allows child processes to gain more permissions than their parent process.",
                    "url": filename,
                    "method": "CONFIG",
                    "parameter": f"Line {idx+1}",
                    "payload": line_strip,
                    "evidence": line_strip,
                    "remediation": "Set allowPrivilegeEscalation: false under container securityContext.",
                    "cwe_id": "CWE-269",
                    "cvss_score": 8.0,
                    "ml_confidence": 0.92,
                    "location": f"{filename}:{idx+1}"
                })
                
            # Missing readOnlyRootFilesystem
            if "readOnlyRootFilesystem: false" in line_strip:
                findings.append({
                    "type": "Writable Container Root Filesystem",
                    "severity": "LOW",
                    "title": "Read-only root filesystem disabled",
                    "description": "Allowing write access to the root filesystem makes it easier for attackers to inject malware or download exploit binaries.",
                    "url": filename,
                    "method": "CONFIG",
                    "parameter": f"Line {idx+1}",
                    "payload": line_strip,
                    "evidence": line_strip,
                    "remediation": "Set readOnlyRootFilesystem: true and use mounted volumes for writable paths.",
                    "cwe_id": "CWE-732",
                    "cvss_score": 3.2,
                    "ml_confidence": 0.88,
                    "location": f"{filename}:{idx+1}"
                })
                
            # Host network usage
            if "hostNetwork: true" in line_strip:
                findings.append({
                    "type": "Insecure Kubernetes Network Sharing",
                    "severity": "HIGH",
                    "title": "Container hostNetwork namespace sharing allowed",
                    "description": "Sharing the host network namespace allows containers to sniff host-level network traffic and loopback loops.",
                    "url": filename,
                    "method": "CONFIG",
                    "parameter": f"Line {idx+1}",
                    "payload": line_strip,
                    "evidence": line_strip,
                    "remediation": "Remove hostNetwork: true and expose container services via standard ClusterIP/NodePort Services.",
                    "cwe_id": "CWE-250",
                    "cvss_score": 7.7,
                    "ml_confidence": 0.9,
                    "location": f"{filename}:{idx+1}"
                })

        return findings

    def audit_package_json(self, filename: str, content: str) -> List[Dict[str, Any]]:
        findings = []
        import json
        try:
            data = json.loads(content)
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            
            # Static list of known vulnerable packages (mock data database logic)
            vulnerable_libs = {
                "axios": {"max_vulnerable": "0.21.1", "cve": "CVE-2020-28168", "desc": "Server-Side Request Forgery in Axios", "severity": "HIGH"},
                "lodash": {"max_vulnerable": "4.17.20", "cve": "CVE-2020-8203", "desc": "Prototype Pollution in Lodash", "severity": "HIGH"},
                "express": {"max_vulnerable": "4.16.0", "cve": "CVE-2018-3717", "desc": "Directory Traversal in Express serving static files", "severity": "MEDIUM"},
                "minimist": {"max_vulnerable": "1.2.5", "cve": "CVE-2020-7598", "desc": "Prototype Pollution in Minimist", "severity": "HIGH"}
            }
            
            for dep_name, version in deps.items():
                # Strip ^, ~, *
                clean_ver = re.sub(r"[^\d\.]", "", version)
                if dep_name in vulnerable_libs:
                    vuln_info = vulnerable_libs[dep_name]
                    max_vuln = vuln_info["max_vulnerable"]
                    
                    # Basic comparison (assuming semver split comparison)
                    clean_split = [int(x) for x in clean_ver.split(".") if x.isdigit()]
                    max_split = [int(x) for x in max_vuln.split(".") if x.isdigit()]
                    
                    is_vuln = False
                    # Pads list to match sizes
                    for i in range(max(len(clean_split), len(max_split))):
                        v1 = clean_split[i] if i < len(clean_split) else 0
                        v2 = max_split[i] if i < len(max_split) else 0
                        if v1 < v2:
                            is_vuln = True
                            break
                        elif v1 > v2:
                            break
                            
                    if is_vuln:
                        findings.append({
                            "type": "Vulnerable Dependency Check",
                            "severity": vuln_info["severity"],
                            "title": f"Vulnerable library '{dep_name}' version {version}",
                            "description": f"Vulnerability {vuln_info['cve']}: {vuln_info['desc']}.",
                            "url": filename,
                            "method": "DEPENDENCY",
                            "parameter": dep_name,
                            "payload": version,
                            "evidence": f'"{dep_name}": "{version}"',
                            "remediation": f"Upgrade {dep_name} to a version higher than {max_vuln}.",
                            "cwe_id": "CWE-1395",
                            "cvss_score": 7.5 if vuln_info["severity"] == "HIGH" else 5.0,
                            "ml_confidence": 0.98,
                            "location": f"{filename}"
                        })
        except Exception:
            pass
        return findings
