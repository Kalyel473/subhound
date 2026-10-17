
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import random
import re
import secrets
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Type

import warnings

import aiohttp
import aiodns

# aiodns 4.x marca query() como deprecated mas ele ainda funciona nas duas
# versoes (3.x e 4.x) e retorna o formato que a gente faz o parse. Silencia
# so esse aviso especifico pra nao poluir a saida da ferramenta.
warnings.filterwarnings("ignore", message=r"query\(\) is deprecated.*")

try:
    from rich.console import Console as _RichConsole
    _RICH = True
except Exception:  # rich e opcional
    _RICH = False

__version__ = "0.1.0"

# =========================================================================== #
#  CONFIG - constantes e settings                                             #
# =========================================================================== #
DEFAULT_RESOLVERS: List[str] = [
    "1.1.1.1", "1.0.0.1",            # Cloudflare
    "8.8.8.8", "8.8.4.4",            # Google
    "9.9.9.9",                       # Quad9
    "208.67.222.222",               # OpenDNS
    "64.6.64.6",                    # Verisign
]

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 subhound/0.1"
)
DEFAULT_HEADERS: Dict[str, str] = {"User-Agent": USER_AGENT}

DEFAULT_DNS_CONCURRENCY = 200
DEFAULT_HTTP_CONCURRENCY = 50
DEFAULT_SOURCE_CONCURRENCY = 10
DEFAULT_DNS_TIMEOUT = 4.0
DEFAULT_HTTP_TIMEOUT = 8.0
DEFAULT_SOURCE_TIMEOUT = 25.0
DEFAULT_DNS_RETRIES = 2
DEFAULT_RECURSION_DEPTH = 2

INTERESTING_KEYWORDS: List[str] = [
    "admin", "adminer", "api", "auth", "backup", "beta", "cdn", "ci", "cloud",
    "confluence", "dashboard", "dev", "develop", "db", "database", "demo",
    "docker", "elastic", "gateway", "gestao", "git", "gitlab", "grafana",
    "homolog", "hml", "internal", "intranet", "jenkins", "jira", "kibana",
    "lab", "ldap", "legacy", "login", "mail", "manage", "monitor", "mysql",
    "old", "oauth", "panel", "phpmyadmin", "pma", "portal", "pre", "prod",
    "proxy", "qa", "redis", "repo", "s3", "sandbox", "secure", "sql", "ssh",
    "stage", "staging", "sso", "svn", "teste", "test", "token", "uat", "vpn",
    "webmail", "wiki",
]

API_KEY_ENV: Dict[str, str] = {
    "virustotal": "VIRUSTOTAL_API_KEY",
    "securitytrails": "SECURITYTRAILS_API_KEY",
    "shodan": "SHODAN_API_KEY",
    "censys_id": "CENSYS_API_ID",
    "censys_secret": "CENSYS_API_SECRET",
}


def get_api_key(name: str) -> Optional[str]:
    env = API_KEY_ENV.get(name)
    return os.environ.get(env) if env else None


@dataclass
class Settings:
    resolvers: List[str] = field(default_factory=lambda: list(DEFAULT_RESOLVERS))
    dns_concurrency: int = DEFAULT_DNS_CONCURRENCY
    http_concurrency: int = DEFAULT_HTTP_CONCURRENCY
    source_concurrency: int = DEFAULT_SOURCE_CONCURRENCY
    dns_timeout: float = DEFAULT_DNS_TIMEOUT
    http_timeout: float = DEFAULT_HTTP_TIMEOUT
    source_timeout: float = DEFAULT_SOURCE_TIMEOUT
    dns_retries: int = DEFAULT_DNS_RETRIES
    verbose: bool = False


# =========================================================================== #
#  MODELS - Subdomain e ProbeResult                                           #
# =========================================================================== #
@dataclass
class ProbeResult:
    url: str
    status: int
    scheme: str
    title: Optional[str] = None
    server: Optional[str] = None
    content_length: Optional[int] = None
    content_type: Optional[str] = None
    redirect: Optional[str] = None
    tech: List[str] = field(default_factory=list)
    words: Optional[int] = None

    def to_dict(self) -> Dict:
        return {
            "url": self.url, "status": self.status, "scheme": self.scheme,
            "title": self.title, "server": self.server,
            "content_length": self.content_length,
            "content_type": self.content_type, "redirect": self.redirect,
            "tech": self.tech,
        }


@dataclass
class Subdomain:
    name: str
    sources: Set[str] = field(default_factory=set)
    ips: Set[str] = field(default_factory=set)
    cname: Optional[str] = None
    resolved: bool = False
    wildcard: bool = False
    depth: int = 0
    interesting: bool = False
    probe: Optional[ProbeResult] = None

    def merge(self, other: "Subdomain") -> None:
        self.sources |= other.sources
        self.ips |= other.ips
        self.cname = self.cname or other.cname
        self.resolved = self.resolved or other.resolved
        self.interesting = self.interesting or other.interesting
        self.depth = min(self.depth, other.depth)

    def to_dict(self) -> Dict:
        d = {
            "subdomain": self.name,
            "sources": sorted(self.sources),
            "ips": sorted(self.ips),
            "cname": self.cname,
            "resolved": self.resolved,
            "wildcard": self.wildcard,
            "depth": self.depth,
            "interesting": self.interesting,
        }
        if self.probe:
            d["http"] = self.probe.to_dict()
        return d


# =========================================================================== #
#  CONSOLE - saida com cores (rich opcional)                                  #
# =========================================================================== #
class Console:
    def __init__(self, verbose=False, silent=False, no_color=False):
        self.verbose = verbose
        self.silent = silent
        self._rich = _RICH and not no_color
        self._c = _RichConsole(stderr=True) if self._rich else None

    def _emit(self, markup, plain):
        if self.silent:
            return
        if self._rich:
            self._c.print(markup, highlight=False)
        else:
            print(plain, file=sys.stderr)

    def info(self, msg):  self._emit(f"[bold cyan][*][/] {msg}", f"[*] {msg}")
    def good(self, msg):  self._emit(f"[bold green][+][/] {msg}", f"[+] {msg}")
    def warn(self, msg):  self._emit(f"[bold yellow][!][/] {msg}", f"[!] {msg}")
    def error(self, msg): self._emit(f"[bold red][x][/] {msg}", f"[x] {msg}")

    def debug(self, msg):
        if self.verbose:
            self._emit(f"[dim][.] {msg}[/]", f"[.] {msg}")

    def banner(self, text):
        if self.silent:
            return
        if self._rich:
            self._c.print(text, style="bold green")
        else:
            print(text, file=sys.stderr)

    def result(self, line):
        print(line)  # stdout (pode ser redirecionado / piped)


BANNER = r"""
    _____       __    __  __                      __
   / ___/__  __/ /_  / / / /___  __  ______  ____/ /
   \__ \/ / / / __ \/ /_/ / __ \/ / / / __ \/ __  /
  ___/ / /_/ / /_/ / __  / /_/ / /_/ / / / / /_/ /
 /____/\__,_/_.___/_/ /_/\____/\__,_/_/ /_/\__,_/
         enumeracao de subdominios  ·  v{ver}
"""


def make_console(verbose=False, silent=False, no_color=False) -> Console:
    return Console(verbose=verbose, silent=silent, no_color=no_color)


# =========================================================================== #
#  WORDLISTS EMBUTIDAS                                                         #
# =========================================================================== #
_EMBEDDED_WORDS = """
www mail ftp webmail smtp pop pop3 imap ns ns1 ns2 ns3 ns4 dns dns1 dns2 mx mx1
email remote server secure vpn m mobile app apps api api1 api2 api-dev apidev
dev dev1 dev2 development staging stage stg test testing tests qa uat homolog
hml prod production preprod demo sandbox beta alpha portal admin administrator
adm panel cpanel whm dashboard manage management console login signin auth oauth
sso account accounts my client clients customer intranet internal extranet corp
office cloud cdn static assets img images media video videos download downloads
upload uploads files file share drive docs doc documentation wiki confluence
jira git gitlab github svn repo ci cd jenkins build nexus registry docker k8s
kube grafana kibana prometheus monitor monitoring status health metrics log logs
elastic elk db database mysql postgres postgresql mssql mongo redis sql oracle
phpmyadmin pma adminer backup backups old new legacy blog news shop store loja
pay payment payments checkout billing gateway proxy lb loadbalancer gw router
firewall fw ids waf relay newsletter mailer marketing crm erp hr rh support
suporte help helpdesk ticket tickets chat forum community events calendar meet
voip sip pbx radius ldap ad kerberos ntp time search solr cache varnish queue
rabbitmq kafka ws websocket socket stream live rtmp sftp tftp scp vnc rdp ssh
telnet jump bastion gestao sistema sistemas servicos service services ms edge
origin public private partner partners vendor affiliate track tracking analytics
stats report reports data bi dw datawarehouse etl ml ai lab labs research school
student alumni library ios android play go link links url short redirect web
web1 web2 host hosting vhost vps srv srv1 srv2 node node1 node2 pool cluster
master slave replica primary secondary failover dr mirror www1 www2 ww
"""

_EMBEDDED_PERMS = """
dev development staging stage stg test testing qa uat homolog hml prod production
preprod pre demo sandbox beta alpha new old legacy internal external private
public admin api app web mobile cdn static media backup mirror secure vpn proxy
gw gateway edge origin us eu br asia east west north south 1 2 3 v1 v2 v3 01 02
node srv cluster primary secondary replica master
"""


def _read_list_text(text: str) -> List[str]:
    out: List[str] = []
    for token in text.split():
        w = token.strip().lower()
        if w and not w.startswith("#"):
            out.append(w)
    return list(dict.fromkeys(out))


def _read_list_file(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        # arquivos externos: uma palavra por linha
        out: List[str] = []
        for line in fh:
            w = line.strip().lower()
            if w and not w.startswith("#"):
                out.append(w)
        return list(dict.fromkeys(out))


def load_wordlist(path: Optional[str] = None) -> List[str]:
    return _read_list_file(path) if path else _read_list_text(_EMBEDDED_WORDS)


def load_permutation_words(path: Optional[str] = None) -> List[str]:
    return _read_list_file(path) if path else _read_list_text(_EMBEDDED_PERMS)


def build_candidates(domain: str, words: Iterable[str]) -> Set[str]:
    domain = domain.lower().strip(".")
    out: Set[str] = set()
    for w in words:
        w = w.strip(". ").lower()
        if w:
            out.add(f"{w}.{domain}")
    return out


# =========================================================================== #
#  SOURCES - fontes passivas de OSINT                                         #
# =========================================================================== #
_HOST_RE = re.compile(
    r"(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}"
)


def extract_subdomains(text: str, domain: str) -> Set[str]:
    domain = domain.lower().strip(".")
    suffix = "." + domain
    out: Set[str] = set()
    for m in _HOST_RE.finditer(text):
        host = m.group(0).lower().strip(".")
        host = host.lstrip("*.").split("@")[-1]
        if host == domain or host.endswith(suffix):
            out.add(host)
    return out


class PassiveSource:
    name: str = "base"
    requires_key: bool = False

    def available(self) -> bool:
        return True

    async def fetch(self, session, domain, settings) -> Set[str]:
        raise NotImplementedError

    async def _get_text(self, session, url, settings, **kw) -> Optional[str]:
        try:
            timeout = aiohttp.ClientTimeout(total=settings.source_timeout)
            async with session.get(url, timeout=timeout, **kw) as r:
                if r.status != 200:
                    return None
                return await r.text()
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeDecodeError):
            return None

    async def _get_json(self, session, url, settings, **kw):
        try:
            timeout = aiohttp.ClientTimeout(total=settings.source_timeout)
            async with session.get(url, timeout=timeout, **kw) as r:
                if r.status != 200:
                    return None
                return await r.json(content_type=None)
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
            return None


class CrtSh(PassiveSource):
    name = "crtsh"

    async def fetch(self, session, domain, settings) -> Set[str]:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        data = await self._get_json(session, url, settings)
        out: Set[str] = set()
        if isinstance(data, list):
            for entry in data:
                for key in ("name_value", "common_name"):
                    for line in (entry.get(key) or "").splitlines():
                        out |= extract_subdomains(line, domain)
        return out


class HackerTarget(PassiveSource):
    name = "hackertarget"

    async def fetch(self, session, domain, settings) -> Set[str]:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        text = await self._get_text(session, url, settings)
        if not text or "error" in text.lower() or "api count" in text.lower():
            return set()
        return extract_subdomains(text, domain)


class RapidDns(PassiveSource):
    name = "rapiddns"

    async def fetch(self, session, domain, settings) -> Set[str]:
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"
        text = await self._get_text(session, url, settings)
        return extract_subdomains(text, domain) if text else set()


class AlienVault(PassiveSource):
    name = "alienvault"

    async def fetch(self, session, domain, settings) -> Set[str]:
        url = (f"https://otx.alienvault.com/api/v1/indicators/domain/"
               f"{domain}/passive_dns")
        data = await self._get_json(session, url, settings)
        out: Set[str] = set()
        if isinstance(data, dict):
            for rec in data.get("passive_dns", []):
                host = (rec.get("hostname") or "").lower().strip(".")
                if host.endswith("." + domain) or host == domain:
                    out.add(host)
        return out


class Anubis(PassiveSource):
    name = "anubis"

    async def fetch(self, session, domain, settings) -> Set[str]:
        url = f"https://jldc.me/anubis/subdomains/{domain}"
        data = await self._get_json(session, url, settings)
        out: Set[str] = set()
        if isinstance(data, list):
            for host in data:
                h = str(host).lower().strip(".")
                if h.endswith("." + domain) or h == domain:
                    out.add(h)
        return out


class Wayback(PassiveSource):
    name = "wayback"

    async def fetch(self, session, domain, settings) -> Set[str]:
        url = (f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
               f"&output=text&fl=original&collapse=urlkey&limit=50000")
        text = await self._get_text(session, url, settings)
        return extract_subdomains(text, domain) if text else set()


class CertSpotter(PassiveSource):
    name = "certspotter"

    async def fetch(self, session, domain, settings) -> Set[str]:
        url = (f"https://api.certspotter.com/v1/issuances?domain={domain}"
               f"&include_subdomains=true&expand=dns_names")
        data = await self._get_json(session, url, settings)
        out: Set[str] = set()
        if isinstance(data, list):
            for entry in data:
                for host in entry.get("dns_names", []):
                    h = str(host).lower().strip(".").lstrip("*.")
                    if h.endswith("." + domain) or h == domain:
                        out.add(h)
        return out


class ThreatMiner(PassiveSource):
    name = "threatminer"

    async def fetch(self, session, domain, settings) -> Set[str]:
        url = f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5"
        data = await self._get_json(session, url, settings)
        out: Set[str] = set()
        if isinstance(data, dict):
            for host in data.get("results", []) or []:
                h = str(host).lower().strip(".")
                if h.endswith("." + domain) or h == domain:
                    out.add(h)
        return out


class VirusTotal(PassiveSource):
    name = "virustotal"
    requires_key = True

    def __init__(self):
        self.key = get_api_key("virustotal")

    def available(self) -> bool:
        return bool(self.key)

    async def fetch(self, session, domain, settings) -> Set[str]:
        out: Set[str] = set()
        headers = {"x-apikey": self.key}
        url = (f"https://www.virustotal.com/api/v3/domains/"
               f"{domain}/subdomains?limit=40")
        for _ in range(10):
            data = await self._get_json(session, url, settings, headers=headers)
            if not isinstance(data, dict):
                break
            for item in data.get("data", []):
                h = str(item.get("id", "")).lower().strip(".")
                if h.endswith("." + domain) or h == domain:
                    out.add(h)
            nxt = (data.get("links") or {}).get("next")
            if not nxt:
                break
            url = nxt
        return out


class SecurityTrails(PassiveSource):
    name = "securitytrails"
    requires_key = True

    def __init__(self):
        self.key = get_api_key("securitytrails")

    def available(self) -> bool:
        return bool(self.key)

    async def fetch(self, session, domain, settings) -> Set[str]:
        headers = {"APIKEY": self.key, "Accept": "application/json"}
        url = (f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
               f"?children_only=false")
        data = await self._get_json(session, url, settings, headers=headers)
        out: Set[str] = set()
        if isinstance(data, dict):
            for prefix in data.get("subdomains", []):
                out.add(f"{prefix}.{domain}".lower())
        return out


_REGISTRY: List[Type[PassiveSource]] = [
    CrtSh, HackerTarget, RapidDns, AlienVault, Anubis, Wayback,
    CertSpotter, ThreatMiner, VirusTotal, SecurityTrails,
]


def all_source_names() -> List[str]:
    return [cls.name for cls in _REGISTRY]


def build_sources(include=None, exclude=None) -> List[PassiveSource]:
    include = [s.lower() for s in include] if include else None
    exclude = [s.lower() for s in exclude] if exclude else []
    chosen: List[PassiveSource] = []
    for cls in _REGISTRY:
        if include is not None and cls.name not in include:
            continue
        if cls.name in exclude:
            continue
        inst = cls()
        if inst.available():
            chosen.append(inst)
    return chosen


# =========================================================================== #
#  RESOLVER - resolucao DNS async (aiodns / c-ares)                           #
# =========================================================================== #
class Resolver:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._sem = asyncio.Semaphore(settings.dns_concurrency)
        self._resolvers: List[aiodns.DNSResolver] = []
        for ns in settings.resolvers:
            try:
                self._resolvers.append(
                    aiodns.DNSResolver(nameservers=[ns],
                                       timeout=settings.dns_timeout, tries=1)
                )
            except Exception:
                continue
        if not self._resolvers:
            self._resolvers.append(
                aiodns.DNSResolver(timeout=settings.dns_timeout, tries=1)
            )

    def _pick(self) -> aiodns.DNSResolver:
        return random.choice(self._resolvers)

    async def _query(self, name: str, rtype: str):
        last_exc = None
        for _ in range(max(1, self.settings.dns_retries)):
            resolver = self._pick()
            try:
                return await resolver.query(name, rtype)
            except aiodns.error.DNSError as e:
                last_exc = e
                if e.args and e.args[0] == aiodns.error.ARES_ENOTFOUND:
                    return None
            except (asyncio.TimeoutError, Exception) as e:
                last_exc = e
        _ = last_exc
        return None

    async def resolve(self, name: str) -> Dict[str, object]:
        async with self._sem:
            ips: List[str] = []
            cname: Optional[str] = None

            a = await self._query(name, "A")
            if a:
                ips.extend(getattr(r, "host", None) for r in a if getattr(r, "host", None))
            aaaa = await self._query(name, "AAAA")
            if aaaa:
                ips.extend(getattr(r, "host", None) for r in aaaa if getattr(r, "host", None))
            if not ips:
                cres = await self._query(name, "CNAME")
                if cres is not None:
                    cname = getattr(cres, "cname", None)

            return {
                "name": name,
                "ips": sorted(set(ip for ip in ips if ip)),
                "cname": cname,
                "resolved": bool(ips) or cname is not None,
            }

    async def resolve_many(self, names: Iterable[str], on_result=None):
        names = list(dict.fromkeys(names))
        results: List[Dict[str, object]] = []

        async def _task(n: str):
            res = await self.resolve(n)
            if res["resolved"]:
                results.append(res)
                if on_result:
                    on_result(res)

        await asyncio.gather(*[_task(n) for n in names])
        return results


# =========================================================================== #
#  WILDCARD - deteccao de wildcard DNS                                        #
# =========================================================================== #
class WildcardDetector:
    def __init__(self, resolver: Resolver, probes: int = 3):
        self.resolver = resolver
        self.probes = probes
        self._cache: Dict[str, Set[str]] = {}

    @staticmethod
    def _rand_label() -> str:
        return "subhound-" + secrets.token_hex(8)

    async def _wildcard_ips_for(self, parent: str) -> Set[str]:
        if parent in self._cache:
            return self._cache[parent]
        ips: Set[str] = set()
        for _ in range(self.probes):
            name = f"{self._rand_label()}.{parent}"
            res = await self.resolver.resolve(name)
            if res["resolved"]:
                ips |= set(res["ips"])  # type: ignore[arg-type]
        self._cache[parent] = ips
        return ips

    async def prime(self, domain: str) -> Set[str]:
        return await self._wildcard_ips_for(domain)

    async def is_wildcard(self, name: str, ips: Set[str]) -> bool:
        if not ips:
            return False
        parent = name.split(".", 1)[1] if "." in name else name
        wildcard_ips = await self._wildcard_ips_for(parent)
        if not wildcard_ips:
            return False
        return set(ips).issubset(wildcard_ips)

    async def filter_results(self, results: List[dict]) -> List[dict]:
        kept: List[dict] = []
        for res in results:
            ips = set(res.get("ips", []))
            if await self.is_wildcard(res["name"], ips):
                res["wildcard"] = True
                continue
            kept.append(res)
        return kept


# =========================================================================== #
#  PERMUTATIONS - geracao estilo altdns / dnsgen                              #
# =========================================================================== #
_DIGIT_RE = re.compile(r"(\d+)")


def _prefix_of(host: str, domain: str) -> str:
    domain = domain.lower().strip(".")
    host = host.lower().strip(".")
    if host == domain:
        return ""
    if host.endswith("." + domain):
        return host[: -(len(domain) + 1)]
    return ""


def _number_mutations(label: str) -> Set[str]:
    out: Set[str] = set()
    m = _DIGIT_RE.search(label)
    if m:
        num = int(m.group(1))
        for delta in (-1, 1, 2):
            n = num + delta
            if n >= 0:
                out.add(label[: m.start(1)] + str(n) + label[m.end(1):])
    else:
        for n in (1, 2, 3, "01", "02"):
            out.add(f"{label}{n}")
    return out


def generate_permutations(known, domain, words, limit: int = 50000) -> Set[str]:
    domain = domain.lower().strip(".")
    words = [w.lower().strip() for w in words if w.strip()]
    known_set = {h.lower().strip(".") for h in known}

    prefixes: Set[str] = set()
    for host in known_set:
        p = _prefix_of(host, domain)
        if p:
            prefixes.add(p)

    candidates: Set[str] = set()

    def add(prefix: str) -> bool:
        prefix = prefix.strip(".-").replace("..", ".")
        if not prefix:
            return True
        host = f"{prefix}.{domain}"
        if host not in known_set:
            candidates.add(host)
        return len(candidates) < limit

    for prefix in prefixes:
        labels = prefix.split(".")
        for w in words:
            if not add(f"{w}.{prefix}"):
                return candidates
        for i, lbl in enumerate(labels):
            head, tail = labels[:i], labels[i + 1:]
            for mut in _number_mutations(lbl):
                if not add(".".join(head + [mut] + tail)):
                    return candidates
            for w in words:
                for v in {f"{w}-{lbl}", f"{lbl}-{w}", f"{w}{lbl}", f"{lbl}{w}", w}:
                    if not add(".".join(head + [v] + tail)):
                        return candidates
    return candidates


# =========================================================================== #
#  HTTP PROBE - liveness + titulo + fingerprint                               #
# =========================================================================== #
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_MAX_BODY = 65536

_TECH_HEADER = {
    "x-powered-by": None, "x-generator": None,
    "x-aspnet-version": "ASP.NET", "x-drupal-cache": "Drupal",
}
_TECH_BODY = [
    (re.compile(r"wp-content|wp-includes", re.I), "WordPress"),
    (re.compile(r"/sites/default/files", re.I), "Drupal"),
    (re.compile(r"Joomla!", re.I), "Joomla"),
    (re.compile(r"__NEXT_DATA__", re.I), "Next.js"),
    (re.compile(r"ng-version=", re.I), "Angular"),
    (re.compile(r"data-reactroot|react", re.I), "React"),
    (re.compile(r"csrfmiddlewaretoken", re.I), "Django"),
    (re.compile(r"Laravel", re.I), "Laravel"),
    (re.compile(r"cf-ray", re.I), "Cloudflare"),
]


def _extract_title(body: str) -> Optional[str]:
    m = _TITLE_RE.search(body)
    if not m:
        return None
    title = re.sub(r"\s+", " ", m.group(1)).strip()
    return title[:200] or None


def _fingerprint(headers, body: str) -> List[str]:
    tech: List[str] = []
    server = headers.get("Server")
    if server:
        tech.append(server.split("/")[0].strip())
    for h, label in _TECH_HEADER.items():
        if h in headers:
            tech.append(label or headers[h].split("/")[0].split(";")[0].strip())
    for rgx, label in _TECH_BODY:
        if rgx.search(body):
            tech.append(label)
    seen, out = set(), []
    for t in tech:
        t = t.strip()
        if t and t.lower() not in seen:
            seen.add(t.lower())
            out.append(t)
    return out


class HttpProber:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._sem = asyncio.Semaphore(settings.http_concurrency)

    async def _try(self, session, scheme, host) -> Optional[ProbeResult]:
        url = f"{scheme}://{host}"
        timeout = aiohttp.ClientTimeout(total=self.settings.http_timeout)
        try:
            async with session.get(url, timeout=timeout, ssl=False,
                                   allow_redirects=False,
                                   headers=DEFAULT_HEADERS) as r:
                raw = await r.content.read(_MAX_BODY)
                body = raw.decode("utf-8", errors="ignore")
                clen = r.headers.get("Content-Length")
                return ProbeResult(
                    url=url, status=r.status, scheme=scheme,
                    title=_extract_title(body),
                    server=r.headers.get("Server"),
                    content_length=int(clen) if clen and clen.isdigit() else len(raw),
                    content_type=(r.headers.get("Content-Type") or "").split(";")[0] or None,
                    redirect=r.headers.get("Location"),
                    tech=_fingerprint(r.headers, body),
                    words=len(body.split()),
                )
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError, ValueError):
            return None

    async def probe(self, host) -> Optional[ProbeResult]:
        async with self._sem:
            async with aiohttp.ClientSession() as session:
                for scheme in ("https", "http"):
                    res = await self._try(session, scheme, host)
                    if res is not None:
                        return res
        return None

    async def probe_many(self, hosts, on_result=None):
        results = {}

        async def _task(h):
            res = await self.probe(h)
            if res is not None:
                results[h] = res
                if on_result:
                    on_result(h, res)

        await asyncio.gather(*[_task(h) for h in hosts])
        return results


# =========================================================================== #
#  OUTPUT - writers txt / json / csv / jsonl                                  #
# =========================================================================== #
def write_txt(path, subs, only_names=True):
    with open(path, "w", encoding="utf-8") as fh:
        for s in subs:
            if only_names:
                fh.write(s.name + "\n")
            else:
                fh.write(f"{s.name}\t{','.join(sorted(s.ips)) or '-'}\n")


def write_json(path, domain, subs, meta):
    payload = {"domain": domain, "meta": meta, "count": len(subs),
               "results": [s.to_dict() for s in subs]}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)


def write_csv(path, subs):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["subdomain", "ips", "cname", "sources", "interesting",
                    "http_status", "http_title", "tech"])
        for s in subs:
            http = s.probe
            w.writerow([
                s.name, ";".join(sorted(s.ips)), s.cname or "",
                ";".join(sorted(s.sources)), "yes" if s.interesting else "",
                http.status if http else "", (http.title or "") if http else "",
                ";".join(http.tech) if http else "",
            ])


def write_jsonl(path, subs):
    with open(path, "w", encoding="utf-8") as fh:
        for s in subs:
            fh.write(json.dumps(s.to_dict(), ensure_ascii=False) + "\n")


# =========================================================================== #
#  ENGINE - orquestrador das fases                                            #
# =========================================================================== #
@dataclass
class EngineConfig:
    domain: str
    settings: Settings = field(default_factory=Settings)
    passive: bool = True
    brute: bool = False
    permutations: bool = False
    recursive: bool = False
    probe: bool = False
    resolve: bool = True
    recursion_depth: int = 1
    wordlist: Optional[str] = None
    perm_wordlist: Optional[str] = None
    include_sources: Optional[List[str]] = None
    exclude_sources: Optional[List[str]] = None
    perm_limit: int = 50000
    only_resolved: bool = False


class Engine:
    def __init__(self, config: EngineConfig, console: Optional[Console] = None):
        self.cfg = config
        self.domain = config.domain.lower().strip(".")
        self.settings = config.settings
        self.console = console or Console(silent=True)
        self.resolver = Resolver(self.settings)
        self.wildcard = WildcardDetector(self.resolver)
        self._subs: Dict[str, Subdomain] = {}
        self.meta: Dict[str, object] = {}

    def _add(self, name, source, depth=0) -> Subdomain:
        name = name.lower().strip(".")
        sub = self._subs.get(name)
        if sub is None:
            sub = Subdomain(name=name, depth=depth)
            self._subs[name] = sub
        sub.sources.add(source)
        return sub

    def _flag_interesting(self, sub: Subdomain) -> None:
        prefix = sub.name[: -(len(self.domain) + 1)] if sub.name != self.domain else ""
        labels = set(re.split(r"[.\-_]", prefix)) if prefix else set()
        if labels & set(INTERESTING_KEYWORDS):
            sub.interesting = True

    async def _run_passive(self, domain, depth=0) -> Set[str]:
        sources = build_sources(self.cfg.include_sources, self.cfg.exclude_sources)
        if depth == 0:
            self.console.info(
                f"Passivo: {len(sources)} fontes -> "
                f"{', '.join(s.name for s in sources)}"
            )
        sem = asyncio.Semaphore(self.settings.source_concurrency)
        found: Set[str] = set()

        async with aiohttp.ClientSession() as session:
            async def _run(src):
                async with sem:
                    try:
                        res = await src.fetch(session, domain, self.settings)
                    except Exception as e:
                        self.console.debug(f"fonte {src.name} falhou: {e}")
                        return
                    if res:
                        self.console.debug(f"{src.name}: {len(res)} hosts")
                        for host in res:
                            found.add(host)
                            self._add(host, src.name, depth)

            await asyncio.gather(*[_run(s) for s in sources])
        return found

    async def _resolve_and_filter(self, candidates, source_tag, depth) -> List[dict]:
        if not candidates:
            return []
        self.console.info(f"Resolvendo {len(candidates)} candidatos ({source_tag})...")
        results = await self.resolver.resolve_many(candidates)
        kept = await self.wildcard.filter_results(results)
        for res in kept:
            sub = self._add(res["name"], source_tag, depth)
            sub.ips |= set(res["ips"])
            sub.cname = sub.cname or res["cname"]
            sub.resolved = True
        dropped = len(results) - len(kept)
        if dropped:
            self.console.warn(f"{dropped} descartados como eco de wildcard")
        self.console.good(f"{len(kept)} resolvidos ({source_tag})")
        return kept

    async def run(self) -> List[Subdomain]:
        start = time.time()
        self.console.info(f"Alvo: {self.domain}")

        if self.cfg.passive:
            await self._run_passive(self.domain, depth=0)
            self.console.good(f"Passivo: {len(self._subs)} subdominios unicos")

        if self.cfg.resolve:
            wc = await self.wildcard.prime(self.domain)
            if wc:
                self.console.warn(
                    f"Wildcard DNS detectado em {self.domain} -> {', '.join(sorted(wc))}"
                )

        candidates: Set[str] = set(self._subs.keys())
        if self.cfg.brute:
            words = load_wordlist(self.cfg.wordlist)
            brute_cands = build_candidates(self.domain, words)
            self.console.info(f"Brute: {len(brute_cands)} candidatos da wordlist")
            candidates |= brute_cands

        if self.cfg.resolve:
            await self._resolve_and_filter(candidates, "resolve", depth=0)

        if self.cfg.permutations and self.cfg.resolve:
            base = {s.name for s in self._subs.values() if s.resolved}
            perm_words = load_permutation_words(self.cfg.perm_wordlist)
            perms = generate_permutations(base, self.domain, perm_words,
                                          self.cfg.perm_limit)
            perms -= set(self._subs.keys())
            self.console.info(f"Permutacoes: {len(perms)} candidatos gerados")
            await self._resolve_and_filter(perms, "permutation", depth=0)

        if self.cfg.recursive and self.cfg.resolve:
            await self._recurse()

        if self.cfg.probe:
            await self._probe()

        for sub in self._subs.values():
            self._flag_interesting(sub)

        self.meta = {
            "duration_sec": round(time.time() - start, 2),
            "passive": self.cfg.passive, "brute": self.cfg.brute,
            "permutations": self.cfg.permutations,
            "recursive": self.cfg.recursive, "probe": self.cfg.probe,
        }

        subs = list(self._subs.values())
        if self.cfg.only_resolved:
            subs = [s for s in subs if s.resolved]
        subs.sort(key=lambda s: s.name)
        self.console.good(
            f"Concluido em {self.meta['duration_sec']}s - "
            f"{sum(1 for s in subs if s.resolved)} resolvidos / {len(subs)} no total"
        )
        return subs

    async def _probe(self) -> None:
        targets = [s.name for s in self._subs.values() if s.resolved]
        if not targets:
            return
        self.console.info(f"Probe HTTP em {len(targets)} hosts vivos...")
        prober = HttpProber(self.settings)

        def _on(host, res):
            self.console.debug(f"{host} -> {res.status} {res.title or ''}")

        results = await prober.probe_many(targets, on_result=_on)
        for host, res in results.items():
            if host in self._subs:
                self._subs[host].probe = res
        self.console.good(f"Probe: {len(results)} responderam na web")

    async def _recurse(self) -> None:
        seen_parents: Set[str] = set()
        for depth in range(1, self.cfg.recursion_depth + 1):
            parents = [
                s.name for s in self._subs.values()
                if s.resolved and s.name not in seen_parents and s.name != self.domain
            ]
            if not parents:
                break
            self.console.info(f"Recursao nivel {depth}: {len(parents)} alvos")
            new_candidates: Set[str] = set()
            for parent in parents:
                seen_parents.add(parent)
                new_candidates |= await self._run_passive(parent, depth=depth)
                if self.cfg.brute:
                    new_candidates |= build_candidates(
                        parent, load_wordlist(self.cfg.wordlist))
            new_candidates -= {n for n in self._subs if self._subs[n].resolved}
            await self._resolve_and_filter(new_candidates, f"recurse-{depth}", depth)


# =========================================================================== #
#  CLI                                                                         #
# =========================================================================== #
def _parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="subhound",
        description="Enumeracao de subdominios robusta: passivo + brute + "
                    "permutacoes + resolucao com wildcard + probe HTTP + recursao.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "exemplos:\n"
            "  python3 main.py exemplo.com\n"
            "  python3 main.py exemplo.com -a -oj out.json\n"
            "  python3 main.py exemplo.com -b -w wordlist.txt -p --probe\n"
            "  python3 main.py -l dominios.txt -r --depth 2 -o subs.txt\n"
            "\nAVISO: use apenas em dominios que voce possui ou tem autorizacao "
            "por escrito pra testar.\n"
        ),
    )
    p.add_argument("domain", nargs="?", help="dominio alvo (ex.: exemplo.com)")
    p.add_argument("-l", "--list", metavar="FILE",
                   help="arquivo com varios dominios (um por linha)")

    g = p.add_argument_group("fases")
    g.add_argument("-a", "--all", action="store_true",
                   help="liga brute + permutacoes + recursao + probe")
    g.add_argument("--no-passive", action="store_true", help="pula a coleta passiva")
    g.add_argument("-b", "--brute", action="store_true", help="brute force DNS")
    g.add_argument("-p", "--permutations", action="store_true",
                   help="gera permutacoes dos hosts encontrados")
    g.add_argument("-r", "--recursive", action="store_true",
                   help="enumeracao recursiva nos subdominios achados")
    g.add_argument("--depth", type=int, default=1, metavar="N",
                   help="profundidade da recursao (padrao: 1)")
    g.add_argument("--probe", action="store_true",
                   help="probe HTTP/HTTPS nos hosts vivos")
    g.add_argument("--no-resolve", action="store_true",
                   help="nao resolve no DNS (so dump passivo)")

    w = p.add_argument_group("wordlists")
    w.add_argument("-w", "--wordlist", metavar="FILE",
                   help="wordlist pro brute (padrao: embutida)")
    w.add_argument("--perm-wordlist", metavar="FILE",
                   help="palavras pras permutacoes (padrao: embutida)")

    s = p.add_argument_group("fontes passivas")
    s.add_argument("--sources", metavar="LISTA",
                   help="usa so estas fontes (separadas por virgula)")
    s.add_argument("--exclude-sources", metavar="LISTA",
                   help="exclui estas fontes (separadas por virgula)")
    s.add_argument("--list-sources", action="store_true",
                   help="lista as fontes disponiveis e sai")

    perf = p.add_argument_group("performance")
    perf.add_argument("-t", "--dns-concurrency", type=int,
                      default=DEFAULT_DNS_CONCURRENCY, metavar="N",
                      help=f"resolucoes DNS simultaneas (padrao: {DEFAULT_DNS_CONCURRENCY})")
    perf.add_argument("--http-concurrency", type=int,
                      default=DEFAULT_HTTP_CONCURRENCY, metavar="N")
    perf.add_argument("--source-concurrency", type=int,
                      default=DEFAULT_SOURCE_CONCURRENCY, metavar="N")
    perf.add_argument("--dns-timeout", type=float, default=DEFAULT_DNS_TIMEOUT, metavar="S")
    perf.add_argument("--http-timeout", type=float, default=DEFAULT_HTTP_TIMEOUT, metavar="S")
    perf.add_argument("--source-timeout", type=float, default=DEFAULT_SOURCE_TIMEOUT, metavar="S")
    perf.add_argument("--retries", type=int, default=DEFAULT_DNS_RETRIES, metavar="N")
    perf.add_argument("--resolvers", metavar="X",
                      help="resolvers DNS (lista por virgula ou arquivo)")

    o = p.add_argument_group("saida")
    o.add_argument("-o", "--output", metavar="FILE", help="salva subdominios em txt")
    o.add_argument("-oj", "--json", metavar="FILE", help="salva resultado completo em json")
    o.add_argument("-oc", "--csv", metavar="FILE", help="salva em csv")
    o.add_argument("--jsonl", metavar="FILE", help="salva em json-lines")
    o.add_argument("--only-resolved", action="store_true",
                   help="so mostra/salva subdominios que resolveram")
    o.add_argument("--interesting-only", action="store_true",
                   help="so mostra/salva subdominios marcados como interessantes")
    o.add_argument("--probe-only", action="store_true",
                   help="so mostra/salva hosts que responderam no probe HTTP")

    p.add_argument("-v", "--verbose", action="store_true", help="saida detalhada")
    p.add_argument("-s", "--silent", action="store_true",
                   help="so imprime subdominios (sem banner/status)")
    p.add_argument("--no-color", action="store_true", help="desliga cores")
    p.add_argument("-V", "--version", action="version", version=f"subhound {__version__}")
    return p.parse_args(argv)


def _load_resolvers(value) -> List[str]:
    if not value:
        return list(DEFAULT_RESOLVERS)
    if os.path.isfile(value):
        with open(value, encoding="utf-8") as fh:
            return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    return [x.strip() for x in value.split(",") if x.strip()]


def _load_domains(args) -> List[str]:
    domains: List[str] = []
    if args.domain:
        domains.append(args.domain.strip())
    if args.list:
        with open(args.list, encoding="utf-8") as fh:
            domains.extend(ln.strip() for ln in fh if ln.strip() and not ln.startswith("#"))
    clean = []
    for d in domains:
        d = d.lower().strip().strip(".")
        d = d.replace("https://", "").replace("http://", "").split("/")[0]
        if d and d not in clean:
            clean.append(d)
    return clean


def _filter_output(subs, args):
    out = subs
    if args.only_resolved:
        out = [s for s in out if s.resolved]
    if args.interesting_only:
        out = [s for s in out if s.interesting]
    if args.probe_only:
        out = [s for s in out if s.probe is not None]
    return out


async def _run_one(domain, args, console):
    settings = Settings(
        resolvers=_load_resolvers(args.resolvers),
        dns_concurrency=args.dns_concurrency,
        http_concurrency=args.http_concurrency,
        source_concurrency=args.source_concurrency,
        dns_timeout=args.dns_timeout, http_timeout=args.http_timeout,
        source_timeout=args.source_timeout, dns_retries=args.retries,
        verbose=args.verbose,
    )
    cfg = EngineConfig(
        domain=domain, settings=settings,
        passive=not args.no_passive,
        brute=args.brute or args.all,
        permutations=args.permutations or args.all,
        recursive=args.recursive or args.all,
        probe=args.probe or args.all,
        resolve=not args.no_resolve,
        recursion_depth=args.depth,
        wordlist=args.wordlist, perm_wordlist=args.perm_wordlist,
        include_sources=args.sources.split(",") if args.sources else None,
        exclude_sources=args.exclude_sources.split(",") if args.exclude_sources else None,
        only_resolved=args.only_resolved,
    )
    engine = Engine(cfg, console=console)
    subs = await engine.run()
    return subs, engine.meta


def _emit(subs, domain, meta, args, console):
    for s in subs:
        console.result(s.name)
    if args.output:
        write_txt(args.output, subs, only_names=True)
        console.good(f"txt salvo em {args.output}")
    if args.json:
        write_json(args.json, domain, subs, meta)
        console.good(f"json salvo em {args.json}")
    if args.csv:
        write_csv(args.csv, subs)
        console.good(f"csv salvo em {args.csv}")
    if args.jsonl:
        write_jsonl(args.jsonl, subs)
        console.good(f"jsonl salvo em {args.jsonl}")


def main(argv=None) -> int:
    args = _parse_args(argv)

    if args.list_sources:
        print("Fontes disponiveis:")
        for name in all_source_names():
            print(f"  - {name}")
        return 0

    console = make_console(verbose=args.verbose, silent=args.silent,
                           no_color=args.no_color)
    if not args.silent:
        console.banner(BANNER.format(ver=__version__))

    domains = _load_domains(args)
    if not domains:
        console.error("informe um dominio ou use -l <arquivo>. Veja --help.")
        return 2

    try:
        for domain in domains:
            subs, meta_obj = asyncio.run(_run_one(domain, args, console))
            _emit(_filter_output(subs, args), domain, meta_obj, args, console)
    except KeyboardInterrupt:
        console.error("interrompido pelo usuario")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())