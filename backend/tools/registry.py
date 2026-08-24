"""
tools/registry.py — Central tool registry.

Add a new tool: import it, add one line to REGISTRY.
The scan engine reads this file — nothing else needs changing.
"""
from __future__ import annotations
from tools.base import BaseTool

# ── Imports ──────────────────────────────────────────────────────
from tools.subdomain.crtsh       import CrtShTool
from tools.subdomain.assetfinder import AssetfinderTool
from tools.subdomain.subfinder   import SubfinderTool
from tools.subdomain.amass       import AmassTool
from tools.subdomain.shuffledns  import ShuffledNSTool
from tools.dns.dnsx              import DnsxTool
from tools.dns.dns_records       import DnsRecordsTool
from tools.dns.zone_transfer     import ZoneTransferTool
from tools.http.httpx_tool       import HttpxTool
from tools.http.naabu            import NaabuTool
from tools.http.tlsx_tool        import TlsxTool
from tools.vuln.nuclei           import NucleiTool
from tools.vuln.cve_check        import CveCheckTool
from tools.vuln.subdomain_takeover import SubdomainTakeoverTool
from tools.vuln.wpscan           import WpscanTool
from tools.screenshots.gowitness import GowitnessTool
from tools.screenshots.whatweb   import WhatWebTool
from tools.urls.waybackurls      import WaybackUrlsTool
from tools.urls.gau              import GauTool
from tools.urls.katana           import KatanaTool
from tools.urls.urlfinder        import UrlFinderTool
from tools.asset.whois_tool      import WhoisTool
from tools.asset.asnmap_tool     import AsnmapTool
from tools.asset.shodan_tool     import ShodanTool
from tools.asset.email_finder    import EmailFinderTool
from tools.analysis.google_dorks  import GoogleDorksTool
from tools.analysis.ai_analysis   import AIAnalysisTool


# ── Registry ─────────────────────────────────────────────────────
# key → class (not instance — instantiated per scan with output/data dirs)
REGISTRY: dict[str, type[BaseTool]] = {
    # Subdomain enumeration (all in parallel group "subdomain")
    "crtsh":        CrtShTool,
    "assetfinder":  AssetfinderTool,
    "subfinder":    SubfinderTool,
    "amass":        AmassTool,
    "shuffledns":   ShuffledNSTool,
    # DNS
    "dnsx":         DnsxTool,
    "dns_records":  DnsRecordsTool,
    "zone_transfer": ZoneTransferTool,
    # HTTP / Ports
    "httpx":        HttpxTool,
    "naabu":        NaabuTool,
    "tlsx":         TlsxTool,
    # Vulnerability scanning
    "nuclei":       NucleiTool,
    "cve_check":    CveCheckTool,
    "subdomain_takeover": SubdomainTakeoverTool,
    "wpscan":       WpscanTool,
    # Screenshots & Tech
    "gowitness":    GowitnessTool,
    "whatweb":      WhatWebTool,
    # URL discovery (all in parallel group "urls")
    "waybackurls":  WaybackUrlsTool,
    "gau":          GauTool,
    "katana":       KatanaTool,
    "urlfinder":    UrlFinderTool,
    # Asset discovery (parallel group "asset")
    "whois":        WhoisTool,
    "asnmap":       AsnmapTool,
    "shodan":       ShodanTool,
    "email_finder": EmailFinderTool,
    "google_dorks": GoogleDorksTool,
    "ai_analysis":  AIAnalysisTool,
}


def get_tool(name: str, output_dir, data_dir) -> BaseTool | None:
    cls = REGISTRY.get(name)
    if cls is None:
        return None
    return cls(output_dir=output_dir, data_dir=data_dir)


def list_tools() -> list[dict]:
    """Return tool metadata for the API /tools endpoint."""
    result = []
    for name, cls in REGISTRY.items():
        binary_name = getattr(cls, "binary_name", "")
        if binary_name is None:
            binary_name = "internal"
        elif binary_name == "":
            binary_name = name

        result.append({
            "name": name,
            "category": cls.category.value,
            "description": cls.description,
            "parallel_group": cls.parallel_group,
            "requires_root": cls.requires_root,
            "binary_name": binary_name,
        })
    return result
