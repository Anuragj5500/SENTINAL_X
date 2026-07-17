"""
Threat Intelligence enrichment — queries VirusTotal, AbuseIPDB, and OTX.
Falls back to simulation in demo mode.
"""
import httpx
from backend.config import settings


async def enrich_ip(ip: str) -> dict:
    results = {"ip": ip, "sources": {}}
    
    if settings.ABUSEIPDB_API_KEY:
        results["sources"]["abuseipdb"] = await _query_abuseipdb(ip)
    else:
        results["sources"]["abuseipdb"] = _demo_ip_result(ip)
    
    if settings.OTX_API_KEY:
        results["sources"]["otx"] = await _query_otx_ip(ip)
    
    if getattr(settings, 'SHODAN_API_KEY', None):
        results["sources"]["shodan"] = await _query_shodan(ip)
    else:
        results["sources"]["shodan"] = _demo_shodan_result(ip)
    
    results["is_malicious"] = _assess_malicious(results["sources"])
    results["risk_score"] = _calculate_risk_score(results["sources"])
    return results


async def enrich_hash(hash_value: str) -> dict:
    results = {"hash": hash_value, "sources": {}}
    
    if settings.VIRUSTOTAL_API_KEY:
        results["sources"]["virustotal"] = await _query_virustotal_hash(hash_value)
    else:
        results["sources"]["virustotal"] = _demo_hash_result(hash_value)
    
    results["is_malicious"] = results["sources"].get("virustotal", {}).get("malicious", False)
    return results


async def enrich_domain(domain: str) -> dict:
    results = {"domain": domain, "sources": {}}
    
    if settings.VIRUSTOTAL_API_KEY:
        results["sources"]["virustotal"] = await _query_virustotal_domain(domain)
    else:
        results["sources"]["virustotal"] = _demo_domain_result(domain)
    
    results["is_malicious"] = results["sources"].get("virustotal", {}).get("malicious", False)
    return results


async def enrich_url(url: str) -> dict:
    """Enrich a URL against URLHaus and VirusTotal."""
    results = {"url": url, "sources": {}}
    results["sources"]["urlhaus"] = await _query_urlhaus(url)
    results["is_malicious"] = _assess_malicious(results["sources"])
    return results


async def enrich_malware(hash_value: str) -> dict:
    """Enrich a file hash against MalwareBazaar and VirusTotal."""
    results = {"hash": hash_value, "sources": {}}
    results["sources"]["malwarebazaar"] = await _query_malwarebazaar(hash_value)
    if settings.VIRUSTOTAL_API_KEY:
        results["sources"]["virustotal"] = await _query_virustotal_hash(hash_value)
    else:
        results["sources"]["virustotal"] = _demo_hash_result(hash_value)
    results["is_malicious"] = _assess_malicious(results["sources"])
    return results


# ─────────────── Real API Clients ─────────────────────────────────────────────

async def _query_abuseipdb(ip: str) -> dict:
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                timeout=10
            )
            data = resp.json().get("data", {})
            return {
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode"),
                "isp": data.get("isp"),
                "is_public": data.get("isPublic", True),
                "malicious": data.get("abuseConfidenceScore", 0) > 50
            }
    except Exception as e:
        return {"error": str(e)}


async def _query_virustotal_hash(hash_value: str) -> dict:
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/files/{hash_value}",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
                timeout=15
            )
            if resp.status_code == 200:
                data = resp.json()["data"]["attributes"]
                stats = data.get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0) > 0,
                    "detections": stats.get("malicious", 0),
                    "total_engines": sum(stats.values()),
                    "file_type": data.get("type_description"),
                    "file_name": data.get("meaningful_name"),
                    "tags": data.get("tags", [])
                }
            return {"error": "Not found", "malicious": False}
    except Exception as e:
        return {"error": str(e)}


async def _query_virustotal_domain(domain: str) -> dict:
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
                timeout=15
            )
            if resp.status_code == 200:
                data = resp.json()["data"]["attributes"]
                stats = data.get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0) > 0,
                    "detections": stats.get("malicious", 0),
                    "reputation": data.get("reputation", 0),
                    "categories": data.get("categories", {}),
                }
            return {"error": "Not found", "malicious": False}
    except Exception as e:
        return {"error": str(e)}


async def _query_otx_ip(ip: str) -> dict:
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": settings.OTX_API_KEY},
                timeout=10
            )
            data = resp.json()
            return {
                "pulse_count": data.get("pulse_info", {}).get("count", 0),
                "reputation": data.get("reputation", 0),
                "malicious": data.get("pulse_info", {}).get("count", 0) > 0
            }
    except Exception as e:
        return {"error": str(e)}


async def _query_shodan(ip: str) -> dict:
    """Query Shodan for host information."""
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": settings.SHODAN_API_KEY},
                timeout=15
            )
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "ports": data.get("ports", []),
                    "hostnames": data.get("hostnames", []),
                    "org": data.get("org"),
                    "os": data.get("os"),
                    "vulns": data.get("vulns", []),
                    "country": data.get("country_code"),
                    "isp": data.get("isp"),
                    "malicious": len(data.get("vulns", [])) > 0,
                    "open_ports_count": len(data.get("ports", [])),
                }
            return {"error": "Not found", "malicious": False}
    except Exception as e:
        return {"error": str(e)}


async def _query_urlhaus(url: str) -> dict:
    """Query URLHaus for malicious URL data."""
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url},
                timeout=10
            )
            data = resp.json()
            if data.get("query_status") == "ok":
                return {
                    "malicious": True,
                    "threat": data.get("threat"),
                    "tags": data.get("tags", []),
                    "url_status": data.get("url_status"),
                    "date_added": data.get("date_added"),
                }
            return {"malicious": False, "status": "not_found"}
    except Exception as e:
        return {"error": str(e), "malicious": False}


async def _query_malwarebazaar(hash_value: str) -> dict:
    """Query MalwareBazaar for malware sample information."""
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": hash_value},
                timeout=10
            )
            data = resp.json()
            if data.get("query_status") == "ok" and data.get("data"):
                sample = data["data"][0]
                return {
                    "malicious": True,
                    "file_type": sample.get("file_type"),
                    "signature": sample.get("signature"),
                    "tags": sample.get("tags", []),
                    "delivery_method": sample.get("delivery_method"),
                }
            return {"malicious": False, "status": "not_found"}
    except Exception as e:
        return {"error": str(e), "malicious": False}


# ─────────────── Demo Mode Results ────────────────────────────────────────────

def _demo_shodan_result(ip: str) -> dict:
    """Simulated Shodan result for demo mode."""
    suspicious = ["185.220", "91.108", "45.33"]
    is_sus = any(ip.startswith(p) for p in suspicious)
    return {
        "ports": [22, 80, 443, 8080, 3389] if is_sus else [80, 443],
        "org": "Suspicious Hosting" if is_sus else "Amazon AWS",
        "vulns": ["CVE-2021-44228"] if is_sus else [],
        "country": "RU" if is_sus else "US",
        "malicious": is_sus,
        "open_ports_count": 5 if is_sus else 2,
        "demo_mode": True,
    }


def _demo_ip_result(ip: str) -> dict:
    # Simulate some malicious IPs for demo
    suspicious = ["185.220", "91.108", "45.33", "103.75", "198.54"]
    is_sus = any(ip.startswith(p) for p in suspicious)
    return {
        "abuse_score": 87 if is_sus else 0,
        "total_reports": 142 if is_sus else 0,
        "country": "RU" if is_sus else "US",
        "isp": "Tor Exit Node" if is_sus else "Amazon AWS",
        "is_public": True,
        "malicious": is_sus,
        "demo_mode": True
    }


def _demo_hash_result(hash_value: str) -> dict:
    malicious_hashes = ["44d88612", "3395856c", "275a021b"]
    is_malicious = any(hash_value.startswith(h) for h in malicious_hashes)
    return {
        "malicious": is_malicious,
        "detections": 52 if is_malicious else 0,
        "total_engines": 72,
        "file_type": "PE32 executable" if is_malicious else "Unknown",
        "tags": ["trojan", "ransomware"] if is_malicious else [],
        "demo_mode": True
    }


def _demo_domain_result(domain: str) -> dict:
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf"]
    is_malicious = any(domain.endswith(t) for t in suspicious_tlds)
    return {
        "malicious": is_malicious,
        "detections": 30 if is_malicious else 0,
        "reputation": -50 if is_malicious else 5,
        "categories": {"malware": "malware-site"} if is_malicious else {"technology": "content-server"},
        "demo_mode": True
    }


def _assess_malicious(sources: dict) -> bool:
    for src_data in sources.values():
        if isinstance(src_data, dict) and src_data.get("malicious"):
            return True
    return False


def _calculate_risk_score(sources: dict) -> float:
    score = 0.0
    if "abuseipdb" in sources:
        score = max(score, sources["abuseipdb"].get("abuse_score", 0))
    if "virustotal" in sources:
        det = sources["virustotal"].get("detections", 0)
        total = sources["virustotal"].get("total_engines", 72)
        if total > 0:
            score = max(score, (det / total) * 100)
    return round(score, 1)
