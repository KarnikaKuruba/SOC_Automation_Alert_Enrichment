"""Threat Intel API utilities (template)

This module provides:
- A template for integrating with VirusTotal and AbuseIPDB via environment variables.
- Safe fallback to simulated lookups if API keys are not provided.

USAGE:
- Set environment variables: VIRUSTOTAL_API_KEY and ABUSEIPDB_API_KEY (optional).
- Replace usage of 'simulate_lookup_*' with 'lookup_ip' / 'lookup_domain' for live lookups.
- Be mindful of API rate limits and terms of service for each provider.

NOTE: This file contains example request structures. Actual API responses may differ.
"""

import os
import random

# Try to load API keys from environment variables
VIRUSTOTAL_KEY = os.getenv('VIRUSTOTAL_API_KEY')
ABUSEIPDB_KEY = os.getenv('ABUSEIPDB_API_KEY')

def simulate_lookup_ip(ip):
    """Fallback simulation for environments without API keys."""
    score = random.randint(0, 85)
    tags = []
    if score > 70:
        tags.append('malicious')
    elif score > 40:
        tags.append('suspicious')
    else:
        tags.append('benign')
    cats = []
    if score > 60:
        cats.append('botnet')
    return {'ip': ip, 'score': score, 'tags': tags, 'categories': cats}

def simulate_lookup_domain(domain):
    score = random.randint(0, 90)
    tags = []
    if score > 65:
        tags.append('malicious')
    elif score > 35:
        tags.append('suspicious')
    else:
        tags.append('benign')
    return {'domain': domain, 'score': score, 'tags': tags}

# --- Template wrappers for real APIs (VirusTotal & AbuseIPDB) ---
def lookup_ip_with_virustotal(ip):
    """Template: How to call VirusTotal IP API (example). Requires VIRUSTOTAL_KEY.

    Example (comments):
        import requests
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VIRUSTOTAL_KEY}
        resp = requests.get(url, headers=headers)
        data = resp.json()
        # parse data to extract malicious count / categories / tags
    """
    if not VIRUSTOTAL_KEY:
        return None
    # Placeholder return structure - replace with parsed response
    return {'ip': ip, 'score': 75, 'tags': ['vt-malicious'], 'categories': ['botnet']}

def lookup_ip_with_abuseipdb(ip):
    """Template: How to call AbuseIPDB IP check (example). Requires ABUSEIPDB_KEY.

    Example (comments):
        import requests
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        resp = requests.get(url, headers=headers, params=params)
        data = resp.json()
        # parse data to extract abuseConfidenceScore etc.
    """
    if not ABUSEIPDB_KEY:
        return None
    # Placeholder return structure - replace with parsed response
    return {'ip': ip, 'score': 70, 'tags': ['abuseipdb-high'], 'categories': []}

def lookup_domain_with_virustotal(domain):
    """Template: VirusTotal domain lookup."""
    if not VIRUSTOTAL_KEY:
        return None
    return {'domain': domain, 'score': 65, 'tags': ['vt-suspicious']}

def lookup_ip(ip):
    """Unified IP lookup that prefers real APIs when keys are available, else simulate."""
    # Try VirusTotal
    vt = lookup_ip_with_virustotal(ip)
    if vt:
        return vt
    # Try AbuseIPDB
    a = lookup_ip_with_abuseipdb(ip)
    if a:
        return a
    # Fallback
    return simulate_lookup_ip(ip)

def lookup_domain(domain):
    """Unified domain lookup preferring real API results if available."""
    vt = lookup_domain_with_virustotal(domain)
    if vt:
        return vt
    return simulate_lookup_domain(domain)

def simulate_enrich(alert):
    """Same simulate_enrich interface for compatibility with main.py."""
    src_ip = alert.get('src_ip')
    dst_ip = alert.get('dst_ip')
    domain = alert.get('domain')
    enriched = dict(alert)
    enriched['threat_score'] = 0
    enriched['tags'] = []
    if src_ip:
        ip_info = lookup_ip(src_ip)
        enriched['threat_score'] += ip_info.get('score', 0)//2
        enriched['tags'].extend(ip_info.get('tags', []))
    if dst_ip:
        ip_info = lookup_ip(dst_ip)
        enriched['threat_score'] += ip_info.get('score', 0)//2
        enriched['tags'].extend(ip_info.get('tags', []))
    if domain:
        d_info = lookup_domain(domain)
        enriched['threat_score'] += d_info.get('score', 0)//3
        enriched['tags'].extend(d_info.get('tags', []))
    enriched['threat_score'] = min(enriched['threat_score'], 100)
    enriched['tags'] = sorted(set(enriched['tags']))
    enriched['enriched_by'] = 'template_intel_v1' if (VIRUSTOTAL_KEY or ABUSEIPDB_KEY) else 'simulated_intel_v1'
    return enriched
