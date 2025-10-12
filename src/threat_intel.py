import aiohttp
import asyncio
import json
import os
import sqlite3
from datetime import datetime, timedelta

CONFIG_PATH = "config/config.json"
CACHE_DB = "cache/threat_intel_cache.db"

def load_api_key() -> str:
    if not os.path.exists(CONFIG_PATH):
        raise FileNotFoundError(f"Missing config file: {CONFIG_PATH} file")
    with open(CONFIG_PATH, "r") as f:
        data = json.load(f)
    return data.get("ABUSEIPDB_API_KEY", "")

def init_cache_db() -> None:
    os.makedirs(os.path.dirname(CACHE_DB), exist_ok=True)
    conn = sqlite3.connect(CACHE_DB)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cache (
            ip TEXT PRIMARY KEY,
            abuse_score INTEGER,
            country TEXT,
            isp TEXT,
            domain TEXT,
            total_reports INTEGER,
            last_seen TEXT,
            last_checked TEXT
        )
    """)
    conn.commit()
    conn.close()

async def fetch_ip_info(ip: str) -> dict | None:
    init_cache_db()

    conn = sqlite3.connect(CACHE_DB)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cache WHERE ip = ?", (ip,))
    row = cursor.fetchone()
    conn.close()

    if row:
        last_checked = datetime.fromisoformat(row[7])
        if datetime.now() - last_checked > timedelta(days=7):
            score = row[1]
            return {
                "ip": row[0],
                "abuse_score": score,
                "country": row[2],
                "isp": row[3],
                "domain": row[4],
                "total_reports": row[5],
                "last_seen": row[6],
                "severity": severity_from_score(score),
                "from_cache": True
            }

    api_key = load_api_key()
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    headers = {
        "Accept": "application/json",
        "Key": api_key
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as response:
                text = await response.text()
                if response.status != 200:
                    print(f"[WARN] API {response.status} for {ip}: {text}")
                    return None
                data = await response.json()
                result = data.get("data", {})
                abuse_score = result.get("abuseConfidenceScore", 0)
                country = result.get("countryCode", "??")
                isp = result.get("isp", "")
                domain = result.get("domain", "")
                total_reports = result.get("totalReports", 0)
                last_seen = result.get("lastReportedAt", "")
                severity = severity_from_score(abuse_score)

                conn = sqlite3.connect(CACHE_DB)
                cursor = conn.cursor()
                cursor.execute("""
                           INSERT OR REPLACE INTO cache (
                               ip, abuse_score, country, isp, domain,
                               total_reports, last_seen, last_checked
                           )
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                       """, (ip, abuse_score, country, isp, domain, total_reports,
                             last_seen, datetime.utcnow().isoformat()))
                conn.commit()
                conn.close()

                return {
                    "ip": ip,
                    "abuse_score": abuse_score,
                    "country": country,
                    "isp": isp,
                    "domain": domain,
                    "total_reports": total_reports,
                    "last_seen": last_seen,
                    "severity": severity,
                    "from_cache": False
                }

    except Exception as e:
        print(f"[ERROR] API returned {e} for IP {ip}")
        return None

def severity_from_score(score: int) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


