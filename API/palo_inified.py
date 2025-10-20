# palo_unified.py
# Palo Alto 로그 API를 호출하여 "records(list[dict])" 형태로 반환.
# pretty.py의 render_*_table()에 바로 넣어 공통 테이블로 출력할 수 있음.

import time
import requests
import xml.etree.ElementTree as ET
from typing import List, Dict, Any

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

def _api_get(base_url: str, params: Dict[str, Any], timeout: int = 30):
    r = requests.get(base_url, params=params, verify=False, timeout=timeout)
    r.raise_for_status()
    return r.text

def _extract_job_id(xml_text: str) -> str:
    try:
        root = ET.fromstring(xml_text)
        job = root.findtext(".//job")
        return job.strip() if job else ""
    except ET.ParseError:
        return ""

def generate_api_key(firewall_ip: str, account: str, password: str) -> str:
    base = f"https://{firewall_ip}/api/"
    params = {"type": "keygen", "user": account, "password": password}
    xml = _api_get(base, params)
    try:
        root = ET.fromstring(xml)
        key = root.findtext(".//key")
        if not key:
            raise RuntimeError(f"API keygen failed: {xml[:400]}")
        return key
    except ET.ParseError as e:
        raise RuntimeError(f"API keygen XML parse error: {e}")

# ─────────────────────────────────────────────────────────────
# Palo SYSTEM → records
# ─────────────────────────────────────────────────────────────
_SEV_MAP = {
    "CRITICAL": "critical",
    "MAJOR": "high",
    "INFO": "informational",
}

def palo_system_records(firewall_ip: str,
                        severity_ui: str,
                        account: str,
                        password: str,
                        nlogs: int = 100,
                        poll_interval: float = 1.0,
                        max_wait_sec: int = 20) -> List[Dict[str, Any]]:
    """
    시스템 로그를 list[dict]로 반환.
    dict 예: {"time": "...", "severity": "critical", "message": "..."}
    """
    key = generate_api_key(firewall_ip, account, password)
    base = f"https://{firewall_ip}/api/"

    sev = _SEV_MAP.get((severity_ui or "").upper(), "critical")
    query = f"(severity eq {sev})"

    start_params = {
        "type": "log",
        "log-type": "system",
        "key": key,
        "query": query,
        "nlogs": str(nlogs),
    }

    start_xml = _api_get(base, start_params)
    jobid = _extract_job_id(start_xml)
    if not jobid:
        raise RuntimeError(f"no job id\n{start_xml[:800]}")

    get_params = {"type": "log", "action": "get", "key": key, "jobid": jobid}

    deadline = time.time() + max_wait_sec
    last_xml = ""
    while time.time() < deadline:
        last_xml = _api_get(base, get_params)
        root = ET.fromstring(last_xml)
        status = (root.findtext(".//status") or "").upper()
        if status == "FIN":
            # 보통 .//log/logs/entry 경로
            entries = root.findall(".//log/logs/entry")
            if not entries:
                entries = root.findall(".//entry")
            out: List[Dict[str, Any]] = []
            for e in entries:
                time_s = e.findtext("time_generated") or e.findtext("receive_time") or ""
                sev_s  = e.findtext("severity") or ""
                msg    = e.findtext("opaque") or e.findtext("msg") or e.findtext("message") or ""
                out.append({"time": time_s, "severity": sev_s, "message": msg})
            return out
        if status == "FAIL":
            raise RuntimeError(f"job {jobid} failed\n{last_xml[:1200]}")
        time.sleep(poll_interval)

    raise RuntimeError(f"timeout waiting job {jobid}\n{last_xml[:1200]}")

# ─────────────────────────────────────────────────────────────
# Palo TRAFFIC → records
# ─────────────────────────────────────────────────────────────
def palo_traffic_records(firewall_ip: str,
                         src_ip: str,
                         dst_ip: str,
                         account: str,
                         password: str,
                         nlogs: int = 100,
                         poll_interval: float = 1.0,
                         max_wait_sec: int = 20) -> List[Dict[str, Any]]:
    """
    트래픽 로그를 list[dict]로 반환.
    dict 예: {"time":"...", "src":"...", "dst":"...", "dport":"...", "app":"...", "action":"...", "rule":"..."}
    """
    key = generate_api_key(firewall_ip, account, password)
    base = f"https://{firewall_ip}/api/"

    q_parts = []
    if src_ip:
        q_parts.append(f"(addr.src in {src_ip})")
    if dst_ip:
        q_parts.append(f"(addr.dst in {dst_ip})")
    query = " and ".join(q_parts) if q_parts else None

    start_params = {
        "type": "log",
        "log-type": "traffic",
        "key": key,
        "nlogs": str(nlogs),
        "dir": "backward",
    }
    if query:
        start_params["query"] = query

    start_xml = _api_get(base, start_params)
    jobid = _extract_job_id(start_xml)
    if not jobid:
        raise RuntimeError(f"no job id\n{start_xml[:800]}")

    get_params = {"type": "log", "action": "get", "key": key, "jobid": jobid}

    deadline = time.time() + max_wait_sec
    last_xml = ""
    while time.time() < deadline:
        last_xml = _api_get(base, get_params)
        root = ET.fromstring(last_xml)
        status = (root.findtext(".//status") or "").upper()
        if status == "FIN":
            entries = root.findall(".//log/logs/entry")
            if not entries:
                entries = root.findall(".//entry")
            out: List[Dict[str, Any]] = []
            for e in entries:
                t   = e.findtext("receive_time") or e.findtext("time_generated") or ""
                src = e.findtext("src") or ""
                dst = e.findtext("dst") or ""
                dpt = e.findtext("dport") or e.findtext("dstport") or ""
                app = e.findtext("app") or e.findtext("application") or ""
                act = e.findtext("action") or ""
                rule= e.findtext("rule") or ""
                out.append({
                    "time": t, "src": src, "dst": dst, "dport": dpt,
                    "app": app, "action": act, "rule": rule
                })
            return out
        if status == "FAIL":
            raise RuntimeError(f"job {jobid} failed\n{last_xml[:1200]}")
        time.sleep(poll_interval)

    raise RuntimeError(f"timeout waiting job {jobid}\n{last_xml[:1200]}")