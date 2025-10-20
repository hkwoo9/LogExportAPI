import time
from html import escape
import requests
import xml.etree.ElementTree as ET

def generate_api_key(firewall_ip, account, password):
    base_url = f"https://{firewall_ip}/api/"
    params = {"type": "keygen", "user": account, "password": password}
    try:
        r = requests.get(base_url, params=params, verify=False, timeout=30)
        r.raise_for_status()
        root = ET.fromstring(r.text)
        api_key = root.findtext(".//key")
        if not api_key:
            raise RuntimeError(f"API 키 생성 실패: {r.text[:500]}")
        return api_key
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"API 키 생성 중 오류 발생: {e}")

def paloalto_fetch_system(firewall_ip, severity, account, password,
                          nlogs=100, poll_interval=1.0, max_wait_sec=20):
    """
    Palo Alto 시스템 로그를 Job ID 기반으로 추출.
    - severity: UI 값(CRITICAL/MAJOR/INFO)을 PA 필드 값으로 매핑하여 쿼리 구성
    - 결과: HTML 문자열 (테이블) 반환 → index.html의 {{ result|safe }}로 바로 표시 가능
    """
    # 1) 키 생성
    api_key = generate_api_key(firewall_ip, account, password)
    base_url = f"https://{firewall_ip}/api/"

    # 2) severity 매핑
    sev_map = {
        "CRITICAL": "critical",
        "MAJOR": "high",
        "INFO": "informational",
    }
    sev = sev_map.get((severity or "").upper(), "critical")
    query = f"(severity eq {sev})"

    # 3) job 생성 요청
    start_params = {
        "type": "log",
        "log-type": "system",
        "key": api_key,
        "query": query,
        "nlogs": str(nlogs),
        # 필요 시 정렬/방향: "dir": "backward"
    }
    try:
        r = requests.get(base_url, params=start_params, verify=False, timeout=30)
        r.raise_for_status()
        start_xml = r.text
        root = ET.fromstring(start_xml)
        job_id = root.findtext(".//job")
        if not job_id:
            # 응답 본문을 같이 반환해 원인 파악 빠르게
            return "[error] Job ID를 찾을 수 없습니다.<br><pre>" + escape(start_xml[:2000]) + "</pre>"

        # 4) 폴링 (FIN/FAIL까지)
        get_params = {
            "type": "log",
            "action": "get",
            "key": api_key,
            "jobid": str(job_id),
        }

        deadline = time.time() + max_wait_sec
        last_body = ""
        while time.time() < deadline:
            rr = requests.get(base_url, params=get_params, verify=False, timeout=30)
            rr.raise_for_status()
            last_body = rr.text
            rroot = ET.fromstring(last_body)
            status = (rroot.findtext(".//status") or "").upper()

            if status == "FIN":
                # 5) 로그 파싱
                entries = rroot.findall(".//log/logs/entry")
                if not entries:
                    entries = rroot.findall(".//entry")

                rows = []
                for e in entries:
                    t = e.findtext("time_generated") or e.findtext("receive_time") or ""
                    s = e.findtext("severity") or ""
                    msg = e.findtext("opaque") or e.findtext("msg") or e.findtext("msgid") or ""
                    rows.append((t, s, msg))

                if not rows:
                    return "[ok] 작업은 완료(FIN)했지만 로그 항목이 없습니다."

                # 6) HTML 테이블로 반환
                out = [
                    '<table border="1" cellpadding="4" cellspacing="0">',
                    "<thead><tr><th>time</th><th>severity</th><th>message</th></tr></thead><tbody>",
                ]
                for t, s, m in rows:
                    out.append(
                        f"<tr><td>{escape(str(t))}</td>"
                        f"<td>{escape(str(s))}</td>"
                        f"<td>{escape(str(m))}</td></tr>"
                    )
                out.append("</tbody></table>")
                return "\n".join(out)

            if status == "FAIL":
                return f"[error] Job {job_id} 실패.<br><pre>{escape(last_body[:2000])}</pre>"

            # PEND/ACT 등 → 잠깐 대기 후 재시도
            time.sleep(poll_interval)

        # 타임아웃
        return f"[error] Job {job_id} 대기 타임아웃.<br><pre>{escape(last_body[:2000])}</pre>"

    except requests.exceptions.RequestException as e:
        return f"[error] 시스템 로그 추출 실패: {escape(str(e))}"
    except ET.ParseError as e:
        return f"[error] XML 파싱 오류: {escape(str(e))}"