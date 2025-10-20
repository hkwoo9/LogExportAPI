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

def paloalto_fetch_traffic(firewall_ip, src_ip, dst_ip, account, password,
                           nlogs=100, poll_interval=1.0, max_wait_sec=20):
    """
    Palo Alto 트래픽 로그를 Job 기반으로 조회해 HTML 테이블 문자열로 반환.
    """
    # 1) 키 생성
    api_key = generate_api_key(firewall_ip, account, password)
    base_url = f"https://{firewall_ip}/api/"

    # 2) 쿼리 조립 (빈 값은 제외)
    q_parts = []
    if src_ip: q_parts.append(f"(addr.src in {src_ip})")
    if dst_ip: q_parts.append(f"(addr.dst in {dst_ip})")
    query = " and ".join(q_parts) if q_parts else None

    start_params = {
        "type": "log",
        "log-type": "traffic",
        "key": api_key,
        "nlogs": str(nlogs),
        "dir": "backward",  # 최신부터
    }
    if query:
        start_params["query"] = query

    try:
        # 3) Job 생성
        r = requests.get(base_url, params=start_params, verify=False, timeout=30)
        r.raise_for_status()
        start_xml = r.text
        root = ET.fromstring(start_xml)
        job_id = root.findtext(".//job")
        if not job_id:
            return "[error] Job ID를 찾을 수 없습니다.<br><pre>" + escape(start_xml[:2000]) + "</pre>"

        # 4) 폴링 (FIN/FAIL까지)
        get_params = {
            "type": "log",
            "action": "get",
            "key": api_key,
            # ⚠️ 정식 파라미터명
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

                if not entries:
                    return "[ok] 작업은 완료(FIN)했지만 로그 항목이 없습니다."

                # 출력 컬럼: 시간, src, dst, dport, app, action, rule
                out = [
                    '<table border="1" cellpadding="4" cellspacing="0">',
                    "<thead><tr>"
                    "<th>time</th><th>src</th><th>dst</th><th>dport</th>"
                    "<th>app</th><th>protocol</th><th>action</th><th>rule</th>"
                    "</tr></thead><tbody>",
                ]
                for e in entries:
                    t   = e.findtext("receive_time") or e.findtext("time_generated") or ""
                    src = e.findtext("src") or ""
                    dst = e.findtext("dst") or ""
                    dpt = e.findtext("dport") or e.findtext("dstport") or ""
                    app = e.findtext("app") or e.findtext("application") or ""
                    protocol = e.findtext("proto") or e.findtext("protocol") or e.findtext("IP Protocol") or ""
                    act = e.findtext("action") or ""
                    rule= e.findtext("rule") or ""
                    out.append(
                        f"<tr><td>{escape(t)}</td><td>{escape(src)}</td><td>{escape(dst)}</td>" 
                        f"<td>{escape(str(dpt))}</td><td>{escape(app)}</td>"
                        f"<td>{escape(act)}</td><td>{escape(rule)}</td></tr>"
                    )
                out.append("</tbody></table>")
                return "\n".join(out)

            if status == "FAIL":
                return f"[error] Job {job_id} 실패.<br><pre>{escape(last_body[:2000])}</pre>"

            time.sleep(poll_interval)

        # 타임아웃
        return f"[error] Job {job_id} 대기 타임아웃.<br><pre>{escape(last_body[:2000])}</pre>"

    except requests.exceptions.RequestException as e:
        return f"[error] 트래픽 로그 추출 실패: {escape(str(e))}"
    except ET.ParseError as e:
        return f"[error] XML 파싱 오류: {escape(str(e))}"