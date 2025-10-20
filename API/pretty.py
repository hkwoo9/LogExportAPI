
import json, re, html
from typing import Any, Dict, List, Sequence


_HEADER_TOKENS = {
    "time","time_generated","receive_time","event_time",
    "severity","level","message","msg","opaque","description","detail",
    "src","dst","dport","app","action","rule","source","destination",
}

def _is_headerish(s: str) -> bool:
    if not s:
        return False
    t = s.strip().lower()
    # 구분선/배너
    if re.fullmatch(r"[-=_*#\s]{3,}", t):
        return True
    if re.match(r"\s*(columns?|headers?)\s*[:=]", t):
        return True
    # 토큰 기반 판정 (숫자가 거의 없고, 헤더 토큰 비율이 높으면 헤더로 간주)
    toks = [x for x in re.split(r"[^a-z0-9_]+", t) if x]
    if not toks:
        return False
    if any(ch.isdigit() for ch in t):
        return False
    hit = sum(1 for x in toks if x in _HEADER_TOKENS)
    return (hit >= 2) and (hit/len(toks) >= 0.6)

# 한국어/영문 심각도 별칭 정규화
_SEV_ALIAS = {
    "critical": "critical", "crit": "critical", "fatal": "critical", "치명": "critical",
    "high": "high", "major": "high", "중요": "high",
    "medium": "medium",
    "low": "low", "minor": "low",
    "warning": "warning", "warn": "warning", "경고": "warning",
    "info": "informational", "informational": "informational", "information": "informational", "정보": "informational",
}

# 자주 보이는 시간 포맷들
_TIME_PATTERNS = [
    r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?",   # 2025-10-20 12:34:56(.123)
    r"\d{4}/\d{2}/\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?",   # 2025/10/20 12:34:56(.123)
    r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",        # Oct 20 12:34:56
    r"\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}",              # 20/10/2025 12:34:56
]

# 대괄호/괄호/공백 구분 등 다양한 패턴에서 심각도 뽑기
_SEV_PATTERNS = [
    r"\[(critical|major|minor|warning|warn|info|informational|high|medium|low|치명|중요|경고|정보)\]",
    r"\b(critical|major|minor|warning|warn|info|informational|high|medium|low|치명|중요|경고|정보)\b",
    r"\((critical|major|minor|warning|warn|info|informational|high|medium|low|치명|중요|경고|정보)\)",
]

def _norm_severity(tok: str) -> str:
    t = (tok or "").strip().lower()
    return _SEV_ALIAS.get(t, t)

def _extract_time_sev_from_string(s: str):
    """문자열 한 줄에서 time, severity, message 추출(휴리스틱)."""
    time_s = ""
    sev_s = ""
    # 시간
    for pat in _TIME_PATTERNS:
        m = re.search(pat, s)
        if m:
            time_s = m.group(0)
            break
    # 심각도
    for pat in _SEV_PATTERNS:
        m = re.search(pat, s, re.IGNORECASE)
        if m:
            sev_s = _norm_severity(m.group(1))
            break
    # 메시지는 전체에서 시간/심각도 토큰을 살짝 제거
    msg = s
    if time_s:
        msg = msg.replace(time_s, "").strip()
    if sev_s:
        # 대소문자 무시 치환
        msg = re.sub(re.escape(sev_s), "", msg, flags=re.IGNORECASE).strip()
    return {"time": time_s, "severity": sev_s, "message": msg}

def _to_records(data: Any) -> List[Dict[str, Any]]:
    # ── list ──
    if isinstance(data, list):
        # list[dict]면 그대로
        if data and all(isinstance(x, dict) for x in data):
            return data
        recs: List[Dict[str, Any]] = []
        for x in data:
            if isinstance(x, dict):
                recs.append(x)
            elif isinstance(x, (list, tuple)):
                # [time, severity, ...message] 유형 가정
                t = str(x[0]) if len(x) > 0 else ""
                sev_raw = str(x[1]) if len(x) > 1 else ""
                sev = _norm_severity(sev_raw)
                msg = " ".join(str(v) for v in x[2:]) if len(x) > 2 else ""
                # 시간/심각도 포맷이 아니면 문자열 휴리스틱으로 한 번 더 보정
                if not t or not re.search("|".join(_TIME_PATTERNS), t) or not sev:
                    recs.append(_extract_time_sev_from_string(" ".join(str(v) for v in x)))
                else:
                    recs.append({"time": t, "severity": sev, "message": msg})
            else:
                # 문자열 한 줄 → 휴리스틱 파싱
                recs.append(_extract_time_sev_from_string(str(x)))
        return recs

    # ── dict ──
    if isinstance(data, dict):
        return [data]

    # ── str ──
    if isinstance(data, str):
        s = data.strip()
        # 1) JSON 시도
        try:
            obj = json.loads(s)
            return _to_records(obj)
        except Exception:
            pass
        # 2) 키:값 텍스트 블록 파싱
        recs: List[Dict[str, Any]] = []
        blocks = re.split(r"\n{2,}", s)
        for block in blocks:
            d: Dict[str, Any] = {}
            for line in block.splitlines():
                m = re.match(r"\s*([\w\-\.\[\]/]+)\s*[:=]\s*(.*)\s*$", line)
                if m:
                    d[m.group(1).lower()] = m.group(2).strip()
            if d:
                # 키:값이면 그대로 dict 기반
                recs.append({
                    "time": d.get("time") or d.get("time_generated") or d.get("receive_time") or "",
                    "severity": _norm_severity(d.get("severity") or d.get("level") or ""),
                    "message": d.get("message") or d.get("msg") or d.get("opaque") or block.strip(),
                })
            else:
                # 순수 텍스트면 휴리스틱
                recs.append(_extract_time_sev_from_string(block.strip()))
        return recs

    # ── 기타 ──
    return []

def _pick(r: dict, keys):
    """우선순위 키 목록 중 첫 값 반환."""
    for k in keys:
        v = r.get(k)
        if v not in (None, ""):
            return v
    return ""

def render_html_table(records, columns, headers):
    """records(list[dict])를 지정 columns(키 후보들)로 테이블 렌더."""
    rows = []
    for rec in records:
        row = [str(_pick(rec, ks)) for ks in columns]
        # 완전히 빈 행은 제외
        if any(cell for cell in row):
            rows.append(row)
    if not rows:
        return "[ok] 표시할 로그가 없습니다."
    out = [
        '<table border="1" cellpadding="4" cellspacing="0">',
        "<thead><tr>" + "".join(f"<th>{html.escape(h)}</th>" for h in headers) + "</tr></thead>",
        "<tbody>",
    ]
    for row in rows:
        out.append("<tr>" + "".join(f"<td>{html.escape(c)}</td>" for c in row) + "</tr>")
    out.append("</tbody></table>")
    return "\n".join(out)

# ── 트래픽/시스템용 표준 컬럼 매핑 ──────────────────────────────
TRAFFIC_COLS = [
    ("time",      ["receive_time","etime","time_generated","time","event_time"]),
    ("src",       ["src","src_ip","source","source_ip"]),
    ("dst",       ["dst","dst_ip","destination","destination_ip"]),
    ("dport",     ["dport","dstport","destination-port","dst_port"]),
    ("app",       ["app","application","app_id"]),
    ("protocol",  ["protocol","application","app_id"]),
    ("action",    ["action","action_name"]),
    ("rule",      ["rule","rule_name"]),
]
TRAFFIC_HEADERS = [c for c,_ in TRAFFIC_COLS]
TRAFFIC_KEYS     = [ks for _,ks in TRAFFIC_COLS]

SYSTEM_COLS = [
    ("time",     ["time_generated","receive_time","time","event_time"]),
    ("severity", ["severity","level"]),
    ("message",  ["opaque","msg","message","description","detail"]),
]
SYSTEM_HEADERS = [c for c,_ in SYSTEM_COLS]
SYSTEM_KEYS     = [ks for _,ks in SYSTEM_COLS]

def render_traffic_table(data):
    """벤더 무관 트래픽 결과 → 공통 표 HTML."""
    recs = _to_records(data)
    return render_html_table(recs, TRAFFIC_KEYS, TRAFFIC_HEADERS)


def render_system_table(data: Any) -> str:
    recs = _to_records(data)

    # ✅ time/severity 비어 있고 message가 헤더/배너처럼 보이면 버림
    cleaned = []
    for r in recs:
        # _pick은 네 파일에 이미 있어요
        t   = _pick(r, ["time_generated","receive_time","time","event_time"])
        sev = _pick(r, ["severity","level"])
        msg = _pick(r, ["opaque","msg","message","description","detail"])
        if (not t) and (not sev) and _is_headerish(msg):
            continue
        cleaned.append(r)

    return render_html_table(cleaned, SYSTEM_KEYS, SYSTEM_HEADERS)    