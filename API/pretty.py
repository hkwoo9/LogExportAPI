# pretty.py
# 벤더별 원본 데이터를 공통 스키마(list[dict])로 정규화하고,
# 지정 컬럼 순서대로 HTML 테이블을 생성하는 유틸.

from typing import Any, Dict, List, Sequence
import json
import html
import re

# ─────────────────────────────────────────────────────────────
# 헤더/배너 라인 감지 (시스템 로그에서 종종 처음에 뜨는 컬럼 라인 제거용)
# ─────────────────────────────────────────────────────────────
_HEADER_TOKENS = {
    "time", "time_generated", "receive_time", "event_time",
    "severity", "level", "message", "msg", "opaque", "description", "detail",
    "src", "dst", "dport", "app", "action", "rule", "source", "destination",
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
    return (hit >= 2) and (hit / len(toks) >= 0.6)

# ─────────────────────────────────────────────────────────────
# 시간/심각도 휴리스틱
# ─────────────────────────────────────────────────────────────
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
_SEV_PATTERNS = [
    r"\[(critical|major|minor|warning|warn|info|informational|high|medium|low|치명|중요|경고|정보)\]",
    r"\b(critical|major|minor|warning|warn|info|informational|high|medium|low|치명|중요|경고|정보)\b",
    r"\((critical|major|minor|warning|warn|info|informational|high|medium|low|치명|중요|경고|정보)\)",
]

def _norm_severity(tok: str) -> str:
    t = (tok or "").strip().lower()
    return _SEV_ALIAS.get(t, t)

def _extract_time_sev_from_string(s: str) -> Dict[str, str]:
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
        msg = re.sub(re.escape(sev_s), "", msg, flags=re.IGNORECASE).strip()
    return {"time": time_s, "severity": sev_s, "message": msg}

# ─────────────────────────────────────────────────────────────
# Any → list[dict] 구조 정규화
# ─────────────────────────────────────────────────────────────
def _to_records(data: Any) -> List[Dict[str, Any]]:
    # list
    if isinstance(data, list):
        if data and all(isinstance(x, dict) for x in data):
            return data
        recs: List[Dict[str, Any]] = []
        for x in data:
            if isinstance(x, dict):
                recs.append(x)
            elif isinstance(x, (list, tuple)):
                # [time, severity, ...message] 가정
                t = str(x[0]) if len(x) > 0 else ""
                sev_raw = str(x[1]) if len(x) > 1 else ""
                sev = _norm_severity(sev_raw)
                msg = " ".join(str(v) for v in x[2:]) if len(x) > 2 else ""
                if not t or not re.search("|".join(_TIME_PATTERNS), t) or not sev:
                    recs.append(_extract_time_sev_from_string(" ".join(str(v) for v in x)))
                else:
                    recs.append({"time": t, "severity": sev, "message": msg})
            else:
                recs.append(_extract_time_sev_from_string(str(x)))
        return recs

    # dict
    if isinstance(data, dict):
        return [data]

    # str
    if isinstance(data, str):
        s = data.strip()
        # JSON 시도
        try:
            obj = json.loads(s)
            return _to_records(obj)
        except Exception:
            pass
        # 키:값 텍스트 블록 파싱
        recs: List[Dict[str, Any]] = []
        blocks = re.split(r"\n{2,}", s)
        for block in blocks:
            d: Dict[str, Any] = {}
            for line in block.splitlines():
                m = re.match(r"\s*([\w\-\.\[\]/]+)\s*[:=]\s*(.*)\s*$", line)
                if m:
                    d[m.group(1).lower()] = m.group(2).strip()
            if d:
                recs.append({
                    "time": d.get("time") or d.get("time_generated") or d.get("receive_time") or "",
                    "severity": _norm_severity(d.get("severity") or d.get("level") or ""),
                    "message": d.get("message") or d.get("msg") or d.get("opaque") or block.strip(),
                })
            else:
                recs.append(_extract_time_sev_from_string(block.strip()))
        return recs

    # 기타
    return []

# ─────────────────────────────────────────────────────────────
# 공통 렌더
# ─────────────────────────────────────────────────────────────
def _pick(r: Dict[str, Any], keys: Sequence[str]) -> str:
    """우선순위 키 목록 중 첫 값 반환."""
    for k in keys:
        v = r.get(k)
        if v not in (None, ""):
            return str(v)
    return ""

def render_html_table(records: List[Dict[str, Any]],
                      columns: Sequence[Sequence[str]],
                      headers: Sequence[str]) -> str:
    """records(list[dict])를 지정 columns(키 후보들)로 테이블 렌더."""
    rows: List[List[str]] = []
    for rec in records:
        row = [_pick(rec, ks) for ks in columns]
        if any(cell for cell in row):  # 완전히 빈 행은 제외
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

# ─────────────────────────────────────────────────────────────
# 컬럼 매핑 (트래픽/시스템)
# ─────────────────────────────────────────────────────────────
TRAFFIC_COLS = [
    # time
    ("time", [
        "receive_time", "etime", "time_generated", "time", "event_time",
        "eventtime", "@timestamp", "log_time", "logtime"
    ]),
    # src
    ("src", [
        "src", "src_ip", "source", "source_ip",
        "srcip", "sip", "saddr", "sourceaddress"
    ]),
    # dst
    ("dst", [
        "dst", "dst_ip", "destination", "destination_ip",
        "dstip", "dip", "daddr", "destinationaddress"
    ]),
    # dport
    ("dport", [
        "dport", "dstport", "destination-port", "dst_port",
        "dpt", "destport", "destinationport", "service_port",
        "service-port"
    ]),
    # app (애플리케이션 명)
    ("app", [
        "app", "application", "application-name", "appname", "app_id"
    ]),
    # protocol (L3/L4 프로토콜)
    ("protocol", [
        "protocol", "proto", "ip-proto", "ip_proto", "transport", "l4proto"
    ]),
    # action
    ("action", [
        "action", "action_name", "act", "action-desc", "log_action"
    ]),
    # rule
    ("rule", [
        "rule", "rule_name", "policy", "policyname", "policy-name"
    ]),
]
TRAFFIC_HEADERS = [c for c, _ in TRAFFIC_COLS]
TRAFFIC_KEYS    = [ks for _, ks in TRAFFIC_COLS]

SYSTEM_COLS = [
    ("time",     ["time_generated", "receive_time", "time", "event_time"]),
    ("severity", ["severity", "level"]),
    ("message",  ["opaque", "msg", "message", "description", "detail"]),
]
SYSTEM_HEADERS = [c for c, _ in SYSTEM_COLS]
SYSTEM_KEYS    = [ks for _, ks in SYSTEM_COLS]

# ─────────────────────────────────────────────────────────────
# 트래픽: 평탄화 + 별칭 보정 + 메시지 파싱
# ─────────────────────────────────────────────────────────────
def _flatten_record(d: Dict[str, Any], parent_key: str = "", sep: str = ".") -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in (d or {}).items():
        key = f"{parent_key}{sep}{k}" if parent_key else str(k)
        if isinstance(v, dict):
            out.update(_flatten_record(v, key, sep=sep))
        else:
            out[key] = v
    return out

def _norm_ascii_key(s: str) -> str:
    return re.sub(r'[^a-z0-9]+', '', (s or '').lower())

_TRAFFIC_ALIASES = {
    "src": ["src","src_ip","source","source_ip","srcip","sip","saddr","sourceaddress","출발지","출발지ip","발신ip","발신"],
    "dst": ["dst","dst_ip","destination","destination_ip","dstip","dip","daddr","destinationaddress","목적지","목적지ip","수신ip","수신"],
    "dport": ["dport","dstport","destination-port","dst_port","dpt","destport","destinationport","service_port","service-port","서비스포트","목적지포트","포트","port"],
    "app": ["app","application","application-name","appname","서비스","애플리케이션","응용프로그램","app_id"],
    "protocol": ["protocol","proto","ip-proto","ip_proto","transport","l4proto","프로토콜"],
    "action": ["action","action_name","act","action-desc","log_action","결과","처리","허용/차단","허용","차단"],
    "rule": ["rule","rule_name","policy","policyname","policy-name","정책","정책명"],
}

def _coerce_traffic_aliases(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for rec in records:
        if not isinstance(rec, dict):
            out.append(rec); continue
        ascii_map = {_norm_ascii_key(k): k for k in rec.keys()}
        new = dict(rec)
        for canon, aliases in _TRAFFIC_ALIASES.items():
            if new.get(canon):
                continue
            val = None
            for a in aliases:
                if a in rec and rec[a] not in (None, ""):
                    val = rec[a]; break
                ak = _norm_ascii_key(a)
                if ak and ak in ascii_map:
                    v = rec.get(ascii_map[ak])
                    if v not in (None, ""):
                        val = v; break
            if val not in (None, ""):
                new[canon] = str(val)
        out.append(new)
    return out

_IP_RE   = r"(?:(?:\d{1,3}\.){3}\d{1,3})"
_PORT_RE = r"(?:^|\s)(?:dport|dstport|destport|destinationport|port)[:=\s]+(\d{1,5})(?:\b|$)"
_RULE_RE = r"(?:^|\s)(?:rule|policy|정책|정책명)[:=\s]+([^\s].+)"
_APP_RE  = r"(?:^|\s)(?:app|application|서비스|애플리케이션)[:=\s]+([^\s].+)"
_ACT_RE  = r"\b(allow|permit|accept|deny|drop|block|reset|차단|허용)\b"
_PROTO_RE= r"(?:^|\s)(?:proto|protocol|프로토콜)[:=\s]+([A-Za-z0-9]+)"

def _coerce_from_message(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for rec in records:
        if not isinstance(rec, dict):
            out.append(rec); continue
        new = dict(rec)
        msg = (new.get("message") or new.get("msg") or new.get("opaque")
               or new.get("description") or new.get("detail") or "")
        if msg:
            if not new.get("src") or not new.get("dst"):
                ips = re.findall(_IP_RE, msg)
                if ips:
                    if not new.get("src"): new["src"] = ips[0]
                    if not new.get("dst") and len(ips) >= 2: new["dst"] = ips[1]
            if not new.get("dport"):
                m = re.search(_PORT_RE, msg, re.IGNORECASE)
                if m: new["dport"] = m.group(1)
            if not new.get("rule"):
                m = re.search(_RULE_RE, msg, re.IGNORECASE)
                if m: new["rule"] = m.group(1).strip()
            if not new.get("app"):
                m = re.search(_APP_RE, msg, re.IGNORECASE)
                if m: new["app"] = m.group(1).strip()
            if not new.get("action"):
                m = re.search(_ACT_RE, msg, re.IGNORECASE)
                if m: new["action"] = m.group(1).lower()
            if not new.get("protocol"):
                m = re.search(_PROTO_RE, msg, re.IGNORECASE)
                if m: new["protocol"] = m.group(1).upper()
        out.append(new)
    return out

def render_traffic_table(data: Any) -> str:
    """벤더 무관 트래픽 결과 → 공통 표 HTML."""
    recs = _to_records(data)
    # 1) 중첩 평탄화
    recs = [(_flatten_record(r) if isinstance(r, dict) else r) for r in recs]
    # 2) 별칭 → 표준키 보정
    recs = _coerce_traffic_aliases(recs)
    # 3) message 문자열에서 추가 추출(모자란 값 채움)
    recs = _coerce_from_message(recs)
    return render_html_table(recs, TRAFFIC_KEYS, TRAFFIC_HEADERS)

# ─────────────────────────────────────────────────────────────
# 시스템: 헤더/배너 라인 제거 후 렌더
# ─────────────────────────────────────────────────────────────
def render_system_table(data: Any) -> str:
    recs = _to_records(data)
    cleaned: List[Dict[str, Any]] = []
    for r in recs:
        t   = _pick(r, ["time_generated", "receive_time", "time", "event_time"])
        sev = _pick(r, ["severity", "level"])
        msg = _pick(r, ["opaque", "msg", "message", "description", "detail"])
        if (not t) and (not sev) and _is_headerish(msg):
            continue
        cleaned.append(r)
    return render_html_table(cleaned, SYSTEM_KEYS, SYSTEM_HEADERS)

# (옵션) 여러 장비 결과를 한 번에 묶어서 렌더할 때 사용
def render_traffic_table_from_records(records: List[Dict[str, Any]]) -> str:
    return render_html_table(records, TRAFFIC_KEYS, TRAFFIC_HEADERS)

def render_system_table_from_records(records: List[Dict[str, Any]]) -> str:
    return render_html_table(records, SYSTEM_KEYS, SYSTEM_HEADERS)