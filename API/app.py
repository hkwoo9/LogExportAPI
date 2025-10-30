# API/app.py
from flask import Flask, render_template, request
import pandas as pd
import logging

# ── 외부 모듈(현재 레포 기준) ─────────────────────────────────
from firewall_ip_check_modi import find_target_firewall

# Secui는 raw를 pretty에 바로 넘겨 렌더
from secui_log_api import (
    fetch_secui_traffic_logs,
    fetch_secui_system_logs,
)

# Palo는 unified 레이어로 records(list[dict])를 만든 뒤 pretty 렌더
from palo_unified import (
    palo_traffic_records,
    palo_system_records,
)

# 공용 렌더러
from pretty import (
    render_traffic_table,
    render_system_table,
)

# ── Flask & 로깅 ─────────────────────────────────────────────
app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

def _peek(obj, n=400):
    try:
        s = str(obj)
    except Exception:
        import pprint
        s = pprint.pformat(obj)
    return s[:n]

def _is_html(s):
    return isinstance(s, str) and ("<table" in s or s.lstrip().startswith("<"))

# ── 데이터 로드(엑셀) ────────────────────────────────────────
# 1) 방화벽 상세(이름→IP/vendor/자격 등)
firewall_info_df = pd.read_excel("firewall_info_new.xlsx")

# 2) UI 표시용 장비 리스트(이름/IP/vendor)
device_list_df = pd.read_excel("firewall_list.xlsx")

# dict: 장비명 → {management_ip, vendor, ...}
firewall_info_dict = {
    row["name"]: {
        "management_ip": row["management_ip"],
        "vendor": row["vendor"],
        "client_id": row.get("client_id"),
        "client_secret": row.get("client_secret"),
        "base_url": row.get("base_url"),
    }
    for _, row in firewall_info_df.iterrows()
}

# ── 라우트 ───────────────────────────────────────────────────
@app.route("/")
def index():
    devices = device_list_df.to_dict(orient="records")
    return render_template("index.html", devices=devices, result="")

@app.route("/run_traffic", methods=["POST"])
def run_traffic():
    # 필수 입력들
    mode     = (request.form.get("mode") or "manual").strip()
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()

    parts: list[str] = []

    # 벤더별 1대 처리 (반드시 문자열 HTML을 리턴)
    def _render_for_device(name: str, info: dict, src_ip: str, dst_ip: str) -> str:
        vendor = (info or {}).get("vendor", "")
        fw_ip  = (info or {}).get("management_ip", "")
        app.logger.info("[traffic] name=%s vendor=%s ip=%s src=%s dst=%s",
                        name, vendor, fw_ip, src_ip, dst_ip)
        try:
            if vendor == "Paloalto":
                # unified → records or HTML
                recs_or_html = palo_traffic_records(fw_ip, src_ip, dst_ip, username, password)
                if isinstance(recs_or_html, str) and (
                    "<table" in recs_or_html or recs_or_html.lstrip().startswith("<")
                ):
                    html = recs_or_html
                else:
                    html = render_traffic_table(recs_or_html)
            elif vendor == "Secui Bluemax":
                raw  = fetch_secui_traffic_logs(info, src_ip, dst_ip)
                html = render_traffic_table(raw)
            else:
                html = f"{vendor}는 지원하지 않는 방화벽입니다."
        except Exception as e:
            app.logger.exception("[traffic] fetch/render error")
            html = f"[error] {name}({vendor}) 처리 중 오류: {e}"
        # 항상 문자열(HTML)로 반환
        return f"<h4>{name} ({vendor})</h4>\n{html}"

    # 자동탐색 결과 원소에서 (name, info) 안정적으로 뽑기
    def _extract_name_and_info(m):
        # "장비명" 문자열
        if isinstance(m, str):
            return m, firewall_info_dict.get(m)
        # dict인 경우
        if isinstance(m, dict):
            name = m.get("name") or m.get("device") or m.get("hostname") or m.get("fw_name")
            # 이미 vendor/ip가 들어있다면 그대로 info로 사용
            if m.get("vendor") and (m.get("management_ip") or m.get("ip") or m.get("mgmt_ip")):
                info = {
                    "vendor": m.get("vendor"),
                    "management_ip": m.get("management_ip") or m.get("ip") or m.get("mgmt_ip"),
                }
                return name or "(unknown)", info
            # 아니면 엑셀 dict에서 조회
            return (name or "(unknown)"), firewall_info_dict.get(name) if name else None
        # tuple/list면 첫 원소가 이름일 수 있음
        if isinstance(m, (list, tuple)) and m and isinstance(m[0], str):
            return m[0], firewall_info_dict.get(m[0])
        # 그 밖은 실패
        return None, None

    # ── 수동 모드 ───────────────────────────────────────────
    if mode == "manual":
        src_ip = (request.form.get("src_ip") or "").strip()
        dst_ip = (request.form.get("dst_ip") or "").strip()
        selected_name = request.form.get("selected_device")
        if not selected_name:
            return render_template("index.html",
                                   devices=device_list_df.to_dict(orient="records"),
                                   result="장비를 선택하세요.")
        info = firewall_info_dict.get(selected_name)
        if not info:
            return render_template("index.html",
                                   devices=device_list_df.to_dict(orient="records"),
                                   result="장비 정보 없음.")
        parts.append(_render_for_device(selected_name, info, src_ip, dst_ip))

    # ── 자동 모드 ───────────────────────────────────────────
    else:
        src_ip = (request.form.get("src_ip") or "").strip()
        dst_ip = (request.form.get("dst_ip") or "").strip()

        matched = find_target_firewall(src_ip, dst_ip) or []
        app.logger.info("[auto] matched type=%s len=%s",
                        type(matched).__name__, len(matched) if hasattr(matched, "__len__") else "?")
        if matched:app.logger.info("[auto] matched sample=%r", matched[0])

        if not matched:
            parts.append("[ok] 일치하는 방화벽이 없습니다.")
        else:
            for m in matched:
                name, info = _extract_name_and_info(m)
                if not info:
                    app.logger.warning("[auto] info not found for %r; skipping", name or m)
                    continue
                parts.append(_render_for_device(name, info, src_ip, dst_ip))

    # ── 모든 분기에서 최종적으로 Response를 리턴 ─────────────
    result_html = "<br>".join(parts) if parts else "[ok] 표시할 로그가 없습니다."
    return render_template("index.html",
                           devices=device_list_df.to_dict(orient="records"),
                           result=result_html)

@app.route("/run_system", methods=["POST"])
def run_system():
    selected_name = request.form.get("selected_device")
    level = (request.form.get("level") or "CRITICAL").upper()
    username = request.form.get("username") or ""
    password = request.form.get("password") or ""

    if not selected_name:
        return render_template(
            "index.html",
            devices=device_list_df.to_dict(orient="records"),
            result="장비 선택 필수"
        )

    info = firewall_info_dict.get(selected_name)
    if not info:
        return render_template(
            "index.html",
            devices=device_list_df.to_dict(orient="records"),
            result="장비 정보 없음."
        )

    vendor = info.get("vendor", "")
    fw_ip  = info.get("management_ip", "")
    app.logger.info("[system] name=%s vendor=%s ip=%s level=%s", selected_name, vendor, fw_ip, level)

    try:
        if vendor == "Paloalto":
            # unified → records → pretty
            recs_or_html = palo_system_records(fw_ip, level, username, password)
            if _is_html(recs_or_html):
                html = recs_or_html
            else:
                if isinstance(recs_or_html, list) and recs_or_html:
                    app.logger.info("[PALO system sample keys] %s", list(recs_or_html[0].keys()))
                    app.logger.info("[PALO system sample] %s", _peek(recs_or_html[0]))
                html = render_system_table(recs_or_html)

        elif vendor == "Secui Bluemax":
            # raw → pretty
            raw = fetch_secui_system_logs(info, level)
            # from pretty import _to_records
            # tmp = _to_records(raw)
            # if tmp:
            #     app.logger.info("[SECUI system to_records keys] %s", list(tmp[0].keys()))
            #     app.logger.info("[SECUI system to_records sample] %s", _peek(tmp[0]))
            html = render_system_table(raw)

        else:
            html = f"{vendor}는 지원하지 않는 방화벽입니다."

    except Exception as e:
        app.logger.exception("[system] fetch/render error")
        html = f"[error] {selected_name}({vendor}) 처리 중 오류: {e}"

    return render_template("index.html", devices=device_list_df.to_dict(orient="records"), result=html)

# ── 엔트리포인트 ─────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True)