from flask import Flask, render_template, request
import pandas as pd
from firewall_ip_check_modi import find_target_firewall
from secui_log_api import fetch_secui_traffic_logs, fetch_secui_system_logs
from paloalto_firewall_log_new import paloalto_fetch_traffic
from paloalto_system_log_new import paloalto_fetch_system

app = Flask(__name__)

# 엑셀 불러오기
firewall_info_df = pd.read_excel("firewall_info_new.xlsx")
device_list_df = pd.read_excel("firewall_list.xlsx")  # UI 표시용 (이름/IP/vendor)

# 장비 정보 딕셔너리화
firewall_info_dict = {
    row['name']: {
        "management_ip": row['management_ip'],
        "vendor": row['vendor'],
        "client_id": row.get('client_id'),
        "client_secret": row.get('client_secret'),
        "base_url": row.get('base_url')
    }
    for _, row in firewall_info_df.iterrows()
}

@app.route("/")
def index():
    devices = device_list_df.to_dict(orient='records')
    return render_template("index.html", devices=devices, result="")

@app.route("/run_traffic", methods=["POST"])
def run_traffic():
    mode = request.form.get("mode")
    username = request.form.get("username")
    password = request.form.get("password")
    result = ""

    if mode == "manual":
        src_ip = request.form.get("src_ip")
        dst_ip = request.form.get("dst_ip")
        selected_name = request.form.get("selected_device")
        if not selected_name:
            return render_template("index.html", devices=device_list_df.to_dict(orient='records'), result="장비를 선택하세요.")
        info = firewall_info_dict.get(selected_name)
        if not info:
            return render_template("index.html", devices=device_list_df.to_dict(orient='records'), result="장비 정보 없음.")
        vendor = info['vendor']
        print(f"[디버깅용] 수동 모드 선택: {selected_name}, vendor: {vendor}")  # 디버깅용

        if vendor == "Paloalto":
            result = paloalto_fetch_traffic(info, src_ip, dst_ip,username, password)
        elif vendor == "Secui Bluemax":
            result = fetch_secui_traffic_logs(info,src_ip,dst_ip)
        else:
            result = f"{vendor}는 지원하지 않는 방화벽입니다."
    else:  # 자동 탐색
        src_ip = request.form.get("src_ip")
        dst_ip = request.form.get("dst_ip")
        print(f"[디버깅용] 자동 탐색 모드: {src_ip} -> {dst_ip}")  # 디버깅용
        matched_firewalls = find_target_firewall(src_ip, dst_ip)
        for fw in matched_firewalls:
            info = firewall_info_dict.get(fw)
            if not info:
                continue
            vendor = info['vendor']
            if vendor == "Paloalto":
                result += paloalto_fetch_traffic(info, src_ip, dst_ip, username, password)
            elif vendor == "Secui Bluemax":
                result += fetch_secui_traffic_logs(info)
            else:
                result += f"{vendor}는 지원하지 않는 방화벽입니다.<br>"

    return render_template("index.html", devices=device_list_df.to_dict(orient='records'), result=result)

@app.route("/run_system", methods=["POST"])
def run_system():
    selected_name = request.form.get("selected_device")
    level = request.form.get("level", "CRITICAL").upper()
    print("GUI에서 전달된 level:",level)
    username = request.form.get("username")
    password = request.form.get("password")

    print(f"[디버깅용] 시스템 로그 요청: {selected_name}, Level: {level}")  # 디버깅용

    if not selected_name:
        return render_template("index.html", devices=device_list_df.to_dict(orient='records'), result="장비 선택 필수")

    info = firewall_info_dict.get(selected_name)
    if not info:
        return render_template("index.html", devices=device_list_df.to_dict(orient='records'), result="장비 정보 없음.")
    vendor = info['vendor']

    if vendor == "Paloalto":
        result = paloalto_fetch_system(info, username, password, level)
    elif vendor == "Secui Bluemax":
        result = fetch_secui_system_logs(info, level)
        print("보낸 level은 뭘까요",level) # 디버깅깅
    else:
        result = f"{vendor}는 지원하지 않는 방화벽입니다."

    return render_template("index.html", devices=device_list_df.to_dict(orient='records'), result=result)

if __name__ == "__main__":
    app.run(debug=True)