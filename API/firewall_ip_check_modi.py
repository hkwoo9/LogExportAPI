import pandas as pd
import ipaddress
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

EXCEL_FILE = r"D:\Microsoft VS Code\test\Firewall_Log_API\firewall_info_new.xlsx"

def load_firewall_info():
  try:
    df = pd.read_excel(EXCEL_FILE)
  except FileNotFoundError:
    raise FileNotFoundError(f"엑셀 파일을 찾을 수 없습니다: {EXCEL_FILE}")
  except Exception as e:
    raise RuntimeError(f"엑셀 파일을 읽는 중 오류가 발생했습니다: {e}")

  required_columns = {"name", "management_ip", "ip_range"}
  if not required_columns.issubset(df.columns):
    raise ValueError(f"엑셀 파일에 다음 열이 포함되어야 합니다.: {required_columns}")
  
  firewall_info = df[["name", "management_ip", "ip_range"]].to_dict(orient="records")
  return firewall_info

def parse_ip_range(ip_range):
  if "/" in ip_range:
    network = ipaddress.ip_network(ip_range, strict=False)
    return network[0], network[-1]
  elif "-" in ip_range:
    start_ip, end_ip = ip_range.split("-")
    return ipaddress.ip_address(start_ip.strip()), ipaddress.ip_address(end_ip.strip())
  else:
    raise ValueError(f"IP 범위 형식이 잘못되었습니다. 지원되는 형식은 'CIDR' 또는 'start-end'입니다: {ip_range}")

def ip_in_range(ip, ip_range):
  try:
    ip = ipaddress.ip_address(ip)
    start_ip, end_ip = parse_ip_range(ip_range)
    return start_ip <= ip <= end_ip
  except ValueError:
    return False

def find_target_firewall(src_ip, dst_ip):
    firewall_info = load_firewall_info()
    src_ip = ipaddress.ip_address(src_ip)
    dst_ip = ipaddress.ip_address(dst_ip)


    ds_gateway = None
    internal_firewalls = []
    gihwa_firewalls = []

    matched_firewalls = []

    for fw in firewall_info:
        if fw['name'] == "DS관문":
            ds_gateway = fw
        elif "기흥화성준사내" in fw['name']:
            gihwa_firewalls.append(fw)
        else:
            internal_firewalls.append(fw)

    
    is_src_internal = any(ip_in_range(src_ip, fw['ip_range']) for fw in internal_firewalls)
    is_dst_internal = any(ip_in_range(dst_ip, fw['ip_range']) for fw in internal_firewalls)
    is_src_gihwa = any(ip_in_range(src_ip, fw['ip_range']) for fw in gihwa_firewalls)
    is_dst_gihwa = any(ip_in_range(dst_ip, fw['ip_range']) for fw in gihwa_firewalls)

    # 내부/기흥 방화벽에서 매칭되는 것들 추가
    for fw in internal_firewalls + gihwa_firewalls:
        if ip_in_range(src_ip, fw['ip_range']) or ip_in_range(dst_ip, fw['ip_range']):
            matched_firewalls.append(fw)

    #  포함 조건
    if ds_gateway:
        if is_src_internal:
            if not is_dst_internal and not is_dst_gihwa:
                # 내부 → 외부
                matched_firewalls.append(ds_gateway)
            elif is_dst_gihwa:
                # 내부 → 기흥화성준사내
                matched_firewalls.append(ds_gateway)
            # 내부 → 내부는 포함 ❌

    # 중복 제거
    seen = set()
    unique_firewalls = []
    for fw in matched_firewalls:
        key = (fw['name'], fw['management_ip'])
        if key not in seen:
            seen.add(key)
            unique_firewalls.append(fw)

    return unique_firewalls

if __name__ == "__main__":
  firewall_info = load_firewall_info()
  src_ip = input("출발지 IP를 입력하세요: ")
  dst_ip = input("목적지 IP를 입력하세요: ")
  
  result = find_target_firewall(src_ip, dst_ip, firewall_info)

  if result:
    print("\n[대상 방화벽 목록]")
    for fw in result:
      print(f"방화벽 이름: {fw['name']}, 관리 IP: {fw['management_ip']}, 담당 IP: {fw['ip_range']}")
  else:
    print("해당하는 방화벽을 찾지 못했습니다.")
