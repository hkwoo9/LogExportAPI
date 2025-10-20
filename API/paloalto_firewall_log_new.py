import requests
import xml.etree.ElementTree as ET

def generate_api_key(firewall_ip, account, password):
    """
    계정 정보를 사용하여 Palo Alto 방화벽 API 키를 생성합니다.
    """
    base_url = f"https://{firewall_ip}/api/"
    params = {
        "type": "keygen",
        "user": account,
        "password": password,
    }
    try:
        response = requests.get(base_url, params=params, verify=False)
        response.raise_for_status()
        root = ET.fromstring(response.text)
        api_key = root.findtext(".//key")
        if not api_key:
            raise RuntimeError("API 키 생성 실패")
        return api_key
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"API 키 생성 중 오류 발생: {e}")

def paloalto_fetch_traffic(firewall_ip, src_ip, dst_ip, account, password):
    """
    Palo Alto 트래픽 로그를 Job ID 기반으로 추출합니다.
    """
    api_key = generate_api_key(firewall_ip, account, password)  # 실제 API 키 생성 로직을 구현해야 함
    base_url = f"https://{firewall_ip}/api/"
    params = {
        "type": "log",
        "log-type": "traffic",
        "query": f"(addr.src in {src_ip}) and (addr.dst in {dst_ip})",
        "key": api_key,
    }
    try:
        # Step 1: 쿼리를 보내 Job ID를 받음
        response = requests.get(base_url, params=params, verify=False)
        response.raise_for_status()

        # XML 파싱하여 Job ID 추출
        root = ET.fromstring(response.text)
        job_id = root.findtext(".//job")
        if not job_id:
            raise RuntimeError("Job ID를 찾을 수 없습니다.")

        # Step 2: Job ID로 결과를 가져옴
        job_params = {
            "type": "log",
            "action": "get",
            "job-id": job_id,
            "key": api_key,
        }

        while True:
            job_response = requests.get(base_url, params=job_params, verify=False)
            job_response.raise_for_status()

            # XML 파싱하여 상태 확인
            job_root = ET.fromstring(job_response.text)
            status = job_root.findtext(".//status")
            if status == "FIN":
                break  # 작업이 완료되었으면 루프 탈출
            elif status == "FAIL":
                raise RuntimeError("Job 처리 실패")
        
        # XML 파싱하여 로그 데이터 추출
        logs = []
        for entry in job_root.findall(".//entry"):
            log_entry = {
                "time": entry.findtext("receive_time"),
                "src_ip": entry.findtext("src"),
                "dst_ip": entry.findtext("dst"),
                "action": entry.findtext("action"),
            }
            logs.append(log_entry)

        return logs

    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"트래픽 로그 추출 실패: {e}")
