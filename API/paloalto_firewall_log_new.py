import requests
import xml.etree.ElementTree as ET
import pandas as pd

class PaloAltoFirewallAPI:
    def __init__(self, management_ip, username, password):
        """
        Palo Alto 방화벽 API 클래스 초기화
        :param management_ip: 방화벽 관리 IP
        :param username: 관리자 계정 사용자 이름
        :param password: 관리자 계정 비밀번호
        """
        self.management_ip = management_ip
        self.username = username
        self.password = password
        self.api_key = self.generate_api_key()
        self.base_url = f"https://{self.management_ip}/api/"

    def generate_api_key(self):
        """
        사용자 계정 정보를 사용해 API Key 생성
        :return: 생성된 API Key
        """
        params = {
            "type": "keygen",
            "user": self.username,
            "password": self.password
        }
        try:
            response = requests.get(f"https://{self.management_ip}/api/", params=params, verify=False)
            response.raise_for_status()

            root = ET.fromstring(response.text)
            key = root.find(".//key")
            if key is not None:
                return key.text
            else:
                raise ValueError("API Key 생성 실패")
        except Exception as e:
            print(f"API Key 생성 중 오류 발생: {e}")
            return None

    def get_logs(self, src_ip=None, dst_ip=None, log_type="traffic", limit=10):
        """
        방화벽에서 로그를 추출
        :param src_ip: 출발지 IP
        :param dst_ip: 목적지 IP
        :param log_type: 로그 타입 (기본값: "traffic")
        :param limit: 반환할 로그 수
        :return: 로그 데이터 (DataFrame 형식)
        """
        if not self.api_key:
            raise ValueError("API Key가 없습니다. 생성 실패")

        query = []
        if src_ip:
            query.append(f"src in {src_ip}")
        if dst_ip:
            query.append(f"dst in {dst_ip}")
        query = " and ".join(query) if query else None

        params = {
            "type": "log",
            "log-type": log_type,
            "query": query,
            "nlogs": limit,
            "key": self.api_key
        }

        try:
            response = requests.get(self.base_url, params=params, verify=False)
            response.raise_for_status()
            root = ET.fromstring(response.text)
            job_id = root.find(".//job").text
            if not job_id:
                raise ValueError("Job ID를 가져올 수 없습니다.")

            # 작업 상태 확인 및 결과 가져오기
            return self.get_log_results(job_id)
        except Exception as e:
            print(f"로그 가져오기 중 오류 발생: {e}")
            return None

    def get_log_results(self, job_id):
        """
        작업 ID를 사용해 로그 결과를 가져옴
        :param job_id: 작업 ID
        :return: 로그 데이터 (DataFrame 형식)
        """
        params = {
            "type": "log",
            "action": "get",
            "jobid": job_id,
            "key": self.api_key
        }

        while True:
            response = requests.get(self.base_url, params=params, verify=False)
            response.raise_for_status()
            root = ET.fromstring(response.text)
            status = root.find(".//status").text
            if status == "FIN":
                break
            elif status == "FAIL":
                raise ValueError("로그 작업 실패")

        # 로그 데이터 파싱
        entries = root.findall(".//entry")
        desired_columns = [
            "receive_time", "src", "dst", "app", "prot", "dport", "action", "rule", "bytes", "bytes_sent", "bytes_received"
        ]
        logs = []
        for entry in entries:
            log_data = {child.tag: child.text for child in entry if child.tag in desired_columns}
            logs.append(log_data)
        return pd.DataFrame(logs)

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    management_ip = input("방화벽 관리 IP를 입력하세요: ")
    username = input("사용자 이름을 입력하세요: ")
    password = input("비밀번호를 입력하세요: ")
    src_ip = input("출발지 IP를 입력하세요 (없으면 Enter): ")
    dst_ip = input("목적지 IP를 입력하세요 (없으면 Enter): ")
    limit = input("로그 개수를 입력하세요 (기본값: 10): ")

    if not limit.isdigit():
        limit = 10
    else:
        limit = int(limit)

    api = PaloAltoFirewallAPI(management_ip, username, password)
    logs = api.get_logs(src_ip=src_ip, dst_ip=dst_ip, limit=limit)

    if logs is not None and not logs.empty:
        print("\n[로그 결과]")
        print(logs)
    else:
        print("로그를 가져오지 못했습니다.")
