import requests
import time

def get_secui_token(base_url, client_id, client_secret):
    url = f"{base_url}/api/au/external/login"
    payload = {
        "ext_clnt_id": client_id,
        "ext_clnt_secret": client_secret,
        "lang": "ko",
        "force": 1
    }
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "python-requests/2.31.0"
    }
    try:
        response = requests.post(url, json=payload, headers=headers, verify=False)
        response.raise_for_status()
        data = response.json()
        token = data.get("result", {}).get("api_token")  # ✅ 수정된 부분
        print("✅ Secui 토큰 발급 성공:", token)  # 디버깅용
        return token
    except Exception as e:
        print("❌ Secui 토큰 발급 실패:", e)
        return None

def fetch_secui_system_logs(info, level):
    base_url = info['base_url']
    client_id = info['client_id']
    client_secret = info['client_secret']
    token = get_secui_token(base_url, client_id, client_secret)
    if not token:
        return "토큰 발급 실패"

    url = f"{base_url}/api/lr/log/start"
    headers = {
        "Authorization": token,
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "python-requests/2.31.0"
    }

    payload = {
        "log_type": "alert",
        "stime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 60000)),
        "etime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "total_rows": 3,
        "page_rows": 100,
        "order_by": "desc",
        "columns": ["level", "time", "module_id", "mach_id", "message"],
        "filters": [{
            "key": "level",
            "value": [level],
            "is_not": False
        }],
#            "level" : "INFO",
 #           "time" : "2025-10-16 13:00:36",
  #          "module_id": "System", 
   #         "mach_id": "NGF_1510SE_M",
    #        "message": "CPU usage(individual) is too high : CPU3(100.00%)" 

     #   }
      #  ],
        #"items":[{
        #    "key": "level",
        #    "value": level,
        #    "is_not": "false"
        #}],
        #"filters":[],
        
    }

    try:
        print("📤 시스템 로그 요청 payload:", payload)  # 디버깅용
        response = requests.post(url, json=payload, headers=headers, verify=False)
        print("전체 응답:",response.text)
        response.raise_for_status()
        data = response.json()
        print("전체 응답:",response)
        print("전체 응답:",data)
        
        if data.get("code") != "ok":
            return f"검색 시작 실패: {data.get('message', 'An unknown error occurred')}"

        request_id = data.get("result", {}).get("request_id")
        if not request_id:
            return "요청 ID가 없습니다"

        # 진행 상태 확인
        status_url = f"{base_url}/api/lr/log/{request_id}/status"
        while True:
            status_response = requests.get(status_url, headers=headers, verify=False)
            status_data = status_response.json()
            if status_data.get("result", {}).get("status") == "DONE":
                break
            time.sleep(1)

        # 결과 조회
        page_rows = 100
        searched_cnt = status_data.get("result", {}).get("searched_cnt", 0)
        end = min(page_rows, searched_cnt)
        
        result_url = f"{base_url}/api/lr/log/{request_id}/page/0/to/{end}"
        result_response = requests.get(result_url, headers=headers, verify=False)
        result_data = result_response.json()
        
   #     res =  result_data.get()
   #     rows = result_data.get("result", {}).get("rows", [])
   #     columns = result_data.get("result", {}).get("columns", [])
   #     output = [columns]
        

        res = result_data.get("result", {})

        # 1) rows: 기본 rows → 없으면 log 로 폴백
        rows = res.get("rows")
        if rows is None:
            rows = res.get("log", [])

        # 2) columns: 응답에 없으면 "예상 스키마" 우선 적용 + 나머지 키들 뒤에 정렬 추가
        columns = res.get("columns")
        if not columns:
            key_union = set()
            if isinstance(rows, list) and rows and isinstance(rows[0], dict):
                for r in rows:
                    key_union.update(r.keys())

            # 요청 payload의 로그 타입 기준으로 기대 컬럼 템플릿 결정
            log_type = (payload.get("properties") or {}).get("log_type") or payload.get("log_type")
            if log_type == "alert":  # 시스템 로그
                template = ["level", "time", "module_id", "mach_id", "message"]
            else:  # 기본: 트래픽 세션
                template = ["etime", "fa_rule_name", "src_ip", "dst_ip", "dst_port", "action", "reason"]

            # 템플릿에 있는 키들 먼저, 나머지 키들은 알파벳 순으로 뒤에
            columns = [c for c in template if c in key_union] + [c for c in sorted(key_union) if c not in template]

        # 3) 표 형태로 정렬된 2차원 배열 구성: [columns] + 각 행의 값(컬럼 순서대로)
        output = [columns]
        if isinstance(rows, list):
            for r in rows:
                if isinstance(r, dict):
                    output.append([r.get(c, "") for c in columns])  # 컬럼 순서대로 값 매핑(누락은 빈칸)
                elif isinstance(r, list):
                    # 리스트 길이가 컬럼 수와 다르면 패딩/자르기
                    row_fixed = (r + [""] * len(columns))[:len(columns)]
                    output.append(row_fixed)
                else:
                    output.append([r])
        else:
            # rows가 리스트가 아니면 그대로 한 셀로
            output.append([rows])
        requests.delete(f"{base_url}/api/lr/log/{request_id}/end", headers=headers, verify=False)
        return output
        #for row in rows:
        #    output.append(row)
        #requests.delete(f"{base_url}/api/lr/log/{request_id}/end", headers=headers, verify=False)
        #return output
    except Exception as e:
        requests.delete(f"{base_url}/api/lr/log/{request_id}/end", headers=headers, verify=False)

        return f"오류 발생: {str(e)}"

def fetch_secui_traffic_logs(info, src_ip, dst_ip):
    base_url = info['base_url']
    client_id = info['client_id']
    client_secret = info['client_secret']
    token = get_secui_token(base_url, client_id, client_secret)
    print("넘어온 SRC IP:",src_ip)
    if not token:
        requests.delete(f"{base_url}/api/lr/log/{request_id}/end", headers=headers, verify=False)

        return "토큰 발급 실패"

    url = f"{base_url}/api/lr/log/start"
    headers = {
        "Authorization": token,
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "python-requests/2.31.0"
    }

    payload = {
        "log_type": "traffic_session",
        "stime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 30000)),
        "etime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "total_rows": 3,
        "page_rows": 100,
        "order_by": "desc",
        "filters": [{
            "key": "src_ip",
            "value": [src_ip],
            "is_not": False },
            {"key": "dst_ip",
            "value": [dst_ip],
            "is_not": False}
            ],
        "columns": ["etime","mach_id","fwrule_name","user_id","src_ip","dst_ip","dst_port","protocol","action","reason","tot_bytes"],
        "print_object_name": "false"
    }

    try:
        print("📤 트래픽 로그 요청 payload:", payload)  # 디버깅용
        response = requests.post(url, json=payload, headers=headers, verify=False)
        response.raise_for_status()
        data = response.json()

        if data.get("code") != "ok":
            return f"검색 시작 실패: {data.get('message', 'An unknown error occurred')}"

        request_id = data.get("result", {}).get("request_id")
        if not request_id:
            return "요청 ID가 없습니다"

        # 진행 상태 확인
        status_url = f"{base_url}/api/lr/log/{request_id}/status"
        while True:
            status_response = requests.get(status_url, headers=headers, verify=False)
            status_data = status_response.json()
            if status_data.get("result", {}).get("status") == "DONE":
                break
            time.sleep(1)

        # 페이지 정보 계산
        page_rows = 100
        searched_cnt = status_data.get("result", {}).get("searched_cnt", 0)
        end = min(page_rows, searched_cnt)
        result_url = f"{base_url}/api/lr/log/{request_id}/page/0/to/{end}"
        result_response = requests.get(result_url, headers=headers, verify=False)
        result_data = result_response.json()
        res = result_data.get("result", {})
        print("결과 : ",result_data)
        rows = res.get("rows")
        if rows is None:
            rows = res.get("log", [])

        # 2) columns: 응답에 없으면 "예상 스키마" 우선 적용 + 나머지 키들 뒤에 정렬 추가
        columns = res.get("columns")
        if not columns:
            key_union = set()
            if isinstance(rows, list) and rows and isinstance(rows[0], dict):
                for r in rows:
                    key_union.update(r.keys())

            # 요청 payload의 로그 타입 기준으로 기대 컬럼 템플릿 결정
            log_type = (payload.get("properties") or {}).get("log_type") or payload.get("log_type")
            if log_type == "alert":  # 시스템 로그
                template = ["level", "time", "module_id", "mach_id", "message"]
            else:  # 기본: 트래픽 세션
                template = ["etime", "fa_rule_name", "src_ip", "dst_ip", "dst_port", "action", "reason"]

            # 템플릿에 있는 키들 먼저, 나머지 키들은 알파벳 순으로 뒤에
            columns = [c for c in template if c in key_union] + [c for c in sorted(key_union) if c not in template]

        # 3) 표 형태로 정렬된 2차원 배열 구성: [columns] + 각 행의 값(컬럼 순서대로)
        output = [columns]
        if isinstance(rows, list):
            for r in rows:
                if isinstance(r, dict):
                    output.append([r.get(c, "") for c in columns])  # 컬럼 순서대로 값 매핑(누락은 빈칸)
                elif isinstance(r, list):
                    # 리스트 길이가 컬럼 수와 다르면 패딩/자르기
                    row_fixed = (r + [""] * len(columns))[:len(columns)]
                    output.append(row_fixed)
                else:
                    output.append([r])
        else:
            # rows가 리스트가 아니면 그대로 한 셀로
            output.append([rows])
        requests.delete(f"{base_url}/api/lr/log/{request_id}/end", headers=headers, verify=False)
        return output
        #for row in rows:
        #    output.append(row)
        #requests.delete(f"{base_url}/api/lr/log/{request_id}/end", headers=headers, verify=False)
        #return output
    except Exception as e:
        requests.delete(f"{base_url}/api/lr/log/{request_id}/end", headers=headers, verify=False)
        return f"오류 발생: {str(e)}"