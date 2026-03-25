import boto3
import json

iam = boto3.client("iam")

users = iam.list_users()["Users"]
results = []

print("=== IAM 사용자 MFA 점검 결과 ===")

for user in users:
    username = user["UserName"]
    mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]

    if len(mfa_devices) == 0:
        result = {
            "rule_id": "IAM-01",
            "category": "IAM",
            "rule_name": "IAM 사용자 MFA 설정 여부",
            "resource": username,
            "status": "FAIL",
            "severity": "HIGH",
            "message": f"{username} 사용자는 MFA가 설정되어 있지 않습니다."
        }
        print(f"[FAIL] {username} - MFA 미설정")
    else:
        result = {
            "rule_id": "IAM-01",
            "category": "IAM",
            "rule_name": "IAM 사용자 MFA 설정 여부",
            "resource": username,
            "status": "PASS",
            "severity": "INFO",
            "message": f"{username} 사용자는 MFA가 설정되어 있습니다."
        }
        print(f"[PASS] {username} - MFA 설정됨")

    results.append(result)

with open("scan_result.json", "w", encoding="utf-8") as f:
    json.dump(results, f, ensure_ascii=False, indent=2)

print("\n진단 결과가 scan_result.json 파일에 저장되었습니다.")