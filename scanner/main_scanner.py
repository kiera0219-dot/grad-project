import os
import json
#전체 포트 개방 검사
from scanner.sg_checks import check_security_group_all_open
#권한 사용자 검사
from scanner.iam_checks import check_iam_admin_users

#Access_key 검사
from scanner.iam_checks import check_iam_access_key_unused

#CloudTrail 검사
from scanner.cloudtrail_checks import check_cloudtrail_enabled

# IAM 검사
from scanner.iam_checks import check_iam_users_mfa, check_root_account_mfa, check_iam_password_policy

# S3 검사
from scanner.s3_checks import check_s3_public_access, check_s3_bucket_encryption, check_s3_bucket_versioning

# Security Group 검사
from scanner.sg_checks import check_security_group_ssh_open, check_security_group_rdp_open

# RDS 검사
from scanner.rds_checks import check_rds_public_access

# 점수 계산
from scoring.security_score import calculate_score

def run_all_checks():
    results = []
    # ======================
    # 전체 포트 개방 검사
    # ======================
    results.extend(check_security_group_all_open())
    # ======================
    # 권한 사용자 검사
    # ======================
    results.extend(check_iam_admin_users())
    # ======================
    # Access_key 검사
    # ======================
    results.extend(check_iam_access_key_unused())
    # ======================
    # CloudTrail 검사
    # ======================
    results.extend(check_cloudtrail_enabled())
    # ======================
    # IAM Security 검사
    # ======================
    results.extend(check_root_account_mfa())
    results.extend(check_iam_users_mfa())
    results.extend(check_iam_password_policy())
    # ======================
    # Storage (S3) 검사
    # ======================
    results.extend(check_s3_public_access())
    results.extend(check_s3_bucket_encryption())
    results.extend(check_s3_bucket_versioning())

    # ======================
    # Network Security 검사
    # ======================
    results.extend(check_security_group_ssh_open())
    results.extend(check_security_group_rdp_open())

    # ======================
    # Database Security 검사
    # ======================
    results.extend(check_rds_public_access())

    summary = {
        "total_checks": len(results),
        "pass_count": sum(1 for r in results if r["status"] == "Pass"),
        "fail_count": sum(1 for r in results if r["status"] == "Fail"),
        "security_score": calculate_score(results)
    }

    final_output = {
        "summary": summary,
        "results": results
    }

    os.makedirs("outputs", exist_ok=True)

    with open("outputs/scan_result.json", "w", encoding="utf-8") as f:
        json.dump(final_output, f, indent=2, ensure_ascii=False)

    print("\n진단 결과가 outputs/scan_result.json 파일에 저장되었습니다.")
    print("=== 점검 요약 ===")
    print(f"전체 점검 수: {summary['total_checks']}")
    print(f"PASS: {summary['pass_count']}")
    print(f"FAIL: {summary['fail_count']}")
    print(f"Security Score: {summary['security_score']}")

    return final_output


if __name__ == "__main__":
    run_all_checks()