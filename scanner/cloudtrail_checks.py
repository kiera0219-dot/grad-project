import boto3
from botocore.exceptions import ClientError


def check_cloudtrail_enabled():

    cloudtrail = boto3.client(
        "cloudtrail",
        region_name="ap-northeast-2"
    )

    results = []

    print("\n=== CloudTrail 점검 결과 ===")

    try:

        response = cloudtrail.describe_trails(
            includeShadowTrails=False
        )

        trails = response.get("trailList", [])

        # -------------------------------------------------
        # CloudTrail 활성화 여부
        # -------------------------------------------------

        if not trails:

            print("[FAIL] CloudTrail - 설정된 트레일 없음")

            results.append({
                "item": "CloudTrail Enabled",
                "target": "CloudTrail",
                "risk": "High",
                "status": "FAIL",
                "kisa_code": "KISA-CLD-08",
                "detail": "설정된 CloudTrail 트레일이 없습니다."
            })

            return results

        print("[PASS] CloudTrail - 트레일이 설정되어 있습니다.")

        results.append({
            "item": "CloudTrail Enabled",
            "target": "CloudTrail",
            "risk": "Low",
            "status": "PASS",
            "kisa_code": "KISA-CLD-08",
            "detail": "CloudTrail 트레일이 설정되어 있습니다."
        })

        # -------------------------------------------------
        # 실제 로그 수집 여부 검사
        # -------------------------------------------------

        print("\n=== CloudTrail Logging 점검 결과 ===")

        for trail in trails:

            trail_name = trail.get("Name", "UnknownTrail")

            status = cloudtrail.get_trail_status(
                Name=trail_name
            )

            is_logging = status.get("IsLogging", False)

            if is_logging:

                print(f"[PASS] {trail_name} - 로그 수집 활성화")

                results.append({
                    "item": "CloudTrail Logging",
                    "target": trail_name,
                    "risk": "Low",
                    "status": "PASS",
                    "kisa_code": "KISA-CLD-08",
                    "detail": f"{trail_name} 트레일은 로그 수집이 활성화되어 있습니다."
                })

            else:

                print(f"[FAIL] {trail_name} - 로그 수집 비활성화")

                results.append({
                    "item": "CloudTrail Logging",
                    "target": trail_name,
                    "risk": "High",
                    "status": "FAIL",
                    "kisa_code": "KISA-CLD-08",
                    "detail": f"{trail_name} 트레일은 로그 수집이 비활성화되어 있습니다."
                })

        # -------------------------------------------------
        # Multi-Region 검사
        # -------------------------------------------------

        print("\n=== CloudTrail Multi-Region 점검 결과 ===")

        for trail in trails:

            trail_name = trail.get("Name", "UnknownTrail")

            is_multi_region = trail.get(
                "IsMultiRegionTrail",
                False
            )

            if is_multi_region:

                print(f"[PASS] {trail_name} - Multi-Region 활성화")

                results.append({
                    "item": "CloudTrail Multi-Region",
                    "target": trail_name,
                    "risk": "Low",
                    "status": "PASS",
                    "kisa_code": "KISA-CLD-09",
                    "detail": f"{trail_name} 트레일은 Multi-Region으로 설정되어 있습니다."
                })

            else:

                print(f"[FAIL] {trail_name} - Multi-Region 비활성화")

                results.append({
                    "item": "CloudTrail Multi-Region",
                    "target": trail_name,
                    "risk": "Medium",
                    "status": "FAIL",
                    "kisa_code": "KISA-CLD-09",
                    "detail": f"{trail_name} 트레일은 Multi-Region으로 설정되어 있지 않습니다."
                })

        # -------------------------------------------------
        # 로그 암호화 검사
        # -------------------------------------------------

        print("\n=== CloudTrail 로그 암호화 점검 결과 ===")

        for trail in trails:

            trail_name = trail.get("Name", "UnknownTrail")

            kms_key = trail.get("KmsKeyId")

            if kms_key:

                print(f"[PASS] {trail_name} - 로그 암호화 설정됨")

                results.append({
                    "item": "CloudTrail Log Encryption",
                    "target": trail_name,
                    "risk": "Low",
                    "status": "PASS",
                    "kisa_code": "KISA-CLD-10",
                    "detail": f"{trail_name} 트레일은 KMS 로그 암호화가 설정되어 있습니다."
                })

            else:

                print(f"[FAIL] {trail_name} - 로그 암호화 미설정")

                results.append({
                    "item": "CloudTrail Log Encryption",
                    "target": trail_name,
                    "risk": "Medium",
                    "status": "FAIL",
                    "kisa_code": "KISA-CLD-10",
                    "detail": f"{trail_name} 트레일은 로그 암호화(KMS)가 설정되어 있지 않습니다."
                })

    except ClientError as e:

        print(f"[ERROR] CloudTrail 조회 실패: {e}")

        results.append({
            "item": "CloudTrail Check",
            "target": "CloudTrail",
            "risk": "Info",
            "status": "INFO",
            "kisa_code": "KISA-CLD-08",
            "detail": "CloudTrail 정보를 조회할 수 없습니다."
        })

    return results