import boto3

def check_cloudtrail_enabled():
    cloudtrail = boto3.client("cloudtrail", region_name="ap-northeast-2")
    results = []

    print("\n=== CloudTrail 활성화 점검 결과 ===")

    response = cloudtrail.describe_trails(includeShadowTrails=False)
    trails = response.get("trailList", [])

    if not trails:
        print("[FAIL] CloudTrail - 설정된 트레일 없음")
        results.append({
            "item": "CloudTrail Enabled",
            "target": "CloudTrail",
            "risk": "High",
            "status": "Fail",
            "kisa_code": "KISA-CLD-08",
            "detail": "설정된 CloudTrail 트레일이 없습니다."
        })
        return results

    print("[PASS] CloudTrail - 트레일이 설정되어 있습니다.")
    results.append({
        "item": "CloudTrail Enabled",
        "target": "CloudTrail",
        "risk": "Low",
        "status": "Pass",
        "kisa_code": "KISA-CLD-08",
        "detail": "CloudTrail 트레일이 설정되어 있습니다."
    })

    print("\n=== CloudTrail Multi-Region 점검 결과 ===")

    for trail in trails:
        trail_name = trail.get("Name", "UnknownTrail")
        is_multi_region = trail.get("IsMultiRegionTrail", False)

        if is_multi_region:
            print(f"[PASS] {trail_name} - Multi-Region 활성화")
            results.append({
                "item": "CloudTrail Multi-Region",
                "target": trail_name,
                "risk": "Low",
                "status": "Pass",
                "kisa_code": "KISA-CLD-09",
                "detail": f"{trail_name} 트레일은 Multi-Region으로 설정되어 있습니다."
            })
        else:
            print(f"[FAIL] {trail_name} - Multi-Region 비활성화")
            results.append({
                "item": "CloudTrail Multi-Region",
                "target": trail_name,
                "risk": "Medium",
                "status": "Fail",
                "kisa_code": "KISA-CLD-09",
                "detail": f"{trail_name} 트레일은 Multi-Region으로 설정되어 있지 않습니다."
            })

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
                "status": "Pass",
                "kisa_code": "KISA-CLD-10",
                "detail": f"{trail_name} 트레일은 KMS를 사용하여 로그 암호화가 설정되어 있습니다."
            })
        else:
            print(f"[FAIL] {trail_name} - 로그 암호화 미설정")
            results.append({
                "item": "CloudTrail Log Encryption",
                "target": trail_name,
                "risk": "Medium",
                "status": "Fail",
                "kisa_code": "KISA-CLD-10",
                "detail": f"{trail_name} 트레일은 로그 암호화(KMS)가 설정되어 있지 않습니다."
            })

    return results