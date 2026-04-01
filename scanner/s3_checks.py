import boto3
from botocore.exceptions import ClientError


def check_s3_public_access():
    s3 = boto3.client("s3")
    results = []

    print("\n=== S3 Public Access 점검 결과 ===")

    buckets = s3.list_buckets()["Buckets"]

    if not buckets:
        print("[INFO] S3 버킷이 없습니다.")
        results.append({
            "item": "S3 Public Access Block",
            "target": "None",
            "risk": "Low",
            "status": "Pass",
            "kisa_code": "KISA-CLD-01",
            "detail": "점검할 S3 버킷이 없습니다."
        })
        return results

    for bucket in buckets:
        bucket_name = bucket["Name"]

        try:
            pab = s3.get_public_access_block(Bucket=bucket_name)
            config = pab["PublicAccessBlockConfiguration"]

            if all(config.values()):
                print(f"[PASS] {bucket_name} - Public Access 차단됨")
                results.append({
                    "item": "S3 Public Access Block",
                    "target": bucket_name,
                    "risk": "High",
                    "status": "Pass",
                    "kisa_code": "KISA-CLD-01",
                    "detail": f"{bucket_name} 버킷은 Public Access Block이 활성화되어 있습니다."
                })
            else:
                print(f"[FAIL] {bucket_name} - Public Access 차단 미흡")
                results.append({
                    "item": "S3 Public Access Block",
                    "target": bucket_name,
                    "risk": "High",
                    "status": "Fail",
                    "kisa_code": "KISA-CLD-01",
                    "detail": f"{bucket_name} 버킷은 Public Access Block 설정이 미흡합니다."
                })

        except ClientError:
            print(f"[FAIL] {bucket_name} - Public Access Block 설정 없음")
            results.append({
                "item": "S3 Public Access Block",
                "target": bucket_name,
                "risk": "High",
                "status": "Fail",
                "kisa_code": "KISA-CLD-01",
                "detail": f"{bucket_name} 버킷의 Public Access Block 설정을 확인할 수 없습니다."
            })

    return results


def check_s3_bucket_encryption():
    s3 = boto3.client("s3")
    results = []

    print("\n=== S3 버킷 암호화 점검 결과 ===")

    buckets = s3.list_buckets()["Buckets"]

    if not buckets:
        print("[INFO] S3 버킷이 없습니다.")
        results.append({
            "item": "S3 Bucket Encryption",
            "target": "None",
            "risk": "Low",
            "status": "Pass",
            "kisa_code": "KISA-CLD-05",
            "detail": "점검할 S3 버킷이 없습니다."
        })
        return results

    for bucket in buckets:
        bucket_name = bucket["Name"]

        try:
            s3.get_bucket_encryption(Bucket=bucket_name)
            print(f"[PASS] {bucket_name} - 암호화 설정됨")
            results.append({
                "item": "S3 Bucket Encryption",
                "target": bucket_name,
                "risk": "Medium",
                "status": "Pass",
                "kisa_code": "KISA-CLD-05",
                "detail": f"{bucket_name} 버킷은 기본 암호화가 설정되어 있습니다."
            })

        except ClientError:
            print(f"[FAIL] {bucket_name} - 암호화 미설정")
            results.append({
                "item": "S3 Bucket Encryption",
                "target": bucket_name,
                "risk": "Medium",
                "status": "Fail",
                "kisa_code": "KISA-CLD-05",
                "detail": f"{bucket_name} 버킷은 기본 암호화가 설정되어 있지 않습니다."
            })

    return results


def check_s3_bucket_versioning():
    s3 = boto3.client("s3")
    results = []

    print("\n=== S3 버킷 버전 관리 점검 결과 ===")

    buckets = s3.list_buckets()["Buckets"]

    if not buckets:
        print("[INFO] S3 버킷이 없습니다.")
        results.append({
            "item": "S3 Bucket Versioning",
            "target": "None",
            "risk": "Low",
            "status": "Pass",
            "kisa_code": "KISA-CLD-06",
            "detail": "점검할 S3 버킷이 없습니다."
        })
        return results

    for bucket in buckets:
        bucket_name = bucket["Name"]

        try:
            response = s3.get_bucket_versioning(Bucket=bucket_name)
            status = response.get("Status", "")

            if status == "Enabled":
                print(f"[PASS] {bucket_name} - 버전 관리 활성화")
                results.append({
                    "item": "S3 Bucket Versioning",
                    "target": bucket_name,
                    "risk": "Low",
                    "status": "Pass",
                    "kisa_code": "KISA-CLD-06",
                    "detail": f"{bucket_name} 버킷은 버전 관리가 활성화되어 있습니다."
                })
            else:
                print(f"[FAIL] {bucket_name} - 버전 관리 비활성화")
                results.append({
                    "item": "S3 Bucket Versioning",
                    "target": bucket_name,
                    "risk": "Low",
                    "status": "Fail",
                    "kisa_code": "KISA-CLD-06",
                    "detail": f"{bucket_name} 버킷은 버전 관리가 비활성화되어 있습니다."
                })

        except ClientError:
            print(f"[FAIL] {bucket_name} - 버전 관리 확인 불가")
            results.append({
                "item": "S3 Bucket Versioning",
                "target": bucket_name,
                "risk": "Low",
                "status": "Fail",
                "kisa_code": "KISA-CLD-06",
                "detail": f"{bucket_name} 버킷의 버전 관리 상태를 확인할 수 없습니다."
            })

    return results