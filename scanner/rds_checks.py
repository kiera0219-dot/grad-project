import boto3

def check_rds_public_access():
    rds = boto3.client("rds", region_name="ap-northeast-2")
    results = []

    print("\n=== RDS 점검 결과 ===")

    response = rds.describe_db_instances()
    db_instances = response["DBInstances"]

    if not db_instances:
        print("RDS 인스턴스가 없습니다.")
        return results

    for db in db_instances:
        db_id = db["DBInstanceIdentifier"]

        # -----------------------------
        # 1. Public Access 검사
        # -----------------------------
        public = db.get("PubliclyAccessible")

        if public:
            print(f"[FAIL] {db_id} - Public 접근 가능")
            results.append({
                "item": "RDS Public Access",
                "target": db_id,
                "risk": "High",
                "status": "Fail",
                "kisa_code": "KISA-CLD-04",
                "detail": f"{db_id} 인스턴스는 Publicly Accessible 상태입니다."
            })
        else:
            print(f"[PASS] {db_id} - Public 접근 차단")
            results.append({
                "item": "RDS Public Access",
                "target": db_id,
                "risk": "Low",
                "status": "Pass",
                "kisa_code": "KISA-CLD-04",
                "detail": f"{db_id} 인스턴스는 Public 접근이 차단되어 있습니다."
            })

        # -----------------------------
        # 2. 암호화 검사
        # -----------------------------
        encrypted = db.get("StorageEncrypted")

        if encrypted:
            print(f"[PASS] {db_id} - 암호화 활성화")
            results.append({
                "item": "RDS Encryption",
                "target": db_id,
                "risk": "Low",
                "status": "Pass",
                "kisa_code": "KISA-CLD-05",
                "detail": f"{db_id} 인스턴스는 암호화가 적용되어 있습니다."
            })
        else:
            print(f"[FAIL] {db_id} - 암호화 비활성화")
            results.append({
                "item": "RDS Encryption",
                "target": db_id,
                "risk": "High",
                "status": "Fail",
                "kisa_code": "KISA-CLD-05",
                "detail": f"{db_id} 인스턴스는 암호화가 적용되어 있지 않습니다."
            })

        # -----------------------------
        # 3. 자동 백업 검사
        # -----------------------------
        backup = db.get("BackupRetentionPeriod", 0)

        if backup > 0:
            print(f"[PASS] {db_id} - 자동 백업 활성화")
            results.append({
                "item": "RDS Backup",
                "target": db_id,
                "risk": "Low",
                "status": "Pass",
                "kisa_code": "KISA-CLD-06",
                "detail": f"{db_id} 인스턴스는 자동 백업이 설정되어 있습니다."
            })
        else:
            print(f"[FAIL] {db_id} - 자동 백업 비활성화")
            results.append({
                "item": "RDS Backup",
                "target": db_id,
                "risk": "Medium",
                "status": "Fail",
                "kisa_code": "KISA-CLD-06",
                "detail": f"{db_id} 인스턴스는 자동 백업이 설정되어 있지 않습니다."
            })

        # -----------------------------
        # 4. Multi-AZ 검사
        # -----------------------------
        multi_az = db.get("MultiAZ")

        if multi_az:
            print(f"[PASS] {db_id} - Multi-AZ 활성화")
            results.append({
                "item": "RDS Multi-AZ",
                "target": db_id,
                "risk": "Low",
                "status": "Pass",
                "kisa_code": "KISA-CLD-07",
                "detail": f"{db_id} 인스턴스는 Multi-AZ 구성이 활성화되어 있습니다."
            })
        else:
            print(f"[FAIL] {db_id} - Multi-AZ 비활성화")
            results.append({
                "item": "RDS Multi-AZ",
                "target": db_id,
                "risk": "Medium",
                "status": "Fail",
                "kisa_code": "KISA-CLD-07",
                "detail": f"{db_id} 인스턴스는 Multi-AZ 구성이 비활성화되어 있습니다."
            })

    return results