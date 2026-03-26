import boto3


def check_iam_users_mfa():
    iam = boto3.client("iam")
    results = []

    users = iam.list_users()["Users"]

    print("=== IAM 사용자 MFA 점검 결과 ===")

    for user in users:
        username = user["UserName"]
        mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]

        if len(mfa_devices) == 0:
            print(f"[FAIL] {username} - MFA 미설정")
            results.append({
                "item": "IAM User MFA Enabled",
                "target": username,
                "risk": "High",
                "status": "Fail",
                "kisa_code": "KISA-CLD-02",
                "detail": f"{username} 사용자는 MFA가 설정되어 있지 않습니다."
            })
        else:
            print(f"[PASS] {username} - MFA 설정됨")
            results.append({
                "item": "IAM User MFA Enabled",
                "target": username,
                "risk": "Low",
                "status": "Pass",
                "kisa_code": "KISA-CLD-02",
                "detail": f"{username} 사용자는 MFA가 설정되어 있습니다."
            })

    return results

def check_root_account_mfa():
    iam = boto3.client("iam")
    results = []

    print("\n=== 루트 계정 MFA 점검 결과 ===")

    summary = iam.get_account_summary()["SummaryMap"]
    root_mfa_enabled = summary.get("AccountMFAEnabled", 0)

    if root_mfa_enabled == 1:
        print("[PASS] Root Account - MFA 설정됨")
        results.append({
            "item": "Root Account MFA Enabled",
            "target": "Root Account",
            "risk": "High",
            "status": "Pass",
            "kisa_code": "KISA-CLD-08",
            "detail": "루트 계정에 MFA가 설정되어 있습니다."
        })
    else:
        print("[FAIL] Root Account - MFA 미설정")
        results.append({
            "item": "Root Account MFA Enabled",
            "target": "Root Account",
            "risk": "High",
            "status": "Fail",
            "kisa_code": "KISA-CLD-08",
            "detail": "루트 계정에 MFA가 설정되어 있지 않습니다."
        })

    return results

def check_iam_password_policy():
    iam = boto3.client("iam")
    results = []

    print("\n=== IAM 비밀번호 정책 점검 결과 ===")

    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]

        min_length = policy.get("MinimumPasswordLength", 0)
        require_uppercase = policy.get("RequireUppercaseCharacters", False)
        require_lowercase = policy.get("RequireLowercaseCharacters", False)
        require_numbers = policy.get("RequireNumbers", False)
        require_symbols = policy.get("RequireSymbols", False)
        password_reuse_prevention = policy.get("PasswordReusePrevention", 0)
        max_password_age = policy.get("MaxPasswordAge", 0)

        if (
            min_length >= 8 and
            require_uppercase and
            require_lowercase and
            require_numbers and
            require_symbols
        ):
            print("[PASS] IAM Password Policy - 강력한 비밀번호 정책 설정됨")
            results.append({
                "item": "IAM Password Policy",
                "target": "Account",
                "risk": "Medium",
                "status": "Pass",
                "kisa_code": "KISA-CLD-09",
                "detail": f"최소 길이 {min_length}, 대/소문자, 숫자, 특수문자 포함 정책이 설정되어 있습니다."
            })
        else:
            print("[FAIL] IAM Password Policy - 비밀번호 정책이 약하거나 일부 누락됨")
            results.append({
                "item": "IAM Password Policy",
                "target": "Account",
                "risk": "Medium",
                "status": "Fail",
                "kisa_code": "KISA-CLD-09",
                "detail": f"최소 길이={min_length}, 대문자={require_uppercase}, 소문자={require_lowercase}, 숫자={require_numbers}, 특수문자={require_symbols}"
            })

        if password_reuse_prevention > 0:
            print(f"[PASS] Password Reuse Prevention - 최근 {password_reuse_prevention}개 재사용 방지")
        else:
            print("[FAIL] Password Reuse Prevention - 재사용 방지 미설정")

        if max_password_age > 0:
            print(f"[PASS] Password Expiration - {max_password_age}일 후 만료")
        else:
            print("[FAIL] Password Expiration - 만료 기간 미설정")

    except iam.exceptions.NoSuchEntityException:
        print("[FAIL] IAM Password Policy - 계정 비밀번호 정책이 설정되어 있지 않습니다.")
        results.append({
            "item": "IAM Password Policy",
            "target": "Account",
            "risk": "Medium",
            "status": "Fail",
            "kisa_code": "KISA-CLD-09",
            "detail": "IAM 계정 비밀번호 정책이 설정되어 있지 않습니다."
        })

    return results

def check_iam_access_key_unused(days_threshold=90):
    import boto3
    from datetime import datetime, timezone

    iam = boto3.client("iam")
    results = []

    print("\n=== IAM Access Key 미사용 점검 결과 ===")

    users = iam.list_users()["Users"]

    for user in users:
        user_name = user["UserName"]

        access_keys = iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]

        for key in access_keys:
            access_key_id = key["AccessKeyId"]

            last_used_info = iam.get_access_key_last_used(AccessKeyId=access_key_id)
            last_used_date = last_used_info["AccessKeyLastUsed"].get("LastUsedDate")

            if last_used_date:
                unused_days = (datetime.now(timezone.utc) - last_used_date).days

                if unused_days >= days_threshold:
                    print(f"[FAIL] {user_name} - {unused_days}일 미사용")
                    results.append({
                        "item": "IAM Access Key Unused",
                        "target": user_name,
                        "risk": "Medium",
                        "status": "Fail",
                        "kisa_code": "KISA-CLD-11",
                        "detail": f"{unused_days}일 동안 사용되지 않음"
                    })
                else:
                    print(f"[PASS] {user_name} - 최근 사용됨")
                    results.append({
                        "item": "IAM Access Key Unused",
                        "target": user_name,
                        "risk": "Low",
                        "status": "Pass",
                        "kisa_code": "KISA-CLD-11",
                        "detail": "최근 사용됨"
                    })

    return results

def check_iam_admin_users():
    import boto3

    iam = boto3.client("iam")
    results = []

    print("\n=== IAM 관리자 권한 사용자 점검 결과 ===")

    users = iam.list_users()["Users"]

    for user in users:
        user_name = user["UserName"]

        attached_policies = iam.list_attached_user_policies(UserName=user_name)["AttachedPolicies"]

        is_admin = False

        for policy in attached_policies:
            if policy["PolicyName"] == "AdministratorAccess":
                is_admin = True
                break

        if is_admin:
            print(f"[FAIL] {user_name} - 관리자 권한 보유")
            results.append({
                "item": "IAM Admin User",
                "target": user_name,
                "risk": "High",
                "status": "Fail",
                "kisa_code": "KISA-CLD-12",
                "detail": f"{user_name} 사용자는 AdministratorAccess 권한을 가지고 있습니다."
            })
        else:
            print(f"[PASS] {user_name} - 관리자 권한 없음")
            results.append({
                "item": "IAM Admin User",
                "target": user_name,
                "risk": "Low",
                "status": "Pass",
                "kisa_code": "KISA-CLD-12",
                "detail": f"{user_name} 사용자는 관리자 권한이 없습니다."
            })

    return results


