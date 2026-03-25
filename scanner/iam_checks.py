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