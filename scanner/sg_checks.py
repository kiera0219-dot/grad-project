import boto3


def check_security_group_ssh_open():
    ec2 = boto3.client("ec2", region_name="ap-northeast-2")
    results = []

    response = ec2.describe_security_groups()
    security_groups = response["SecurityGroups"]

    print("\n=== Security Group SSH(22) 점검 결과 ===")

    for sg in security_groups:
        sg_name = sg.get("GroupName", "Unknown")
        sg_id = sg.get("GroupId", "Unknown")
        target = f"{sg_name} ({sg_id})"

        found_risk = False

        for permission in sg.get("IpPermissions", []):
            from_port = permission.get("FromPort")
            to_port = permission.get("ToPort")

            if from_port == 22 and to_port == 22:
                for ip_range in permission.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        found_risk = True
                        print(f"[FAIL] {target} - SSH 전체 개방")
                        results.append({
                            "item": "Security Group SSH Open",
                            "target": target,
                            "risk": "High",
                            "status": "Fail",
                            "kisa_code": "KISA-CLD-03",
                            "detail": f"{target}에서 22번 포트가 0.0.0.0/0으로 열려 있습니다."
                        })

        if not found_risk:
            print(f"[PASS] {target} - SSH 전체 개방 없음")
            results.append({
                "item": "Security Group SSH Open",
                "target": target,
                "risk": "Low",
                "status": "Pass",
                "kisa_code": "KISA-CLD-03",
                "detail": f"{target}는 22번 포트 전체 개방이 없습니다."
            })

    return results


def check_security_group_rdp_open():
    ec2 = boto3.client("ec2", region_name="ap-northeast-2")
    results = []

    response = ec2.describe_security_groups()
    security_groups = response["SecurityGroups"]

    print("\n=== Security Group RDP(3389) 점검 결과 ===")

    for sg in security_groups:
        sg_name = sg.get("GroupName", "Unknown")
        sg_id = sg.get("GroupId", "Unknown")
        target = f"{sg_name} ({sg_id})"

        found_risk = False

        for permission in sg.get("IpPermissions", []):
            from_port = permission.get("FromPort")
            to_port = permission.get("ToPort")

            if from_port == 3389 and to_port == 3389:
                for ip_range in permission.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        found_risk = True
                        print(f"[FAIL] {target} - RDP 전체 개방")
                        results.append({
                            "item": "Security Group RDP Open",
                            "target": target,
                            "risk": "High",
                            "status": "Fail",
                            "kisa_code": "KISA-CLD-07",
                            "detail": f"{target}에서 3389번 포트가 0.0.0.0/0으로 열려 있습니다."
                        })

        if not found_risk:
            print(f"[PASS] {target} - RDP 전체 개방 없음")
            results.append({
                "item": "Security Group RDP Open",
                "target": target,
                "risk": "Low",
                "status": "Pass",
                "kisa_code": "KISA-CLD-07",
                "detail": f"{target}는 3389번 포트 전체 개방이 없습니다."
            })

    return results


def check_security_group_all_open():
    ec2 = boto3.client("ec2", region_name="ap-northeast-2")
    results = []

    print("\n=== Security Group 전체 포트 개방 점검 결과 ===")

    response = ec2.describe_security_groups()
    security_groups = response["SecurityGroups"]

    for sg in security_groups:
        sg_name = sg.get("GroupName", "Unknown")
        sg_id = sg.get("GroupId", "Unknown")
        target = f"{sg_name} ({sg_id})"

        found_risk = False

        for permission in sg.get("IpPermissions", []):
            from_port = permission.get("FromPort")
            to_port = permission.get("ToPort")
            ip_ranges = permission.get("IpRanges", [])

            for ip in ip_ranges:
                cidr = ip.get("CidrIp")

                if cidr == "0.0.0.0/0" and (
                    from_port is None or
                    to_port is None or
                    (from_port == 0 and to_port == 65535)
                ):
                    found_risk = True
                    print(f"[FAIL] {target} - 전체 포트 개방")
                    results.append({
                        "item": "Security Group ALL Open",
                        "target": target,
                        "risk": "High",
                        "status": "Fail",
                        "kisa_code": "KISA-CLD-13",
                        "detail": f"{target}은 모든 포트가 0.0.0.0/0에 개방되어 있습니다."
                    })
                    break

            if found_risk:
                break

        if not found_risk:
            print(f"[PASS] {target} - 전체 개방 없음")
            results.append({
                "item": "Security Group ALL Open",
                "target": target,
                "risk": "Low",
                "status": "Pass",
                "kisa_code": "KISA-CLD-13",
                "detail": f"{target}은 전체 포트 개방이 없습니다."
            })

    return results