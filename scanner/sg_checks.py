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

        found_risk = False

        for permission in sg.get("IpPermissions", []):
            from_port = permission.get("FromPort")
            to_port = permission.get("ToPort")

            if from_port == 22 and to_port == 22:
                for ip_range in permission.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        found_risk = True
                        print(f"[FAIL] {sg_name} ({sg_id}) - SSH 전체 개방")
                        results.append({
                            "item": "Security Group SSH Open",
                            "target": f"{sg_name} ({sg_id})",
                            "risk": "High",
                            "status": "Fail",
                            "kisa_code": "KISA-CLD-03",
                            "detail": f"{sg_name} 보안그룹에서 22번 포트가 0.0.0.0/0 으로 열려 있습니다."
                        })

        if not found_risk:
            print(f"[PASS] {sg_name} ({sg_id}) - SSH 전체 개방 없음")
            results.append({
                "item": "Security Group SSH Open",
                "target": f"{sg_name} ({sg_id})",
                "risk": "Low",
                "status": "Pass",
                "kisa_code": "KISA-CLD-03",
                "detail": f"{sg_name} 보안그룹은 22번 포트 전체 개방이 없습니다."
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

        found_risk = False

        for permission in sg.get("IpPermissions", []):
            from_port = permission.get("FromPort")
            to_port = permission.get("ToPort")

            if from_port == 3389 and to_port == 3389:
                for ip_range in permission.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        found_risk = True
                        print(f"[FAIL] {sg_name} ({sg_id}) - RDP 전체 개방")
                        results.append({
                            "item": "Security Group RDP Open",
                            "target": f"{sg_name} ({sg_id})",
                            "risk": "High",
                            "status": "Fail",
                            "kisa_code": "KISA-CLD-07",
                            "detail": f"{sg_name} 보안그룹에서 3389번 포트가 0.0.0.0/0 으로 열려 있습니다."
                        })

        if not found_risk:
            print(f"[PASS] {sg_name} ({sg_id}) - RDP 전체 개방 없음")
            results.append({
                "item": "Security Group RDP Open",
                "target": f"{sg_name} ({sg_id})",
                "risk": "Low",
                "status": "Pass",
                "kisa_code": "KISA-CLD-07",
                "detail": f"{sg_name} 보안그룹은 3389번 포트 전체 개방이 없습니다."
            })

    return results

def check_security_group_all_open():
    import boto3

    ec2 = boto3.client("ec2")
    results = []

    print("\n=== Security Group 전체 포트 개방 점검 결과 ===")

    response = ec2.describe_security_groups()
    security_groups = response["SecurityGroups"]

    for sg in security_groups:
        sg_name = sg["GroupName"]
        sg_id = sg["GroupId"]

        for permission in sg["IpPermissions"]:
            from_port = permission.get("FromPort")
            to_port = permission.get("ToPort")
            ip_ranges = permission.get("IpRanges", [])

            for ip in ip_ranges:
                cidr = ip["CidrIp"]

                # 모든 포트 허용 (FromPort / ToPort 없거나 0-65535)
                if cidr == "0.0.0.0/0" and (
                    from_port is None or
                    to_port is None or
                    (from_port == 0 and to_port == 65535)
                ):
                    print(f"[FAIL] {sg_name} ({sg_id}) - 전체 포트 개방")
                    results.append({
                        "item": "Security Group ALL Open",
                        "target": sg_name,
                        "risk": "High",
                        "status": "Fail",
                        "kisa_code": "KISA-CLD-13",
                        "detail": f"{sg_name} ({sg_id})은 모든 포트가 0.0.0.0/0에 개방되어 있습니다."
                    })
                    break
        else:
            print(f"[PASS] {sg_name} ({sg_id}) - 전체 개방 없음")
            results.append({
                "item": "Security Group ALL Open",
                "target": sg_name,
                "risk": "Low",
                "status": "Pass",
                "kisa_code": "KISA-CLD-13",
                "detail": f"{sg_name} ({sg_id})은 전체 포트 개방이 없습니다."
            })

    return results