import json
import yaml
from pathlib import Path


INPUT_SCAN_RESULT = "outputs/scan_result.json"
KB_PATH = "base/sk_aws_kb.yaml"
OUTPUT_ENRICHED = "outputs/enriched_findings.json"


def load_json(path):
    print(f"JSON 읽는 중: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_yaml(path):
    print(f"YAML 읽는 중: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def map_to_sk_guide_id(result):
    """
    scan_result.json의 item 이름을
    SK쉴더스 클라우드 보안 가이드 항목 번호와 매핑하는 함수
    """
    item = result.get("item", "")

    item_mapping = {
        # 계정 관리
        "IAM Admin User": "1.7",
        "IAM Access Key Unused": "1.8",
        "Root Account MFA Enabled": "1.9",
        "IAM User MFA Enabled": "1.9",
        "IAM Password Policy": "1.10",

        # 보안 그룹 / 네트워크
        "Security Group ALL Open": "3.1",
        "Security Group SSH Open": "3.1",
        "Security Group RDP Open": "3.1",
        "Security Group Unused Rule": "3.2",
        "Network ACL Open": "3.3",
        "Route Table Public Route": "3.4",
        "Internet Gateway Attached": "3.5",
        "NAT Gateway Attached": "3.6",

        # S3
        "S3 Public Access Block": "3.7",
        "S3 Bucket Encryption": "4.3",
        "S3 Bucket Versioning": "4.13",
        "S3 Bucket Logging": "4.10",

        # RDS
        "RDS Public Access": "3.8",
        "RDS Encryption": "4.2",
        "RDS Logging": "4.9",

        # EBS / EC2
        "EBS Encryption": "4.1",
        "EC2 Instance Logging": "4.8",
        "Key Pair Access": "1.5",
        "Key Pair Storage": "1.6",

        # CloudTrail / CloudWatch / VPC Flow Logs
        "CloudTrail Enabled": "4.7",
        "CloudTrail Encryption": "4.5",
        "CloudWatch Encryption": "4.6",
        "VPC Flow Logs Enabled": "4.11",
        "Log Retention Period": "4.12",

        # EKS
        "EKS User Management": "1.11",
        "EKS Service Account": "1.12",
        "EKS Anonymous Access": "1.13",
        "EKS Pod Security": "3.9",
        "EKS Control Plane Logging": "4.14",
        "EKS Cluster Encryption": "4.15",

        # ELB / 통신구간
        "ELB Connection": "3.10",
        "TLS Encryption": "4.4",
        "Communication Encryption": "4.4",

        # 권한 관리
        "Instance Service Policy": "2.1",
        "Network Service Policy": "2.2",
        "Other Service Policy": "2.3",
    }

    return item_mapping.get(item)


def normalize_risk(risk):
    """
    영어 위험도를 한국어 위험도로 변환
    """
    risk_map = {
        "High": "상",
        "Medium": "중",
        "Low": "하"
    }

    return risk_map.get(risk, risk)


def normalize_status(status):
    """
    Pass/Fail을 PASS/FAIL 형태로 통일
    """
    status_map = {
        "Pass": "PASS",
        "Fail": "FAIL"
    }

    return status_map.get(status, status)


def enrich_findings(scan_result, kb):
    """
    scan_result.json의 Fail 항목만 골라서
    SK쉴더스 YAML 지식베이스와 연결
    """
    enriched = []

    results = scan_result.get("results", [])
    print(f"전체 점검 결과 수: {len(results)}")

    for result in results:
        status = normalize_status(result.get("status"))

        # 리포트에는 취약 항목만 포함
        if status != "FAIL":
            continue

        sk_guide_id = map_to_sk_guide_id(result)

        if sk_guide_id:
            guide_context = kb.get(str(sk_guide_id))
        else:
            guide_context = None

        finding = {
            "item": result.get("item"),
            "target": result.get("target"),
            "risk": normalize_risk(result.get("risk")),
            "status": status,
            "kisa_code": result.get("kisa_code"),
            "sk_guide_id": sk_guide_id,
            "detail": result.get("detail")
        }

        enriched.append({
            "finding": finding,
            "guide_context": guide_context,
            "context_status": "FOUND" if guide_context else "NOT_FOUND"
        })

    return enriched


def main():
    print("enrich_findings.py 실행 시작")

    scan_result = load_json(INPUT_SCAN_RESULT)
    print("scan_result.json 로드 성공")

    kb = load_yaml(KB_PATH)
    print("SK쉴더스 YAML 로드 성공")

    enriched = enrich_findings(scan_result, kb)

    Path("outputs").mkdir(exist_ok=True)

    with open(OUTPUT_ENRICHED, "w", encoding="utf-8") as f:
        json.dump(enriched, f, ensure_ascii=False, indent=2)

    print(f"컨텍스트 매칭 완료: {OUTPUT_ENRICHED}")
    print(f"취약 항목 수: {len(enriched)}")

    not_found = [x for x in enriched if x["context_status"] == "NOT_FOUND"]

    if not_found:
        print(f"매칭 실패 항목 수: {len(not_found)}")
        for item in not_found:
            finding = item["finding"]
            print(
                "-",
                finding.get("item"),
                "/ 대상:",
                finding.get("target"),
                "/ KISA 코드:",
                finding.get("kisa_code")
            )
    else:
        print("모든 취약 항목이 SK쉴더스 가이드와 매칭되었습니다.")


if __name__ == "__main__":
    main()