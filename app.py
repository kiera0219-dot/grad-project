from flask import Flask, request, render_template_string, send_file
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import json
import subprocess
import sys
from pathlib import Path

app = Flask(__name__)
app.secret_key = "change-this-secret-key"

# =========================
# 경로 설정
# =========================
OUTPUT_DIR = Path("outputs")
SCAN_RESULT_PATH = OUTPUT_DIR / "scan_result.json"
REPORT_MD_PATH = OUTPUT_DIR / "security_report.md"
REPORT_PDF_PATH = OUTPUT_DIR / "security_report.pdf"

# =========================
# 공통 유틸
# =========================
def make_result(service, check, status, score, message):
    return {
        "service": service,
        "check": check,
        "status": status,
        "score": score,
        "message": message
    }

def error_result(service, check, error):
    return {
        "service": service,
        "check": check,
        "status": "ERROR",
        "score": 0,
        "message": str(error)
    }

# =========================
# AWS 보안 점검 함수
# =========================
def check_iam_admin_users(session):
    iam = session.client("iam")

    try:
        users = iam.list_users().get("Users", [])
        admin_users = []

        for user in users:
            username = user["UserName"]

            attached_policies = iam.list_attached_user_policies(
                UserName=username
            ).get("AttachedPolicies", [])

            for policy in attached_policies:
                if policy.get("PolicyName") == "AdministratorAccess":
                    admin_users.append(username)

        if admin_users:
            return make_result(
                "IAM",
                "IAM 관리자 권한 사용자 점검",
                "FAIL",
                0,
                f"AdministratorAccess 권한 사용자: {', '.join(admin_users)}"
            )

        return make_result(
            "IAM",
            "IAM 관리자 권한 사용자 점검",
            "PASS",
            10,
            "AdministratorAccess 권한을 가진 IAM 사용자가 없습니다."
        )

    except ClientError as e:
        return error_result("IAM", "IAM 관리자 권한 사용자 점검", e)

def check_iam_mfa(session):
    iam = session.client("iam")

    try:
        users = iam.list_users().get("Users", [])

        if not users:
            return make_result(
                "IAM",
                "IAM 사용자 MFA 설정 여부",
                "PASS",
                10,
                "IAM 사용자가 없습니다."
            )

        no_mfa_users = []

        for user in users:
            username = user["UserName"]
            mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])

            if not mfa_devices:
                no_mfa_users.append(username)

        if no_mfa_users:
            return make_result(
                "IAM",
                "IAM 사용자 MFA 설정 여부",
                "FAIL",
                0,
                f"MFA 미설정 사용자: {', '.join(no_mfa_users)}"
            )

        return make_result(
            "IAM",
            "IAM 사용자 MFA 설정 여부",
            "PASS",
            10,
            "모든 IAM 사용자에게 MFA가 설정되어 있습니다."
        )

    except ClientError as e:
        return error_result("IAM", "IAM 사용자 MFA 설정 여부", e)

def check_root_mfa(session):
    iam = session.client("iam")

    try:
        summary = iam.get_account_summary().get("SummaryMap", {})
        root_mfa_enabled = summary.get("AccountMFAEnabled", 0)

        if root_mfa_enabled == 1:
            return make_result(
                "IAM",
                "Root 계정 MFA 설정 여부",
                "PASS",
                10,
                "Root 계정에 MFA가 설정되어 있습니다."
            )

        return make_result(
            "IAM",
            "Root 계정 MFA 설정 여부",
            "FAIL",
            0,
            "Root 계정에 MFA가 설정되어 있지 않습니다."
        )

    except ClientError as e:
        return error_result("IAM", "Root 계정 MFA 설정 여부", e)

def check_password_policy(session):
    iam = session.client("iam")

    try:
        policy = iam.get_account_password_policy().get("PasswordPolicy", {})

        min_length = policy.get("MinimumPasswordLength", 0)
        require_symbols = policy.get("RequireSymbols", False)
        require_numbers = policy.get("RequireNumbers", False)
        require_uppercase = policy.get("RequireUppercaseCharacters", False)
        require_lowercase = policy.get("RequireLowercaseCharacters", False)

        if (
            min_length >= 8
            and require_symbols
            and require_numbers
            and require_uppercase
            and require_lowercase
        ):
            return make_result(
                "IAM",
                "계정 비밀번호 정책 설정",
                "PASS",
                10,
                "비밀번호 정책이 적절하게 설정되어 있습니다."
            )

        return make_result(
            "IAM",
            "계정 비밀번호 정책 설정",
            "FAIL",
            0,
            "비밀번호 길이, 대소문자, 숫자, 특수문자 정책이 부족합니다."
        )

    except ClientError as e:
        return make_result(
            "IAM",
            "계정 비밀번호 정책 설정",
            "FAIL",
            0,
            f"비밀번호 정책이 설정되어 있지 않거나 확인할 수 없습니다: {e}"
        )

def check_s3_public_access(session):
    s3 = session.client("s3")

    try:
        buckets = s3.list_buckets().get("Buckets", [])

        if not buckets:
            return make_result(
                "S3",
                "S3 버킷 퍼블릭 접근 차단",
                "PASS",
                10,
                "S3 버킷이 없습니다."
            )

        weak_buckets = []

        for bucket in buckets:
            bucket_name = bucket["Name"]

            try:
                block = s3.get_public_access_block(Bucket=bucket_name)
                config = block.get("PublicAccessBlockConfiguration", {})

                if not all([
                    config.get("BlockPublicAcls", False),
                    config.get("IgnorePublicAcls", False),
                    config.get("BlockPublicPolicy", False),
                    config.get("RestrictPublicBuckets", False),
                ]):
                    weak_buckets.append(bucket_name)

            except ClientError:
                weak_buckets.append(bucket_name)

        if weak_buckets:
            return make_result(
                "S3",
                "S3 버킷 퍼블릭 접근 차단",
                "FAIL",
                0,
                f"퍼블릭 접근 차단 미흡 버킷: {', '.join(weak_buckets)}"
            )

        return make_result(
            "S3",
            "S3 버킷 퍼블릭 접근 차단",
            "PASS",
            10,
            "모든 S3 버킷의 퍼블릭 접근 차단이 설정되어 있습니다."
        )

    except ClientError as e:
        return error_result("S3", "S3 버킷 퍼블릭 접근 차단", e)

def check_s3_encryption(session):
    s3 = session.client("s3")

    try:
        buckets = s3.list_buckets().get("Buckets", [])

        if not buckets:
            return make_result(
                "S3",
                "S3 버킷 암호화 설정",
                "PASS",
                10,
                "S3 버킷이 없습니다."
            )

        unencrypted_buckets = []

        for bucket in buckets:
            bucket_name = bucket["Name"]

            try:
                s3.get_bucket_encryption(Bucket=bucket_name)
            except ClientError:
                unencrypted_buckets.append(bucket_name)

        if unencrypted_buckets:
            return make_result(
                "S3",
                "S3 버킷 암호화 설정",
                "FAIL",
                0,
                f"암호화 미설정 버킷: {', '.join(unencrypted_buckets)}"
            )

        return make_result(
            "S3",
            "S3 버킷 암호화 설정",
            "PASS",
            10,
            "모든 S3 버킷에 암호화가 설정되어 있습니다."
        )

    except ClientError as e:
        return error_result("S3", "S3 버킷 암호화 설정", e)

def check_security_group_ssh_open(session):
    ec2 = session.client("ec2")

    try:
        groups = ec2.describe_security_groups().get("SecurityGroups", [])
        risky_groups = []

        for group in groups:
            group_name = group.get("GroupName", "")
            group_id = group.get("GroupId", "")

            for rule in group.get("IpPermissions", []):
                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")

                if from_port is None or to_port is None:
                    continue

                for ip_range in rule.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp")

                    if cidr == "0.0.0.0/0" and from_port <= 22 <= to_port:
                        risky_groups.append(f"{group_name}({group_id})")

        if risky_groups:
            return make_result(
                "Security Group",
                "SSH 22번 포트 전체 공개 여부",
                "FAIL",
                0,
                f"SSH가 전체 공개된 보안 그룹: {', '.join(risky_groups)}"
            )

        return make_result(
            "Security Group",
            "SSH 22번 포트 전체 공개 여부",
            "PASS",
            10,
            "SSH 포트가 전체 공개되어 있지 않습니다."
        )

    except ClientError as e:
        return error_result("Security Group", "SSH 22번 포트 전체 공개 여부", e)

def check_rds_public_access(session):
    rds = session.client("rds")

    try:
        instances = rds.describe_db_instances().get("DBInstances", [])

        if not instances:
            return make_result(
                "RDS",
                "RDS 퍼블릭 접근 여부",
                "PASS",
                10,
                "RDS 인스턴스가 없습니다."
            )

        public_instances = []

        for db in instances:
            if db.get("PubliclyAccessible", False):
                public_instances.append(db.get("DBInstanceIdentifier"))

        if public_instances:
            return make_result(
                "RDS",
                "RDS 퍼블릭 접근 여부",
                "FAIL",
                0,
                f"퍼블릭 접근 가능한 RDS: {', '.join(public_instances)}"
            )

        return make_result(
            "RDS",
            "RDS 퍼블릭 접근 여부",
            "PASS",
            10,
            "퍼블릭 접근 가능한 RDS가 없습니다."
        )

    except ClientError as e:
        return error_result("RDS", "RDS 퍼블릭 접근 여부", e)

def check_cloudtrail_enabled(session):
    cloudtrail = session.client("cloudtrail")

    try:
        trails = cloudtrail.describe_trails().get("trailList", [])

        if not trails:
            return make_result(
                "CloudTrail",
                "CloudTrail 활성화 여부",
                "FAIL",
                0,
                "CloudTrail이 생성되어 있지 않습니다."
            )

        return make_result(
            "CloudTrail",
            "CloudTrail 활성화 여부",
            "PASS",
            10,
            "CloudTrail이 생성되어 있습니다."
        )

    except ClientError as e:
        return error_result("CloudTrail", "CloudTrail 활성화 여부", e)

def run_security_scan(session):
    results = []

    results.append(check_iam_admin_users(session))
    results.append(check_iam_mfa(session))
    results.append(check_root_mfa(session))
    results.append(check_password_policy(session))
    results.append(check_s3_public_access(session))
    results.append(check_s3_encryption(session))
    results.append(check_security_group_ssh_open(session))
    results.append(check_rds_public_access(session))
    results.append(check_cloudtrail_enabled(session))

    return results

# =========================
# 리포팅 시스템 연동
# =========================
def convert_to_reporting_item(result):
    check = result.get("check", "")
    service = result.get("service", "")
    message = result.get("message", "")
    status = result.get("status", "")

    mapping = {
        "IAM 관리자 권한 사용자 점검": {
            "item": "IAM Admin User",
            "risk": "High",
            "kisa_code": "KISA-CLD-12"
        },
        "IAM 사용자 MFA 설정 여부": {
            "item": "IAM User MFA Enabled",
            "risk": "High",
            "kisa_code": "KISA-CLD-02"
        },
        "Root 계정 MFA 설정 여부": {
            "item": "Root Account MFA Enabled",
            "risk": "High",
            "kisa_code": "KISA-CLD-02"
        },
        "계정 비밀번호 정책 설정": {
            "item": "IAM Password Policy",
            "risk": "High",
            "kisa_code": "KISA-CLD-09"
        },
        "S3 버킷 퍼블릭 접근 차단": {
            "item": "S3 Public Access Block",
            "risk": "High",
            "kisa_code": "KISA-CLD-01"
        },
        "S3 버킷 암호화 설정": {
            "item": "S3 Bucket Encryption",
            "risk": "Medium",
            "kisa_code": "KISA-CLD-05"
        },
        "SSH 22번 포트 전체 공개 여부": {
            "item": "Security Group SSH Open",
            "risk": "High",
            "kisa_code": "KISA-CLD-03"
        },
        "RDS 퍼블릭 접근 여부": {
            "item": "RDS Public Access",
            "risk": "High",
            "kisa_code": "KISA-CLD-04"
        },
        "CloudTrail 활성화 여부": {
            "item": "CloudTrail Enabled",
            "risk": "High",
            "kisa_code": "KISA-CLD-08"
        },
    }

    info = mapping.get(check, {
        "item": check,
        "risk": "Medium",
        "kisa_code": "UNKNOWN"
    })

    converted_status = "Pass" if status == "PASS" else "Fail"

    return {
        "item": info["item"],
        "target": service,
        "risk": info["risk"],
        "status": converted_status,
        "kisa_code": info["kisa_code"],
        "detail": message
    }

def save_scan_result_for_reporting(results):
    converted_results = [
        convert_to_reporting_item(result)
        for result in results
    ]

    total_checks = len(converted_results)
    pass_count = sum(1 for item in converted_results if item["status"] == "Pass")
    fail_count = sum(1 for item in converted_results if item["status"] == "Fail")

    security_score = int((pass_count / total_checks) * 100) if total_checks else 0

    scan_result = {
        "summary": {
            "total_checks": total_checks,
            "pass_count": pass_count,
            "fail_count": fail_count,
            "security_score": security_score
        },
        "results": converted_results
    }

    OUTPUT_DIR.mkdir(exist_ok=True)

    with open(SCAN_RESULT_PATH, "w", encoding="utf-8") as f:
        json.dump(scan_result, f, ensure_ascii=False, indent=2)

    return scan_result

def run_script(script_path):
    result = subprocess.run(
        [sys.executable, script_path],
        capture_output=True,
        text=True,
        encoding="utf-8"
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"{script_path} 실행 실패\n\n"
            f"STDOUT:\n{result.stdout}\n\n"
            f"STDERR:\n{result.stderr}"
        )

    return result.stdout

def generate_security_report():
    run_script("reporting/enrich_findings.py")
    run_script("reporting/generate_report.py")
    run_script("reporting/generate_pdf.py")

def load_report_markdown():
    if REPORT_MD_PATH.exists():
        return REPORT_MD_PATH.read_text(encoding="utf-8")
    return ""

# =========================
# 웹 화면
# =========================
@app.route("/")
def index():
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <title>AWS 보안 점검 시스템</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background: #f4f6f8;
                padding: 40px;
            }

            .container {
                max-width: 720px;
                margin: auto;
                background: white;
                padding: 40px;
                border-radius: 16px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            }

            h1 {
                text-align: center;
                color: #1f2937;
            }

            label {
                display: block;
                margin-top: 20px;
                font-weight: bold;
            }

            input {
                width: 100%;
                padding: 12px;
                margin-top: 8px;
                border: 1px solid #d1d5db;
                border-radius: 8px;
                font-size: 15px;
            }

            button {
                width: 100%;
                margin-top: 30px;
                padding: 15px;
                background: #2563eb;
                color: white;
                border: none;
                border-radius: 10px;
                font-size: 18px;
                cursor: pointer;
            }

            .notice {
                margin-top: 20px;
                padding: 15px;
                background: #fef3c7;
                border-radius: 8px;
                color: #92400e;
                font-size: 14px;
            }

            .notice strong {
                color: #78350f;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>AWS 보안 점검 시스템</h1>

            <form action="/scan" method="POST">
                <label>AWS Access Key ID</label>
                <input type="text" name="access_key" required>

                <label>AWS Secret Access Key</label>
                <input type="password" name="secret_key" required>

                <label>Region</label>
                <input type="text" name="region" value="ap-northeast-2" required>

                <button type="submit">보안 점검 실행 및 리포트 생성</button>
            </form>

            <div class="notice">
                <strong>안내:</strong>
                입력한 AWS 키는 서버에 저장하지 않고 점검 요청 처리에만 사용됩니다.
                점검 후 자동으로 자연어 리포트와 PDF 리포트가 생성됩니다.
            </div>
        </div>
    </body>
    </html>
    """)

@app.route("/scan", methods=["POST"])
def scan():
    access_key = request.form.get("access_key")
    secret_key = request.form.get("secret_key")
    region = request.form.get("region")

    report_error = None
    report_md = ""

    try:
        aws_session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )

        # 자격 증명 확인
        sts = aws_session.client("sts")
        sts.get_caller_identity()

        # 1. AWS 자동 보안 점검
        results = run_security_scan(aws_session)

        # 2. 네 리포트 로직 입력 파일 생성
        save_scan_result_for_reporting(results)

        # 3. 네 리포팅 파이프라인 실행
        try:
            generate_security_report()
            report_md = load_report_markdown()
        except Exception as e:
            report_error = str(e)

    except NoCredentialsError:
        return "<h2>AWS 자격 증명이 올바르지 않습니다.</h2>"

    except Exception as e:
        return f"<h2>점검 중 오류 발생</h2><pre>{str(e)}</pre>"

    total_score = sum(item["score"] for item in results)
    max_score = len(results) * 10
    percent = round((total_score / max_score) * 100, 1) if max_score else 0

    pass_count = sum(1 for item in results if item["status"] == "PASS")
    fail_count = sum(1 for item in results if item["status"] == "FAIL")
    error_count = sum(1 for item in results if item["status"] == "ERROR")

    pdf_exists = REPORT_PDF_PATH.exists()

    return render_template_string("""
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <title>AWS 보안 점검 리포트</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background: #f4f6f8;
                padding: 40px;
            }

            .container {
                max-width: 1200px;
                margin: auto;
            }

            .summary {
                background: white;
                padding: 30px;
                border-radius: 16px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                margin-bottom: 30px;
            }

            .score {
                font-size: 48px;
                font-weight: bold;
                color: #2563eb;
            }

            .cards {
                display: flex;
                gap: 20px;
                margin-top: 20px;
            }

            .card {
                flex: 1;
                background: #f9fafb;
                padding: 20px;
                border-radius: 12px;
                text-align: center;
            }

            table {
                width: 100%;
                border-collapse: collapse;
                background: white;
                border-radius: 16px;
                overflow: hidden;
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                margin-bottom: 30px;
            }

            th, td {
                padding: 15px;
                border-bottom: 1px solid #e5e7eb;
                text-align: center;
            }

            th {
                background: #1f2937;
                color: white;
            }

            .PASS {
                color: #16a34a;
                font-weight: bold;
            }

            .FAIL {
                color: #dc2626;
                font-weight: bold;
            }

            .ERROR {
                color: #d97706;
                font-weight: bold;
            }

            .pdf-button {
                display: inline-block;
                padding: 14px 20px;
                background: #2563eb;
                color: white;
                border-radius: 10px;
                text-decoration: none;
                font-weight: bold;
                margin-bottom: 20px;
            }

            .report-box {
                background: white;
                padding: 25px;
                border-radius: 16px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                margin-top: 30px;
            }

            pre {
                white-space: pre-wrap;
                word-break: break-word;
                background: #f9fafb;
                padding: 20px;
                border-radius: 12px;
                max-height: 500px;
                overflow: auto;
            }

            .error-box {
                background: #fee2e2;
                color: #991b1b;
                padding: 20px;
                border-radius: 12px;
                margin-bottom: 30px;
                white-space: pre-wrap;
            }

            .back {
                display: inline-block;
                margin-top: 25px;
                color: #2563eb;
                text-decoration: none;
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <div class="container">

            <div class="summary">
                <h1>AWS 보안 점검 리포트</h1>
                <p>Region: {{ region }}</p>

                <div class="score">{{ total_score }} / {{ max_score }}점</div>
                <p>보안 준수율: {{ percent }}%</p>

                <div class="cards">
                    <div class="card">
                        <h3>PASS</h3>
                        <p>{{ pass_count }}개</p>
                    </div>
                    <div class="card">
                        <h3>FAIL</h3>
                        <p>{{ fail_count }}개</p>
                    </div>
                    <div class="card">
                        <h3>ERROR</h3>
                        <p>{{ error_count }}개</p>
                    </div>
                </div>
            </div>

            {% if report_error %}
            <div class="error-box">
                <strong>리포트 생성 중 오류가 발생했습니다.</strong>
                <br><br>
                {{ report_error }}
            </div>
            {% endif %}

            {% if pdf_exists %}
                <a class="pdf-button" href="/download-report">PDF 리포트 다운로드</a>
            {% endif %}

            <table>
                <thead>
                    <tr>
                        <th>서비스</th>
                        <th>점검 항목</th>
                        <th>상태</th>
                        <th>점수</th>
                        <th>상세 내용</th>
                    </tr>
                </thead>
                <tbody>
                    {% for item in results %}
                    <tr>
                        <td>{{ item.service }}</td>
                        <td>{{ item.check }}</td>
                        <td class="{{ item.status }}">{{ item.status }}</td>
                        <td>{{ item.score }}</td>
                        <td>{{ item.message }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>

            <div class="report-box">
                <h2>자연어 기반 리포트 미리보기</h2>
                {% if report_md %}
                    <pre>{{ report_md }}</pre>
                {% else %}
                    <p>리포트가 아직 생성되지 않았습니다.</p>
                {% endif %}
            </div>

            <a class="back" href="/">← 다시 점검하기</a>
        </div>
    </body>
    </html>
    """,
    results=results,
    total_score=total_score,
    max_score=max_score,
    percent=percent,
    pass_count=pass_count,
    fail_count=fail_count,
    error_count=error_count,
    region=region,
    pdf_exists=pdf_exists,
    report_md=report_md,
    report_error=report_error)

@app.route("/download-report")
def download_report():
    if not REPORT_PDF_PATH.exists():
        return "<h2>PDF 리포트가 아직 생성되지 않았습니다.</h2>"

    return send_file(
        REPORT_PDF_PATH,
        as_attachment=True,
        download_name="security_report.pdf"
    )

if __name__ == "__main__":
    app.run(debug=True)

