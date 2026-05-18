from flask import Flask, request, render_template_string
import boto3
import os
import json
import google.generativeai as genai
from dotenv import load_dotenv
from botocore.exceptions import ClientError, NoCredentialsError

load_dotenv()

app = Flask(__name__)
app.secret_key = "super-secret-key-change-this"

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")


# =========================
# Gemini 자연어 리포트 생성
# =========================
def generate_gemini_report(results, total_score, max_score, percent):
    if not GEMINI_API_KEY:
        return """
Gemini API Key가 설정되어 있지 않아 기본 요약을 출력합니다.

AWS 보안 점검 결과를 기준으로 PASS 항목은 양호한 설정이며,
FAIL 항목은 보안상 개선이 필요한 항목입니다.
ERROR 항목은 AWS 권한 또는 리전 설정 문제일 수 있으므로 확인이 필요합니다.
"""

    try:
        genai.configure(api_key=GEMINI_API_KEY)

        model = genai.GenerativeModel("gemini-1.5-flash")

        prompt = f"""
너는 AWS 클라우드 보안 점검 보고서를 작성하는 보안 컨설턴트야.

아래는 사용자가 입력한 AWS 환경을 코드로 점검한 결과야.
점검 결과를 바탕으로 한국어 자연어 리포트를 작성해줘.

총점: {total_score}/{max_score}
보안 준수율: {percent}%

점검 결과:
{json.dumps(results, ensure_ascii=False, indent=2)}

아래 형식으로 작성해줘.

1. 전체 보안 상태 요약
2. 주요 취약점 요약
3. 위험도가 높은 항목
4. 개선 조치 제안
5. 발표용 한 문단 요약

조건:
- 실제 점검 결과에 없는 내용은 지어내지 말 것
- PASS, FAIL, ERROR를 구분해서 설명할 것
- 졸업작품 발표에 사용할 수 있게 자연스럽게 작성할 것
"""

        response = model.generate_content(prompt)
        return response.text

    except Exception as e:
        return f"Gemini 자연어 리포트 생성 중 오류가 발생했습니다.\n\n{str(e)}"


# =========================
# AWS 보안 점검 함수들
# =========================
def check_iam_mfa(session):
    iam = session.client("iam")

    try:
        users = iam.list_users()["Users"]

        if not users:
            return {
                "service": "IAM",
                "check": "IAM 사용자 MFA 설정 여부",
                "status": "PASS",
                "score": 10,
                "message": "IAM 사용자가 없습니다."
            }

        no_mfa_users = []

        for user in users:
            username = user["UserName"]
            mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]

            if len(mfa_devices) == 0:
                no_mfa_users.append(username)

        if no_mfa_users:
            return {
                "service": "IAM",
                "check": "IAM 사용자 MFA 설정 여부",
                "status": "FAIL",
                "score": 0,
                "message": f"MFA 미설정 사용자: {', '.join(no_mfa_users)}"
            }

        return {
            "service": "IAM",
            "check": "IAM 사용자 MFA 설정 여부",
            "status": "PASS",
            "score": 10,
            "message": "모든 IAM 사용자에게 MFA가 설정되어 있습니다."
        }

    except ClientError as e:
        return error_result("IAM", "IAM 사용자 MFA 설정 여부", e)


def check_password_policy(session):
    iam = session.client("iam")

    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]

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
            return {
                "service": "IAM",
                "check": "계정 비밀번호 정책 설정",
                "status": "PASS",
                "score": 10,
                "message": "비밀번호 정책이 적절하게 설정되어 있습니다."
            }

        return {
            "service": "IAM",
            "check": "계정 비밀번호 정책 설정",
            "status": "FAIL",
            "score": 0,
            "message": "비밀번호 길이, 대소문자, 숫자, 특수문자 정책이 부족합니다."
        }

    except ClientError as e:
        return error_result("IAM", "계정 비밀번호 정책 설정", e)


def check_s3_public_access(session):
    s3 = session.client("s3")

    try:
        buckets = s3.list_buckets()["Buckets"]

        if not buckets:
            return {
                "service": "S3",
                "check": "S3 버킷 퍼블릭 접근 차단",
                "status": "PASS",
                "score": 10,
                "message": "S3 버킷이 없습니다."
            }

        public_buckets = []

        for bucket in buckets:
            bucket_name = bucket["Name"]

            try:
                block = s3.get_public_access_block(Bucket=bucket_name)
                config = block["PublicAccessBlockConfiguration"]

                if not all([
                    config.get("BlockPublicAcls", False),
                    config.get("IgnorePublicAcls", False),
                    config.get("BlockPublicPolicy", False),
                    config.get("RestrictPublicBuckets", False)
                ]):
                    public_buckets.append(bucket_name)

            except ClientError:
                public_buckets.append(bucket_name)

        if public_buckets:
            return {
                "service": "S3",
                "check": "S3 버킷 퍼블릭 접근 차단",
                "status": "FAIL",
                "score": 0,
                "message": f"퍼블릭 접근 차단 미흡 버킷: {', '.join(public_buckets)}"
            }

        return {
            "service": "S3",
            "check": "S3 버킷 퍼블릭 접근 차단",
            "status": "PASS",
            "score": 10,
            "message": "모든 S3 버킷의 퍼블릭 접근 차단이 설정되어 있습니다."
        }

    except ClientError as e:
        return error_result("S3", "S3 버킷 퍼블릭 접근 차단", e)


def check_s3_encryption(session):
    s3 = session.client("s3")

    try:
        buckets = s3.list_buckets()["Buckets"]

        if not buckets:
            return {
                "service": "S3",
                "check": "S3 버킷 암호화 설정",
                "status": "PASS",
                "score": 10,
                "message": "S3 버킷이 없습니다."
            }

        unencrypted_buckets = []

        for bucket in buckets:
            bucket_name = bucket["Name"]

            try:
                s3.get_bucket_encryption(Bucket=bucket_name)
            except ClientError:
                unencrypted_buckets.append(bucket_name)

        if unencrypted_buckets:
            return {
                "service": "S3",
                "check": "S3 버킷 암호화 설정",
                "status": "FAIL",
                "score": 0,
                "message": f"암호화 미설정 버킷: {', '.join(unencrypted_buckets)}"
            }

        return {
            "service": "S3",
            "check": "S3 버킷 암호화 설정",
            "status": "PASS",
            "score": 10,
            "message": "모든 S3 버킷에 암호화가 설정되어 있습니다."
        }

    except ClientError as e:
        return error_result("S3", "S3 버킷 암호화 설정", e)


def check_security_group_ssh_open(session):
    ec2 = session.client("ec2")

    try:
        groups = ec2.describe_security_groups()["SecurityGroups"]
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
            return {
                "service": "Security Group",
                "check": "SSH 22번 포트 전체 공개 여부",
                "status": "FAIL",
                "score": 0,
                "message": f"SSH가 전체 공개된 보안 그룹: {', '.join(risky_groups)}"
            }

        return {
            "service": "Security Group",
            "check": "SSH 22번 포트 전체 공개 여부",
            "status": "PASS",
            "score": 10,
            "message": "SSH 포트가 전체 공개되어 있지 않습니다."
        }

    except ClientError as e:
        return error_result("Security Group", "SSH 22번 포트 전체 공개 여부", e)


def check_rds_public_access(session):
    rds = session.client("rds")

    try:
        instances = rds.describe_db_instances()["DBInstances"]

        if not instances:
            return {
                "service": "RDS",
                "check": "RDS 퍼블릭 접근 여부",
                "status": "PASS",
                "score": 10,
                "message": "RDS 인스턴스가 없습니다."
            }

        public_instances = []

        for db in instances:
            if db.get("PubliclyAccessible", False):
                public_instances.append(db.get("DBInstanceIdentifier"))

        if public_instances:
            return {
                "service": "RDS",
                "check": "RDS 퍼블릭 접근 여부",
                "status": "FAIL",
                "score": 0,
                "message": f"퍼블릭 접근 가능한 RDS: {', '.join(public_instances)}"
            }

        return {
            "service": "RDS",
            "check": "RDS 퍼블릭 접근 여부",
            "status": "PASS",
            "score": 10,
            "message": "퍼블릭 접근 가능한 RDS가 없습니다."
        }

    except ClientError as e:
        return error_result("RDS", "RDS 퍼블릭 접근 여부", e)


def check_cloudtrail_enabled(session):
    cloudtrail = session.client("cloudtrail")

    try:
        trails = cloudtrail.describe_trails()["trailList"]

        if not trails:
            return {
                "service": "CloudTrail",
                "check": "CloudTrail 활성화 여부",
                "status": "FAIL",
                "score": 0,
                "message": "CloudTrail이 생성되어 있지 않습니다."
            }

        return {
            "service": "CloudTrail",
            "check": "CloudTrail 활성화 여부",
            "status": "PASS",
            "score": 10,
            "message": "CloudTrail이 생성되어 있습니다."
        }

    except ClientError as e:
        return error_result("CloudTrail", "CloudTrail 활성화 여부", e)


def error_result(service, check, error):
    return {
        "service": service,
        "check": check,
        "status": "ERROR",
        "score": 0,
        "message": str(error)
    }


def run_security_scan(session):
    results = []

    results.append(check_iam_mfa(session))
    results.append(check_password_policy(session))
    results.append(check_s3_public_access(session))
    results.append(check_s3_encryption(session))
    results.append(check_security_group_ssh_open(session))
    results.append(check_rds_public_access(session))
    results.append(check_cloudtrail_enabled(session))

    return results


# =========================
# 메인 화면
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
                max-width: 700px;
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
                line-height: 1.6;
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

                <button type="submit">보안 점검 실행</button>
            </form>

            <div class="notice">
                입력한 AWS 키는 서버에 저장하지 않고, 점검 요청 처리에만 사용됩니다.<br>
                점검 결과는 Gemini를 통해 자연어 리포트로 변환되어 함께 표시됩니다.
            </div>
        </div>
    </body>
    </html>
    """)


# =========================
# 점검 실행 후 report 출력
# =========================
@app.route("/scan", methods=["POST"])
def scan():
    access_key = request.form.get("access_key")
    secret_key = request.form.get("secret_key")
    region = request.form.get("region")

    try:
        aws_session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )

        results = run_security_scan(aws_session)

    except NoCredentialsError:
        return "<h2>AWS 자격 증명이 올바르지 않습니다.</h2>"

    except Exception as e:
        return f"<h2>점검 실행 중 오류 발생</h2><pre>{str(e)}</pre>"

    total_score = sum(item["score"] for item in results)
    max_score = len(results) * 10
    percent = round((total_score / max_score) * 100, 1) if max_score else 0

    pass_count = sum(1 for item in results if item["status"] == "PASS")
    fail_count = sum(1 for item in results if item["status"] == "FAIL")
    error_count = sum(1 for item in results if item["status"] == "ERROR")

    gemini_report = generate_gemini_report(
        results,
        total_score,
        max_score,
        percent
    )

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

            .summary h1 {
                margin-top: 0;
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

            .gemini {
                background: white;
                padding: 30px;
                border-radius: 16px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                margin-bottom: 30px;
                line-height: 1.8;
                white-space: pre-wrap;
            }

            table {
                width: 100%;
                border-collapse: collapse;
                background: white;
                border-radius: 16px;
                overflow: hidden;
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);
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

            .back {
                display: inline-block;
                margin-top: 25px;
                text-decoration: none;
                color: #2563eb;
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

            <div class="gemini">
                <h2>Gemini 자연어 분석 리포트</h2>
                {{ gemini_report }}
            </div>

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
    gemini_report=gemini_report)


if __name__ == "__main__":
    app.run(debug=True)