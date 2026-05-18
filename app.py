from flask import Flask, request, render_template_string, send_file
import boto3
from botocore.exceptions import NoCredentialsError
import json
import subprocess
import sys
import os
from pathlib import Path


app = Flask(__name__)
app.secret_key = "change-this-secret-key"


# =========================
# 경로 설정
# =========================
BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "outputs"
SCAN_RESULT_PATH = OUTPUT_DIR / "scan_result.json"
REPORT_MD_PATH = OUTPUT_DIR / "security_report.md"
REPORT_PDF_PATH = OUTPUT_DIR / "security_report.pdf"


# =========================
# 전체 스캐너 모듈 설정
# =========================
SCANNER_MODULE = "scanner.main_scanner"


# =========================
# 공통 실행 함수
# =========================
def run_script(script_path):
    result = subprocess.run(
        [sys.executable, script_path],
        cwd=BASE_DIR,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    if result.returncode != 0:
        stdout = result.stdout if result.stdout else "(출력 없음)"
        stderr = result.stderr if result.stderr else "(에러 출력 없음)"

        raise RuntimeError(
            f"{script_path} 실행 실패\n\n"
            f"STDOUT:\n{stdout}\n\n"
            f"STDERR:\n{stderr}"
        )

    return result.stdout


def run_module_with_aws_credentials(module_name, access_key, secret_key, region):
    env = os.environ.copy()
    env["AWS_ACCESS_KEY_ID"] = access_key
    env["AWS_SECRET_ACCESS_KEY"] = secret_key
    env["AWS_DEFAULT_REGION"] = region
    env["AWS_REGION"] = region

    result = subprocess.run(
        [sys.executable, "-m", module_name],
        cwd=BASE_DIR,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env
    )

    if result.returncode != 0:
        stdout = result.stdout if result.stdout else "(출력 없음)"
        stderr = result.stderr if result.stderr else "(에러 출력 없음)"

        raise RuntimeError(
            f"{module_name} 실행 실패\n\n"
            f"STDOUT:\n{stdout}\n\n"
            f"STDERR:\n{stderr}"
        )

    return result.stdout


# =========================
# 결과 정규화 함수
# =========================
def normalize_status(status):
    status = str(status).strip().upper()

    if status == "PASS":
        return "Pass"

    if status == "FAIL":
        return "Fail"

    if status == "INFO":
        return "INFO"

    return "INFO"


def recompute_summary(results, original_score=None):
    normalized_results = []

    for item in results:
        fixed = dict(item)
        fixed["status"] = normalize_status(fixed.get("status"))
        normalized_results.append(fixed)

    total_checks = len(normalized_results)

    pass_count = sum(
        1 for item in normalized_results
        if item.get("status") == "Pass"
    )

    fail_count = sum(
        1 for item in normalized_results
        if item.get("status") == "Fail"
    )

    info_count = sum(
        1 for item in normalized_results
        if item.get("status") == "INFO"
    )

    # scanner의 점수가 정상이라면 그대로 사용
    if isinstance(original_score, (int, float)) and original_score > 0:
        security_score = int(original_score)

    # scanner 점수가 0인데 PASS가 있으면 화면 표시용 점수 재계산
    else:
        score_target_count = pass_count + fail_count

        if score_target_count > 0:
            security_score = int((pass_count / score_target_count) * 100)
        else:
            security_score = 0

    summary = {
        "total_checks": total_checks,
        "pass_count": pass_count,
        "fail_count": fail_count,
        "info_count": info_count,
        "security_score": security_score
    }

    return summary, normalized_results


def load_and_fix_scan_result():
    if not SCAN_RESULT_PATH.exists():
        raise FileNotFoundError(
            "outputs/scan_result.json 파일이 없습니다."
        )

    with open(SCAN_RESULT_PATH, "r", encoding="utf-8") as f:
        scan_result = json.load(f)

    results = scan_result.get("results", [])
    old_summary = scan_result.get("summary", {})
    original_score = old_summary.get("security_score")

    summary, fixed_results = recompute_summary(
        results,
        original_score=original_score
    )

    fixed_scan_result = {
        "summary": summary,
        "results": fixed_results
    }

    with open(SCAN_RESULT_PATH, "w", encoding="utf-8") as f:
        json.dump(
            fixed_scan_result,
            f,
            ensure_ascii=False,
            indent=2
        )

    return fixed_scan_result


def generate_security_report():
    run_script("reporting/enrich_findings.py")
    run_script("reporting/generate_report.py")
    run_script("reporting/generate_pdf.py")


def load_report_markdown():
    if REPORT_MD_PATH.exists():
        return REPORT_MD_PATH.read_text(encoding="utf-8")

    return ""


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
                box-sizing: border-box;
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

            button:hover {
                background: #1d4ed8;
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
                점검 후 <strong>scanner/main_scanner.py</strong> 전체 점검 결과를 기반으로
                자연어 리포트와 PDF 리포트가 생성됩니다.
            </div>
        </div>
    </body>
    </html>
    """)


# =========================
# 점검 실행
# =========================
@app.route("/scan", methods=["POST"])
def scan():
    access_key = request.form.get("access_key")
    secret_key = request.form.get("secret_key")
    region = request.form.get("region")

    report_error = None
    report_md = ""
    scan_result = None
    results = []

    try:
        # 1. AWS 자격 증명 확인
        aws_session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )

        sts = aws_session.client("sts")
        sts.get_caller_identity()

        # 2. scanner/main_scanner.py 전체 점검 실행
        run_module_with_aws_credentials(
            SCANNER_MODULE,
            access_key,
            secret_key,
            region
        )

        # 3. scan_result.json 읽고 상태값/점수 정리 후 다시 저장
        scan_result = load_and_fix_scan_result()
        results = scan_result.get("results", [])

        # 4. 리포트 생성
        try:
            generate_security_report()
            report_md = load_report_markdown()
        except Exception as e:
            report_error = str(e)

    except NoCredentialsError:
        return "<h2>AWS 자격 증명이 올바르지 않습니다.</h2>"

    except Exception as e:
        return f"<h2>점검 중 오류 발생</h2><pre>{str(e)}</pre>"

    summary = scan_result.get("summary", {})

    total_checks = summary.get("total_checks", len(results))
    pass_count = summary.get("pass_count", 0)
    fail_count = summary.get("fail_count", 0)
    info_count = summary.get("info_count", 0)
    security_score = summary.get("security_score", 0)

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
                font-size: 14px;
            }

            th {
                background: #1f2937;
                color: white;
            }

            .Pass {
                color: #16a34a;
                font-weight: bold;
            }

            .Fail {
                color: #dc2626;
                font-weight: bold;
            }

            .INFO {
                color: #2563eb;
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

                <div class="score">{{ security_score }} / 100점</div>
                <p>보안 점수: {{ security_score }}점</p>

                <div class="cards">
                    <div class="card">
                        <h3>전체 점검</h3>
                        <p>{{ total_checks }}개</p>
                    </div>
                    <div class="card">
                        <h3>PASS</h3>
                        <p>{{ pass_count }}개</p>
                    </div>
                    <div class="card">
                        <h3>FAIL</h3>
                        <p>{{ fail_count }}개</p>
                    </div>
                    <div class="card">
                        <h3>INFO</h3>
                        <p>{{ info_count }}개</p>
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
                        <th>점검 항목</th>
                        <th>대상</th>
                        <th>위험도</th>
                        <th>상태</th>
                        <th>KISA 코드</th>
                        <th>상세 내용</th>
                    </tr>
                </thead>
                <tbody>
                    {% for item in results %}
                    <tr>
                        <td>{{ item.item }}</td>
                        <td>{{ item.target }}</td>
                        <td>{{ item.risk }}</td>
                        <td class="{{ item.status }}">{{ item.status }}</td>
                        <td>{{ item.kisa_code }}</td>
                        <td>{{ item.detail }}</td>
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
    total_checks=total_checks,
    pass_count=pass_count,
    fail_count=fail_count,
    info_count=info_count,
    security_score=security_score,
    region=region,
    pdf_exists=pdf_exists,
    report_md=report_md,
    report_error=report_error)


# =========================
# PDF 다운로드
# =========================
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
