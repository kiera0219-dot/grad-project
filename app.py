from flask import Flask, render_template, request, redirect, url_for, session
from scanner.main_scanner import run_all_checks

app = Flask(__name__)
app.secret_key = "my_secret_key_1234"

# 로그인용 계정
USER_DATA = {
    "username": "admin",
    "password": "1234"
}

# 13개 검사 이름 고정
EXPECTED = [
    "전체 포트 개방 검사",
    "권한 사용자 검사",
    "Access Key 미사용 검사",
    "CloudTrail 활성화 검사",
    "루트 계정 MFA 검사",
    "IAM 사용자 MFA 검사",
    "IAM 비밀번호 정책 검사",
    "S3 Public Access 검사",
    "S3 버킷 암호화 검사",
    "S3 버킷 버전 관리 검사",
    "보안 그룹 SSH 개방 검사",
    "보안 그룹 RDP 개방 검사",
    "RDS Public Access 검사",
]

# 검사 결과를 13개로 묶기 (핵심)
def group_results(raw_results):
    grouped = {name: {"item_name": name, "status": "PASS"} for name in EXPECTED}

    for r in raw_results:
        text = str(r).lower()

        for name in EXPECTED:
            if any(k in text for k in name.lower().split()):
                if r.get("status", "").lower() == "fail":
                    grouped[name]["status"] = "FAIL"

    return list(grouped.values())

@app.route("/")
def start():
    if "username" in session:
        return redirect("/dashboard")
    return redirect("/login")

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        if request.form["username"] == "admin" and request.form["password"] == "1234":
            session["username"] = "admin"
            return redirect("/dashboard")
        else:
            error = "로그인 실패"

    return render_template("login.html", error=error)

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect("/login")

    data = run_all_checks()

    raw_results = data["results"]
    summary_raw = data["summary"]

    results = group_results(raw_results)

    summary = {
        "total_checks": 13,
        "pass_count": sum(1 for r in results if r["status"] == "PASS"),
        "fail_count": sum(1 for r in results if r["status"] == "FAIL"),
        "security_score": summary_raw["security_score"]
    }

    return render_template("index.html", results=results, summary=summary)

@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect("/login")

if __name__ == "__main__":
    app.run(debug=True)