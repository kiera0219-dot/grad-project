# AWS Security Scanner

## 프로젝트 소개

AWS 환경에서 보안 설정을 자동으로 점검하는 시스템입니다.
IAM, S3, RDS, CloudTrail 등 주요 서비스를 대상으로 취약점을 탐지하고 Security Score를 계산합니다.

---

## 실행 방법

### 1. 프로젝트 다운로드

```bash
git clone https://github.com/kiera0219-dot/grad-project.git
cd grad-project

```

### 2. 가상환경 생성 및 실행

```bash
python -m venv venv
venv\Scripts\activate
```

### 3. 라이브러리 설치

```bash
pip install boto3
```

### 4. 실행

```bash
python -m scanner.main_scanner
```

---

## AWS 사전 설정 (필수)

### 1. Region

* 반드시 `ap-northeast-2 (서울)` 사용

---

### 2. RDS 생성 (테스트용)

* Public access: No
* Multi-AZ: No
* Encryption: OFF

---

### 3. CloudTrail 생성

* Multi-Region: ON
* 로그 암호화: OFF

---

## 결과 설명

* PASS → 안전
* FAIL → 취약
* Security Score → 전체 보안 수준 점수

---

## 주의사항

* 테스트 후 반드시 RDS 삭제 (비용 발생 방지)
* CloudTrail도 필요 없으면 삭제

---

## 팀원 역할

* Detection: AWS 설정 점검
* Reporting: 결과 분석 및 리포트 생성
* UI: 웹 화면 구현

---

## 향후 계획

* LLM 기반 보안 리포트 생성
* Flask 기반 웹 UI 개발
