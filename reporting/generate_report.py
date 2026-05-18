import os
import json
from pathlib import Path

from dotenv import load_dotenv
from google import genai
from google.genai import types


load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")

INPUT_ENRICHED = "outputs/enriched_findings.json"
INPUT_SCAN_RESULT = "outputs/scan_result.json"
OUTPUT_MD = "outputs/security_report.md"


if not GEMINI_API_KEY:
    raise ValueError(".env 파일에 GEMINI_API_KEY가 없습니다.")


client = genai.Client(api_key=GEMINI_API_KEY)


def call_gemini(prompt):
    response = client.models.generate_content(
        model=MODEL_NAME,
        contents=prompt,
        config=types.GenerateContentConfig(
            temperature=0.1,
            top_p=0.8
        )
    )
    return response.text


def build_full_report_prompt(scan_result, enriched_findings):
    return f"""
너는 클라우드 보안 진단 리포트를 작성하는 보안 컨설턴트다.

[절대 규칙]
1. 반드시 [스캔 결과]와 [SK쉴더스 승인 컨텍스트가 포함된 취약점 목록]에 있는 내용만 사용한다.
2. 컨텍스트에 없는 AWS 메뉴명, 명령어, 보안 기준, 조치 방법을 새로 만들지 않는다.
3. 모르는 내용은 "제공된 가이드 기준으로는 추가 확인이 필요합니다."라고 작성한다.
4. target, risk, kisa_code, sk_guide_id는 절대 변경하지 않는다.
5. 단계별 조치 가이드는 guide_context.remediation_steps를 우선 사용한다.
6. 보안 비전문가도 이해할 수 있도록 쉬운 한국어로 작성한다.
7. 출력은 Markdown 형식으로만 작성한다.
8. 코드블록은 사용하지 않는다.


[스캔 결과 요약]
{json.dumps(scan_result.get("summary", {}), ensure_ascii=False, indent=2)}

[SK쉴더스 승인 컨텍스트가 포함된 취약점 목록]
{json.dumps(enriched_findings, ensure_ascii=False, indent=2)}

[리포트 출력 형식]

# 클라우드 보안 진단 리포트

## 1. 진단 요약
- 전체 점검 수:
- 양호 항목 수:
- 취약 항목 수:
- 보안 점수:
- 종합 의견:

## 2. 우선 조치 대상
위험도와 영향도를 기준으로 우선 조치해야 할 항목을 정리한다.

## 3. 상세 취약점 분석

각 취약점마다 아래 형식으로 작성한다.

### 취약점명

#### 점검 항목
- 진단 항목:
- 대상:
- 위험도:
- KISA 코드:
- SK쉴더스 가이드 항목:

#### 원인 분석

#### 보안 영향

#### 단계별 조치 가이드
1. ...
2. ...
3. ...

#### 조치 후 확인 방법
1. ...
2. ...

#### 근거 출처
- 문서:
- 항목:
"""


def main():
    print("Gemini 통합 리포트 생성 시작")

    with open(INPUT_SCAN_RESULT, "r", encoding="utf-8") as f:
        scan_result = json.load(f)

    with open(INPUT_ENRICHED, "r", encoding="utf-8") as f:
        enriched_findings = json.load(f)

    print(f"취약 항목 수: {len(enriched_findings)}")
    print(f"사용 모델: {MODEL_NAME}")

    prompt = build_full_report_prompt(scan_result, enriched_findings)
    report = call_gemini(prompt)

    Path("outputs").mkdir(exist_ok=True)

    with open(OUTPUT_MD, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"Gemini 리포트 생성 완료: {OUTPUT_MD}")


if __name__ == "__main__":
    main()