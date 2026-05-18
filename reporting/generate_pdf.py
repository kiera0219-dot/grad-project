import markdown
from pathlib import Path
from playwright.sync_api import sync_playwright


INPUT_MD = "outputs/security_report.md"
OUTPUT_HTML = "outputs/security_report.html"
OUTPUT_PDF = "outputs/security_report.pdf"


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <style>
    body {{
      font-family: "Malgun Gothic", "맑은 고딕", Arial, sans-serif;
      margin: 40px;
      line-height: 1.7;
      color: #222;
      font-size: 14px;
    }}

    h1 {{
      border-bottom: 3px solid #222;
      padding-bottom: 10px;
      color: #1f3a5f;
    }}

    h2 {{
      margin-top: 36px;
      border-bottom: 1px solid #aaa;
      padding-bottom: 6px;
      color: #1f3a5f;
    }}

    h3 {{
      margin-top: 28px;
      color: #234;
    }}

    h4 {{
      margin-top: 20px;
      color: #333;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      margin: 20px 0;
    }}

    th, td {{
      border: 1px solid #ccc;
      padding: 8px;
      font-size: 13px;
    }}

    th {{
      background-color: #f0f4fa;
    }}

    code {{
      background: #f2f2f2;
      padding: 2px 5px;
      border-radius: 4px;
      font-family: Consolas, monospace;
    }}

    pre {{
      background: #f7f7f7;
      padding: 12px;
      border-radius: 8px;
      white-space: pre-wrap;
      word-break: break-word;
    }}

    hr {{
      margin: 32px 0;
      border: none;
      border-top: 1px solid #ddd;
    }}

    ul, ol {{
      margin-bottom: 16px;
    }}

    li {{
      margin-bottom: 6px;
    }}

    @page {{
      size: A4;
      margin: 20mm;
    }}
  </style>
</head>
<body>
{body}
</body>
</html>
"""


def markdown_to_html():
    md_path = Path(INPUT_MD)

    if not md_path.exists():
        raise FileNotFoundError(f"Markdown 파일이 없습니다: {INPUT_MD}")

    md_text = md_path.read_text(encoding="utf-8")

    html_body = markdown.markdown(
        md_text,
        extensions=["tables", "fenced_code", "nl2br"]
    )

    html = HTML_TEMPLATE.format(body=html_body)

    Path("outputs").mkdir(exist_ok=True)
    Path(OUTPUT_HTML).write_text(html, encoding="utf-8")

    print(f"HTML 생성 완료: {OUTPUT_HTML}")

    return Path(OUTPUT_HTML).resolve()


def html_to_pdf(html_path):
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()

        page.goto(html_path.as_uri(), wait_until="networkidle")

        page.pdf(
            path=OUTPUT_PDF,
            format="A4",
            print_background=True,
            margin={
                "top": "20mm",
                "right": "15mm",
                "bottom": "20mm",
                "left": "15mm"
            }
        )

        browser.close()

    print(f"PDF 생성 완료: {OUTPUT_PDF}")


def main():
    html_path = markdown_to_html()
    html_to_pdf(html_path)


if __name__ == "__main__":
    main()