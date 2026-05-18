import re
import fitz
from pathlib import Path


PDF_PATH = "data/guide.pdf"
OUTPUT_DIR = "outputs/extracted_guide_sections"


TARGET_SECTIONS = {
    "1.7": "Admin Console 관리자 정책 관리",
    "1.9": "MFA",
    "1.10": "AWS 계정 패스워드 정책 관리",
    "3.1": "보안 그룹 인/아웃바운드 ANY 설정 관리",
    "3.7": "S3 버킷/객체 접근 관리",
    "4.3": "S3 암호화 설정",
    "4.7": "AWS 사용자 계정 로깅 설정",
    "4.10": "S3 버킷 로깅 설정",
}


def extract_pages_text():
    doc = fitz.open(PDF_PATH)

    pages = []

    for page_num, page in enumerate(doc, start=1):
        text = page.get_text()
        pages.append({
            "page": page_num,
            "text": text
        })

    return pages


def make_full_text_with_page_markers(pages):
    parts = []

    for page in pages:
        parts.append(f"\n\n===== PAGE {page['page']} =====\n")
        parts.append(page["text"])

    return "\n".join(parts)


def find_section_positions(full_text):
    positions = []

    for section_id, title_keyword in TARGET_SECTIONS.items():
        pattern = rf"\n{re.escape(section_id)}\s+.*{re.escape(title_keyword)}"
        match = re.search(pattern, full_text)

        if match:
            positions.append({
                "section_id": section_id,
                "title_keyword": title_keyword,
                "start": match.start()
            })
        else:
            print(f"[경고] 항목을 찾지 못함: {section_id} {title_keyword}")

    positions.sort(key=lambda x: x["start"])
    return positions


def split_sections(full_text, positions):
    sections = []

    for idx, pos in enumerate(positions):
        start = pos["start"]

        if idx + 1 < len(positions):
            end = positions[idx + 1]["start"]
        else:
            end = len(full_text)

        section_text = full_text[start:end].strip()

        sections.append({
            "section_id": pos["section_id"],
            "title_keyword": pos["title_keyword"],
            "text": section_text
        })

    return sections


def save_sections(sections):
    output_dir = Path(OUTPUT_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)

    for section in sections:
        section_id = section["section_id"]
        safe_id = section_id.replace(".", "_")

        output_path = output_dir / f"{safe_id}.txt"

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(section["text"])

        print(f"저장 완료: {output_path}")


def main():
    pages = extract_pages_text()
    full_text = make_full_text_with_page_markers(pages)

    Path("outputs").mkdir(exist_ok=True)

    with open("outputs/sk_guide_full_text.txt", "w", encoding="utf-8") as f:
        f.write(full_text)

    positions = find_section_positions(full_text)
    sections = split_sections(full_text, positions)
    save_sections(sections)

    print("항목별 추출 완료")


if __name__ == "__main__":
    main()