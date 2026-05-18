import os
from dotenv import load_dotenv
from google import genai

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    raise ValueError(".env 파일에 GEMINI_API_KEY가 없습니다.")

client = genai.Client(api_key=api_key)

print("사용 가능한 Gemini 모델 목록:")
print("=" * 60)

for model in client.models.list():
    methods = getattr(model, "supported_actions", None) or getattr(model, "supported_generation_methods", None)

    print("이름:", model.name)
    print("표시명:", getattr(model, "display_name", ""))
    print("지원 기능:", methods)
    print("-" * 60)