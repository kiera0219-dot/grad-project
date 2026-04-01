def calculate_score(results):
    total = len(results)
    fail_score = 0

    risk_weights = {
        "High": 3,
        "Medium": 2,
        "Low": 1
    }

    for result in results:
        if result["status"] == "Fail":
            fail_score += risk_weights.get(result["risk"], 1)

    max_score = total * 3  # 최고 위험 기준
    score = 100 - int((fail_score / max_score) * 100)

    return max(score, 0)