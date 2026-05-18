def calculate_score(results):

    score = 100

    risk_weights = {
        "High": 20,
        "Medium": 10,
        "Low": 5
    }

    for result in results:

        # INFO 항목 제외
        if result["status"] == "INFO":
            continue

        # FAIL만 감점
        if result["status"] == "FAIL":

            risk = result.get("risk", "Low")

            score -= risk_weights.get(risk, 5)

    return max(score, 0)