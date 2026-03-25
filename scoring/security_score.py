def calculate_score(results):
    score = 100

    risk_weights = {
        "High": 10,
        "Medium": 5,
        "Low": 2
    }

    for result in results:
        if result["status"] == "Fail":
            score -= risk_weights.get(result["risk"], 3)

    return max(score, 0)