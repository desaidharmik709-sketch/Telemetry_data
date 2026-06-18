def calculate_scores(findings):
    scores = {}
    frameworks = set(x["framework"] for x in findings)
    
    for fw in frameworks:
        controls = [x for x in findings if x["framework"] == fw]
        passed = len([x for x in controls if x["status"] == "PASS"])
        total = len(controls)
        
        score = round((passed / total) * 100, 2) if total > 0 else 0.0
        scores[fw] = score
        
    return scores
