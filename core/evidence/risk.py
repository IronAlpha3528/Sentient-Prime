def validate_score_range(score: float, name: str = "score") -> bool:
    """Validates that a score is a float and is strictly between 0.0 and 1.0."""
    try:
        val = float(score)
        return 0.0 <= val <= 1.0
    except (ValueError, TypeError):
        return False

def normalize_score(score: float) -> float:
    """Clips and converts score to float between 0.0 and 1.0."""
    try:
        val = float(score)
        return max(0.0, min(1.0, val))
    except (ValueError, TypeError) as e:
        raise ValueError(f"Could not normalize value {score} to float: {e}")
