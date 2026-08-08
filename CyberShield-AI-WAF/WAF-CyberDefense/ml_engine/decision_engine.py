from ml_engine.config import (
    ENABLE_ML, ENABLE_ANOMALY, ENABLE_CLASSIFIER,
    REGEX_WEIGHT, ANOMALY_WEIGHT, CLASSIFIER_WEIGHT,
    ANOMALY_THRESHOLD, CLASSIFIER_THRESHOLD,
    COMBINED_BLOCK_THRESHOLD, COMBINED_FLAG_THRESHOLD
)
from ml_engine.feature_extractor import extract_features
from ml_engine.anomaly_model import AnomalyDetector
from ml_engine.classifier_model import AttackClassifier

# Instantiate model managers
anomaly_detector = AnomalyDetector()
classifier_model = AttackClassifier()

def get_ml_status():
    """Returns whether the model binaries are loaded and online."""
    return {
        "enabled": ENABLE_ML,
        "anomaly_online": anomaly_detector.model is not None,
        "classifier_online": classifier_model.model is not None
    }

def evaluate_payload(payload: str, regex_match: bool, regex_score: int) -> dict:
    """
    Evaluates a payload using Signature (Regex) + Anomaly (unsupervised) + Classifier (supervised).
    
    Returns a decision dictionary:
    {
        "block": bool,
        "flag": bool,
        "threat_score": int, (0-100)
        "regex_score": int,
        "anomaly_score": float,
        "classifier_score": float,
        "details": list[str]
    }
    """
    details = []
    
    # 1. Signature Score
    sig_score = float(regex_score) / 100.0  # Normalize to 0-1
    if regex_match:
        details.append(f"Signature Match Detected (Regex Score: {regex_score})")

    # If ML is disabled or models are not loaded, fallback immediately to regex matching
    if not ENABLE_ML or (anomaly_detector.model is None and classifier_model.model is None):
        # Fallback decision
        is_blocked = regex_match and regex_score >= COMBINED_BLOCK_THRESHOLD
        is_flagged = regex_match and regex_score >= COMBINED_FLAG_THRESHOLD
        return {
            "block": is_blocked,
            "flag": is_flagged,
            "threat_score": regex_score,
            "regex_score": regex_score,
            "anomaly_score": 0.0,
            "classifier_score": 0.0,
            "details": details + ["ML Engine Offline (Signature Only Mode)"]
        }

    # Extract numeric representation
    features = extract_features(payload)

    # 2. Anomaly Score
    anomaly_val = 0.0
    if ENABLE_ANOMALY and anomaly_detector.model is not None:
        anomaly_val = anomaly_detector.get_anomaly_score(features)
        if anomaly_val > ANOMALY_THRESHOLD:
            details.append(f"Unsupervised Anomaly Flagged (Score: {anomaly_val:.3f})")
    
    # 3. Classifier Score
    classifier_val = 0.0
    if ENABLE_CLASSIFIER and classifier_model.model is not None:
        classifier_val = classifier_model.get_attack_probability(features)
        if classifier_val > CLASSIFIER_THRESHOLD:
            details.append(f"Supervised Classifier Flagged (Attack Prob: {classifier_val:.3f})")

    # 4. Score Fusion (Weighted sum)
    # If a model isn't online, redistributes weight to signature matching
    w_regex = REGEX_WEIGHT
    w_anomaly = ANOMALY_WEIGHT if (ENABLE_ANOMALY and anomaly_detector.model is not None) else 0.0
    w_class = CLASSIFIER_WEIGHT if (ENABLE_CLASSIFIER and classifier_model.model is not None) else 0.0
    
    # Normalize weights in case any model is missing
    total_w = w_regex + w_anomaly + w_class
    if total_w > 0:
        w_regex /= total_w
        w_anomaly /= total_w
        w_class /= total_w

    combined_score_norm = (sig_score * w_regex) + (anomaly_val * w_anomaly) + (classifier_val * w_class)
    combined_score = int(combined_score_norm * 100)

    # Decisions based on fusion
    is_blocked = combined_score >= COMBINED_BLOCK_THRESHOLD
    is_flagged = combined_score >= COMBINED_FLAG_THRESHOLD

    # Force block if regex matched high/critical signatures
    if regex_match and regex_score >= 80:
        is_blocked = True
        details.append("Critical Signature Match Force-Blocked.")

    return {
        "block": is_blocked,
        "flag": is_flagged,
        "threat_score": combined_score,
        "regex_score": regex_score,
        "anomaly_score": float(anomaly_val),
        "classifier_score": float(classifier_val),
        "details": details
    }
