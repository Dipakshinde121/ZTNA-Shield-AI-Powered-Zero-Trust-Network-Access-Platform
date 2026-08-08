import os

# Root directory of the ML engine
ML_ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(ML_ENGINE_DIR, "models")

# Ensure models directory exists
os.makedirs(MODELS_DIR, exist_ok=True)

# Toggles for ML layers
ENABLE_ML = True
ENABLE_ANOMALY = True
ENABLE_CLASSIFIER = True

# Combined Decision Engine Weights (must sum to 1.0)
REGEX_WEIGHT = 0.40
ANOMALY_WEIGHT = 0.30
CLASSIFIER_WEIGHT = 0.30

# Detection thresholds
ANOMALY_CONTAMINATION = 0.05  # Outlier proportion for Isolation Forest
ANOMALY_THRESHOLD = 0.60       # Scores above this are flagged as anomalous (typical range 0-1)
CLASSIFIER_THRESHOLD = 0.50    # Class probability above this is labeled as malicious

# Combined score thresholds
COMBINED_BLOCK_THRESHOLD = 70  # Out of 100, above this triggers direct block
COMBINED_FLAG_THRESHOLD = 40   # Out of 100, above this triggers soft warning/flag

# Model binary paths
ANOMALY_MODEL_PATH = os.path.join(MODELS_DIR, "anomaly_forest.pkl")
CLASSIFIER_MODEL_PATH = os.path.join(MODELS_DIR, "random_forest.pkl")
BENIGN_SEEDS_PATH = os.path.join(MODELS_DIR, "benign_seeds.json")
