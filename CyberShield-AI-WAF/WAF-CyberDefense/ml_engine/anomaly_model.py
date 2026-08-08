import os
import joblib
from sklearn.ensemble import IsolationForest
from ml_engine.config import ANOMALY_MODEL_PATH, ANOMALY_CONTAMINATION

class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.load_model()

    def load_model(self):
        """Loads the serialized Isolation Forest model if it exists."""
        if os.path.exists(ANOMALY_MODEL_PATH):
            try:
                self.model = joblib.load(ANOMALY_MODEL_PATH)
            except Exception as e:
                print(f"[ML-ANOMALY] Error loading anomaly model: {e}")
                self.model = None
        else:
            self.model = None

    def train(self, X_train: list[list[float]]):
        """
        Trains the Isolation Forest model on benign baseline payloads.
        X_train should be a list of feature vectors representing normal traffic.
        """
        if not X_train or len(X_train) < 5:
            print("[ML-ANOMALY] Insufficient benign samples to train Isolation Forest.")
            return False

        print(f"[ML-ANOMALY] Training Isolation Forest on {len(X_train)} samples...")
        self.model = IsolationForest(
            n_estimators=100,
            contamination=ANOMALY_CONTAMINATION,
            random_state=42
        )
        self.model.fit(X_train)
        
        # Save model
        os.makedirs(os.path.dirname(ANOMALY_MODEL_PATH), exist_ok=True)
        joblib.dump(self.model, ANOMALY_MODEL_PATH)
        print(f"[ML-ANOMALY] Isolation Forest saved to {ANOMALY_MODEL_PATH}")
        return True

    def get_anomaly_score(self, features: list[float]) -> float:
        """
        Returns an anomaly score in range [0, 1] where:
        - 0.0 means completely normal
        - 1.0 means highly anomalous / outlier
        """
        if self.model is None:
            return 0.0
            
        try:
            # decision_function returns positive values for inliers, negative for outliers
            decision_val = float(self.model.decision_function([features])[0])
            
            # Map decision_function to a 0 to 1 score where higher is more anomalous
            # Typic decision_function output is roughly in range [-0.5, 0.5]
            anomaly_score = 0.5 - (decision_val * 2.0)
            return max(0.0, min(1.0, anomaly_score))
        except Exception as e:
            print(f"[ML-ANOMALY] Prediction error: {e}")
            return 0.0
