import os
import joblib
from sklearn.ensemble import RandomForestClassifier
from ml_engine.config import CLASSIFIER_MODEL_PATH

class AttackClassifier:
    def __init__(self):
        self.model = None
        self.load_model()

    def load_model(self):
        """Loads the serialized Random Forest classifier model if it exists."""
        if os.path.exists(CLASSIFIER_MODEL_PATH):
            try:
                self.model = joblib.load(CLASSIFIER_MODEL_PATH)
            except Exception as e:
                print(f"[ML-CLASSIFIER] Error loading classifier model: {e}")
                self.model = None
        else:
            self.model = None

    def train(self, X: list[list[float]], y: list[int]):
        """
        Trains a Random Forest classifier.
        - X: Feature vectors
        - y: Binary labels (0 = Benign/Safe, 1 = Attack/Malicious)
        """
        if not X or len(X) < 10:
            print("[ML-CLASSIFIER] Insufficient training data for Classifier.")
            return False

        # Ensure we have both classes represented
        if len(set(y)) < 2:
            print("[ML-CLASSIFIER] Training data must contain both benign and malicious samples.")
            return False

        print(f"[ML-CLASSIFIER] Training Random Forest Classifier on {len(X)} samples...")
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=12,
            random_state=42
        )
        self.model.fit(X, y)
        
        # Save model
        os.makedirs(os.path.dirname(CLASSIFIER_MODEL_PATH), exist_ok=True)
        joblib.dump(self.model, CLASSIFIER_MODEL_PATH)
        print(f"[ML-CLASSIFIER] Classifier model saved to {CLASSIFIER_MODEL_PATH}")
        return True

    def get_attack_probability(self, features: list[float]) -> float:
        """
        Returns probability of request being an attack in range [0.0, 1.0].
        """
        if self.model is None:
            return 0.0
            
        try:
            # predict_proba returns probability for both classes [safe, attack]
            prob = self.model.predict_proba([features])[0]
            # Probabilities should sum to 1. Return the probability for class 1 (attack)
            return float(prob[1])
        except Exception as e:
            print(f"[ML-CLASSIFIER] Prediction error: {e}")
            return 0.0
