class VulnClassifier:
    @staticmethod
    def load(path):
        return VulnClassifier()

    def predict_proba(self, features):
        # Mock: return random probability
        import random
        return [0.5, random.random()]