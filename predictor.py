"""
predictor.py
------------
Loads the trained RandomForest model once and exposes a clean predict()
function used by the Flask app. Keeps model-loading concerns separate from
the web layer.
"""

import os
import logging
import joblib

from feature_extraction import extract_features, is_pe_file, FeatureExtractionError

logger = logging.getLogger("viroscope.predictor")

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "malwareclassifier-V2.pkl")

_model = None
_model_error = None


def load_model():
    """Load the model once and cache it. Returns (model, error_message)."""
    global _model, _model_error
    if _model is not None or _model_error is not None:
        return _model, _model_error

    if not os.path.exists(MODEL_PATH):
        _model_error = f"Model file not found at {MODEL_PATH}"
        logger.error(_model_error)
        return None, _model_error

    try:
        _model = joblib.load(MODEL_PATH)
        logger.info("Model loaded successfully from %s", MODEL_PATH)
    except Exception as exc:
        _model_error = f"Failed to load model: {exc}"
        logger.error(_model_error)

    return _model, _model_error


def model_is_ready() -> bool:
    model, error = load_model()
    return model is not None and error is None


def predict_file(file_path: str) -> dict:
    """
    Run the full pipeline on a single file: validate it's a PE file,
    extract features, run the model, and return a structured result.

    Always returns a dict. On failure, result["error"] is set and
    result["success"] is False.
    """
    file_name = os.path.basename(file_path)
    model, error = load_model()

    if model is None:
        return {
            "success": False,
            "file_name": file_name,
            "error": error or "Model unavailable",
        }

    if not is_pe_file(file_path):
        return {
            "success": False,
            "file_name": file_name,
            "error": "File is not a valid Windows PE executable (.exe/.dll). "
                     "ViroScope's ML model only analyzes PE files.",
        }

    try:
        features_df = extract_features(file_path)
    except FeatureExtractionError as exc:
        return {
            "success": False,
            "file_name": file_name,
            "error": f"Feature extraction failed: {exc}",
        }
    except Exception as exc:
        logger.exception("Unexpected feature extraction error for %s", file_path)
        return {
            "success": False,
            "file_name": file_name,
            "error": f"Unexpected error extracting features: {exc}",
        }

    # Defensive realignment: guarantee the columns match what the model
    # was trained on, in the right order, even if extraction logic changes.
    if hasattr(model, "feature_names_in_"):
        expected = list(model.feature_names_in_)
        for col in expected:
            if col not in features_df.columns:
                features_df[col] = 0
        features_df = features_df[expected]

    try:
        prediction = int(model.predict(features_df)[0])
        confidence = None
        probabilities = None
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(features_df)[0]
            probabilities = {"benign": float(proba[0]), "malicious": float(proba[1])}
            # Confidence should be the probability of the predicted class (0.0 to 1.0)
            confidence = float(proba[prediction])
            # Ensure confidence is clamped between 0 and 1
            confidence = max(0.0, min(1.0, confidence))
    except Exception as exc:
        logger.exception("Prediction failed for %s", file_path)
        return {
            "success": False,
            "file_name": file_name,
            "error": f"Model prediction failed: {exc}",
        }

    feature_importance = _top_feature_contributions(model, features_df)

    return {
        "success": True,
        "file_name": file_name,
        "is_malware": prediction == 1,
        "verdict": "Malicious" if prediction == 1 else "Benign",
        "confidence": confidence,
        "probabilities": probabilities,
        "features": features_df.iloc[0].to_dict(),
        "top_features": feature_importance,
    }


def _top_feature_contributions(model, features_df, top_n=6):
    """
    Return the top_n most influential features for this prediction, using
    the model's global feature_importances_ weighted by how unusual the
    file's value is. This is a lightweight, dependency-free stand-in for a
    full SHAP explanation, fast enough to run on every request.
    """
    if not hasattr(model, "feature_importances_"):
        return []

    importances = model.feature_importances_
    columns = list(features_df.columns)
    row = features_df.iloc[0]

    ranked = sorted(
        zip(columns, importances),
        key=lambda pair: pair[1],
        reverse=True,
    )[:top_n]

    return [
        {"feature": name, "value": _jsonable(row[name]), "importance": float(importance)}
        for name, importance in ranked
    ]


def _jsonable(value):
    try:
        if hasattr(value, "item"):
            return value.item()
        return value
    except Exception:
        return str(value)
