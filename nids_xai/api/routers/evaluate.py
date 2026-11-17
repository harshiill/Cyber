from pathlib import Path
from typing import Optional, Dict
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from api.services.model_service import model_service

router = APIRouter()
_BASE = Path(__file__).parent.parent.parent

# Cache last evaluation's raw probabilities so the threshold slider can
# recompute precision/recall/F1 on the frontend without re-predicting.
_last_eval_cache: Dict = {}


class EvalRequest(BaseModel):
    dataset: Optional[str] = None   # "2017", "2018", or None → use model's dataset


@router.post("/api/evaluate")
def run_evaluation(req: EvalRequest = EvalRequest()):
    """Evaluate the loaded model on a dataset's holdout split, OR on a different
    dataset entirely (cross-dataset generalisation test)."""
    if not model_service.is_loaded:
        raise HTTPException(status_code=400, detail="No model loaded.")

    train_dataset = model_service.dataset or "2017"
    test_dataset  = req.dataset or train_dataset
    if test_dataset not in ("2017", "2018"):
        raise HTTPException(status_code=400, detail="dataset must be '2017' or '2018'.")

    cross_dataset = (test_dataset != train_dataset)

    import numpy as np
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        confusion_matrix, roc_auc_score, roc_curve, precision_recall_curve,
    )

    if cross_dataset:
        # Correct cross-dataset test: read the OTHER dataset's RAW traffic and
        # transform it through the loaded model's OWN preprocessor, so the
        # features land in the model's feature space. (Feeding the other
        # dataset's pre-selected NPZ directly would mis-align columns, since each
        # dataset selects a different top-K feature set.)
        import glob
        import pandas as pd

        if model_service.preprocessor is None:
            raise HTTPException(status_code=400,
                detail="Loaded model has no preprocessor; cannot run cross-dataset evaluation.")

        sub = "CIC-IDS-2018" if test_dataset == "2018" else "CIC-IDS-2017"
        raw_dir = _BASE / "data" / "raw" / sub
        files = sorted(glob.glob(str(raw_dir / "*.csv")))
        if not files:
            raise HTTPException(status_code=404,
                detail=f"No raw CIC-IDS{test_dataset} CSVs in {raw_dir} for cross-dataset evaluation.")

        frames, total = [], 0
        for f in files:
            try:
                frames.append(pd.read_csv(f, nrows=150000, low_memory=False))
                total += len(frames[-1])
            except Exception:
                continue
            if total >= 400000:
                break
        if not frames:
            raise HTTPException(status_code=500, detail="Could not read raw data for cross-dataset evaluation.")
        df = pd.concat(frames, ignore_index=True)

        res = model_service.preprocessor.transform(df, include_labels=True)
        if not isinstance(res, tuple):
            raise HTTPException(status_code=500, detail="Cross-dataset transform did not return labels.")
        X_test, y_test = res[0], res[1]
        y_types_test, attack_types = None, []
    else:
        # Same dataset → 80/20 holdout split with the trainer's seed.
        npz_path = _BASE / "data" / "processed" / f"processed_data_{test_dataset}.npz"
        if not npz_path.exists():
            raise HTTPException(status_code=404,
                detail=f"No processed data for {test_dataset}. Run preprocessing first.")
        data = np.load(npz_path, allow_pickle=True)
        if "split_version" not in data:
            raise HTTPException(status_code=400, detail="This processed cache has no independent holdout. Retrain from raw data first.")
        X_test, y_test = data["X_test"], data["y_test"]
        y_types_test = data["types_test"] if "types_test" in data else None
        attack_types = list(data["attack_types"]) if "attack_types" in data else []

    expected = len(model_service.feature_names)
    if expected and X_test.shape[1] != expected:
        raise HTTPException(status_code=400, detail=(
            f"Feature mismatch: model expects {expected} features but got {X_test.shape[1]}."
        ))

    try:
        y_pred  = model_service.model.predict(X_test)
        y_proba = model_service.model.predict_proba(X_test)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {e}")

    acc  = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec  = float(recall_score(y_test, y_pred, zero_division=0))
    f1   = float(f1_score(y_test, y_pred, zero_division=0))

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
    specificity   = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    false_pos_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    false_neg_rate = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    try:
        roc_auc = float(roc_auc_score(y_test, y_proba[:, 1]))
    except Exception:
        roc_auc = 0.0

    # ROC curve — downsample to ~80 points for compact wire format
    try:
        fpr, tpr, _ = roc_curve(y_test, y_proba[:, 1])
        if len(fpr) > 80:
            idx = np.linspace(0, len(fpr) - 1, 80).astype(int)
            fpr, tpr = fpr[idx], tpr[idx]
        roc_points = [{"fpr": round(float(f), 4), "tpr": round(float(t), 4)}
                      for f, t in zip(fpr, tpr)]
    except Exception:
        roc_points = []

    # Precision-Recall curve
    try:
        prec_arr, rec_arr, _ = precision_recall_curve(y_test, y_proba[:, 1])
        if len(prec_arr) > 80:
            idx = np.linspace(0, len(prec_arr) - 1, 80).astype(int)
            prec_arr, rec_arr = prec_arr[idx], rec_arr[idx]
        pr_points = [{"recall": round(float(r), 4), "precision": round(float(p), 4)}
                     for r, p in zip(rec_arr, prec_arr)]
    except Exception:
        pr_points = []

    # Confidence histogram — 20 bins of attack_prob, separated by true class
    try:
        attack_probs = y_proba[:, 1]
        bins = np.linspace(0.0, 1.0, 21)
        benign_hist, _ = np.histogram(attack_probs[y_test == 0], bins=bins)
        attack_hist, _ = np.histogram(attack_probs[y_test == 1], bins=bins)
        confidence_histogram = [
            {
                "bin": f"{bins[i]:.2f}–{bins[i+1]:.2f}",
                "bin_low":  round(float(bins[i]), 4),
                "bin_high": round(float(bins[i+1]), 4),
                "benign":   int(benign_hist[i]),
                "attack":   int(attack_hist[i]),
            }
            for i in range(20)
        ]
    except Exception:
        confidence_histogram = []

    attack_breakdown = []
    if y_types_test is not None and attack_types:
        for i, name in enumerate(attack_types):
            if str(name).strip().upper() == "BENIGN":
                continue
            mask = (y_types_test == i) & (y_test == 1)
            if mask.sum() == 0:
                continue
            type_acc = float((y_pred[mask] == y_test[mask]).mean())
            attack_breakdown.append({
                "attack": name,
                "accuracy": round(type_acc, 4),
                "count": int(mask.sum()),
            })
        attack_breakdown.sort(key=lambda x: x["count"], reverse=True)

    # Cache for threshold slider
    _last_eval_cache.clear()
    _last_eval_cache.update({
        "y_test": y_test.tolist(),
        "y_proba_attack": y_proba[:, 1].tolist(),
        "test_dataset": test_dataset,
    })

    return {
        "train_dataset": train_dataset,
        "test_dataset":  test_dataset,
        "cross_dataset": cross_dataset,
        "dataset":       test_dataset,           # legacy field for older UI code
        "test_samples":  int(len(X_test)),
        "accuracy":      round(acc, 4),
        "precision":     round(prec, 4),
        "recall":        round(rec, 4),
        "f1":            round(f1, 4),
        "roc_auc":       round(roc_auc, 4),
        "specificity":   round(specificity, 4),
        "fpr":           round(false_pos_rate, 4),
        "fnr":           round(false_neg_rate, 4),
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "attack_breakdown": attack_breakdown,
        "roc_curve": roc_points,
        "pr_curve":  pr_points,
        "confidence_histogram": confidence_histogram,
    }


class ExplainValidationRequest(BaseModel):
    dataset: Optional[str] = None   # "2017" / "2018" / None → model's dataset
    n: int = 24                     # samples to validate (balanced attack/benign)
    k: int = 3                      # top-k features compared / masked


@router.post("/api/evaluate/explanations")
def validate_explanations(req: ExplainValidationRequest = ExplainValidationRequest()):
    """
    Measure EXPLANATION quality (not just detection) on a labelled holdout sample.

    For each sampled flow we run both SHAP and LIME and compute:
      • Agreement  — do the two independent methods pick the same top-k drivers?
                     (Jaccard overlap of top-k sets + top-1 match rate)
      • Faithfulness — if we remove the features SHAP called most important, how far
                     does the model's confidence in its own decision collapse?
                     Compared against masking the SAME number of RANDOM features,
                     which is the control: a faithful explanation should cause a
                     much larger drop than random.
      • Timing     — average SHAP vs LIME explanation time.

    This is additive and read-only; it does not change the model or any state.
    """
    if not model_service.is_loaded:
        raise HTTPException(status_code=400, detail="No model loaded.")

    train_dataset = model_service.dataset or "2017"
    test_dataset  = req.dataset or train_dataset
    if test_dataset not in ("2017", "2018"):
        raise HTTPException(status_code=400, detail="dataset must be '2017' or '2018'.")
    n = max(2, min(int(req.n), 80))
    k = max(1, min(int(req.k), 8))

    npz_path = _BASE / "data" / "processed" / f"processed_data_{test_dataset}.npz"
    if not npz_path.exists():
        raise HTTPException(status_code=404,
            detail=f"No processed data for {test_dataset}. Run preprocessing first.")

    import numpy as np
    from sklearn.model_selection import train_test_split
    from api.services.explainer_service import explainer_service

    if test_dataset != train_dataset:
        raise HTTPException(status_code=400, detail="Explanation validation requires the loaded model's own holdout dataset.")
    data = np.load(npz_path, allow_pickle=True)
    if "split_version" not in data:
        raise HTTPException(status_code=400, detail="Retrain from raw data to create an independent holdout.")
    X, y = data["X_test"], data["y_test"]
    expected = len(model_service.feature_names)
    if expected and X.shape[1] != expected:
        raise HTTPException(status_code=400, detail="Feature mismatch between model and held-out data.")
    test_idx = np.arange(len(y))

    # Balanced sample: half attack, half benign (within what's available).
    rng = np.random.default_rng(42)
    atk_pool = test_idx[y[test_idx] == 1]
    ben_pool = test_idx[y[test_idx] == 0]
    n_atk = min(n // 2, len(atk_pool))
    n_ben = min(n - n_atk, len(ben_pool))
    n_atk = min(n - n_ben, len(atk_pool))
    picks = np.concatenate([
        rng.choice(atk_pool, n_atk, replace=False) if n_atk else np.array([], dtype=int),
        rng.choice(ben_pool, n_ben, replace=False) if n_ben else np.array([], dtype=int),
    ]).astype(int)
    rng.shuffle(picks)
    if len(picks) == 0:
        raise HTTPException(status_code=400, detail="No samples available to validate.")

    try:
        explainer = explainer_service.get_explainer(model_service)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not build explainer: {e}")
    if not explainer.shap_explainer or not explainer.lime_explainer:
        raise HTTPException(status_code=500,
            detail="Both SHAP and LIME are required (check shap + lime are installed).")

    model = model_service.model
    feat_names = list(model_service.feature_names)

    # SHAP base value for the attack class (for the local-accuracy check).
    ev = explainer.shap_explainer.expected_value
    base_attack = float(ev[1]) if hasattr(ev, "__len__") else float(ev)

    def _topk(contribs, value_key, kk):
        """Return [(feature, direction), …] for the kk largest-magnitude contributions."""
        ranked = sorted(contribs, key=lambda c: abs(c.get(value_key, 0.0)), reverse=True)
        out, seen = [], set()
        for c in ranked:
            f = c.get("feature")
            if f and f not in seen:
                out.append((f, c.get("direction", "")))
                seen.add(f)
            if len(out) >= kk:
                break
        return out

    samples = []
    jaccards, top1_hits, dir_agrees, overlaps = [], 0, [], []
    recon_errors, cov_top1, cov_topk = [], [], []
    shap_times, lime_times = [], []
    abs_shap_accum = np.zeros(len(feat_names))   # for SHAP↔model faithfulness

    for idx in picks:
        x = X[idx:idx + 1].astype(np.float32)
        result = explainer.explain(x, method="both")
        shap_exp = result.get("shap_explanation") or {}
        lime_exp = result.get("lime_explanation") or {}
        shap_contribs = shap_exp.get("all_contributions") or shap_exp.get("contributions") or []
        lime_contribs = lime_exp.get("contributions") or []
        shap_times.append(float(shap_exp.get("time_seconds", 0.0)))
        lime_times.append(float(lime_exp.get("time_seconds", 0.0)))

        p_attack = float(result["probabilities"]["Attack"])

        # Local accuracy (SHAP additivity): base + Σ shap_values ≈ model output.
        sv_by_name = {c["feature"]: float(c["shap_value"]) for c in shap_contribs}
        sv = np.array([sv_by_name.get(n, 0.0) for n in feat_names])
        recon_errors.append(abs((base_attack + sv.sum()) - p_attack))
        abs_shap_accum += np.abs(sv)

        # Concentration: share of total |SHAP| mass held by the top features.
        mags = np.sort(np.abs(sv))[::-1]
        total = mags.sum() or 1.0
        cov_top1.append(mags[0] / total)
        cov_topk.append(mags[:k].sum() / total)

        # SHAP vs LIME on the top-k.
        shap_top = _topk(shap_contribs, "shap_value", k)
        lime_top = _topk(lime_contribs, "lime_weight", k)
        sdir = dict(shap_top); ldir = dict(lime_top)
        sset, lset = set(sdir), set(ldir)
        inter, union = sset & lset, sset | lset
        jac = len(inter) / len(union) if union else 0.0
        jaccards.append(jac); overlaps.append(len(inter))
        top1 = bool(shap_top and lime_top and shap_top[0][0] == lime_top[0][0])
        if top1:
            top1_hits += 1
        if inter:   # do the methods agree on direction for the features they share?
            dir_agrees.append(float(np.mean([1.0 if sdir[f] == ldir[f] else 0.0 for f in inter])))

        pred_code = int(result["prediction_code"])
        samples.append({
            "index":       int(idx),
            "true_label":  int(y[idx]),
            "prediction":  result["prediction"],
            "correct":     bool(pred_code == int(y[idx])),
            "attack_prob": round(p_attack, 4),
            "shap_top":    [f for f, _ in shap_top],
            "lime_top":    [f for f, _ in lime_top],
            "overlap":     len(inter),
            "topk_coverage": round(float(mags[:k].sum() / total), 3),
            "top1_match":  top1,
        })

    def _mean(a):
        return float(np.mean(a)) if len(a) else 0.0

    n_done = len(picks)

    # SHAP↔model faithfulness: do SHAP's global importances track the RF's own?
    try:
        from scipy.stats import spearmanr
        rf_imp = np.asarray(model.feature_importances_)
        rho = spearmanr(abs_shap_accum / n_done, rf_imp).correlation
        shap_model_rho = float(rho) if rho == rho else None  # guard NaN
    except Exception:
        shap_model_rho = None

    mean_recon = _mean(recon_errors)

    return {
        "dataset":   test_dataset,
        "n_samples": n_done,
        "k":         k,
        "local_accuracy": {
            "mean_recon_error": mean_recon,
            "max_recon_error":  float(max(recon_errors)) if recon_errors else 0.0,
            "passes":           bool(mean_recon < 1e-3),
        },
        "concentration": {
            "top1_pct": round(_mean(cov_top1), 4),
            "topk_pct": round(_mean(cov_topk), 4),
        },
        "model_faithfulness": {
            "spearman": round(shap_model_rho, 4) if shap_model_rho is not None else None,
        },
        "agreement": {
            "mean_jaccard":     round(_mean(jaccards), 4),
            "top1_match_rate":  round(top1_hits / n_done, 4),
            "directional_rate": round(_mean(dir_agrees), 4),
            "mean_overlap":     round(_mean(overlaps), 3),
        },
        "timing": {
            "shap_avg_ms": round(_mean(shap_times) * 1000, 1),
            "lime_avg_ms": round(_mean(lime_times) * 1000, 1),
        },
        "samples": samples,
    }


@router.post("/api/evaluate/threshold")
def evaluate_threshold(threshold: float):
    """Recompute precision/recall/F1 against the cached probabilities at a new threshold."""
    if not _last_eval_cache:
        raise HTTPException(status_code=400, detail="Run /api/evaluate first to populate the cache.")
    if not (0.0 <= threshold <= 1.0):
        raise HTTPException(status_code=400, detail="threshold must be between 0 and 1.")

    import numpy as np
    from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score

    y_test  = np.array(_last_eval_cache["y_test"])
    y_proba = np.array(_last_eval_cache["y_proba_attack"])
    y_pred  = (y_proba >= threshold).astype(int)

    return {
        "threshold": round(threshold, 3),
        "test_dataset": _last_eval_cache["test_dataset"],
        "accuracy":  round(float(accuracy_score(y_test, y_pred)), 4),
        "precision": round(float(precision_score(y_test, y_pred, zero_division=0)), 4),
        "recall":    round(float(recall_score(y_test, y_pred, zero_division=0)), 4),
        "f1":        round(float(f1_score(y_test, y_pred, zero_division=0)), 4),
        "tp": int(((y_pred == 1) & (y_test == 1)).sum()),
        "tn": int(((y_pred == 0) & (y_test == 0)).sum()),
        "fp": int(((y_pred == 1) & (y_test == 0)).sum()),
        "fn": int(((y_pred == 0) & (y_test == 1)).sum()),
    }
