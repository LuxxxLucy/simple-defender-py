"""Benchmark simple-defender-py against public prompt injection datasets.

Expected F1 at threshold 0.5:
  - Qualifire: ~0.87
  - xxz224:    ~0.88
  - jayavibhav (adversarial): ~0.97

Usage:
    uv run python benchmarks/run_benchmarks.py
"""

from __future__ import annotations

import os
import sys
import time

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from simple_defender import Defender

DATASETS = [
    {
        "name": "Qualifire",
        "hf_id": "qualifire/Qualifire-prompt-injection-benchmark",
        "expected_f1": 0.87,
        "text_col": "text",
        "label_col": "label",
        "positive_label": 1,
    },
    {
        "name": "xxz224",
        "hf_id": "xxz224/prompt-injection-attack-dataset",
        "expected_f1": 0.88,
        "text_col": "text",
        "label_col": "label",
        "positive_label": 1,
    },
    {
        "name": "jayavibhav",
        "hf_id": "jayavibhav/prompt-injection-attack-dataset",
        "expected_f1": 0.97,
        "text_col": "text",
        "label_col": "label",
        "positive_label": 1,
        "split": "train",  # this dataset has no test split
    },
]

THRESHOLD = 0.5


def compute_f1(tp: int, fp: int, fn: int) -> float:
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


def run_benchmark(ds_config: dict) -> dict:
    try:
        from datasets import load_dataset
    except ImportError:
        return {"error": "pip install datasets"}

    print(f"\n{'='*60}")
    print(f"Dataset: {ds_config['name']} ({ds_config['hf_id']})")
    print(f"{'='*60}")

    split = ds_config.get("split", "test")
    ds = load_dataset(ds_config["hf_id"], split=split)

    model_path = os.path.join(os.path.dirname(__file__), "..", "models", "minilm-full-aug")
    defender = Defender(model_path=model_path)
    defender.warmup()

    tp = fp = fn = tn = 0
    total = len(ds)
    start = time.time()

    for i, row in enumerate(ds):
        text = row[ds_config["text_col"]]
        label = row[ds_config["label_col"]]
        is_positive = label == ds_config["positive_label"]

        result = defender.scan(str(text))
        predicted = result.score is not None and result.score >= THRESHOLD

        if predicted and is_positive:
            tp += 1
        elif predicted and not is_positive:
            fp += 1
        elif not predicted and is_positive:
            fn += 1
        else:
            tn += 1

        if (i + 1) % 100 == 0:
            print(f"  [{i+1}/{total}] tp={tp} fp={fp} fn={fn} tn={tn}")

    elapsed = time.time() - start
    f1 = compute_f1(tp, fp, fn)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    avg_latency_ms = (elapsed / total) * 1000 if total > 0 else 0.0

    print(f"\nResults:")
    print(f"  F1:        {f1:.3f} (expected ~{ds_config['expected_f1']})")
    print(f"  FPR:       {fpr:.4f}")
    print(f"  TP={tp} FP={fp} FN={fn} TN={tn}")
    print(f"  Time:      {elapsed:.1f}s ({total / elapsed:.1f} samples/sec)")
    print(f"  Latency:   {avg_latency_ms:.1f}ms/sample")
    print(f"  Delta:     {f1 - ds_config['expected_f1']:+.3f}")

    return {
        "f1": f1,
        "expected": ds_config["expected_f1"],
        "delta": f1 - ds_config["expected_f1"],
        "fpr": fpr,
        "avg_latency_ms": avg_latency_ms,
    }


def main():
    print("simple-defender-py Benchmark Suite")
    print(f"Threshold: {THRESHOLD}")

    results = {}
    for ds_config in DATASETS:
        try:
            results[ds_config["name"]] = run_benchmark(ds_config)
        except Exception as e:
            print(f"\nERROR on {ds_config['name']}: {e}")
            results[ds_config["name"]] = {"error": str(e)}

    print(f"\n{'='*60}")
    print("Summary:")
    has_failure = False
    for name, r in results.items():
        if "error" in r:
            print(f"  {name}: ERROR - {r['error']}")
            has_failure = True
        else:
            status = "PASS" if abs(r["delta"]) <= 0.02 else "FAIL"
            print(
                f"  {name}: F1={r['f1']:.3f} (expected {r['expected']:.2f})"
                f" FPR={r['fpr']:.4f} latency={r['avg_latency_ms']:.1f}ms [{status}]"
            )
            if abs(r["delta"]) > 0.02:
                has_failure = True

    if has_failure:
        print("\nBenchmark FAILED: one or more datasets outside tolerance.")
        sys.exit(1)
    else:
        print("\nAll benchmarks PASSED.")


if __name__ == "__main__":
    main()
