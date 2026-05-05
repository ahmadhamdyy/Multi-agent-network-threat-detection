#!/usr/bin/env python3
"""
Evaluate the ML pre-screener on a sample of 100,000 rows from rba-dataset-milrow.csv.
Shows which rows the model flags as anomalies and provides analysis.
"""

import csv
import os
import json
from typing import Dict, List, Tuple
import numpy as np

from ml_anomaly import load as load_anomaly_model, row_to_features


def sample_rows_from_csv(csv_path: str, sample_size: int = 100_000, random_seed: int = 42) -> List[Dict[str, str]]:
    """
    Sample rows uniformly from the large CSV using reservoir sampling.
    """
    print(f"Sampling {sample_size:,} rows from {csv_path}...")
    
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Training CSV not found: {csv_path}")

    rng = np.random.default_rng(random_seed)
    reservoir: List[Dict[str, str]] = []
    seen = 0
    
    with open(csv_path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            seen += 1
            
            if len(reservoir) < sample_size:
                reservoir.append(row)
                continue
                
            # Reservoir sampling
            j = int(rng.integers(0, seen))
            if j < sample_size:
                reservoir[j] = row
                
            # Progress indicator
            if seen % 50_000 == 0:
                print(f"  Processed {seen:,} rows...")
    
    print(f"Sampled {len(reservoir):,} rows from {seen:,} total rows")
    return reservoir


def evaluate_prescreener(
    csv_path: str,
    model_path: str,
    sample_size: int = 100_000,
    anomaly_threshold: float = 0.0,
    top_k: int = 20
) -> Dict:
    """
    Evaluate the pre-screener on a sample and return analysis.
    """
    # Load the trained model
    print(f"Loading anomaly model from {model_path}...")
    detector = load_anomaly_model(model_path)
    
    # Sample rows from the large dataset
    sampled_rows = sample_rows_from_csv(csv_path, sample_size)
    
    # Score each row
    print("Computing anomaly scores...")
    scored_rows = []
    
    for i, row in enumerate(sampled_rows):
        features = row_to_features(row)
        score = float(detector.score_features(features))
        
        scored_rows.append({
            'row_index': i,
            'anomaly_score': score,
            'is_anomaly': score >= anomaly_threshold,
            'features': features,
            'raw_row': row
        })
        
        if (i + 1) % 10_000 == 0:
            print(f"  Scored {i + 1:,} rows...")
    
    # Sort by anomaly score (highest first)
    scored_rows.sort(key=lambda x: x['anomaly_score'], reverse=True)
    
    # Analysis
    total_anomalies = sum(1 for r in scored_rows if r['is_anomaly'])
    anomaly_rate = total_anomalies / len(scored_rows)
    
    print(f"\n=== ANALYSIS ===")
    print(f"Total rows analyzed: {len(scored_rows):,}")
    print(f"Anomalies detected: {total_anomalies:,} ({anomaly_rate:.2%})")
    print(f"Threshold used: {anomaly_threshold}")
    
    # Score distribution
    scores = [r['anomaly_score'] for r in scored_rows]
    print(f"\nScore distribution:")
    print(f"  Min: {min(scores):.4f}")
    print(f"  Max: {max(scores):.4f}")
    print(f"  Mean: {np.mean(scores):.4f}")
    print(f"  Std: {np.std(scores):.4f}")
    print(f"  Median: {np.median(scores):.4f}")
    
    # Show top anomalies
    print(f"\n=== TOP {top_k} ANOMALIES ===")
    for i, row in enumerate(scored_rows[:top_k]):
        print(f"\n#{i+1} (Score: {row['anomaly_score']:.4f})")
        raw = row['raw_row']
        print(f"  IP: {raw.get('IP Address', 'N/A')}")
        print(f"  User: {raw.get('User ID', 'N/A')}")
        print(f"  Country: {raw.get('Country', 'N/A')}")
        print(f"  Device: {raw.get('Device Type', 'N/A')}")
        print(f"  Login Success: {raw.get('Login Successful', 'N/A')}")
        print(f"  Is Attack IP: {raw.get('Is Attack IP', 'N/A')}")
        print(f"  Is Account Takeover: {raw.get('Is Account Takeover', 'N/A')}")
        print(f"  RTT: {raw.get('Round-Trip Time [ms]', 'N/A')}")
    
    # Ground truth analysis (if available)
    attack_ips = sum(1 for r in scored_rows if r['raw_row'].get('Is Attack IP', '').lower() == 'true')
    takeovers = sum(1 for r in scored_rows if r['raw_row'].get('Is Account Takeover', '').lower() == 'true')
    
    print(f"\n=== GROUND TRUTH LABELS ===")
    print(f"Attack IPs in sample: {attack_ips} ({attack_ips/len(scored_rows):.2%})")
    print(f"Account Takeovers in sample: {takeovers} ({takeovers/len(scored_rows):.2%})")
    
    # Check how many ground truth positives are caught
    if total_anomalies > 0:
        flagged_rows = [r for r in scored_rows if r['is_anomaly']]
        flagged_attacks = sum(1 for r in flagged_rows if r['raw_row'].get('Is Attack IP', '').lower() == 'true')
        flagged_takeovers = sum(1 for r in flagged_rows if r['raw_row'].get('Is Account Takeover', '').lower() == 'true')
        
        print(f"\n=== COVERAGE ANALYSIS ===")
        print(f"Flagged anomalies that are Attack IPs: {flagged_attacks}/{attack_ips} ({flagged_attacks/max(attack_ips,1):.1%})")
        print(f"Flagged anomalies that are Takeovers: {flagged_takeovers}/{takeovers} ({flagged_takeovers/max(takeovers,1):.1%})")
    
    return {
        'total_rows': len(scored_rows),
        'total_anomalies': total_anomalies,
        'anomaly_rate': anomaly_rate,
        'top_anomalies': scored_rows[:top_k],
        'score_stats': {
            'min': min(scores),
            'max': max(scores),
            'mean': np.mean(scores),
            'std': np.std(scores),
            'median': np.median(scores)
        },
        'ground_truth': {
            'attack_ips': attack_ips,
            'takeovers': takeovers
        }
    }


def save_anomalies_to_csv(results: Dict, output_path: str):
    """
    Save the top anomalies to a CSV file for further analysis.
    """
    print(f"\nSaving top anomalies to {output_path}...")
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['rank', 'anomaly_score', 'ip_address', 'user_id', 'country', 'device_type', 
                     'login_successful', 'is_attack_ip', 'is_account_takeover', 'rtt_ms', 'timestamp']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for i, row in enumerate(results['top_anomalies']):
            raw = row['raw_row']
            writer.writerow({
                'rank': i + 1,
                'anomaly_score': f"{row['anomaly_score']:.6f}",
                'ip_address': raw.get('IP Address', ''),
                'user_id': raw.get('User ID', ''),
                'country': raw.get('Country', ''),
                'device_type': raw.get('Device Type', ''),
                'login_successful': raw.get('Login Successful', ''),
                'is_attack_ip': raw.get('Is Attack IP', ''),
                'is_account_takeover': raw.get('Is Account Takeover', ''),
                'rtt_ms': raw.get('Round-Trip Time [ms]', ''),
                'timestamp': raw.get('Login Timestamp', '')
            })


if __name__ == "__main__":
    # Configuration
    csv_path = os.getenv("RBA_EVAL_CSV_PATH", "rba-dataset-milrow.csv")
    model_path = os.getenv("ANOMALY_MODEL_PATH", "data/anomaly_model.joblib")
    sample_size = int(os.getenv("EVAL_SAMPLE_SIZE", "100000"))
    threshold = float(os.getenv("ANOMALY_THRESHOLD", "0.0"))
    top_k = int(os.getenv("TOP_K_ANOMALIES", "20"))
    output_csv = os.getenv("ANOMALIES_OUTPUT_CSV", "top_anomalies.csv")
    
    print("=== ML PRE-SCREENER EVALUATION ===")
    print(f"Dataset: {csv_path}")
    print(f"Model: {model_path}")
    print(f"Sample size: {sample_size:,}")
    print(f"Threshold: {threshold}")
    print(f"Top K: {top_k}")
    
    try:
        results = evaluate_prescreener(
            csv_path=csv_path,
            model_path=model_path,
            sample_size=sample_size,
            anomaly_threshold=threshold,
            top_k=top_k
        )
        
        # Save results
        save_anomalies_to_csv(results, output_csv)
        
        # Save summary JSON
        summary_path = "prescreener_evaluation.json"
        with open(summary_path, 'w') as f:
            # Make results JSON serializable
            json_results = {
                'total_rows': results['total_rows'],
                'total_anomalies': results['total_anomalies'],
                'anomaly_rate': results['anomaly_rate'],
                'score_stats': {k: float(v) for k, v in results['score_stats'].items()},
                'ground_truth': results['ground_truth'],
                'top_anomaly_count': len(results['top_anomalies'])
            }
            json.dump(json_results, f, indent=2)
        
        print(f"\nResults saved:")
        print(f"  Detailed anomalies: {output_csv}")
        print(f"  Summary: {summary_path}")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()