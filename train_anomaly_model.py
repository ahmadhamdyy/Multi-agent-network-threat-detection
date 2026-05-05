import os

from ml_anomaly import save, train_from_csv


if __name__ == "__main__":
    train_csv = os.getenv("RBA_TRAIN_CSV_PATH", "").strip() or os.path.join(
        os.path.dirname(__file__), "rba-dataset-milrow.csv"
    )
    out_path = os.getenv("ANOMALY_MODEL_PATH", "").strip() or os.path.join(
        os.path.dirname(__file__), "data", "anomaly_model.joblib"
    )

    sample_size = int(os.getenv("ANOMALY_SAMPLE_SIZE", "1000000"))
    max_rows_env = os.getenv("ANOMALY_MAX_ROWS", "").strip()
    max_rows = int(max_rows_env) if max_rows_env else None

    contamination = float(os.getenv("ANOMALY_CONTAMINATION", "0.02"))

    detector = train_from_csv(
        train_csv,
        sample_size=sample_size,
        max_rows=max_rows,
        contamination=contamination,
    )
    save(detector, out_path)
    print(f"Saved anomaly model to: {out_path}")

