"""Create a reviewed, versioned model from compatible analyst feedback."""
import argparse
import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.config import FEEDBACK_FILE, MODEL_DIR, PROCESSED_DATA_DIR, RF_PARAMS, get_processed_data_filename
from src.preprocessor import Preprocessor
from src.training_data import preprocessing_id


def collect_feedback_samples(records, dataset, feature_names, schema_id):
    latest = {r.get('alert_id'): r for r in records if r.get('alert_id')}
    X, y = [], []
    for record in latest.values():
        if (record.get('dataset') != dataset or record.get('feature_names') != list(feature_names)
                or not schema_id or record.get('schema_id') != schema_id
                or record.get('traffic_origin') != 'live'
                or record.get('label') not in ('true_positive', 'false_positive')):
            continue
        try:
            features = np.asarray(record.get('features'), dtype=float)
            if features.shape != (len(feature_names),) or not np.isfinite(features).all():
                continue
        except (TypeError, ValueError):
            continue
        X.append(features)
        y.append(int(record['label'] == 'true_positive'))
    return np.asarray(X).reshape(-1, len(feature_names)), np.asarray(y, dtype=int)


def register_candidate(metadata_path, filename, dataset, sample_count):
    metadata_path = Path(metadata_path)
    metadata = json.loads(metadata_path.read_text(encoding='utf-8')) if metadata_path.exists() else {}
    metadata[filename] = {'filename': filename, 'dataset': dataset, 'last_used': '',
                          'display_name': f'{filename} (review required)',
                          'feedback_samples': sample_count, 'review_required': True}
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', choices=['2017', '2018'], default='2017')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    path = Path(FEEDBACK_FILE)
    if not path.exists():
        sys.exit('No analyst feedback exists.')
    records = []
    for line in path.read_text(encoding='utf-8').splitlines():
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    data = np.load(PROCESSED_DATA_DIR / get_processed_data_filename(args.dataset), allow_pickle=True)
    if 'split_version' not in data:
        sys.exit('Retrain from raw data first to create an independent holdout.')
    prep = Preprocessor()
    prep.load(args.dataset)
    names = list(data['feature_names'])
    X_feedback, y_feedback = collect_feedback_samples(records, args.dataset, names, preprocessing_id(prep))
    if not len(X_feedback):
        sys.exit('No compatible live feedback with feature vectors was found.')
    print(f'Using {len(X_feedback)} reviewed live samples; the held-out dataset is excluded from training.')
    if args.dry_run:
        return
    model = RandomForestClassifier(**RF_PARAMS)
    model.fit(np.concatenate([data['X_train'], X_feedback]), np.concatenate([data['y_train'], y_feedback]))
    print(classification_report(data['y_test'], model.predict(data['X_test']), zero_division=0))
    destination = Path(MODEL_DIR) / f'nids_model_{args.dataset}_feedback_{int(time.time())}.joblib'
    joblib.dump({'model': model, 'feature_names': names, 'schema_id': preprocessing_id(prep), 'mode': 'feedback',
                 'training_info': {'feedback_samples': len(X_feedback), 'dataset': args.dataset}}, destination)
    register_candidate(Path(MODEL_DIR) / 'model_metadata.json', destination.name, args.dataset, len(X_feedback))
    print(f'Saved {destination}. Review the held-out results before loading this model from Settings.')


if __name__ == '__main__':
    main()
