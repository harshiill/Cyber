"""Prepare an untouched holdout before fitting any data-dependent transforms."""
import numpy as np
from sklearn.model_selection import train_test_split
from config.config import RANDOM_STATE, TEST_SIZE


def prepare_holdout(data, preprocessor, dataset):
    data = data.copy()
    data.columns = data.columns.str.strip()
    label = preprocessor._find_label_column(data)
    if label is None:
        raise ValueError('Dataset has no Label column')
    binary = data[label].astype(str).str.strip().str.upper().ne('BENIGN').astype(int)
    train, test = train_test_split(data, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=binary)
    X_train, y_train, types_train, names = preprocessor.fit_transform(train.copy(), dataset_name=dataset)
    X_test, y_test, types_test = preprocessor.transform(test.copy(), include_labels=True)
    return {'X_train': X_train, 'X_test': X_test, 'y_train': y_train, 'y_test': y_test,
            'types_train': types_train, 'types_test': types_test, 'feature_names': names}


def save_holdout(result, preprocessor, dataset):
    from config.config import PROCESSED_DATA_DIR, get_processed_data_filename
    path = PROCESSED_DATA_DIR / get_processed_data_filename(dataset)
    np.savez_compressed(path,
        X=np.concatenate((result['X_train'], result['X_test'])),
        y=np.concatenate((result['y_train'], result['y_test'])),
        y_types=np.concatenate((result['types_train'], result['types_test'])),
        X_train=result['X_train'], X_test=result['X_test'],
        y_train=result['y_train'], y_test=result['y_test'],
        types_train=result['types_train'], types_test=result['types_test'],
        feature_names=np.array(result['feature_names'], dtype=object),
        attack_types=np.array(preprocessor.attack_types, dtype=object),
        classes=np.array(preprocessor.classes_, dtype=object),
        split_version=np.array(1))
    preprocessor.save(dataset)
    return path


def preprocessing_id(preprocessor):
    import joblib
    if preprocessor is None or preprocessor.scaler is None:
        return None
    return joblib.hash((list(preprocessor.feature_names), preprocessor.scaler))
