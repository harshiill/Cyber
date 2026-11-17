#!/usr/bin/env python3
"""
NIDS with XAI - Network Intrusion Detection with Explainable AI

Main Application with CLI and GUI support.

Author: Final Year CS Project
Version: 2.0 - Enhanced with GUI and cross-dataset support
"""

import sys
import gc
import argparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np

from config.config import (
    MODEL_DIR, PROCESSED_DATA_DIR,
    PROCESSED_DATA_FILENAME, TRAINING_DATASET,
    get_data_dir,
)
from src.utils import (
    display_banner, display_menu, get_menu_choice,
    print_header, print_subheader, print_success, print_error,
    print_warning, print_info, clear_screen, confirm_action,
    format_number,
)
from src.data_loader import DataLoader
from src.preprocessor import Preprocessor
from src.model_trainer import ModelTrainer
from src.evaluator import Evaluator
from src.explainer import Explainer
from src.classifier import Classifier


class NIDSApp:
    """NIDS with XAI Application - Command Line Interface."""

    def __init__(self):
        self.preprocessor = None
        self.trainer = None
        self.evaluator = None
        self.explainer = None

        # Data splits
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        self.y_types_test = None  # Original attack types
        self.feature_names = []

        self.data_ready = False
        self.model_ready = False
        self.current_dataset = TRAINING_DATASET

    def run(self):
        """Main application loop."""
        clear_screen()
        display_banner()

        # Simplified menu - 8 options
        menu = [
            "Load & Preprocess Data",
            "Load Saved Data (Quick)",
            "Train Model",
            "Evaluate Model",
            "Test & Explain Predictions",
            "Classify New CSV File",
            "View Status",
            "Exit"
        ]

        while True:
            display_menu(menu)
            choice = get_menu_choice(len(menu))

            if choice == 1:
                self.load_data()
            elif choice == 2:
                self.load_saved()
            elif choice == 3:
                self.train()
            elif choice == 4:
                self.evaluate()
            elif choice == 5:
                self.test_and_explain()
            elif choice == 6:
                self.classify()
            elif choice == 7:
                self.status()
            elif choice == 8:
                print("\nGoodbye!")
                break

            input("\nPress Enter to continue...")

    def load_data(self, dataset: str = None):
        """Load and preprocess data from CSV files."""
        print_header("Load & Preprocess Data")

        # Allow dataset selection
        if dataset is None:
            print_info("Select dataset:")
            print_info("  1. CIC-IDS2017 (default)")
            print_info("  2. CIC-IDS2018")
            ds_choice = input("\nChoice [1]: ").strip() or "1"
            dataset = "2017" if ds_choice == "1" else "2018"

        self.current_dataset = dataset
        data_dir = get_data_dir(dataset)

        print_info(f"Dataset: CIC-IDS{dataset}")
        print_info(f"Data folder: {data_dir}")

        loader = DataLoader(dataset=dataset)
        available, missing = loader.get_available_files()

        if not available:
            print_error("No CSV files found!")
            print_info(f"Please add files to: {data_dir}")
            return

        raw_data = loader.load_all()
        if raw_data is None:
            return

        self.preprocessor = Preprocessor()

        try:
            from src.training_data import prepare_holdout, save_holdout
            split = prepare_holdout(raw_data, self.preprocessor, dataset)
            save_holdout(split, self.preprocessor, dataset)
            self.feature_names = split["feature_names"]
            self.X_train, self.X_test = split["X_train"], split["X_test"]
            self.y_train, self.y_test = split["y_train"], split["y_test"]
            self.y_types_test = split["types_test"]
            del raw_data
            gc.collect()

            self.data_ready = True
            print_success("Data ready!")

        except Exception as e:
            print_error(f"Failed: {e}")
            import traceback
            traceback.print_exc()

    def load_saved(self):
        """Load previously saved data."""
        print_header("Load Saved Data")

        from config.config import get_processed_data_filename
        path = PROCESSED_DATA_DIR / get_processed_data_filename(self.current_dataset)
        if not path.exists():
            print_error("No saved data. Use option 1 first.")
            return
        try:
            data = np.load(path, allow_pickle=True)
            if "split_version" not in data:
                raise ValueError("Processed data has no independent holdout; preprocess raw data again.")
            self.preprocessor = Preprocessor()
            self.preprocessor.load(self.current_dataset)
            self.feature_names = list(data["feature_names"])
            self.X_train, self.X_test = data["X_train"], data["X_test"]
            self.y_train, self.y_test = data["y_train"], data["y_test"]
            self.y_types_test = data["types_test"]

            self.data_ready = True
            print_success("Data loaded!")

        except Exception as e:
            print_error(f"Failed: {e}")

    def train(self, mode: str = None):
        """Train the model."""
        if not self.data_ready:
            print_error("Load data first (Option 1 or 2)")
            return

        # Select training mode
        if mode is None:
            print_info("\nTraining Modes:")
            print_info("  1. Quick    - Fast training, basic accuracy (~94%)")
            print_info("  2. Standard - Balanced speed and accuracy (~96%) [default]")
            print_info("  3. Optimized - Slower training, higher accuracy (~98%)")
            print_info("  4. Auto     - Automatic hyperparameter tuning (slowest)")
            mode_choice = input("\nChoice [2]: ").strip() or "2"
            modes = {"1": "quick", "2": "standard", "3": "optimized", "4": "auto"}
            mode = modes.get(mode_choice, "standard")

        self.trainer = ModelTrainer(mode=mode)
        self.trainer.train(self.X_train, self.y_train, self.feature_names)
        self.model_ready = True

        # Quick accuracy
        print_subheader("Quick Test Accuracy")
        test_acc = (self.trainer.predict(self.X_test) == self.y_test).mean()

        # Visual bar
        bar_width = 30
        filled = int(test_acc * bar_width)
        bar = "#" * filled + "-" * (bar_width - filled)
        print(f"  Test Accuracy: |{bar}| {test_acc*100:.1f}%")

        # Setup explainer
        print_info("\nSetting up XAI...")
        self.explainer = Explainer(self.trainer.model, self.feature_names)
        self.explainer.setup(self.X_train)

    def evaluate(self):
        """Full model evaluation with visuals."""
        if not self._ensure_model():
            return

        if self.X_test is None:
            print_error("Load data first")
            return

        y_pred = self.trainer.predict(self.X_test)
        y_proba = self.trainer.predict_proba(self.X_test)

        self.evaluator = Evaluator()
        self.evaluator.evaluate(
            self.y_test, y_pred, y_proba,
            self.y_types_test,
            self.preprocessor.attack_types if self.preprocessor else None
        )

        if confirm_action("\nSave report?"):
            self.evaluator.save_report()

    def test_and_explain(self):
        """Test model and show XAI explanations (SHAP + LIME)."""
        if not self._ensure_model():
            return

        if self.X_test is None:
            print_error("Load data first")
            return

        # Setup explainer
        if self.explainer is None or not self.explainer.is_ready:
            self.explainer = Explainer(self.trainer.model, self.feature_names)
            self.explainer.setup(self.X_train)

        print_header("Test & Explain Predictions")

        print_info("\nOptions:")
        print_info("  1. Test random samples")
        print_info("  2. Test attack samples only")
        print_info("  3. Test benign samples only")
        print_info("  4. Global feature importance")

        choice = input("\nChoice [1]: ").strip() or "1"

        if choice == "4":
            self.explainer.get_global_importance(self.X_test, save_plot=True)
        elif choice == "2":
            self._test_samples(attack_only=True)
        elif choice == "3":
            self._test_samples(benign_only=True)
        else:
            self._test_samples()

    def _test_samples(self, attack_only=False, benign_only=False, n=5):
        """Test samples with SHAP + LIME explanations."""
        if attack_only:
            indices = np.where(self.y_test == 1)[0]
            label = "Attack"
        elif benign_only:
            indices = np.where(self.y_test == 0)[0]
            label = "Benign"
        else:
            indices = np.arange(len(self.X_test))
            label = "Random"

        if len(indices) == 0:
            print_warning(f"No {label.lower()} samples found")
            return

        n = min(n, len(indices))
        selected = np.random.choice(indices, n, replace=False)

        print_subheader(f"Testing {n} {label} Samples")

        correct = 0
        for i, idx in enumerate(selected):
            print(f"\n{'='*70}")
            print(f"  SAMPLE {i+1}/{n}  (Index: {idx})")
            print(f"{'='*70}")

            true_label = self.y_test[idx]
            true_name = "ATTACK" if true_label == 1 else "BENIGN"

            # Get attack type if available
            if self.y_types_test is not None and self.preprocessor:
                attack_type = self.preprocessor.get_attack_type_name(self.y_types_test[idx])
                print(f"  Actual: {true_name} ({attack_type})")
            else:
                print(f"  Actual: {true_name}")

            # Explain with both SHAP and LIME
            result = self.explainer.explain(self.X_test[idx], true_label)
            self.explainer.print_explanation(result)

            if result.get("correct"):
                correct += 1

        # Summary
        print(f"\n{'='*70}")
        pct = correct / n * 100
        bar_width = 20
        filled = int(pct / 100 * bar_width)
        bar = "#" * filled + "-" * (bar_width - filled)
        print(f"  RESULT: {correct}/{n} correct |{bar}| {pct:.1f}%")
        print(f"{'='*70}")

    def classify(self):
        """Classify new data from CSV."""
        if not self._ensure_model():
            return

        print_header("Classify New CSV File")

        filepath = input("Enter CSV file path: ").strip()
        if not filepath or not Path(filepath).exists():
            print_error("File not found")
            return

        # Setup explainer
        if self.explainer is None or not self.explainer.is_ready:
            self.explainer = Explainer(self.trainer.model, self.feature_names)
            self.explainer.setup(self.X_train)

        classifier = Classifier(self.trainer.model, self.preprocessor, self.explainer)
        results = classifier.classify_csv(filepath, explain=True)

        if results.get("success") and confirm_action("\nSave results?"):
            classifier.save_results(results)

    def status(self):
        """Show system status."""
        print_header("System Status")

        # Data status
        print_subheader("Data")
        if self.data_ready:
            print_info(f"  [OK] Data loaded")
            print_info(f"    Training: {format_number(len(self.X_train))} samples")
            print_info(f"    Testing:  {format_number(len(self.X_test))} samples")
            print_info(f"    Features: {len(self.feature_names)}")

            if self.preprocessor and self.preprocessor.attack_types:
                print_info(f"    Attack types: {len(self.preprocessor.attack_types)}")
        else:
            print_info(f"  [--] No data loaded")

        # Model status
        print_subheader("Model")
        if self.model_ready:
            print_info(f"  [OK] Model trained")
            info = self.trainer.get_info()
            print_info(f"    Type: Random Forest")
            print_info(f"    Mode: {info.get('mode', 'standard')}")
            print_info(f"    Trees: {info['n_estimators']}")
            print_info(f"    Depth: {info['max_depth']}")
        else:
            print_info(f"  [--] No model trained")

        # XAI status
        print_subheader("XAI Explainer")
        if self.explainer and self.explainer.is_ready:
            print_info(f"  [OK] Explainer ready")
        else:
            print_info(f"  [--] Explainer not initialized")

        # Paths
        print_subheader("Paths")
        print_info(f"  Data (2017): {get_data_dir('2017')}")
        print_info(f"  Data (2018): {get_data_dir('2018')}")
        print_info(f"  Models:      {MODEL_DIR}")

    def _ensure_model(self) -> bool:
        """Load model if not already loaded."""
        if self.model_ready:
            return True

        model_path = MODEL_DIR / "nids_model.joblib"
        if model_path.exists():
            print_info("Loading saved model...")
            self.trainer = ModelTrainer()
            self.trainer.load()
            self.feature_names = self.trainer.feature_names
            self.model_ready = True
            return True

        print_error("No model found. Train first (Option 3)")
        return False


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="NIDS-XAI: Network Intrusion Detection with Explainable AI"
    )
    parser.add_argument(
        "--dataset", "-d",
        choices=["2017", "2018"],
        default="2017",
        help="Dataset to use (default: 2017)"
    )
    parser.add_argument(
        "--train", "-t",
        action="store_true",
        help="Train model after loading data"
    )
    parser.add_argument(
        "--mode", "-m",
        choices=["quick", "standard", "optimized", "auto"],
        default="standard",
        help="Training mode (default: standard)"
    )
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()

    # CLI mode
    try:
        app = NIDSApp()
        app.run()
    except KeyboardInterrupt:
        print("\n\nGoodbye!")
        sys.exit(0)


if __name__ == "__main__":
    main()
