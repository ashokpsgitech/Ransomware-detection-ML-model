# Real-Time Pre-Execution Ransomware Detection

Windows-focused internship project for detecting possible ransomware before execution using static Portable Executable (PE) features and machine learning.

The project trains a PE-only ransomware classifier, extracts PE header/section features from executable files, and predicts whether a sample is likely ransomware.

## Current Status

Implemented:

- Dataset preprocessing
- PE-only feature allowlist
- Random Forest training pipeline
- Evaluation metrics
- PE feature extractor using `pefile`
- Ransomware sample feature-dataset builder
- Custom model training using original dataset plus extracted ransomware samples

Not yet implemented:

- Clean predictor CLI
- Real-time folder monitor integration
- Desktop/UI alert system

## Architecture

```text
Dataset / PE Samples
        |
        v
PE Feature Preprocessing
        |
        v
Model Training
        |
        v
Trained Model (.pkl)
        |
        v
PE Feature Extractor
        |
        v
Prediction
```

## Project Structure

```text
.
├── datasets/
│   ├── Final_Dataset_without_duplicate.csv
│   └── my_ransomware_samples.csv
├── models/
├── reports/
├── src/
│   ├── data/
│   │   ├── preprocess.py
│   │   └── sample_dataset_builder.py
│   ├── evaluation/
│   │   └── evaluate.py
│   ├── extractor/
│   │   └── pe_extractor.py
│   ├── inference/
│   │   └── predictor.py
│   ├── monitor/
│   │   └── folder_monitor.py
│   ├── training/
│   │   └── train.py
│   └── utils/
├── tests/
├── requirements.txt
└── README.md
```

## Important Safety Notes

Do not run ransomware samples on your normal machine.

Recommended setup for malware samples:

```text
VirtualBox Windows VM
Network disabled
Shared clipboard disabled
Drag and drop disabled
No shared folders after sample transfer
Snapshot before adding samples
Never double-click or execute samples
Only read samples with the PE extractor
```

The extractor only reads PE file headers and sections. It does not execute the file.

## Python Version

Use Python 3.10 or Python 3.11.

Do not use Python 3.14 for this project. Some pinned ML packages and saved model files are not compatible with it.

Check installed Python versions:

```cmd
py -0p
```

If Python 3.11 is missing, install it:

```cmd
py install 3.11
```

Or download it from:

```text
https://www.python.org/downloads/release/python-3119/
```

During install, enable:

```text
Add python.exe to PATH
```

## Setup On A New Machine

Clone the repository:

```cmd
git clone https://github.com/ashokpsgitech/Ransomware-detection-ML-model.git
cd Ransomware-detection-ML-model
```

Create a Python 3.11 virtual environment:

```cmd
py -3.11 -m venv .venv
.\.venv\Scripts\activate
```

Upgrade build tools:

```cmd
python -m pip install --upgrade pip setuptools wheel
```

Install dependencies:

```cmd
pip install -r requirements.txt
```

Verify versions:

```cmd
python -c "import sklearn, pandas, numpy; print(sklearn.__version__); print(pandas.__version__); print(numpy.__version__)"
```

Expected versions:

```text
1.3.0
2.0.3
1.24.3
```

Run tests:

```cmd
python -B -m pytest tests
```

## Dataset Files

Tracked training datasets:

```text
datasets/Final_Dataset_without_duplicate.csv
datasets/my_ransomware_samples.csv
```

Ignored generated files:

```text
models/*.pkl
models/*.joblib
reports/*.json
reports/*.png
reports/*.pdf
reports/*.html
.venv/
```

This means a new user can train locally, but generated models and reports are not committed by default.

## Preprocess Dataset

Run preprocessing and write a dataset profile:

```cmd
python -B -m src.data.preprocess --dataset datasets\Final_Dataset_without_duplicate.csv --profile-output reports\dataset_profile_pe.json
```

This creates:

```text
reports/dataset_profile_pe.json
```

The preprocessing step:

- Creates binary target: `1` for `Category == Ransomware`, else `0`
- Drops leakage columns like `md5`, `sha1`, `Class`, `Category`, `Family`
- Keeps only PE-derived features
- Converts PE hex-like strings into numbers
- Adds ratio features
- Removes duplicate cleaned rows

## Train PE-Only Model

Train using the original PE-only dataset:

```cmd
python -B -m src.training.train --dataset datasets\Final_Dataset_without_duplicate.csv --model-output models\ransomware_detector_pe.pkl --metrics-output reports\training_metrics_pe.json --profile-output reports\dataset_profile_pe.json --n-estimators 300
```

Generated files:

```text
models\ransomware_detector_pe.pkl
reports\training_metrics_pe.json
reports\dataset_profile_pe.json
```

## Extract Features From Real Ransomware Samples

Place samples inside the VM:

```cmd
mkdir C:\samples\ransomware
```

Put all ransomware files in:

```text
C:\samples\ransomware
```

File names and extensions do not matter. The script scans every file and keeps only valid PE files.

Extract PE features into a CSV:

```cmd
python -B -m src.data.sample_dataset_builder --samples "C:\samples\ransomware" --label Ransomware --output datasets\my_ransomware_samples.csv
```

Check the extracted dataset:

```cmd
python -c "import pandas as pd; df=pd.read_csv('datasets\\my_ransomware_samples.csv'); print(df.shape); print(df.head())"
```

If the row count is `0`, the files may be zipped, encrypted, corrupted, or not valid PE files.

## Train Custom Model With Original Dataset Plus Sample Dataset

Train with both datasets:

```cmd
python -B -m src.training.train --dataset datasets\Final_Dataset_without_duplicate.csv --dataset datasets\my_ransomware_samples.csv --model-output models\ransomware_detector_custom.pkl --metrics-output reports\training_metrics_custom.json --profile-output reports\dataset_profile_custom.json --n-estimators 300
```

Generated files:

```text
models\ransomware_detector_custom.pkl
reports\training_metrics_custom.json
reports\dataset_profile_custom.json
```

Use this custom model for future predictions:

```text
models\ransomware_detector_custom.pkl
```

## Test A Real EXE With The Model

Test one executable file:

```cmd
python -B -c "from pathlib import Path; import joblib; from src.extractor.pe_extractor import PEFeatureExtractor; f=Path('C:\\samples\\ransomware\\YOUR_SAMPLE_NAME'); df=PEFeatureExtractor().to_dataframe(f); b=joblib.load('models\\ransomware_detector_custom.pkl'); p=b['model'].predict(df)[0]; prob=b['model'].predict_proba(df)[0][1]; print('Prediction:', 'Ransomware' if p == 1 else 'Non-ransomware'); print('Probability:', prob)"
```

Replace:

```text
YOUR_SAMPLE_NAME
```

with the actual file name.

For a benign smoke test, use a trusted Windows executable:

```cmd
python -B -c "from pathlib import Path; import sys, joblib; from src.extractor.pe_extractor import PEFeatureExtractor; f=Path(sys.executable); df=PEFeatureExtractor().to_dataframe(f); b=joblib.load('models\\ransomware_detector_custom.pkl'); p=b['model'].predict(df)[0]; prob=b['model'].predict_proba(df)[0][1]; print('File:', f); print('Prediction:', 'Ransomware' if p == 1 else 'Non-ransomware'); print('Probability:', prob)"
```

## Delete Ransomware Samples After Feature Extraction

After `datasets\my_ransomware_samples.csv` is created and the custom model is trained, delete the live samples:

```cmd
rmdir /s /q C:\samples\ransomware
```

Safer option:

```text
Restore the VirtualBox snapshot taken before adding malware samples.
```

The extracted CSV is only PE feature data, not executable malware.

If you also want to delete the extracted CSV after training:

```cmd
del datasets\my_ransomware_samples.csv
```

Keep:

```text
models\ransomware_detector_custom.pkl
```

## What Reports Mean

Dataset profiles:

```text
reports\dataset_profile_*.json
```

These include:

- dataset shape
- duplicate rows
- missing values
- target distribution
- feature count
- dropped columns

Training metrics:

```text
reports\training_metrics_*.json
```

These include:

- accuracy
- precision
- recall
- F1 score
- ROC AUC
- confusion matrix values

Reports are useful for the internship report and presentation, but they are not required to run prediction.

## Common VM Error: scikit-learn Version Mismatch

If you see warnings like:

```text
InconsistentVersionWarning
Trying to unpickle estimator from version 1.3.0 when using version 1.9.0
```

or an error like:

```text
AttributeError: 'SimpleImputer' object has no attribute '_fill_dtype'
```

then your VM is using incompatible package versions.

Fix it:

```cmd
cd "C:\ransomware detection"
rmdir /s /q .venv
py -3.11 -m venv .venv
.\.venv\Scripts\activate
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

Then verify:

```cmd
python -c "import sklearn, pandas, numpy; print(sklearn.__version__); print(pandas.__version__); print(numpy.__version__)"
```

Expected:

```text
1.3.0
2.0.3
1.24.3
```

## Git Commands

Check local changes:

```cmd
git status
```

Commit code changes:

```cmd
git add .
git commit -m "Update project instructions"
```

Push to GitHub:

```cmd
git push origin main
```

Do not force-add ignored model/report files unless you intentionally want to upload them.

## Next Development Step

Recommended next implementation:

```text
Predictor CLI
```

Target command:

```cmd
python -m src.inference.predictor --file "C:\samples\sample.exe" --model models\ransomware_detector_custom.pkl
```

After that, implement:

```text
Folder monitor -> Extract PE features -> Predict -> Alert
```
