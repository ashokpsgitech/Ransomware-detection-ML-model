# Real-Time Pre-Execution Ransomware Detection

Internship project for detecting potential ransomware before execution using static Portable Executable (PE) features and machine learning.

## Goal

Build a Windows-focused Python application that monitors for newly created or executed PE files, extracts static PE features, predicts whether the file is ransomware, and generates an alert in real time.

This first milestone contains only the project architecture and skeleton code. Functionality will be implemented incrementally in later milestones.

## Planned Architecture

```text
Folder / Process Monitor
        |
        v
PE Feature Extractor
        |
        v
Trained ML Model
        |
        v
Prediction Engine
        |
        v
Alert System
```

## Project Structure

```text
.
├── datasets/
├── models/
├── reports/
├── src/
│   ├── data/
│   ├── evaluation/
│   ├── extractor/
│   ├── inference/
│   ├── monitor/
│   ├── training/
│   └── utils/
└── tests/
```

## Setup

Use Python 3.10 or 3.11. The saved `.pkl` model must be loaded with the same
major dependency versions used during training.

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Milestones

1. Data preprocessing pipeline
2. Model training pipeline
3. PE feature extraction
4. Real-time folder monitoring
5. Prediction and alert integration
6. Evaluation, reporting, and demo polish

## Status

Current milestone: project skeleton only.
