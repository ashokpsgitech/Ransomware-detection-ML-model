# Real-Time Ransomware Monitor Startup Script
$ErrorActionPreference = "Stop"

# 1. Define folder to watch (Default is the user's Downloads folder)
$default_downloads = "$env:USERPROFILE\Downloads"
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "    Ransomware Pre-Execution Folder Monitor Launcher      " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

$watch_folder = Read-Host "Enter absolute path to monitor (default: $default_downloads)"
if ([string]::IsNullOrWhiteSpace($watch_folder)) {
    $watch_folder = $default_downloads
}

# Resolve folder path and verify it exists
$watch_folder = [System.IO.Path]::GetFullPath($watch_folder)
if (-not (Test-Path $watch_folder)) {
    Write-Host "Monitored folder does not exist! Creating it: $watch_folder" -ForegroundColor Yellow
    New-Item -ItemType Directory -Force -Path $watch_folder | Out-Null
}
Write-Host "Monitoring directory: $watch_folder" -ForegroundColor Green

# 2. Check if the ML model is trained
$model_file = "models/ransomware_detector_custom.pkl"
if (-not (Test-Path $model_file)) {
    Write-Host "ML Model not found at $model_file! Training the model first..." -ForegroundColor Yellow
    & .\.venv\Scripts\python -B -m src.training.train `
        --dataset datasets/Final_Dataset_without_duplicate.csv `
        --dataset datasets/my_ransomware_samples.csv `
        --model-output models/ransomware_detector_custom.pkl `
        --metrics-output reports/training_metrics_custom.json `
        --profile-output reports/dataset_profile_custom.json `
        --n-estimators 300
    Write-Host "Training complete!" -ForegroundColor Green
} else {
    Write-Host "Trained ML model found." -ForegroundColor Green
}

# 3. Start the host notification bridge in a separate window
Write-Host "Starting Windows Toast Notification Host Bridge..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoProfile", "-Command", "python -B -m src.utils.notification_host" -WindowStyle Normal

# Give the server 2 seconds to bind to the port
Start-Sleep -Seconds 2

# 4. Build the Docker Image
Write-Host "Building Docker image 'ransomware-detector'..." -ForegroundColor Cyan
docker build -t ransomware-detector .

# 5. Run the Docker Container
Write-Host ""
Write-Host "Starting the Docker container..." -ForegroundColor Green
Write-Host "The container is running. Copy any .exe file into '$watch_folder' to test it." -ForegroundColor Yellow
Write-Host "Press Ctrl+C inside the docker terminal to stop." -ForegroundColor DarkYellow
Write-Host ""

docker run --rm -it `
  --add-host=host.docker.internal:host-gateway `
  -v "${watch_folder}:/app/monitored_folder" `
  ransomware-detector
