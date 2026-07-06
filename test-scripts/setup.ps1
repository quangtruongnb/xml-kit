Write-Host "Creating virtual environment..."

python -m venv .venv

Write-Host "Activating virtual environment..."

& ".\.venv\Scripts\Activate.ps1"

python -m pip install --upgrade pip

pip install -r requirements.txt

Write-Host ""
Write-Host "Done."
Write-Host ""
Write-Host "Activate the environment with:"
Write-Host ".\.venv\Scripts\Activate.ps1"