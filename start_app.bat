@echo off
setlocal
cd /d %~dp0

echo ==========================================
echo    SIATI - Pentest Assistant Dashboard
echo ==========================================

:: Check if virtual environment exists, create it if not
if not exist .venv (
    echo [!] Environnement virtuel .venv non trouve. Creation...
    python -m venv .venv
)

:: Activate venv
echo [+] Activation de l'environnement virtuel...
call .venv\Scripts\activate

:: Install/Update requirements
echo [+] Verification des dependances (cela peut prendre un moment)...
pip install -r requirements.txt

:: Launch UI
echo.
echo [+] Lancement du Dashboard SIATI...
echo [+] URL: http://127.0.0.1:8505
echo.
python main.py ui

pause
