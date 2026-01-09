@echo off
setlocal ENABLEDELAYEDEXPANSION

python -m pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller

pyinstaller --noconfirm --clean ^
  --name "BaitBusterDesktopProPlus" ^
  --icon "icon.ico" ^
  --onefile ^
  --windowed ^
  baitbuster_desktop_pro_plus.py

echo.
echo Built: dist\BaitBusterDesktopProPlus.exe
pause
