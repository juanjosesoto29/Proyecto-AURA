@echo off
REM ── Lanzador del MVP AURA (doble clic) ──
cd /d "%~dp0"
echo Iniciando AURA MVP...
echo Se abrira en http://127.0.0.1:8000
echo (cierra esta ventana para detener el servidor)
python main.py
pause
