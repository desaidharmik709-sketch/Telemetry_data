
@echo off

cd /d "%~dp0"

python compliance_collector.py

python compliance_engine.py

python score_engine.py

python report_generator.py
