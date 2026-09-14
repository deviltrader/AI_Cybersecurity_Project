#!/bin/bash
cd "$(dirname "$0")"

echo "=========================================="
echo "  SentinelAI - Starting Application"
echo "=========================================="
echo

if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3 was not found."
    echo "Please install Python 3 from https://www.python.org/downloads/"
    read -p "Press Enter to close..."
    exit 1
fi

echo "Installing/checking required packages..."
python3 -m pip install -r requirements.txt

echo
echo "Starting SentinelAI..."
python3 -m streamlit run app.py
