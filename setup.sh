#!/bin/bash
echo "Setting up SentiHealth..."
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cd webapp && npm install && cd ..
mkdir -p logs reports
echo "Setup complete. Run: source .venv/bin/activate"
