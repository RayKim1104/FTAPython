#!/bin/bash

# P2P File Share Launcher for Mac/Linux

echo "Starting P2P File Share..."

# Check if Python is installed
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
else
    echo "Error: Python 3 is not installed or not found in PATH."
    echo "Please install Python 3 to run this application."
    exit 1
fi

# Check Python version
$PYTHON_CMD -c "import sys; exit(0) if sys.version_info >= (3, 6) else exit(1)"
if [ $? -ne 0 ]; then
    echo "Error: Python 3.6 or higher is required."
    exit 1
fi

# Check for Tkinter (often separate on Linux)
$PYTHON_CMD -c "import tkinter" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Error: Tkinter module not found."
    echo "On Linux (Ubuntu/Debian), try: sudo apt install python3-tk"
    echo "On Fedora: sudo dnf install python3-tkinter"
    echo "On Mac: It should be included with standard Python installations."
    exit 1
fi

# Set up virtual environment
VENV_DIR="venv_p2p"

if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    $PYTHON_CMD -m venv "$VENV_DIR"
fi

# Activate virtual environment
source "$VENV_DIR/bin/activate"

# Upgrade pip
pip install --upgrade pip > /dev/null 2>&1

# Install dependencies if requirements.txt exists
if [ -f "requirements.txt" ]; then
    echo "Checking dependencies..."
    pip install -r requirements.txt
fi

# Run the application
echo "Launching application..."
python main.py

# Deactivate on exit (optional, as script ends anyway)
deactivate
