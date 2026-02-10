# P2P File Share (Mac/Linux Guide)

This application is written in Python and uses Tkinter for the GUI. It works on macOS and Linux.

## Prerequisites

- **Python 3.6+**: Most Mac and Linux systems come with Python 3 installed.
- **Tkinter**: The GUI library.
    - **macOS**: Included with standard Python.
    - **Linux (Ubuntu/Debian)**: `sudo apt-get install python3-tk`
    - **Linux (Fedora)**: `sudo dnf install python3-tkinter`

## Quick Start (Recommended)

Does everything for you (creates virtual environment, installs dependencies, launches app).

1. Open Terminal.
2. Navigate to the folder containing these files.
3. Run the following command:

```bash
chmod +x run.sh
./run.sh
```

## Manual Installation

If you prefer to run it manually:

1. **Create Virtual Environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run Application:**
   ```bash
   python3 main.py
   ```

## Troubleshooting

- **"ModuleNotFoundError: No module named 'tkinter'"**: Install `python3-tk` as shown in Prerequisites.
- **"Permission denied"**: Make sure you ran `chmod +x run.sh`.

## Creating a DMG (macOS)

To create a standalone `.dmg` installer for macOS:

1.  **Install Homebrew** (if not already installed):
    ```bash
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    ```

2.  **Run the Build Script:**
    This script will install necessary tools (`pyinstaller`, `create-dmg`) and generate the DMG file.

    ```bash
    chmod +x build_mac.sh
    ./build_mac.sh
    ```

3.  **Locate the DMG:**
    Once the script finishes, you will find the `P2PFileShare.dmg` file in the same directory. You can distribute this file to other Mac users.

