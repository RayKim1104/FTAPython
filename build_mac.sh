#!/bin/bash

# Exit on error
set -e

APP_NAME="P2PFileShare"
MAIN_SCRIPT="main.py"

echo "Check for required tools..."

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is not installed. Please install it first."
    exit 1
fi

# Check for pip
if ! command -v pip3 &> /dev/null; then
    echo "pip3 is not installed. Please install it first."
    exit 1
fi

# Install dependencies
echo "Installing Python dependencies..."
pip3 install -r requirements.txt

# Install PyInstaller if not installed
if ! python3 -c "import PyInstaller" &> /dev/null; then
    echo "Installing PyInstaller..."
    pip3 install pyinstaller
fi

# Check for create-dmg (brew install create-dmg)
if ! command -v create-dmg &> /dev/null; then
    echo "create-dmg is not installed. Trying to install via Homebrew..."
    if command -v brew &> /dev/null; then
        brew install create-dmg
    else
        echo "Homebrew is not installed. Please install Homebrew and run: brew install create-dmg"
        echo "Homebrew website: https://brew.sh/"
        exit 1
    fi
fi

# Clean up previous builds
echo "Cleaning up previous builds..."
rm -rf build dist "${APP_NAME}.dmg"

# Build the .app bundle
echo "Building the application..."
# Use --windowed to avoid terminal popup, --name for app name
pyinstaller --clean --noconfirm --windowed --name "$APP_NAME" "$MAIN_SCRIPT"

# Verify .app creation
APP_BUNDLE="dist/${APP_NAME}.app"
if [ ! -d "$APP_BUNDLE" ]; then
    echo "Error: Failed to create ${APP_NAME}.app"
    exit 1
fi

# Create DMG
echo "Creating DMG..."
create-dmg \
  --volname "${APP_NAME} Installer" \
  --volicon "dist/${APP_NAME}.app/Contents/Resources/icon-windowed.icns" \
  --window-pos 200 120 \
  --window-size 800 400 \
  --icon-size 100 \
  --icon "${APP_NAME}.app" 200 190 \
  --hide-extension "${APP_NAME}.app" \
  --app-drop-link 600 185 \
  "${APP_NAME}.dmg" \
  "dist/${APP_NAME}.app"

if [ -f "${APP_NAME}.dmg" ]; then
    echo "Success! ${APP_NAME}.dmg has been created."
else
    echo "Error: Failed to create DMG file."
    exit 1
fi
