#!/bin/bash
# build.sh - Setup script for Render deployment

set -e  # Exit immediately if a command fails

echo "===== Starting build process ====="

# Install system dependencies
echo "Installing system dependencies..."
apt-get update -qq || { echo "Failed to update package lists"; exit 1; }
apt-get install -y curl jq unzip sudo ncurses-bin || { echo "Failed to install dependencies"; exit 1; }
apt-get clean

# Install Steampipe
echo "Installing Steampipe..."
TEMP_DIR=$(mktemp -d)
cd $TEMP_DIR

# Download and run the installer
echo "Downloading Steampipe installer..."
curl -fsSL https://steampipe.io/install/steampipe.sh -o steampipe_install.sh || { 
  echo "Failed to download Steampipe installer"; 
  exit 1; 
}
chmod +x steampipe_install.sh

echo "Running Steampipe installer..."
./steampipe_install.sh || {
  echo "Failed to install Steampipe using script"
  # Fallback to direct download
  echo "Attempting direct binary installation"
  mkdir -p ~/.steampipe/bin
  curl -fsSL https://github.com/turbot/steampipe/releases/latest/download/steampipe_linux_amd64.tar.gz -o steampipe.tar.gz || { 
    echo "Failed to download Steampipe binary"; 
    exit 1; 
  }
  tar -xzf steampipe.tar.gz || { 
    echo "Failed to extract Steampipe archive"; 
    exit 1; 
  }
  mv steampipe ~/.steampipe/bin/ || { 
    echo "Failed to move Steampipe binary"; 
    exit 1; 
  }
  chmod +x ~/.steampipe/bin/steampipe || { 
    echo "Failed to make Steampipe executable"; 
    exit 1; 
  }
}

# Create symlink for system-wide access
echo "Creating system-wide symlink for steampipe..."
sudo mkdir -p /usr/local/bin || { echo "Failed to create /usr/local/bin directory"; }
sudo ln -sf ~/.steampipe/bin/steampipe /usr/local/bin/steampipe || { echo "Failed to create symlink"; }

# Set up PATH in profiles
echo 'export PATH="$HOME/.steampipe/bin:$PATH"' >> ~/.bashrc
echo 'export PATH="$HOME/.steampipe/bin:$PATH"' >> ~/.profile

# Verify installation
export PATH="$HOME/.steampipe/bin:$PATH"
echo "Checking Steampipe installation..."
which steampipe || echo "Warning: steampipe not found in PATH"

if [ -f ~/.steampipe/bin/steampipe ]; then
  echo "Steampipe binary exists at ~/.steampipe/bin/steampipe"
  ~/.steampipe/bin/steampipe --version || echo "Failed to run steampipe --version"
else
  echo "ERROR: Steampipe binary not found at ~/.steampipe/bin/steampipe"
  find ~ -name steampipe
  exit 1
fi

cd -  # Return to original directory
rm -rf $TEMP_DIR

# Install AWS plugin
echo "Installing AWS plugin for Steampipe..."
export PATH="$HOME/.steampipe/bin:$PATH"
steampipe plugin install aws || { 
  echo "AWS plugin installation with PATH failed"
  ~/.steampipe/bin/steampipe plugin install aws || {
    echo "AWS plugin installation with direct path failed"
    echo "WARNING: AWS plugin not installed, continuing anyway"
  }
}

# Install Python dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt || { echo "Failed to install requirements"; exit 1; }
pip install --upgrade semgrep || { echo "Failed to install semgrep"; exit 1; }

# Create database tables
echo "Creating database tables..."
python create_tables.py || { echo "Failed to create database tables"; exit 1; }

echo "===== Build completed successfully! ====="