#!/bin/bash

# Function to check and install dependencies
check_dependencies() {
    echo "Checking and installing dependencies..."
    
    # Check for arp-scan
    if ! command -v arp-scan &> /dev/null; then
        echo "Installing arp-scan..."
        sudo apt-get update
        sudo apt-get install -y arp-scan
    else
        echo "arp-scan is already installed."
    fi

    # Check for cjson parser
    if ! dpkg -s libjson-c-dev &> /dev/null; then
        echo "Installing cjson parser..."
        sudo apt-get update
        sudo apt-get install -y libjson-c-dev
    else
        echo "cjson parser is already installed."
    fi

    # Check for libssl-dev
    if ! dpkg -s libssl-dev &> /dev/null; then
        echo "Installing libssl-dev..."
        sudo apt-get update
        sudo apt-get install -y libssl-dev
    else
        echo "libssl-dev is already installed."
    fi

    # Check for Node.js and npm
    if ! command -v node &> /dev/null; then
        echo "Installing Node.js and npm..."
        curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
        sudo apt-get install -y nodejs
    else
        echo "Node.js and npm are already installed."
    fi

    # Check for libcurl
    if ! dpkg -s libcurl4-openssl-dev &> /dev/null; then
        echo "Installing libcurl..."
        sudo apt-get update
        sudo apt-get install -y libcurl4-openssl-dev
    else
        echo "libcurl is already installed."
    fi

    echo "All dependencies are installed."
}

# Function to compile the programs
compile_programs() {
    echo "Compiling multicast receiver..."
    gcc -o multicast_receiver multicast_daemon_receiver.c -lssl -lcrypto

    echo "Compiling admin panel..."
    gcc -o admin_panel admin_panel.c -lssl -lcrypto -lm -lcjson

    echo "Compiling TUI client..."
    gcc -o tui_client ./TUI/ui_program.c -lssl -lcrypto -lcurl -ljson-c

    echo "Compilation complete."
}

# Function to set up and start the Node.js server
setup_node_server() {
    echo "Setting up Node.js server..."
    npm install
    echo "Starting Node.js server in the background..."
    node ./backend/index.js &
}

# Function to start the TUI
start_tui() {
    echo "Starting TUI in the background..."
    ./tui_client 
}

# Main script
echo "Welcome to the Multicast File Transfer System Compiler and Setup"

# Check and install dependencies
check_dependencies

# Compile the programs
compile_programs

# Set up and start Node.js server
setup_node_server

# Start TUI
start_tui

echo "To run the multicast receiver: ./multicast_receiver"
echo "To run the admin panel: ./admin_panel"
echo "Node.js server and TUI are running in the background."
