pip install pyinstaller
pip install scapy

# Create the executable using PyInstaller
pyinstaller --onefile NetworkTools.py

# Provide executable permissions to the generated file

echo "NetworkTools executable created successfully."
