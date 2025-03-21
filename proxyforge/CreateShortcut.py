# Create a Windows shortcut for the ProxyForge executable


import os
import winshell
from win32com.client import Dispatch
import sys

# Get the directory where the script is located
script_dir = os.path.dirname(os.path.abspath(__file__))
# Parent directory (project root)
project_root = os.path.dirname(script_dir)
# Path to executable
exe_path = os.path.join(project_root, "dist", "ProxyForge.exe")
# Path to icon
icon_path = os.path.join(project_root, "proxyforge.ico")

# Verify paths exist
if not os.path.exists(exe_path):
    print(f"Error: Executable not found at {exe_path}")
    sys.exit(1)

desktop = winshell.desktop()
shortcut_path = os.path.join(desktop, "ProxyForge.lnk")

# Create shortcut
shell = Dispatch("WScript.Shell")
shortcut = shell.CreateShortcut(shortcut_path)
shortcut.TargetPath = exe_path
shortcut.WorkingDirectory = os.path.dirname(exe_path)
shortcut.Description = "Nginx Reverse Proxy Manager"
# Use absolute path for icon
if os.path.exists(icon_path):
    shortcut.IconLocation = icon_path
shortcut.Save()

print(f"Shortcut created on Desktop pointing to: {exe_path}")
print("Note: You'll need to manually set 'Run as administrator' in the shortcut properties")