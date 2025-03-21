# ProxyForge

![ProxyForge Logo](proxyforge.ico)

A streamlined GUI application for managing Nginx as a local reverse proxy with automatic SSL certificate generation.

## Overview

ProxyForge simplifies the process of configuring and managing Nginx as a reverse proxy for local development. It provides a user-friendly interface to:

- Configure custom domains for local services

#### The application also:

- Automatically generate self-signed SSL certificates
- Manages hosts file entries

## Features

- **Custom Domain Configuration**: Easily map any local port to a custom domain
- **Automatic SSL**: Self-signed certificate generation for HTTPS development
- **Host File Management**: Automatic updates to your system's hosts file (Your antivirus may block this).
- **Nginx Service Control**: Automatically starts/restarts Nginx.
- **Configuration Management**: Add or remove proxy configurations with a few clicks

## Prerequisites

- Windows 10/11
- Nginx installed
- OpenSSL (typically included with Nginx)
- Python 3.8+ (if running from source)
- Poetry (if running from source)

*The application needs Administrative Privileges.*

## Installation

1. Clone this repository
2. Install python if you haven't already (https://www.python.org/downloads/)
   - Make sure to add Python to your PATH during installation
3. Install Poetry if you haven't already (https://python-poetry.org/docs/#installation)
4. Install dependencies:
   ```
   poetry install
   ```
5. Install Nginx if you haven't already (https://nginx.org/en/docs/install.html)
   - For some reason, Nginx seems to want you to cd into the directory before running it, so I use this simple alias to allow me to run it from anywhere:
   ```
   # alias
   function nginx {
       Push-Location "C:\TechStacks\nginx"
       & ".\nginx.exe" @Args
       Pop-Location
   }
   ```
6. Install OpenSSL if you haven't already (https://slproweb.com/products/Win32OpenSSL.html)
   - Make sure to add OpenSSL to your PATH during installation
7. Run the build script to create the executable:
   ```
   poetry run pyinstaller --noconsole --onefile --name=ProxyForge --manifest=admin_manifest.xml --icon=proxyforge.ico proxyforge/NginxManager.py
   ```
8. Create a shortcut to the executable on desktop for easy access (Optional)
   ```
      python .\proxyforge\CreateShortcut.py
   ```
9. Run as administrator.

## Usage

1. **Add a New Domain**:
   - Enter your custom domain (e.g., `myapp.local`)
   - Specify the local port your service is running on (e.g., `9000`)
   - Click "Apply Configuration"

2. **Access Your Service**:
   - Navigate to your custom domain in any browser
   - The connection will be secured with HTTPS via the self-signed certificate

3. **Manage Domains**:
   - The domain list shows all configured domains
   - Select a domain and click "Delete Selected" to remove it

## Troubleshooting

- **Certificate Warnings**: Because the certificates are self-signed, browsers will show security warnings. You can add an exception or import the certificate to your system's trust store.
- **Permission Issues**: The application requires administrator privileges to modify the hosts file and manage the Nginx service. Even with Administrator privileges, you antivirus might prevent the application from automatically modifying the hosts file. If this happens you will need to manually add the entries (127.0.0.1 myapp.local).
- **Port Conflicts**: Ensure Nginx is not conflicting with other web servers (like IIS) that might be using ports 80/443.

## Configuration

The application uses these default paths:

- Nginx: `C:\nginx`
- Configuration files: `C:\nginx\conf`
- SSL certificates: `C:\nginx\certs`
- Windows hosts file: `C:\Windows\System32\drivers\etc\hosts`

To modify these paths, edit the constants at the top of `NginxManager.py`.

## License

MIT License

## Acknowledgements

- [Nginx](https://nginx.org/) for the powerful web server
- [PyQt6](https://www.riverbankcomputing.com/software/pyqt/) for the GUI framework
- [OpenSSL](https://www.openssl.org/) for SSL certificate generation
