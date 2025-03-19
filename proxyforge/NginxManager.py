import os
import sys
import ctypes
import subprocess
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton,
    QListWidget, QMessageBox
)
from PyQt6.QtCore import pyqtSlot

# Paths
NGINX_PATH = r"C:\nginx"  # Change to actual Nginx path
HOSTS_FILE = r"C:\Windows\System32\drivers\etc\hosts"
CERTS_PATH = os.path.join(NGINX_PATH, "certs")
CONFIG_PATH = os.path.join(NGINX_PATH, "conf")

# Ensure directories exist
os.makedirs(CERTS_PATH, exist_ok=True)
os.makedirs(CONFIG_PATH, exist_ok=True)


class NginxManager(QWidget):
    def __init__(self):
        super().__init__()

        # Initialize instance attributes
        self.domain_label = None
        self.domain_input = None
        self.port_label = None
        self.port_input = None
        self.apply_button = None
        self.domain_list = None
        self.delete_button = None

        self.init_ui()
        self.check_nginx_installation()

    def check_nginx_installation(self):
        """Verify Nginx is installed at the specified path"""
        nginx_exe = os.path.join(NGINX_PATH, "nginx.exe")
        if not os.path.exists(nginx_exe):
            QMessageBox.warning(
                self,
                "Nginx Not Found",
                f"Nginx executable not found at {nginx_exe}.\n"
                "Please install Nginx or update the NGINX_PATH variable."
            )
            return False
        return True

    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("Nginx Reverse Proxy Manager (SSL)")
        self.setGeometry(200, 200, 500, 400)

        layout = QVBoxLayout()

        # Input fields
        self.domain_label = QLabel("Custom Domain:")
        self.domain_input = QLineEdit(self)
        self.port_label = QLabel("Local Port (e.g., 9000):")
        self.port_input = QLineEdit(self)

        self.apply_button = QPushButton("Apply Configuration", self)
        # noinspection PyUnresolvedReferences
        self.apply_button.clicked.connect(self.apply_config)

        # Domain list
        self.domain_list = QListWidget(self)
        self.refresh_domain_list()

        self.delete_button = QPushButton("Delete Selected", self)
        # noinspection PyUnresolvedReferences
        self.delete_button.clicked.connect(self.delete_domain)

        # Layout arrangement
        layout.addWidget(self.domain_label)
        layout.addWidget(self.domain_input)
        layout.addWidget(self.port_label)
        layout.addWidget(self.port_input)
        layout.addWidget(self.apply_button)
        layout.addWidget(QLabel("Configured Domains:"))
        layout.addWidget(self.domain_list)
        layout.addWidget(self.delete_button)

        self.setLayout(layout)

    @pyqtSlot()
    def apply_config(self):
        """Generate & apply Nginx configuration"""
        if not self.check_nginx_installation():
            return

        domain = self.domain_input.text().strip()
        port = self.port_input.text().strip()

        if not domain or not port:
            QMessageBox.critical(self, "Error", "Both domain and port are required!")
            return

        # Append .local if no TLD is provided
        if "." not in domain:
            domain += ".local"

        try:
            port = int(port)
            if port < 1 or port > 65535:
                raise ValueError("Port must be between 1 and 65535")
        except ValueError as e:
            QMessageBox.critical(self, "Error", str(e))
            return

        try:
            crt_file, key_file = self.generate_ssl_cert(domain)

            nginx_config = f"""
server {{
    listen 80;
    server_name {domain};

    # Redirect all HTTP to HTTPS
    return 301 https://$host$request_uri;
}}

server {{
    listen 443 ssl;
    server_name {domain};

    ssl_certificate {crt_file};
    ssl_certificate_key {key_file};

    location / {{
        proxy_pass http://127.0.0.1:{port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }}
}}
"""

            config_file = os.path.join(CONFIG_PATH, f"{domain}.conf")
            with open(config_file, "w") as f:
                f.write(nginx_config)

            # Check if the main config file exists and create it if not
            main_config = os.path.join(CONFIG_PATH, "nginx.conf")
            if not os.path.exists(main_config):
                with open(main_config, "w") as f:
                    f.write("""
worker_processes  1;
events {
    worker_connections  1024;
}
http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile        on;
    keepalive_timeout  65;

    # Domain-specific configurations will be included below
}
""")

            # Update the main config file to include our domain config
            with open(main_config, "r") as f:
                content = f.read()

            include_line = f'include conf/{domain}.conf;'
            if include_line not in content:
                # Insert it before the last closing brace
                if content.rstrip().endswith("}"):
                    new_content = content.rstrip()[:-1] + f"\n    {include_line}\n}}"
                    with open(main_config, "w") as f:
                        f.write(new_content)
                else:
                    with open(main_config, "a") as f:
                        f.write(f"\n{include_line}")

            self.update_hosts_file(domain)
            self.restart_nginx()
            self.refresh_domain_list()
            QMessageBox.information(self, "Success",
                                   f"Nginx configured for {domain} with HTTPS!\nAccess: https://{domain}")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to configure Nginx: {str(e)}")

    @staticmethod
    def generate_ssl_cert(domain):
        """Generate a self-signed SSL certificate"""
        crt_file = os.path.join(CERTS_PATH, f"{domain}.crt")
        key_file = os.path.join(CERTS_PATH, f"{domain}.key")

        if os.path.exists(crt_file) and os.path.exists(key_file):
            return crt_file, key_file  # Certificate already exists

        try:
            cmd = f'openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "{key_file}" -out "{crt_file}" -subj "/CN={domain}"'
            subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)

            if not os.path.exists(crt_file) or not os.path.exists(key_file):
                raise Exception("Certificate files not created successfully")

            return crt_file, key_file
        except subprocess.CalledProcessError as e:
            raise Exception(f"OpenSSL error: {e.stderr}")
        except Exception as e:
            raise Exception(f"Certificate generation failed: {str(e)}")

    def update_hosts_file(self, domain, remove=False):
        """Modify the Windows hosts file"""
        try:
            if not os.path.exists(HOSTS_FILE):
                raise FileNotFoundError(f"Hosts file not found at {HOSTS_FILE}")

            with open(HOSTS_FILE, "r") as file:
                lines = file.readlines()

            new_lines = [line for line in lines if domain not in line]

            if not remove:
                new_lines.append(f"127.0.0.1 {domain}\n")

            with open(HOSTS_FILE, "w") as file:
                file.writelines(new_lines)

            subprocess.run("ipconfig /flushdns", shell=True, check=False)
            action = "removed from" if remove else "added to"
            QMessageBox.information(self, "Hosts File Updated", f"{domain} {action} hosts file!")

        except PermissionError:
            QMessageBox.critical(self, "Permission Denied", "Run this script as Administrator!")
        except FileNotFoundError as e:
            QMessageBox.critical(self, "File Not Found", str(e))
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to update hosts file: {str(e)}")

    @staticmethod
    def restart_nginx():
        """Restart Nginx"""
        try:
            # First check if nginx is running
            result = subprocess.run(f'cd "{NGINX_PATH}" && nginx -t', shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                raise Exception(f"Nginx config test failed: {result.stderr}")

            # Reload if running, otherwise start it
            subprocess.run(f'cd "{NGINX_PATH}" && nginx -s reload', shell=True, check=True)
        except subprocess.CalledProcessError:
            # Nginx might not be running, try to start it
            try:
                subprocess.run(f'cd "{NGINX_PATH}" && start nginx', shell=True, check=True)
            except subprocess.CalledProcessError as e:
                raise Exception(f"Failed to start Nginx: {str(e)}")

    @staticmethod
    def list_configured_domains():
        """List configured domains"""
        if not os.path.exists(CONFIG_PATH):
            return []
        return [f[:-5] for f in os.listdir(CONFIG_PATH) if f.endswith(".conf") and f != "nginx.conf"]

    def refresh_domain_list(self):
        """Refresh domain list in GUI"""
        if self.domain_list is None:
            return

        self.domain_list.clear()
        for domain in self.list_configured_domains():
            self.domain_list.addItem(domain)

    @pyqtSlot()
    def delete_domain(self):
        """Delete selected domain's configuration"""
        if self.domain_list is None:
            return

        selected_item = self.domain_list.currentItem()
        if not selected_item:
            QMessageBox.critical(self, "Error", "Select a domain to delete!")
            return

        domain = selected_item.text()
        confirm = QMessageBox.question(
            self,
            "Confirm Deletion",
            f"Delete {domain}?",
            QMessageBox.StandardButton.Yes,
            QMessageBox.StandardButton.No
        )

        if confirm == QMessageBox.StandardButton.Yes:
            try:
                # Remove domain config files
                config_file = os.path.join(CONFIG_PATH, f"{domain}.conf")
                crt_file = os.path.join(CERTS_PATH, f"{domain}.crt")
                key_file = os.path.join(CERTS_PATH, f"{domain}.key")

                for file_path in [config_file, crt_file, key_file]:
                    if os.path.exists(file_path):
                        os.remove(file_path)

                # Remove include line from main config
                main_config = os.path.join(CONFIG_PATH, "nginx.conf")
                if os.path.exists(main_config):
                    with open(main_config, "r") as f:
                        lines = f.readlines()

                    include_line = f'include conf/{domain}.conf;'
                    new_lines = [line for line in lines if include_line not in line]

                    with open(main_config, "w") as f:
                        f.writelines(new_lines)

                self.update_hosts_file(domain, remove=True)
                self.restart_nginx()
                self.refresh_domain_list()
                QMessageBox.information(self, "Success", f"{domain} removed successfully!")

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete domain: {str(e)}")


if __name__ == "__main__":
    if not ctypes.windll.shell32.IsUserAnAdmin():
        QMessageBox.warning(None, "Admin Rights Required", "Restart as Administrator!")
        sys.exit(1)

    app = QApplication(sys.argv)
    window = NginxManager()
    window.show()
    sys.exit(app.exec())