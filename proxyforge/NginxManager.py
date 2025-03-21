import ctypes
import os
import platform
import subprocess
import sys

from PyQt6.QtCore import pyqtSlot
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton,
    QListWidget, QMessageBox
)

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

        # Set application icon
        self.setWindowIcon(QIcon('../proxyforge.ico'))

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
        except ValueError as error:
            QMessageBox.critical(self, "Error", str(error))
            return

        try:
            crt_file = os.path.join(CERTS_PATH, f"{domain}.crt").replace("\\", "/")
            key_file = os.path.join(CERTS_PATH, f"{domain}.key").replace("\\", "/")

            self.generate_ssl_cert(domain)

            nginx_config = f"""
server {{
    listen 80;
    server_name {domain};

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
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
}}
"""

            config_file = os.path.join(CONFIG_PATH, f"{domain}.conf")
            with open(config_file, "w") as file:
                file.write(nginx_config)

            # Check if the main config file exists and create it if not
            main_config = os.path.join(CONFIG_PATH, "nginx.conf")
            if not os.path.exists(main_config):
                with open(main_config, "w") as file:
                    file.write("""
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
            with open(main_config, "r") as file:
                content = file.read()

            # Use a relative path with forward slashes for Nginx
            config_file_path = f"{domain}.conf"
            include_line = f'include "{config_file_path}";'

            if include_line not in content:
                # Insert it before the last closing brace
                if content.rstrip().endswith("}"):
                    new_content = content.rstrip()[:-1] + f"\n    {include_line}\n}}"
                    with open(main_config, "w") as file:
                        file.write(new_content)
                else:
                    with open(main_config, "a") as file:
                        file.write(f"\n{include_line}")

            self.update_hosts_file(domain)
            self.restart_nginx()
            self.refresh_domain_list()
            QMessageBox.information(self, "Success",
                                    f"Nginx configured for {domain} with HTTPS!\nAccess: https://{domain}")

        except Exception as error:
            QMessageBox.critical(self, "Error", f"Failed to configure Nginx: {str(error)}")

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
        except subprocess.CalledProcessError as error:
            raise Exception(f"OpenSSL error: {error.stderr}")
        except Exception as error:
            raise Exception(f"Certificate generation failed: {str(error)}")

    @staticmethod
    def edit_hosts(hostname, ip_address, action="add"):
        """
        Edits the Windows hosts file.

        Args:
            hostname (str): The hostname to add or remove.
            ip_address (str): The IP address associated with the hostname.
            action (str): "add" to add an entry, "remove" to remove.

        Returns:
            tuple: (bool, str) - Success status and message
        """

        system = platform.system()
        if system != "Windows":
            return False, "This script is designed for Windows."

        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"

        try:
            if action == "add":
                with open(hosts_path, "a") as hosts_file:  # Append mode
                    hosts_file.write(f"\n{ip_address} {hostname}")
                return True, f"Added {ip_address} {hostname} to hosts file."

            elif action == "remove":
                with open(hosts_path, "r") as hosts_file:
                    lines = hosts_file.readlines()

                with open(hosts_path, "w") as hosts_file:
                    removed = False
                    for line in lines:
                        if f"{ip_address} {hostname}" not in line:
                            hosts_file.write(line)
                        else:
                            removed = True

                    if removed:
                        return True, f"Removed {ip_address} {hostname} from hosts file."
                    else:
                        return False, f"{ip_address} {hostname} not found in hosts file."
            else:
                return False, "Invalid action. Use 'add' or 'remove'."

        except PermissionError:
            return False, f"Permission denied. You antivirus might be blocking the application. Manually edit the hosts file and add: '{ip_address} {hostname}'"
        except FileNotFoundError:
            return False, f"Hosts file not found at {hosts_path}"
        except Exception as error:
            return False, f"An error occurred: {error}"

    def update_hosts_file(self, domain, remove=False):
        """Modify the Windows hosts file"""
        try:
            # Default to localhost IP
            ip_address = "127.0.0.1"

            # Call the edit_hosts method with the appropriate action
            action = "remove" if remove else "add"
            success, message = self.edit_hosts(domain, ip_address, action)

            if success:
                QMessageBox.information(self, "Hosts File Updated", message)
            else:
                QMessageBox.warning(self, "Hosts File Warning", message)

        except Exception as error:
            QMessageBox.critical(self, "Error", f"Failed to update hosts file: {str(error)}")

    @staticmethod
    def is_nginx_running(parent=None):
        """Check if Nginx is running"""
        try:
            # Check using Windows services
            service_check = subprocess.run(
                "sc query nginx | find \"RUNNING\"",
                shell=True,
                capture_output=True,
                text=True
            )

            if "RUNNING" in service_check.stdout:
                return True

            # Fallback: check for nginx.exe in process list
            process_check = subprocess.run(
                "tasklist /FI \"IMAGENAME eq nginx.exe\" /NH",
                shell=True,
                capture_output=True,
                text=True
            )

            return "nginx.exe" in process_check.stdout
        except subprocess.SubprocessError as err:
            if parent:
                QMessageBox.warning(
                    parent,
                    "Process Check Error",
                    f"Failed to check if Nginx is running: {str(err)}"
                )
            return False
        except FileNotFoundError as err:
            if parent:
                QMessageBox.warning(
                    parent,
                    "Command Error",
                    f"Command not found: {str(err)}"
                )
            return False

    def restart_nginx(self):
        """Restart or start Nginx based on its current state"""
        try:
            # Check if Nginx is running
            is_running = self.is_nginx_running(self)

            if is_running:
                # Try service restart first
                service_restart = subprocess.run("net stop nginx && net start nginx",
                                                 shell=True, capture_output=True, text=True)

                # Check if the service restart was successful
                if service_restart.returncode == 0:
                    QMessageBox.information(self, "Success", "Nginx service restarted successfully!")
                    return

                # If service restart fails, try reload
                QMessageBox.information(self, "Nginx", "Service restart failed. Trying to reload Nginx...")
                reload_cmd = f'cd "{NGINX_PATH}" && nginx -s reload'
                reload_result = subprocess.run(reload_cmd, shell=True, capture_output=True, text=True)

                # Check if the reload was successful
                if reload_result.returncode == 0:
                    QMessageBox.information(self, "Success", "Nginx reloaded successfully!")
                else:
                    QMessageBox.critical(self, "Nginx Error", f"Failed to reload Nginx:\n{reload_result.stderr}")
            else:
                # Nginx is not running, try starting it
                # Try starting as a service first
                start_service = subprocess.run("net start nginx", shell=True, capture_output=True, text=True)

                # Check if the service start was successful
                if start_service.returncode == 0:
                    QMessageBox.information(self, "Success", "Nginx service started successfully!")
                else:
                    # Fallback to manual start
                    start_result = subprocess.run(f'cd "{NGINX_PATH}" && start nginx',
                                                  shell=True, capture_output=True, text=True)

                    # Check if the manual start was successful
                    if start_result.returncode == 0:
                        QMessageBox.information(self, "Success", "Nginx started successfully!")
                    else:
                        QMessageBox.critical(self, "Nginx Error", f"Failed to start Nginx:\n{start_result.stderr}")

        except Exception as error:
            QMessageBox.critical(self, "Error",
                                 f"An unexpected error occurred while managing Nginx:\n{str(error)}")


    @staticmethod
    def list_configured_domains():
        """List configured domains"""
        if not os.path.exists(CONFIG_PATH):
            return []
        excluded_files = ["nginx.conf", "fastcgi.conf"]
        return [file[:-5] for file in os.listdir(CONFIG_PATH)
                if file.endswith(".conf") and file not in excluded_files]

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
                    with open(main_config, "r") as file:
                        lines = file.readlines()

                    # Use the same include format as in apply_config
                    config_file_path = f"{domain}.conf"
                    include_line = f'include "{config_file_path}";'
                    new_lines = [line for line in lines if include_line not in line]

                    with open(main_config, "w") as file:
                        file.writelines(new_lines)

                self.update_hosts_file(domain, remove=True)
                self.restart_nginx()
                self.refresh_domain_list()
                QMessageBox.information(self, "Success", f"{domain} removed successfully!")

            except Exception as error:
                QMessageBox.critical(self, "Error", f"Failed to delete domain: {str(error)}")


if __name__ == "__main__":
    try:
        # Check for admin rights
        if not ctypes.windll.shell32.IsUserAnAdmin():
            # Restart the script with admin rights
            if sys.argv[0].endswith('.exe'):
                args = " ".join(sys.argv)
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, args, None, 1
                )
                sys.exit(0)
            else:
                QMessageBox.warning(None, "Admin Rights Required", "Please restart as Administrator!")
                sys.exit(1)

        app = QApplication(sys.argv)
        window = NginxManager()
        window.show()
        sys.exit(app.exec())
    except Exception as e:
        import traceback
        # Log the error to a file
        log_file = os.path.join(os.path.expanduser("~"), "proxyforge_error.log")
        with open(log_file, "a") as f:
            f.write(f"Error: {str(e)}\n")
            f.write(traceback.format_exc())
        sys.exit(1)