import sys
import threading
from PyQt5.QtCore import Qt, QTimer, QTime
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit,
    QPushButton, QTabWidget, QFormLayout, QMessageBox
)
from PyQt5.QtGui import QFont
import requests
from email_validator import validate_email, EmailNotValidError
from .vpn_client import VPNClient  # Adjust the import as per your project structure

class VPNClientGUI(QWidget):
    def __init__(self):
        super().__init__()

        self.vpn_client = None
        self.authenticated = False

        self.setWindowTitle("Secure VPN")
        self.setGeometry(400, 200, 400, 320)

        self.setStyleSheet("""
            QWidget {
                background-color: #2C2F38;
                color: white;
                font-family: Arial;
            }
            QLineEdit {
                background-color: #3A3F47;
                color: white;
                border: 1px solid #555;
                padding: 8px;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton {
                background-color: #1B6B93;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #135a7e;
            }
            QLabel {
                font-size: 14px;
                margin-bottom: 4px;
            }
            QTabBar::tab {
                background-color: #3A3F47;
                padding: 10px;
                color: white;
                font-weight: bold;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                min-width: 100px;
            }
            QTabBar::tab:selected {
                background-color: #1B6B93;
            }
        """)

        self.init_ui()

    def init_ui(self):
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        self.tabs = QTabWidget()
        self.layout.addWidget(self.tabs)

        self.init_login_tab()
        self.init_register_tab()

    def init_login_tab(self):
        login_tab = QWidget()
        login_layout = QFormLayout()

        self.username_login = QLineEdit()
        self.username_login.setPlaceholderText("Username")
        self.password_login = QLineEdit()
        self.password_login.setEchoMode(QLineEdit.Password)
        self.password_login.setPlaceholderText("Password")

        login_button = QPushButton("Login")
        login_button.clicked.connect(self.login)

        login_layout.addRow(QLabel("Username:"), self.username_login)
        login_layout.addRow(QLabel("Password:"), self.password_login)
        login_layout.addRow(login_button)

        login_tab.setLayout(login_layout)
        self.tabs.addTab(login_tab, "Login")

    def init_register_tab(self):
        register_tab = QWidget()
        register_layout = QFormLayout()

        self.username_register = QLineEdit()
        self.username_register.setPlaceholderText("Username")
        self.password_register = QLineEdit()
        self.password_register.setEchoMode(QLineEdit.Password)
        self.password_register.setPlaceholderText("Password")
        self.email_register = QLineEdit()
        self.email_register.setPlaceholderText("Email")

        register_button = QPushButton("Register")
        register_button.clicked.connect(self.register)

        register_layout.addRow(QLabel("Username:"), self.username_register)
        register_layout.addRow(QLabel("Password:"), self.password_register)
        register_layout.addRow(QLabel("Email:"), self.email_register)
        register_layout.addRow(register_button)

        register_tab.setLayout(register_layout)
        self.tabs.addTab(register_tab, "Register")

    def login(self):
        username = self.username_login.text()
        password = self.password_login.text()

        if not username or not password:
            QMessageBox.warning(self, "Input Error", "Please fill in both fields")
            return

        self.vpn_client = VPNClient(tun_device_name='tun1', tun_device_ip='10.1.0.1', server_address=('localhost', 3000))

        def auth_thread():
            try:
                if self.vpn_client.receive_token(username, password, "localhost"):
                    QTimer.singleShot(0, self.on_login_success)
                else:
                    QTimer.singleShot(0, lambda: QMessageBox.warning(self, "Login Failed", "Incorrect credentials."))
            except Exception as e:
                QTimer.singleShot(0, lambda: QMessageBox.critical(self, "Login Error", str(e)))

        threading.Thread(target=auth_thread, daemon=True).start()

    def register(self):
        username = self.username_register.text()
        password = self.password_register.text()
        email = self.email_register.text()

        if not username or not password or not email:
            QMessageBox.warning(self, "Input Error", "Please fill in all fields")
            return

        # Email format validation
        try:
            validate_email(email)
        except EmailNotValidError as e:
            QMessageBox.warning(self, "Invalid Email", f"Email format is invalid: {e}")
            return

        self.vpn_client = VPNClient(tun_device_name='tun1', tun_device_ip='10.1.0.1', server_address=('localhost', 3000))

        def register_thread():
            try:
                response = self.vpn_client.signup("localhost", username, password, email)
                print(response)
                if response is None:
                    QTimer.singleShot(0, lambda: QMessageBox.critical(self, "Server Error", "No response from server."))
                    return

                if response.status_code == 200:
                    QTimer.singleShot(0, lambda: QMessageBox.information(self, "Success", "Registered successfully."))
                    QTimer.singleShot(0, lambda: self.tabs.setCurrentIndex(0))
                elif response.status_code == 400:
                    msg = response.json().get("detail", "Bad request.")
                    QTimer.singleShot(0, lambda: QMessageBox.warning(self, "Registration Failed", msg))
                else:
                    msg = response.json().get("detail", "An unexpected error occurred.")
                    QTimer.singleShot(0, lambda: QMessageBox.critical(self, "Error", f"Status {response.status_code}: {msg}"))

            except Exception as e:
                QTimer.singleShot(0, lambda: QMessageBox.critical(self, "Register Error", str(e)))

        threading.Thread(target=register_thread, daemon=True).start()

    def on_login_success(self):
        self.connected_window = ConnectedWindow()
        self.connected_window.show()
        self.close()
        self.start_vpn_client_thread()

    def start_vpn_client_thread(self):
        def vpn_thread():
            from .tcp_handshake_client import SecureTCPClient
            client = SecureTCPClient(auth_token=self.vpn_client.auth_token)
            self.vpn_client.session_id, self.vpn_client.aes_key = client.perform()
            print("[*] VPN Handshake complete. Starting VPN...")
            self.vpn_client.start()

        threading.Thread(target=vpn_thread, daemon=True).start()

class ConnectedWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PiperVPN - Connected")
        self.setGeometry(450, 250, 350, 250)

        self.setStyleSheet("""
            QWidget {
                background-color: #1E1F26;
                color: white;
                font-family: 'Segoe UI', sans-serif;
                font-size: 15px;
            }
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
            QLabel {
                margin-bottom: 10px;
            }
        """)

        layout = QVBoxLayout()

        title = QLabel("🔒 PiperVPN")
        title.setFont(QFont("Arial", 20, QFont.Bold))
        title.setStyleSheet("color: #00FF88;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        connected_label = QLabel("Connected securely to the VPN.")
        connected_label.setStyleSheet("color: #cccccc; font-size: 14px;")
        connected_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(connected_label)

        self.uptime = QTime(0, 0, 0)
        self.status_label = QLabel("Session Duration: 00:00:00")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("color: #AAAAAA; font-size: 13px;")
        layout.addWidget(self.status_label)

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_uptime)
        self.timer.start(1000)

        disconnect_btn = QPushButton("Disconnect")
        disconnect_btn.clicked.connect(self.disconnect_vpn)
        layout.addWidget(disconnect_btn)

        self.setLayout(layout)

    def update_uptime(self):
        self.uptime = self.uptime.addSecs(1)
        self.status_label.setText(f"Session Duration: {self.uptime.toString('hh:mm:ss')}")

    def disconnect_vpn(self):
        QMessageBox.information(self, "Disconnected", "You have disconnected from PiperVPN.")
        self.close()

import signal

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    app = QApplication(sys.argv)
    window = VPNClientGUI()
    window.show()
    sys.exit(app.exec_())
