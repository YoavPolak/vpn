import sys
from threading import Thread
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QStackedLayout, QMessageBox
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt

# ✅ Import your VPNClient + State Enum
from .test_client import VPNClient, State


class VPNDashboard(QWidget):
    def __init__(self, vpn_client: VPNClient, username):
        super().__init__()
        self.vpn_client = vpn_client
        self.username = username
        self.vpn_connected = True
        self.setWindowTitle("VPN Dashboard")
        self.setGeometry(550, 250, 450, 300)
        self.setWindowFlags(Qt.Window | Qt.WindowMinimizeButtonHint | Qt.WindowCloseButtonHint)
        self.setStyleSheet("background-color: #0f1c2e; color: white;")
        self.setFixedSize(self.width(), self.height())
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        welcome = QLabel(f"👋 Welcome, {self.username}")
        welcome.setFont(QFont("Arial", 18))
        welcome.setAlignment(Qt.AlignCenter)
        welcome.setStyleSheet("color: #00c2ff; margin-bottom: 20px;")
        layout.addWidget(welcome)

        self.status_label = QLabel("🟢 VPN Connected")
        self.status_label.setFont(QFont("Arial", 16))
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)

        self.vpn_button = QPushButton("Disconnect VPN")
        self.vpn_button.setCursor(Qt.PointingHandCursor)
        self.vpn_button.setStyleSheet("""
            QPushButton {
                background-color: #00c2ff;
                border: none;
                padding: 12px;
                font-weight: bold;
                font-size: 16px;
                color: #0f1c2e;
                border-radius: 10px;
            }
            QPushButton:hover {
                background-color: #00a8d4;
            }
        """)
        self.vpn_button.clicked.connect(self.toggle_vpn)
        layout.addWidget(self.vpn_button)

        location_label = QLabel("🌍 Server: United States (New York)")
        location_label.setFont(QFont("Arial", 14))
        location_label.setAlignment(Qt.AlignCenter)
        location_label.setStyleSheet("margin-top: 20px; color: #b0bec5;")
        layout.addWidget(location_label)

        self.setLayout(layout)

    def toggle_vpn(self):
        if self.vpn_connected:
            self.status_label.setText("🔴 VPN Disconnected")
            self.vpn_button.setText("Connect VPN")
            # self.vpn_client.disconnect()
        else:
            self.status_label.setText("🟢 VPN Connected")
            self.vpn_button.setText("Disconnect VPN")
        self.vpn_connected = not self.vpn_connected


class VPNAuthApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("VPN Connect - Secure Access")
        self.setGeometry(500, 200, 400, 500)
        self.setWindowFlags(Qt.Window | Qt.WindowMinimizeButtonHint | Qt.WindowCloseButtonHint)
        self.setStyleSheet("background-color: #0f1c2e; color: white;")
        self.setFixedSize(self.width(), self.height())

        self.vpn_client = VPNClient(
            tun_device_name="tun1",
            tun_device_ip="10.1.0.1",
            server_address=("127.0.0.1", 3000)
        )
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        logo = QLabel("🔒 VPN Connect")
        logo.setFont(QFont("Arial", 20, QFont.Bold))
        logo.setAlignment(Qt.AlignCenter)
        logo.setStyleSheet("color: #00c2ff; margin-top: 20px;")
        layout.addWidget(logo)

        toggle_layout = QHBoxLayout()
        self.login_btn = QPushButton("Login")
        self.register_btn = QPushButton("Register")

        for btn in (self.login_btn, self.register_btn):
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #1a2b44;
                    border: none;
                    padding: 10px;
                    color: white;
                    font-weight: bold;
                    border-radius: 10px;
                }
                QPushButton:hover {
                    background-color: #00c2ff;
                    color: #0f1c2e;
                }
            """)
            btn.setCursor(Qt.PointingHandCursor)

        self.login_btn.clicked.connect(self.show_login)
        self.register_btn.clicked.connect(self.show_register)

        toggle_layout.addWidget(self.login_btn)
        toggle_layout.addWidget(self.register_btn)
        layout.addLayout(toggle_layout)

        self.stack_layout = QStackedLayout()
        self.login_widget = self.create_login_form()
        self.register_widget = self.create_register_form()
        self.stack_layout.addWidget(self.login_widget)
        self.stack_layout.addWidget(self.register_widget)

        layout.addLayout(self.stack_layout)
        self.setLayout(layout)

    def create_login_form(self):
        widget = QWidget()
        layout = QVBoxLayout()

        self.login_username = QLineEdit()
        self.login_password = QLineEdit()
        login_submit = QPushButton("Login")

        for field, placeholder in [(self.login_username, "Username"), (self.login_password, "Password")]:
            field.setPlaceholderText(placeholder)
            field.setStyleSheet("""
                QLineEdit {
                    padding: 10px;
                    border-radius: 8px;
                    border: 1px solid #2c3e50;
                    background-color: #1a2b44;
                    color: white;
                }
            """)
            layout.addWidget(field)

        self.login_password.setEchoMode(QLineEdit.Password)

        login_submit.setStyleSheet("""
            QPushButton {
                background-color: #00c2ff;
                border: none;
                padding: 10px;
                color: #0f1c2e;
                font-weight: bold;
                border-radius: 10px;
            }
            QPushButton:hover {
                background-color: #00a8d4;
            }
        """)
        login_submit.clicked.connect(self.handle_login)
        layout.addWidget(login_submit)

        widget.setLayout(layout)
        return widget

    def create_register_form(self):
        widget = QWidget()
        layout = QVBoxLayout()

        self.register_username = QLineEdit()
        self.register_email = QLineEdit()
        self.register_password = QLineEdit()
        register_submit = QPushButton("Register")

        for field, placeholder in [
            (self.register_username, "Username"),
            (self.register_email, "Email"),
            (self.register_password, "Password")
        ]:
            field.setPlaceholderText(placeholder)
            field.setStyleSheet("""
                QLineEdit {
                    padding: 10px;
                    border-radius: 8px;
                    border: 1px solid #2c3e50;
                    background-color: #1a2b44;
                    color: white;
                }
            """)
            layout.addWidget(field)

        self.register_password.setEchoMode(QLineEdit.Password)

        register_submit.setStyleSheet("""
            QPushButton {
                background-color: #00c2ff;
                border: none;
                padding: 10px;
                color: #0f1c2e;
                font-weight: bold;
                border-radius: 10px;
            }
            QPushButton:hover {
                background-color: #00a8d4;
            }
        """)
        register_submit.clicked.connect(self.handle_register)
        layout.addWidget(register_submit)

        widget.setLayout(layout)
        return widget

    def show_login(self):
        self.stack_layout.setCurrentIndex(0)

    def show_register(self):
        self.stack_layout.setCurrentIndex(1)

    def switch_to_login_tab(self):
        self.stack_layout.setCurrentIndex(0)

    def handle_login(self):
        username = self.login_username.text()
        password = self.login_password.text()
        domain = "localhost"

        self.vpn_client.login(username, password, domain)

        if self.vpn_client.state == State.AUTHENTICATED:
            self.dashboard = VPNDashboard(self.vpn_client, username)
            self.dashboard.show()

            vpn_thread = Thread(target=self.vpn_client.start, daemon=True)
            vpn_thread.start()

            self.close()
        else:
            QMessageBox.warning(self, "Login Failed", "Invalid username, password, or handshake failed.")

    def handle_register(self):
        username = self.register_username.text()
        email = self.register_email.text()
        password = self.register_password.text()
        domain = "localhost"

        if not username or not email or not password:
            QMessageBox.warning(self, "Input Error", "Please fill in all fields.")
            return

        try:
            success = self.vpn_client.signup(domain=domain, username=username, password=password, email=email)

            if success:
                QMessageBox.information(self, "Success", "Registration successful! You can now log in.")
                self.switch_to_login_tab()
            else:
                QMessageBox.warning(self, "Registration Failed", "Signup failed. Username or email may already exist.")
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Signup error: {str(e)}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    vpn_window = VPNAuthApp()
    vpn_window.show()
    sys.exit(app.exec_())
