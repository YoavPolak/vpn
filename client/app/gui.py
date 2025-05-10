import flet as ft
from flet import Colors, icons
import threading
import re
from client.core.vpn_client import VPNClient
from client.core.handshake_client import TCPClient

class PiperVPNApp:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "PiperVPN"
        self.page.bgcolor = Colors.GREY_900
        self.page.window_width = 300
        self.page.window_height = 400
        self.page.window_resizable = False
        self.page.vertical_alignment = ft.MainAxisAlignment.CENTER
        self.page.horizontal_alignment = ft.CrossAxisAlignment.CENTER

        self.vpn_thread = None
        self.vpn_client = None

        self.domain = ft.TextField(label="Server Domain", value="localhost", width=300, color=Colors.WHITE)
        self.username = ft.TextField(label="Username", width=300, color=Colors.WHITE)
        self.password = ft.TextField(label="Password", password=True, can_reveal_password=True, width=300, color=Colors.WHITE)
        self.email = ft.TextField(label="Email", width=300, color=Colors.WHITE)
        self.status_text = ft.Text("", size=18, color=Colors.WHITE)

        self.page.on_route_change = self.route_change
        self.page.go(self.page.route or "/")

    def clear_fields(self):
        self.domain.value = "localhost"
        self.username.value = ""
        self.password.value = ""
        self.email.value = ""
        self.status_text.value = ""

    def route_change(self, e):
        if self.page.route == "/signup":
            self.build_signup_ui()
        elif self.page.route == "/dashboard":
            self.show_dashboard()
        else:
            self.build_login_ui()

    def build_login_ui(self):
        self.clear_fields()
        self.page.controls.clear()
        self.page.add(
            ft.Container(
                content=ft.Column([
                    ft.Text("PiperVPN", style="headlineLarge", color=Colors.CYAN_500),
                    self.domain,
                    self.username,
                    self.password,
                    ft.Row([
                        ft.ElevatedButton("Login", on_click=self.login, icon=icons.LOGIN, color=Colors.WHITE, bgcolor=Colors.CYAN_500),
                        ft.TextButton("Sign Up", on_click=lambda _: self.page.go("/signup")),
                    ], alignment=ft.MainAxisAlignment.CENTER),
                    self.status_text,
                ], alignment=ft.MainAxisAlignment.CENTER),
                padding=30,
                width=400,
                bgcolor=Colors.GREY_800,
                border_radius=12
            )
        )
        self.page.update()

    def build_signup_ui(self):
        self.clear_fields()
        self.page.controls.clear()
        self.page.add(
            ft.Container(
                content=ft.Column([
                    ft.Text("Create Account", style="headlineLarge", color=Colors.CYAN_500),
                    self.domain,
                    self.username,
                    self.password,
                    self.email,
                    ft.Row([
                        ft.ElevatedButton("Sign Up", on_click=self.signup, icon=icons.PERSON_ADD, color=Colors.WHITE, bgcolor=Colors.CYAN_500),
                        ft.TextButton("Back to Login", on_click=lambda _: self.page.go("/")),
                    ], alignment=ft.MainAxisAlignment.CENTER),
                    self.status_text,
                ], alignment=ft.MainAxisAlignment.CENTER),
                padding=30,
                width=400,
                bgcolor=Colors.GREY_800,
                border_radius=12
            )
        )
        self.page.update()

    def login(self, e):
        self.vpn_client = VPNClient(
            tun_device_name='tun1',
            tun_device_ip='10.1.0.1',
            server_address=('127.0.0.1', 3000)
        )

        success = self.vpn_client.receive_token(
            username=self.username.value,
            password=self.password.value,
            domain=self.domain.value
        )
        if success:
            self.status_text.value = "Login successful!"
            self.status_text.color = Colors.GREEN_500
            tcp_client = TCPClient(auth_token=self.vpn_client.auth_token)
            self.vpn_client.session_id, self.vpn_client.aes_key = tcp_client.perform()
            self.page.go("/dashboard")
        else:
            self.status_text.value = "Login failed."
            self.status_text.color = Colors.RED_500
        self.page.update()

    def signup(self, e):
        username = self.username.value.strip()
        password = self.password.value.strip()
        email = self.email.value.strip()
        domain = self.domain.value.strip()

        if len(username) < 4 or not re.match(r"^\w+$", username):
            self.status_text.value = "Username must be 4+ characters (letters/numbers/_ only)"
            self.status_text.color = Colors.RED_500
        elif len(password) < 8 or not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) or not re.search(r"\d", password):
            self.status_text.value = "Password must be 8+ chars, upper/lower/digit"
            self.status_text.color = Colors.RED_500
        elif not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            self.status_text.value = "Invalid email address."
            self.status_text.color = Colors.RED_500
        elif any(c in username for c in [";", "'", "--"]):
            self.status_text.value = "Username contains invalid characters."
            self.status_text.color = Colors.RED_500
        else:
            temp_client = VPNClient('tun1', '10.1.0.1', ('127.0.0.1', 3000))
            response = temp_client.signup(
                domain=domain,
                username=username,
                password=password,
                email=email
            )
            if response and response.status_code == 200:
                self.status_text.value = "Signup successful. Please log in."
                self.status_text.color = Colors.GREEN_500
            else:
                self.status_text.value = f"Signup failed: {response.text if response else 'No response'}"
                self.status_text.color = Colors.RED_500

        self.page.update()

    def show_dashboard(self):
        self.vpn_thread = threading.Thread(target=self.vpn_client.start, daemon=True)
        self.vpn_thread.start()

        tun_ip = self.vpn_client.tun_device_ip or "Unavailable"
        self.page.controls.clear()
        self.page.add(
            ft.Container(
                content=ft.Column([
                    ft.Text("Welcome to PiperVPN!", style="headlineLarge", color=Colors.CYAN_500),
                    ft.Text(f"Authenticated IP: {tun_ip}", style="bodyLarge", color=Colors.WHITE),
                    ft.Text("VPN Status: Connected ✅", color=Colors.GREEN_500),
                    ft.Text("Encryption: AES-256-CBC", color=Colors.CYAN_500),
                    ft.Text("Connection Time: 00:34:56", color=Colors.WHITE),
                    ft.Text("Server Location: United States - New York", color=Colors.CYAN_500),
                    ft.Row([
                        ft.Icon(icons.SHIELD, size=40, color=Colors.GREEN_500),
                        ft.Text("Secure Connection", style="bodyLarge", color=Colors.GREEN_500),
                    ], alignment=ft.MainAxisAlignment.START),
                    ft.Text("Data Usage: 1.2GB / 5GB", color=Colors.WHITE),
                    ft.ElevatedButton("Disconnect", on_click=self.disconnect, icon=icons.POWER_SETTINGS_NEW, color=Colors.WHITE, bgcolor=Colors.RED_500),
                ], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                width=400,
                padding=20,
                bgcolor=Colors.GREY_800,
                border_radius=12
            )
        )
        self.page.update()

    def disconnect(self, e):
        if self.vpn_client:
            self.vpn_client.running = False
        if self.vpn_thread and self.vpn_thread.is_alive():
            self.vpn_thread.join(timeout=5)

        self.status_text.value = "Disconnected."
        self.status_text.color = Colors.RED_500
        self.vpn_client = None
        self.vpn_thread = None

        self.page.go("/")


# def main(page: ft.Page):
#     PiperVPNApp(page)

# # ft.app(target=main, view=ft.WEB_BROWSER)
# ft.app(target=main)