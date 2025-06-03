import flet as ft
from .gui import PiperVPNApp
import os

def main(page: ft.Page):
    # os.system("bash ./tools/setup_client_nat.sh")
    PiperVPNApp(page)

# ft.app(target=main, view=ft.WEB_BROWSER)
ft.app(target=main)