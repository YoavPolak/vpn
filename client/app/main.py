import flet as ft
from .gui import PiperVPNApp
import os
#Remember to set vpn_client.py, tun.py to prod
def main(page: ft.Page):
    # os.system("bash ./tools/setup_client_nat.sh")
    PiperVPNApp(page)

# ft.app(target=main, view=ft.WEB_BROWSER)
ft.app(target=main)