import flet as ft
from .gui import PiperVPNApp

def main(page: ft.Page):
    PiperVPNApp(page)

# ft.app(target=main, view=ft.WEB_BROWSER)
ft.app(target=main)