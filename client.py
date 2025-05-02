import os
import ipinfo
from dotenv import load_dotenv
import pyotp

load_dotenv()


class Client:

    def __init__(self):
        self._secret = None

    def cadastrar_usuario(self):
        print("Cadastro: ")
        nome = input("Informe seu nome: ")
        senha = input("Informe sua senha: ")
        pais = self.obter_pais()
        return (nome, senha, pais)

    def logar_usuario(self):
        print("Login: ")
        nome = input("Informe seu nome: ")
        senha = input("Informe sua senha: ")
        pais = self.obter_pais()

        totp = pyotp.TOTP(self._secret)
        totp_code = totp.now()
        return (nome, senha, pais, totp_code)

    def obter_pais(self):

        access_token = os.environ["API_KEY"]
        handler = ipinfo.getHandler(access_token)
        details = handler.getDetails()

        return details.country_name

    def store_totp_secret(self, secret: str):
        self._secret = secret
