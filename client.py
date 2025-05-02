import os
import hmac
import hashlib
import ipinfo
from dotenv import load_dotenv
import pyotp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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

    def enviar_mensagem(self):
        mensagem = input("Digita uma mensagem: ")

        mensagem_encriptada = self.encriptar_mensagem(mensagem)

        return mensagem_encriptada

    def obter_pais(self):

        access_token = os.environ["API_KEY"]
        handler = ipinfo.getHandler(access_token)
        details = handler.getDetails()

        return details.country_name

    def store_totp_secret(self, secret: str):
        self._secret = secret

    def derivar_chave(self, secret: str, totp_code: str):
        return hmac.new(secret.encode(), totp_code.encode(), hashlib.sha256).digest()

    def encriptar_mensagem(self, mensagem: str):

        totp = pyotp.TOTP(self._secret)
        totp_code = totp.now()
        chave = self.derivar_chave(self._secret, totp_code)
        aesgcm = AESGCM(chave)
        iv = os.urandom(12)
        ciphertext = aesgcm.encrypt(iv, mensagem.encode(), None)
        return {
            "iv": iv,
            "ciphertext": ciphertext
        }
