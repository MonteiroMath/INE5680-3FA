import os
import hmac
import hashlib
import base64
from cryptography.fernet import Fernet
import ipinfo
from dotenv import load_dotenv
import pyotp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

load_dotenv()


class Client:

    def __init__(self, server):

        self._server = server
        self._secret = None
        self._nome_usuario = None

    def cadastrar_usuario(self):
        print("Cadastro: ")
        nome = input("Informe seu nome: ")
        senha = input("Informe sua senha: ")
        pais = self.obter_pais()

        totp_secret = self.requisitar_cadastro(nome, senha, pais)
        print("Usuário cadastrado")

        self.store_totp_secret(senha, totp_secret)
        print("Segredo totp armazenado")

    def logar_usuario(self):
        print("Login: ")
        nome = input("Informe seu nome: ")
        senha = input("Informe sua senha: ")
        pais = self.obter_pais()

        self.carregar_totp_secret(senha)
        print("Segredo totp recuperado")
        totp = pyotp.TOTP(self._secret)
        totp_code = totp.now()

        isAutenticado = self.requisitar_autenticacao(
            nome, senha, pais, totp_code)

        if (not isAutenticado):
            print("Usuário não autenticado.")
            return

        # Armazena nome do usuário logado
        self._nome_usuario = nome

    def enviar_mensagem(self):
        mensagem = input("Digita uma mensagem: ")

        # criptografa mensagem
        mensagem_criptografada = self.criptografar_mensagem(mensagem)

        self.requisitar_envio_mensagem(
            self._nome_usuario, mensagem_criptografada)

    def obter_pais(self):
        # obtem localização do usuário (país) a partir do ip do usuário
        access_token = os.environ["API_KEY"]
        handler = ipinfo.getHandler(access_token)
        details = handler.getDetails()

        return details.country_name

    def store_totp_secret(self, senha: str, totp_secret: str):
        # Guarda o segredo do totp em um arquivo criptografado. Utiliza a senha do usuário para derivar a chave.

        salt = os.urandom(16)
        chave = self.derivar_chave_armazenamento_local(
            senha, salt)
        cipher = Fernet(chave)
        secret_criptografado = cipher.encrypt(totp_secret.encode())

        with open("totp_secret.txt", "wb") as f:
            f.write(salt+secret_criptografado)

    def carregar_totp_secret(self, senha: str):
        # Recupera o segredo do totp de um arquivo criptogrado. Utiliza a senha do usuário na reviação da chave.
        with open("totp_secret.txt", "rb") as f:
            data = f.read()

        salt = data[:16]
        secret_criptografado = data[16:]
        chave = self.derivar_chave_armazenamento_local(senha, salt)
        cipher = Fernet(chave)
        secret = cipher.decrypt(secret_criptografado)
        self._secret = secret.decode()

    def derivar_chave_armazenamento_local(self, password: str, salt: bytes) -> bytes:
        # Deriva chave para armazenamento do totp em arquivo local. Utiliza a senha do usuário na derivação

        # Parâmetros para SCRYPT conforme documentação: https://docs.python.org/3/library/hashlib.html#hashlib.scrypt
        cost_factor = 2**14
        block_size = 8
        parallelization_factor = 1
        derived_key_length = 32

        key = hashlib.scrypt(password.encode(), salt=salt, n=cost_factor,
                             r=block_size, p=parallelization_factor, dklen=derived_key_length)

        return base64.b64encode(key)

    def derivar_chave_mensagem(self, secret: str, totp_code: str):
        # Deriva chave para criptografar mensagem. Utiliza o segredo do totp e o totp na derivação
        return hmac.new(secret.encode(), totp_code.encode(), hashlib.sha256).digest()

    def criptografar_mensagem(self, mensagem: str):

        # criptografa mensagem utilizando o segredo totp e o totp para derivar uma chave
        totp = pyotp.TOTP(self._secret)
        totp_code = totp.now()
        chave = self.derivar_chave_mensagem(self._secret, totp_code)
        aesgcm = AESGCM(chave)
        iv = os.urandom(12)
        ciphertext = aesgcm.encrypt(iv, mensagem.encode(), None)
        return {
            "iv": iv,
            "ciphertext": ciphertext
        }

    # Funções para fazer requisições ao servidor
    def requisitar_cadastro(self, nome, senha, pais):
        return self._server.adicionar_usuario(nome, senha, pais)

    def requisitar_autenticacao(self, nome, senha, pais, totp_code):
        return self._server.autenticar_usuario(nome, senha, pais, totp_code)

    def requisitar_envio_mensagem(self, nome_usuario, mensagem):
        return self._server.receber_mensagem(nome_usuario, mensagem)
