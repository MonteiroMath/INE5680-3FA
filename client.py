import os
import ipinfo
from dotenv import load_dotenv

load_dotenv()


class Client:

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
        return (nome, senha, pais)

    def obter_pais(self):

        access_token = os.environ["API_KEY"]
        handler = ipinfo.getHandler(access_token)
        details = handler.getDetails()

        return details.country_name
