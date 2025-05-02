from client import Client
from server import Server

client = Client()
server = Server()

# Obtém dados para registro de um usuário
nome, senha = client.cadastrar_usuario()

# registra um usuário no servidor
server.adicionar_usuario(nome, senha)


# solicita dados de login ao usuário

nome, senha = client.logar_usuario()

server.autenticar_usuario(nome, senha)
