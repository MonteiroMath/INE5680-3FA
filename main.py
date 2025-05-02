from client import Client
from server import Server

client = Client()
server = Server()

# Obtém dados para registro de um usuário
nome, senha, pais = client.cadastrar_usuario()

# registra um usuário no servidor
pyotp_secret = server.adicionar_usuario(nome, senha, pais)
client.store_totp_secret(pyotp_secret)

# solicita dados de login ao usuário

nome, senha, pais, totp_code = client.logar_usuario()

# Solicita login ao servidor
server.autenticar_usuario(nome, senha, pais, totp_code)

mensagem = client.enviar_mensagem()
print(mensagem)