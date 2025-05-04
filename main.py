from client import Client
from server import Server

server = Server()
client = Client(server)


# Cadastro de usuário
client.cadastrar_usuario()

# Autenticação de usuário
client.logar_usuario()


# Envio de mensagem
mensagem = client.enviar_mensagem()
