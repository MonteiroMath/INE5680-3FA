
class Server:

    def __init__(self):
        self._usuarios = []

    def adicionar_usuario(self, nome, senha):
        novo_usuario = {"nome": nome, "senha": senha}
        self._usuarios.append(novo_usuario)
        print(self._usuarios)
