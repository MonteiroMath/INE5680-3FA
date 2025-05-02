import os
import hashlib
import base64


class Server:

    def __init__(self):
        self._usuarios = []

    def adicionar_usuario(self, nome, senha):

        # Obtém hash da senha com SCRYPT e o respectivo salt
        senha_hashed, salt = self.hash_senha(senha)

        # Cria novo usuário com hash da senha e o respectivo salt, após realizar o encoding em base64
        novo_usuario = {"nome": nome, "senha": encodeStr(
            senha_hashed), "salt": encodeStr(salt)}

        # Armazena usuários em memória
        self._usuarios.append(novo_usuario)


    def hash_senha(self, senha):
        # Cria um salt e aplica o SCRYPT à senha

        # Obtém os bytes da string contendo a senha
        senha_bytes = senha.encode()
        
        
        # Parâmetros para SCRYPT conforme documentação: https://docs.python.org/3/library/hashlib.html#hashlib.scrypt

        salt = os.urandom(16)
        cost_factor = 2**14
        block_size = 8
        parallelization_factor = 1
        derived_key_length = 64

        senha_hashed = hashlib.scrypt(
            senha_bytes, salt=salt, n=cost_factor, r=block_size, p=parallelization_factor, dklen=derived_key_length)

        return senha_hashed, salt


def encodeStr(bytes):
    ## Encoda uma sequencia de bytes em base64, decoda e retorna a string equivalente
    return base64.b64encode(bytes).decode()
