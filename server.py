import os
import hashlib
import base64
import pyotp


class Server:

    def __init__(self):
        self._usuarios = {}

    def adicionar_usuario(self, nome: str, senha: str, pais: str):

        # Obtém hash da senha com SCRYPT e o respectivo salt
        senha_hashed, salt = self.hash_senha(senha)

        # Gera o secret para o pyotp
        pyotp_secret = pyotp.random_base32()

        # Cria novo usuário com hash da senha e o respectivo salt, após realizar o encoding em base64
        novo_usuario = {
            "nome": nome,
            "senha": encodeStrToBase64(senha_hashed),
            "salt": encodeStrToBase64(salt),
            "pais": pais,
            "pyotp_secret": pyotp_secret
        }

        # Armazena usuários em memória
        self._usuarios[nome] = novo_usuario
        print(self._usuarios)
        return pyotp_secret

    def autenticar_usuario(self, nome: str, senha: str, pais: str):

        try:
            usuario = self.obter_usuario_por_nome(nome)
        except KeyError:
            print(f"Usuário com o nome {nome} não localizado")
            return

        senha_registrada = decodeStrFromBase64(usuario["senha"])
        salt = usuario["salt"]

        senha_hashed, _ = self.hash_senha(senha, decodeStrFromBase64(salt))

        if (not (senha_hashed == senha_registrada)):
            print("Senha incorreta")
            return

        if (not (pais == usuario["pais"])):
            print("Localização inválida")
            return

        print("Usuário autenticado")

    def obter_usuario_por_nome(self, nome):

        return self._usuarios[nome]

    def hash_senha(self, senha: str, salt: bytes = None):
        # Aplica o SCRYPT à senha. Cria um salt se um não foi informado.

        # Obtém os bytes da string contendo a senha
        senha_bytes = senha.encode()

        # Parâmetros para SCRYPT conforme documentação: https://docs.python.org/3/library/hashlib.html#hashlib.scrypt

        if salt is None:
            salt = os.urandom(16)

        cost_factor = 2**14
        block_size = 8
        parallelization_factor = 1
        derived_key_length = 64

        senha_hashed = hashlib.scrypt(
            senha_bytes, salt=salt, n=cost_factor, r=block_size, p=parallelization_factor, dklen=derived_key_length)

        return senha_hashed, salt


def encodeStrToBase64(bytes: bytes):
    # Encoda uma sequencia de bytes em base64, decoda e retorna a string equivalente
    return base64.b64encode(bytes).decode()


def decodeStrFromBase64(bytes: bytes):
    # Decoda uma string em uma sequência de bytes de base 64
    return base64.b64decode(bytes)
