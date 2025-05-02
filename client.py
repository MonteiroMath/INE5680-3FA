import ipinfo


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
        return (nome, senha)

    def obter_pais(self):

        access_token = 'token_here'
        handler = ipinfo.getHandler(access_token)
        details = handler.getDetails()

        return details.country_name
