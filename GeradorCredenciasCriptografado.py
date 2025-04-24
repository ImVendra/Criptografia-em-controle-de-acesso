import mysql.connector
import openai
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

#INSIRA SUA CHAVE DE API AQUI
openai.api_key = "sk-xxxxxxSUA_CHAVE_AQUIxxxxx"
#ONDE PEGAR? BASTA PERGUNTAR PARA O CHATGPT :)

#Função para salvar credenciais no banco de dados
def salvar_credencial_no_banco(cliente: str, tempo: str, usuario: str, senha_criptografada: bytes):
    #Passa a senha criptografada para base64
    senha_em_base64 = base64.b64encode(senha_criptografada).decode('utf-8')

    #Faz a conexao no banco de dados
    conexao = mysql.connector.connect(
        host="localhost",
        user="UserDB",
        password="SenhaDB",
        database="ProjetoIntegrador"
    )
    cursor = conexao.cursor()
    #Cria a tabela caso ela nao exista
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS credenciais (
            id INT AUTO_INCREMENT PRIMARY KEY,
            cliente VARCHAR(255),
            tempo_expirar VARCHAR(50),
            usuario VARCHAR(255),
            senha TEXT
        )
    """)
    #Insere as credenciais na tabela
    cursor.execute("INSERT INTO credenciais (cliente, tempo_expirar, usuario, senha) VALUES (%s, %s, %s, %s)",
                   (cliente, tempo, usuario, senha_em_base64))
    conexao.commit()
    #Fecha as conexoes
    cursor.close()
    conexao.close()

#Funcao para mostrar as credenciais salvas na tabelas
def listar_credenciais():
    conexao = mysql.connector.connect(
        host="localhost",
        user="root",
        password="sua_senha",
        database="seguranca"
    )
    cursor = conexao.cursor()
    cursor.execute("SELECT cliente, tempo_expirar, usuario, senha FROM credenciais")
    resultados = cursor.fetchall()
    conexao.close()

    if resultados:
        print("\n\033[96m=== CREDENCIAIS CADASTRADAS ===\033[0m\n")
        for id, cliente, tempo_expirar, usuario, senha in resultados:
            print(f"\033[93mID:\033[0m {id}")
            print(f"\033[93mEmpresa:\033[0m {cliente}")
            print(f"\033[93mValidade:\033[0m {tempo_expirar}")
            print(f"\033[93mCredencial:\033[0m\n{usuario}\n")
            print("-" * 50)
    else:
        print("\n\033[91mNenhuma credencial encontrada na base de dados.\033[0m\n")

#Função para Gerar Credenciais Através de IA
def gerar_credenciais_com_ia(nome: str, tempo: str) -> tuple[str, str]:
    prompt = f"Crie uma credencial de acesso com usuário e senha para o cliente {nome}, válida até {tempo} minutos. Formato: usuario: valor, senha: valor."
    #Envia a mensagem e recebe a resposta da IA
    resposta = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3
    )
    conteudo = resposta.choices[0].message['content']
    usuario = ""
    senha = ""
    #Pega a resposta e passa para as variaveis
    for linha in conteudo.strip().split("\n"):
        if 'usuario:' in linha.lower():
            usuario = linha.split(":", 1)[1].strip()
        elif 'senha:' in linha.lower():
            senha = linha.split(":", 1)[1].strip()
    return usuario, senha

#Funções de criptografia
def gerar_chaves():
    chave_privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    chave_publica = chave_privada.public_key()
    return chave_publica

def criptografar(chave_publica, dado: str) -> bytes:
    return chave_publica.encrypt(
        dado.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def menu():
    while True:
        print("\n" + "=" * 50)
        print(" MENU PARA GERAR CREDENCIAIS PARA ACESSO ".center(50, "="))
        print("=" * 50)
        print("1. Gerar credencias")
        print("2. Listar usuários ativos")
        print("3. Sair")
        print("=" * 50)
        opcao = input("Escolha uma opção: ").strip()

        if opcao == "1":
            cliente = input("Nome: ")
            tempo_expirar = input("Tempo para expirar (minutos): ")
            usuario, senha = gerar_credenciais_com_ia(cliente, tempo_expirar)

            chave_publica = gerar_chaves()
            senha_criptografada = criptografar(chave_publica, senha)

            salvar_credencial_no_banco(cliente, tempo_expirar, usuario, senha_criptografada)

            print("\033[92mCredencial gerada e salva com sucesso!\033[0m")
            input("\nPressione Enter para voltar ao menu...")

        elif opcao == "2":
            listar_credenciais()
            input("\nPressione Enter para voltar ao menu...")

        elif opcao == "3":
            print("\nEncerrando o programa. Até logo!")
            break
        else:
            print("\033[91mOpção inválida. Tente novamente.\033[0m")
            input("\nPressione Enter para voltar ao menu...")

if __name__ == "__main__":
    menu()