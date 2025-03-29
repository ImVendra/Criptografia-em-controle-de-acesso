import os
import tkinter as tk
from tkinter import messagebox
from typing import Optional, Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import openai

# === INSIRA SUA CHAVE DE API AQUI ===
openai.api_key = "sk-xxxxxxSUA_CHAVE_AQUIxxxxx"

def gerar_credencial_com_ia(empresa: str, validade: str) -> str:
    prompt = f"Crie uma credencial de acesso para a empresa {empresa}, válida até {validade}. Formato chave: valor."
    resposta = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3
    )
    return resposta.choices[0].message['content']


class TerminalMensagens:
    @staticmethod
    def info(mensagem: str):
        print(f"\033[94m[INFO]\033[0m {mensagem}")

    @staticmethod
    def sucesso(mensagem: str):
        print(f"\033[92m[SUCESSO]\033[0m {mensagem}")
        TerminalMensagens._popup(mensagem, "sucesso")

    @staticmethod
    def erro(mensagem: str):
        print(f"\033[91m[ERRO]\033[0m {mensagem}")
        TerminalMensagens._popup(mensagem, "erro")

    @staticmethod
    def _popup(mensagem: str, tipo: str):
        root = tk.Tk()
        root.withdraw()
        if tipo == "erro":
            messagebox.showerror("Erro", mensagem)
        elif tipo == "sucesso":
            messagebox.showinfo("Sucesso", mensagem)
        elif tipo == "aviso":
            messagebox.showwarning("Aviso", mensagem)


def gerar_chaves() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    TerminalMensagens.info("Gerando chaves RSA de 2048 bits...")
    chave_privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    TerminalMensagens.sucesso("Chaves geradas com sucesso.")
    return chave_privada, chave_privada.public_key()


def salvar_chaves(priv: rsa.RSAPrivateKey, pub: rsa.RSAPublicKey) -> None:
    with open("private_key.pem", "wb") as f:
        f.write(priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("public_key.pem", "wb") as f:
        f.write(pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    TerminalMensagens.sucesso("Chaves salvas como 'private_key.pem' e 'public_key.pem'")


def assinar_arquivo(chave_privada: rsa.RSAPrivateKey, caminho_arquivo: str, caminho_assinatura: str):
    if not os.path.exists(caminho_arquivo):
        TerminalMensagens.erro(f"Arquivo '{caminho_arquivo}' não encontrado.")
        return
    with open(caminho_arquivo, "r", encoding="utf-8") as f:
        conteudo = f.read()
    assinatura = chave_privada.sign(
        conteudo.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    with open(caminho_assinatura, "wb") as f:
        f.write(assinatura)
    TerminalMensagens.sucesso(f"Assinatura salva em '{caminho_assinatura}'.")


def verificar_arquivo(chave_publica: rsa.RSAPublicKey, caminho_arquivo: str, caminho_assinatura: str) -> bool:
    if not os.path.exists(caminho_arquivo) or not os.path.exists(caminho_assinatura):
        TerminalMensagens.erro("Arquivo da credencial ou assinatura não encontrado.")
        return False
    try:
        with open(caminho_arquivo, "r", encoding="utf-8") as f:
            conteudo = f.read()
        with open(caminho_assinatura, "rb") as f:
            assinatura = f.read()
        chave_publica.verify(
            assinatura,
            conteudo.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        TerminalMensagens.sucesso("Assinatura verificada com sucesso.")
        return True
    except Exception as e:
        TerminalMensagens.erro(f"Falha na verificação da assinatura: {str(e)}")
        return False


def iniciar_software():
    if not os.path.exists("software.txt"):
        TerminalMensagens.erro("Arquivo 'software.txt' não encontrado.")
        return
    with open("software.txt", "r", encoding="utf-8") as f:
        conteudo = f.read()
    print("\n\033[93m=== SOFTWARE LIBERADO ===\033[0m\n")
    print(conteudo)


def menu():
    while True:
        print("\n" + "=" * 50)
        print(" MENU DE CREDENCIAL DE ACESSO ".center(50, "="))
        print("=" * 50)
        print("1. Gerar chaves")
        print("2. Gerar credencial com IA (OpenAI)")
        print("3. Assinar credencial.txt")
        print("4. Verificar credencial e liberar software")
        print("5. Sair")
        print("=" * 50)
        opcao = input("Escolha uma opção: ").strip()

        if opcao == "1":
            priv, pub = gerar_chaves()
            salvar_chaves(priv, pub)
            input("\nPressione Enter para voltar ao menu...")

        elif opcao == "2":
            empresa = input("Nome da empresa: ")
            validade = input("Validade (AAAA-MM-DD): ")
            credencial = gerar_credencial_com_ia(empresa, validade)
            with open("credencial.txt", "w", encoding="utf-8") as f:
                f.write(credencial)
            TerminalMensagens.sucesso("credencial.txt gerada com IA e salva com sucesso.")
            input("\nPressione Enter para voltar ao menu...")

        elif opcao == "3":
            if not os.path.exists("private_key.pem"):
                TerminalMensagens.erro("Gere as chaves primeiro.")
            else:
                with open("private_key.pem", "rb") as f:
                    chave_privada = serialization.load_pem_private_key(f.read(), password=None)
                assinar_arquivo(chave_privada, "credencial.txt", "assinatura.bin")
            input("\nPressione Enter para voltar ao menu...")

        elif opcao == "4":
            if not os.path.exists("public_key.pem"):
                TerminalMensagens.erro("Chave pública não encontrada.")
            else:
                with open("public_key.pem", "rb") as f:
                    chave_publica = serialization.load_pem_public_key(f.read())
                if verificar_arquivo(chave_publica, "credencial.txt", "assinatura.bin"):
                    iniciar_software()
            input("\nPressione Enter para voltar ao menu...")

        elif opcao == "5":
            print("\nEncerrando o programa. Até logo!")
            break
        else:
            TerminalMensagens.erro("Opção inválida. Tente novamente.")
            input("\nPressione Enter para voltar ao menu...")


if __name__ == "__main__":
    menu()
