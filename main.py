import os
import getpass
import base64
from typing import Set, Optional, List
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

TARGET_DIR: str = "files_to_encrypt"
ALLOWED_EXTENSIONS: Set[str] = {'.jpg', '.jpeg', '.png', '.pdf', '.txt', '.docx', '.xlsx', '.ZIP', '.zip'}
KEY_FILE: str = ".encryption_key.bin"
SALT_FILE: str = ".salt.bin"
ENCRYPTED_SUFFIX: str = ".encrypted"


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Deriva uma chave Fernet a partir de uma senha e um salt usando PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000, # Valor seguro e estável para PBKDF2HMAC (Jun/2024)
    )
    # A chave deve ser codificada em base64 urlsafe para Fernet
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def setup_password() -> bool:
    """
    Configura a senha inicial, gera um salt, deriva a chave e salva ambos em arquivos.
    Retorna True se a configuração for bem-sucedida, False caso contrário.
    """
    print("=== CONFIGURAÇÃO INICIAL ===")
    
    # 1. Coleta e validação da senha
    while True:
        password = getpass.getpass("Crie uma senha forte: ")
        confirm = getpass.getpass("Confirme a senha: ")

        if password != confirm:
            print("Erro: As senhas digitadas não coincidem. Tente novamente.")
            continue
        
        if len(password) < 8:
            print("Erro: A senha deve ter no mínimo 8 caracteres!")
            continue
        
        break

    # 2. Geração e salvamento do Salt
    salt = os.urandom(16)
    try:
        with open(SALT_FILE, 'wb') as f:
            f.write(salt)
    except IOError as e:
        print(f"Erro ao salvar o arquivo de salt: {e}")
        return False

    # 3. Geração e salvamento da Chave
    key = derive_key_from_password(password, salt)
    try:
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
    except IOError as e:
        print(f"Erro ao salvar o arquivo de chave: {e}")
        # Se a chave falhar, o salt também deve ser removido para evitar estado inconsistente
        os.remove(SALT_FILE)
        return False

    print("Senha configurada com sucesso!")
    return True


def verify_password() -> Optional[bytes]:
    """
    Solicita a senha ao usuário, verifica se ela corresponde à chave salva
    e retorna a chave Fernet se a verificação for bem-sucedida.
    """
    # 1. Verifica a existência dos arquivos de configuração
    if not os.path.exists(SALT_FILE) or not os.path.exists(KEY_FILE):
        print("Erro: Arquivos de configuração de senha não encontrados. Por favor, configure a senha primeiro (Opção 1).")
        return None

    password = getpass.getpass("Digite sua senha: ")

    # 2. Leitura do Salt e da Chave Correta
    try:
        with open(SALT_FILE, 'rb') as f:
            salt = f.read()
        with open(KEY_FILE, 'rb') as f:
            correct_key = f.read()
    except IOError as e:
        print(f"Erro ao ler arquivos de configuração: {e}")
        return None

    # 3. Derivação da chave fornecida e comparação
    provided_key = derive_key_from_password(password, salt)

    if provided_key == correct_key:
        return provided_key
    else:
        print("Erro: Senha incorreta!")
        return None


def list_files_to_encrypt(directory: str) -> List[str]:
    """
    Lista todos os arquivos na pasta que correspondem às extensões permitidas
    e que AINDA NÃO estão criptografados.
    """
    files_to_process: List[str] = []

    if not os.path.exists(directory):
        print(f"Erro: Pasta alvo '{directory}' não existe!")
        return files_to_process

    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        
        if os.path.isfile(filepath):
            # Ignora arquivos já criptografados
            if filename.endswith(ENCRYPTED_SUFFIX):
                continue
            
            # Verifica a extensão
            _, ext = os.path.splitext(filename)
            if ext.lower() in ALLOWED_EXTENSIONS:
                files_to_process.append(filepath)

    return files_to_process


def list_files_to_decrypt(directory: str) -> List[str]:
    """
    Lista todos os arquivos na pasta que possuem o sufixo de criptografia.
    """
    files_to_process: List[str] = []

    if not os.path.exists(directory):
        print(f"Erro: Pasta alvo '{directory}' não existe!")
        return files_to_process

    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        
        if os.path.isfile(filepath) and filename.endswith(ENCRYPTED_SUFFIX):
            files_to_process.append(filepath)

    return files_to_process


def encrypt_files(directory: str):
    """Criptografa os arquivos elegíveis na pasta alvo."""
    key = verify_password()
    if not key:
        return

    cipher = Fernet(key)
    files = list_files_to_encrypt(directory)

    if not files:
        print("Nenhum arquivo encontrado para criptografar.")
        return

    print(f"\n📁 {len(files)} arquivo(s) encontrado(s):")
    for arq in files:
        print(f"  • {os.path.basename(arq)}")

    confirma = input("\nDeseja criptografar estes arquivos? (s/N): ")
    if confirma.lower() != 's':
        print("Operação cancelada.")
        return

    count = 0
    for filepath in files:
        filename = os.path.basename(filepath)
        try:
            # 1. Leitura dos dados
            with open(filepath, 'rb') as f:
                data = f.read()

            # 2. Criptografia
            encrypted_data = cipher.encrypt(data)

            # 3. Escrita do novo arquivo
            new_filepath = filepath + ENCRYPTED_SUFFIX
            with open(new_filepath, 'wb') as f:
                f.write(encrypted_data)

            # 4. Remoção do arquivo original
            os.remove(filepath)
            print(f"✓ {filename}")
            count += 1
        except InvalidToken:
            # Este erro não deve ocorrer na criptografia, mas é bom ter
            print(f"✗ {filename}: Erro de token inválido (deve ser um erro de leitura/escrita).")
        except IOError as e:
            print(f"✗ {filename}: Erro de I/O (leitura/escrita/permissão): {e}")
        except Exception as e:
            print(f"✗ {filename}: Erro inesperado: {e}")

    print(f"\n✅ {count} arquivo(s) criptografado(s)!")


def decrypt_files(directory: str):
    """Descriptografa os arquivos criptografados na pasta alvo."""
    key = verify_password()
    if not key:
        return

    cipher = Fernet(key)
    files = list_files_to_decrypt(directory)

    if not files:
        print("Nenhum arquivo criptografado encontrado.")
        return

    print(f"\n📁 {len(files)} arquivo(s) criptografado(s) encontrado(s)")

    count = 0
    for filepath in files:
        filename = os.path.basename(filepath)
        try:
            # 1. Leitura dos dados criptografados
            with open(filepath, 'rb') as f:
                encrypted_data = f.read()

            # 2. Descriptografia
            data = cipher.decrypt(encrypted_data)

            # 3. Escrita do arquivo original
            # Uso de replace() é mais robusto que slicing [:-10]
            original_filepath = filepath.replace(ENCRYPTED_SUFFIX, "")
            original_filename = os.path.basename(original_filepath)
            
            with open(original_filepath, 'wb') as f:
                f.write(data)

            # 4. Remoção do arquivo criptografado
            os.remove(filepath)
            print(f"✓ {original_filename}")
            count += 1
        except InvalidToken:
            print(f"✗ {filename}: Erro de senha/chave incorreta ou arquivo corrompido.")
        except IOError as e:
            print(f"✗ {filename}: Erro de I/O (leitura/escrita/permissão): {e}")
        except Exception as e:
            print(f"✗ {filename}: Erro inesperado: {e}")

    print(f"\n✅ {count} arquivo(s) descriptografado(s)!")


def menu():
    """Exibe o menu principal e solicita a opção ao usuário."""
    print("\n" + "=" * 50)
    print("     CRIPTOGRAFADOR SEGURO DE ARQUIVOS")
    print("=" * 50)
    print("\n1 - Configurar senha (primeira vez)")
    print("2 - Criptografar arquivos")
    print("3 - Descriptografar arquivos")
    print("0 - Sair")
    print(f"\n📂 Pasta alvo: {TARGET_DIR}")
    print(f"📝 Extensões: {', '.join(ALLOWED_EXTENSIONS)}")

    option = input("\nEscolha uma opção: ")
    return option


if __name__ == "__main__":
    # Cria a pasta alvo se ela não existir
    if not os.path.exists(TARGET_DIR):
        os.makedirs(TARGET_DIR)
        print(f"Pasta alvo '{TARGET_DIR}' criada.")

    while True:
        choice = menu()

        if choice == "1":
            setup_password()
        elif choice == "2":
            encrypt_files(TARGET_DIR)
        elif choice == "3":
            decrypt_files(TARGET_DIR)
        elif choice == "0":
            print("Saindo...")
            break
        else:
            print("❌ Opção inválida!")

        input("\nPressione ENTER para continuar...")
