import socket

HOST = '127.0.0.1'  # O mesmo host usado pelo servidor
PORT = 65432        # A mesma porta usada pelo servidor

# --- Configurações de handshake (podem ser definidas pelo usuário também) ---
MODO_OPERACAO = input("Informe o modo de operação (ex: texto/binario): ").strip() or "texto"
try:
    # Garantimos que o tamanho máximo é um inteiro
    TAMANHO_MAXIMO = int(input("Informe o tamanho máximo da MENSAGEM (ex: 100): ").strip() or "100")
except ValueError:
    TAMANHO_MAXIMO = 100

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    try:
        print(f"Tentando conectar a {HOST}:{PORT}...")
        s.connect((HOST, PORT))
        print("Conectado ao servidor!")

        # ---------- HANDSHAKE INICIAL ----------
        handshake_msg = f"HELLO;MODE={MODO_OPERACAO};MAX={TAMANHO_MAXIMO}"
        print(f"Enviando handshake: {handshake_msg}")
        s.sendall(handshake_msg.encode('utf-8'))

        # Aguarda a confirmação do servidor
        resposta_handshake = s.recv(1024).decode('utf-8')
        print(f"Confirmação do servidor: {resposta_handshake}")

        # Se o servidor aceitar, entra no loop de envio
        if not resposta_handshake.startswith("OK"):
            print("Servidor não aceitou o handshake. Encerrando.")
        else:
            print("\n=== Digite suas mensagens para o servidor ===")
            print(f"Tamanho máximo por mensagem: {TAMANHO_MAXIMO} caracteres.")
            print("Digite 'sair' para encerrar.\n")

            while True:
                mensagem = input("Você: ").strip()
                if mensagem.lower() == "sair":
                    print("Encerrando conexão...")
                    # Informa ao servidor que está saindo (opcional, mas boa prática)
                    s.sendall(mensagem.encode('utf-8'))
                    break

                # --- ALTERAÇÃO PRINCIPAL: VERIFICA O TAMANHO DA STRING ---
                if len(mensagem) > TAMANHO_MAXIMO:
                    print(f"ERRO: A mensagem excede o tamanho máximo de {TAMANHO_MAXIMO} caracteres.")
                    # Pula para a próxima iteração do loop, sem enviar a mensagem
                    continue

                # Envia a mensagem se o tamanho for válido
                s.sendall(mensagem.encode('utf-8'))

                # Recebe a resposta do servidor
                data = s.recv(1024)
                if not data:
                    print("Servidor desconectou.")
                    break
                print(f"Servidor respondeu: {data.decode('utf-8')}")

    except ConnectionRefusedError:
        print(f"Não foi possível conectar a {HOST}:{PORT}. Verifique se o servidor está rodando.")
    except Exception as e:
        print(f"Ocorreu um erro: {e}")

print("Conexão fechada.")