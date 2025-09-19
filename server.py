import socket

HOST = '127.0.0.1'  # Endereço IP do Servidor (localhost)
PORT = 65432        # Porta que o Servidor vai escutar

print("Iniciando servidor...")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Servidor escutando em {HOST}:{PORT}")

    # O servidor fica esperando por conexões
    conn, addr = s.accept()
    with conn:
        print(f"Conexão estabelecida por {addr}")
        
        # Variáveis para guardar os parâmetros da conexão
        modo_operacao = ""
        tamanho_max_msg = 0

        # ---------- HANDSHAKE INICIAL ----------
        handshake_data = conn.recv(1024)
        if not handshake_data:
            print("Cliente desconectou antes do handshake.")
        else:
            handshake_msg = handshake_data.decode("utf-8")
            print(f"Handshake recebido: {handshake_msg}")

            if handshake_msg.startswith("HELLO"):
                try:
                    parametros = {}
                    partes = handshake_msg.split(";")[1:]
                    for p in partes:
                        k, v = p.split("=")
                        parametros[k.strip().upper()] = v.strip()

                    # Armazena os parâmetros negociados
                    modo_operacao = parametros.get("MODE", "texto")
                    # --- ALTERAÇÃO: Converte o tamanho para inteiro e armazena ---
                    tamanho_max_msg = int(parametros.get("MAX", "1024"))
                    
                    print(f"Modo acordado: {modo_operacao}, Tamanho máximo da string: {tamanho_max_msg}")

                    # Resposta de confirmação
                    resposta_hs = f"OK;MODE={modo_operacao};MAX={tamanho_max_msg}"
                    conn.sendall(resposta_hs.encode("utf-8"))
                    print("Handshake confirmado com o cliente.")

                except (ValueError, IndexError) as e:
                    print(f"Erro ao analisar handshake: {e}")
                    conn.sendall("ERRO Formato de handshake inválido".encode("utf-8"))
                    conn.close()
                    exit()
            else:
                conn.sendall("ERRO Handshake esperado".encode("utf-8"))
                conn.close()
                exit()

            # ---------- TROCA DE MENSAGENS NORMAL ----------
            while True:
                data = conn.recv(1024)
                if not data:
                    print(f"Cliente {addr} desconectou.")
                    break

                mensagem_cliente = data.decode('utf-8')

                # --- REQUISITO ATENDIDO: A MENSAGEM APARECE NO TERMINAL DO SERVIDOR ---
                print(f"Cliente diz: {mensagem_cliente}")
                print(f"o tamanho da mensagem foi: {len(mensagem_cliente)}")
                
                if mensagem_cliente.lower() == 'sair':
                    print(f"Cliente {addr} solicitou o encerramento.")
                    break

                # Resposta padrão
                resposta = f"Recebido: '{mensagem_cliente}'"
                
                # Opcional: checagem de segurança no lado do servidor
                if len(mensagem_cliente) > tamanho_max_msg:
                    resposta = f"ERRO: Sua mensagem excedeu o limite de {tamanho_max_msg} caracteres."
                
                conn.sendall(resposta.encode('utf-8'))
                # print("Resposta enviada ao cliente.") # Descomente se quiser mais verbosidade

print("Servidor finalizado.")