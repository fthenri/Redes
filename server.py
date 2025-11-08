import socket
import random
import time

def caesar_cipher(text, shift, encrypt=False):
    if not encrypt:
        shift = -shift
    result = ""
    for char in text:
        if char.isalpha():
            start = ord('a') if char.islower() else ord('A')
            shifted = (ord(char) - start + shift) % 26
            result += chr(start + shifted)
        else:
            result += char
    return result

def calculate_checksum(data):
    return sum(ord(char) for char in data)

HOST = '127.0.0.1'
PORT = 65432
CHAVE_CIFRA = 5
SERVER_WINDOW_SIZE = 5

print("Iniciando servidor...")
print(f"Servidor escutando em {HOST}:{PORT}, pronto para aceitar conexões.")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    
    while True:
        print("\n-----------------------------------------")
        print("Aguardando nova conexão de cliente...")
        conn, addr = s.accept()
        
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        with conn:
            print(f"Conexão estabelecida por {addr}")

            try:
                handshake_data = conn.recv(1024).decode('utf-8')
                if not handshake_data:
                    raise ConnectionError("Cliente desconectou antes do handshake.")
                
                print(f"[SERVER] Handshake recebido: {handshake_data}")
                
                params = dict(item.split("=") for item in handshake_data.split(";"))
                RECOVERY_MODE = params.get("RECOVERY", "gbn")
                CLIENT_WINDOW = params.get("WINDOW", "")
                

                if CLIENT_WINDOW and CLIENT_WINDOW.isdigit():
                    client_window_size = int(CLIENT_WINDOW)
                    WINDOW_SIZE = min(SERVER_WINDOW_SIZE, client_window_size)
                    print(f"[HANDSHAKE] Cliente solicitou Modo={RECOVERY_MODE.upper()} com Janela={client_window_size}.")
                else:
                    WINDOW_SIZE = SERVER_WINDOW_SIZE
                    print(f"[HANDSHAKE] Cliente solicitou Modo={RECOVERY_MODE.upper()}.")
                
                print(f"[HANDSHAKE] Servidor DEFINIU Janela={WINDOW_SIZE}.")
                
                handshake_response = f"WINDOW={WINDOW_SIZE}"
                conn.sendall(handshake_response.encode('utf-8'))

                reconstructed_message = {}
                # ALTERAÇÃO: Numeração baseada em 1
                expected_seq_num = 1
                selective_repeat_buffer = {}
                
                # ALTERAÇÃO: Removido 'ack_is_pending' e 'conn.settimeout(0.5)'
                # Socket agora é bloqueante por padrão para aguardar pacotes
                conn.settimeout(None)

                while True:
                    try:
                        packet_data = conn.recv(4096)
                        if not packet_data:
                            print(f"Cliente {addr} desconectou inesperadamente.")
                            break
                        
                        packet_str = packet_data.decode('utf-8')
                        if packet_str == "FIN":
                            print("[SERVER] Sinal de FIM de transmissão recebido.")
                            break

                        parts = dict(item.split(":", 1) for item in packet_str.split("|"))
                        seq_num = int(parts.get("SEQ"))
                        checksum_received = int(parts.get("CHK"))
                        data_encrypted = parts.get("DATA")

                        checksum_calculated = calculate_checksum(data_encrypted)
                        data_decrypted = caesar_cipher(data_encrypted, CHAVE_CIFRA, encrypt=False)

                        if checksum_calculated != checksum_received:
                            print(f"[SERVER] PACOTE COM ERRO! Seq={seq_num}. Conteúdo: '{data_decrypted}' -> '{data_encrypted}' (Checksum: {checksum_received} vs Calculado: {checksum_calculated}).")
                            
                            # A lógica de NACK para ERRO (não PERDA) permanece
                            if RECOVERY_MODE == 'sr':
                                nack_packet = f"TIPO:NACK|SEQ:{seq_num}".encode('utf-8')
                                conn.sendall(nack_packet)
                                print(f"[SERVER] (SR) ENVIANDO NACK para Seq={seq_num}.")
                            elif RECOVERY_MODE == 'gbn':
                                # Mantendo a lógica original do arquivo (enviar NACK) para o MODO ERRO.
                                # A sua solicitação foi apenas para o MODO PERDA.
                                print(f"[SERVER] (GBN) Pacote com erro. Enviando NACK.")
                                nack_packet = f"TIPO:NACK|SEQ:{seq_num}".encode('utf-8')
                                conn.sendall(nack_packet)

                            continue

                        print(f"[SERVER] Pacote Seq={seq_num} recebido. Conteúdo: '{data_decrypted}' -> '{data_encrypted}' (Checksum: {checksum_received})")

                        if RECOVERY_MODE == 'gbn':
                            # --- ESTA É A LÓGICA GBN SOLICITADA ---
                            
                            if seq_num == expected_seq_num:
                                # Cenário 1 (Recebe P1) ou Cenário 2 (Recebe P1 após retransmissão)
                                print(f"[SERVER] Pacote Seq={seq_num} recebido em ordem.")
                                reconstructed_message[seq_num] = data_decrypted
                                
                                # Envia ACK imediato (ACK N para Pacote N)
                                ack_packet = f"TIPO:ACK|SEQ:{seq_num}".encode('utf-8')
                                conn.sendall(ack_packet)
                                print(f"[SERVER] ENVIANDO ACK para Seq={seq_num}.")
                                
                                expected_seq_num += 1
                            else:
                                # Pacote fora de ordem (P3 chegou, P2 perdido | OU | P2 chegou, P1 perdido)
                                print(f"[SERVER] Pacote Seq={seq_num} fora de ordem (esperando {expected_seq_num}). Descartando.")
                                
                                if expected_seq_num > 1:
                                    # Cenário 1 (Perda no Meio): Já recebemos P1 (expected_seq_num > 1).
                                    # Reenvia o ACK do último pacote recebido (P1).
                                    ack_to_send = expected_seq_num - 1
                                    print(f"[SERVER] Reenviando ACK para {ack_to_send} (sinalizando que ainda espera {expected_seq_num}).")
                                    ack_packet = f"TIPO:ACK|SEQ:{ack_to_send}".encode('utf-8')
                                    conn.sendall(ack_packet)
                                else:
                                    # Cenário 2 (Perda Inicial): Não recebemos NADA ainda (expected_seq_num == 1).
                                    # Descarta silenciosamente, não envia nada.
                                    print(f"[SERVER] Esperando P1, nenhum ACK enviado.")
                        
                        elif RECOVERY_MODE == 'sr':
                            if seq_num >= expected_seq_num:
                                selective_repeat_buffer[seq_num] = data_decrypted
                                ack_packet = f"TIPO:ACK|SEQ:{seq_num}".encode('utf-8')
                                conn.sendall(ack_packet)
                                print(f"[SERVER] Enviando ACK para Seq={seq_num}.")
                                while expected_seq_num in selective_repeat_buffer:
                                    reconstructed_message[expected_seq_num] = selective_repeat_buffer.pop(expected_seq_num)
                                    expected_seq_num += 1
                            else:
                                ack_packet = f"TIPO:ACK|SEQ:{seq_num}".encode('utf-8')
                                conn.sendall(ack_packet)
                                print(f"[SERVER] Pacote duplicado Seq={seq_num}. Reenviando ACK.")

                    except socket.timeout:
                        # Este bloco não deve mais ser executado, pois removemos o timeout
                        pass
                
                # ALTERAÇÃO: Removido 'if ack_is_pending:' no final
                
                print("\n" + "="*40)
                print("TRANSMISSÃO FINALIZADA. RECONSTRUINDO MENSAGEM...")
                if not reconstructed_message:
                    print("Nenhuma mensagem foi recebida corretamente.")
                else:
                    final_message = "".join(reconstructed_message[key] for key in sorted(reconstructed_message.keys()))
                    print("Mensagem Original Reconstruída:")
                    print(final_message)
                print("="*40)

            except Exception as e:
                print(f"Ocorreu um erro durante a sessão com {addr}: {e}")

        print(f"Sessão com {addr} finalizada.")