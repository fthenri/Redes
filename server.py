import socket
import random
import time

# --- Funções de Suporte (caesar_cipher, calculate_checksum) - Sem alterações ---

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

# --- Configurações do Servidor ---
HOST = '127.0.0.1'
PORT = 65432
CHAVE_CIFRA = 5

print("Iniciando servidor...")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Servidor escutando em {HOST}:{PORT}, pronto para aceitar conexões.")

    # --- MUDANÇA PRINCIPAL: Loop para aceitar múltiplos clientes em sequência ---
    while True:
        print("\n-----------------------------------------")
        print("Aguardando nova conexão de cliente...")
        conn, addr = s.accept()
        
        # Desabilita o Algoritmo de Nagle para esta conexão
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        with conn:
            print(f"Conexão estabelecida por {addr}")

            try:
                # 1. ---------- HANDSHAKE APRIMORADO ----------
                handshake_data = conn.recv(1024).decode('utf-8')
                if not handshake_data:
                    raise ConnectionError("Cliente desconectou antes do handshake.")
                
                params = dict(item.split("=") for item in handshake_data.split(";"))
                WINDOW_SIZE = int(params.get("WINDOW", "4"))
                RECOVERY_MODE = params.get("RECOVERY", "gbn")
                
                print(f"[HANDSHAKE] Cliente configurado com: Modo={RECOVERY_MODE.upper()}, Janela={WINDOW_SIZE}")
                conn.sendall(b"OK")

                # 2. ---------- RECEBIMENTO E PROCESSAMENTO DE MENSAGENS ----------
                reconstructed_message = {}
                expected_seq_num = 0
                selective_repeat_buffer = {}
                ack_is_pending = False
                conn.settimeout(0.5)

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

                        if calculate_checksum(data_encrypted) != checksum_received:
                            print(f"[SERVER] PACOTE COM ERRO! Seq={seq_num}. Descartado.")
                            continue

                        # Lógica GBN com Delayed ACK
                        if RECOVERY_MODE == 'gbn':
                            if seq_num == expected_seq_num:
                                print(f"[SERVER] Pacote Seq={seq_num} recebido em ordem. Aguardando próximos...")
                                data_decrypted = caesar_cipher(data_encrypted, CHAVE_CIFRA, encrypt=False)
                                reconstructed_message[seq_num] = data_decrypted
                                expected_seq_num += 1
                                ack_is_pending = True
                            else:
                                print(f"[SERVER] Pacote Seq={seq_num} fora de ordem (esperando {expected_seq_num}). Descartado.")
                                ack_packet = f"TIPO:ACK|SEQ:{expected_seq_num}".encode('utf-8')
                                conn.sendall(ack_packet)
                                print(f"[SERVER] ENVIANDO ACK IMEDIATO: ACK={expected_seq_num} para forçar retransmissão.")
                                ack_is_pending = False
                        
                        # Lógica da Repetição Seletiva
                        elif RECOVERY_MODE == 'sr':
                            if seq_num >= expected_seq_num:
                                data_decrypted = caesar_cipher(data_encrypted, CHAVE_CIFRA, encrypt=False)
                                selective_repeat_buffer[seq_num] = data_decrypted
                                ack_packet = f"TIPO:ACK|SEQ:{seq_num}".encode('utf-8')
                                conn.sendall(ack_packet)
                                print(f"[SERVER] Enviando ACK para Seq={seq_num}.")
                                while expected_seq_num in selective_repeat_buffer:
                                    reconstructed_message[expected_seq_num] = selective_repeat_buffer.pop(expected_seq_num)
                                    expected_seq_num += 1
                            else: # ACK para pacote antigo
                                ack_packet = f"TIPO:ACK|SEQ:{seq_num}".encode('utf-8')
                                conn.sendall(ack_packet)

                    except socket.timeout:
                        if ack_is_pending:
                            ack_packet = f"TIPO:ACK|SEQ:{expected_seq_num}".encode('utf-8')
                            conn.sendall(ack_packet)
                            print(f"[SERVER] Pausa detectada. ENVIANDO ACK CUMULATIVO: ACK={expected_seq_num} (confirmando tudo até {expected_seq_num-1}).")
                            ack_is_pending = False
                
                if ack_is_pending:
                    ack_packet = f"TIPO:ACK|SEQ:{expected_seq_num}".encode('utf-8')
                    conn.sendall(ack_packet)
                    print(f"[SERVER] Finalizando. ENVIANDO ACK CUMULATIVO FINAL: ACK={expected_seq_num} (confirmando tudo até {expected_seq_num-1}).")

                # 3. ---------- RECONSTRUÇÃO FINAL DA MENSAGEM ----------
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