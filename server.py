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
                
                ACK_MODE = params.get("ACK_MODE", "individual") 

                if CLIENT_WINDOW and CLIENT_WINDOW.isdigit():
                    client_window_size = int(CLIENT_WINDOW)
                    WINDOW_SIZE = min(SERVER_WINDOW_SIZE, client_window_size)
                    print(f"[HANDSHAKE] Cliente solicitou Modo={RECOVERY_MODE.upper()}, Janela={client_window_size}, ACK={ACK_MODE.upper()}.")
                else:
                    WINDOW_SIZE = SERVER_WINDOW_SIZE
                    print(f"[HANDSHAKE] Cliente solicitou Modo={RECOVERY_MODE.upper()}, ACK={ACK_MODE.upper()}.")
                
                print(f"[HANDSHAKE] Servidor DEFINIU Janela={WINDOW_SIZE}.")
                
                handshake_response = f"WINDOW={WINDOW_SIZE}"
                conn.sendall(handshake_response.encode('utf-8'))

                reconstructed_message = {}
                expected_seq_num = 1
                selective_repeat_buffer = {}
                
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
                            
                            if RECOVERY_MODE == 'sr':
                                nack_packet = f"TIPO:NACK|SEQ:{seq_num}".encode('utf-8')
                                conn.sendall(nack_packet) 
                                print(f"[SERVER] (SR) ENVIANDO NACK para Seq={seq_num}.")
                            elif RECOVERY_MODE == 'gbn':
                                print(f"[SERVER] (GBN) Pacote com erro. Enviando NACK.")
                                nack_packet = f"TIPO:NACK|SEQ:{seq_num}".encode('utf-8')
                                conn.sendall(nack_packet)

                            continue

                        if RECOVERY_MODE == 'gbn':
                            print(f"[SERVER] (GBN) Pacote Seq={seq_num} recebido. Conteúdo: '{data_decrypted}'")

                        if RECOVERY_MODE == 'gbn':
                            if seq_num == expected_seq_num:
                                print(f"[SERVER] (GBN) Pacote Seq={seq_num} recebido em ordem.")
                                reconstructed_message[seq_num] = data_decrypted
                                
                                ack_packet = f"TIPO:ACK|SEQ:{seq_num}".encode('utf-8')
                                conn.sendall(ack_packet)
                                print(f"[SERVER] (GBN) ENVIANDO ACK para Seq={seq_num}.")
                                
                                expected_seq_num += 1
                            else:
                                print(f"[SERVER] (GBN) Pacote Seq={seq_num} fora de ordem (esperando {expected_seq_num}). Descartando.")
                                
                                if expected_seq_num > 1:
                                    ack_to_send = expected_seq_num - 1
                                    print(f"[SERVER] (GBN) Reenviando ACK para {ack_to_send} (sinalizando que ainda espera {expected_seq_num}).")
                                    ack_packet = f"TIPO:ACK|SEQ:{ack_to_send}".encode('utf-8')
                                    conn.sendall(ack_packet)
                                else:
                                    print(f"[SERVER] (GBN) Esperando P1, nenhum ACK enviado.")
                        
                        elif RECOVERY_MODE == 'sr':
                            print(f"[SERVER] (SR) Pacote Seq={seq_num} recebido. Conteúdo: '{data_decrypted}'")

                            if seq_num >= expected_seq_num:
                                selective_repeat_buffer[seq_num] = data_decrypted
                                ack_packet = f"TIPO:ACK|SEQ:{seq_num}".encode('utf-8')
                                
                                if ACK_MODE == 'individual':
                                    conn.sendall(ack_packet)
                                    print(f"[SERVER] (SR) Enviando ACK (Individual) para Seq={seq_num}.")
                                else:
                                    print(f"[SERVER] (SR) ACK (Grupo) para Seq={seq_num} retido.")

                                while expected_seq_num in selective_repeat_buffer:
                                    reconstructed_message[expected_seq_num] = selective_repeat_buffer.pop(expected_seq_num)
                                    expected_seq_num += 1
                            else:
                                ack_packet = f"TIPO:ACK|SEQ:{seq_num}".encode('utf-8')
                                
                                if ACK_MODE == 'individual':
                                    conn.sendall(ack_packet)
                                    print(f"[SERVER] (SR) Pacote duplicado Seq={seq_num}. Reenviando ACK (Individual).")

                    except socket.timeout:
                        pass
                
                if RECOVERY_MODE == 'sr' and ACK_MODE == 'grupo':
                    last_seq_received = expected_seq_num - 1
                    if last_seq_received > 0:
                        print(f"[SERVER] (SR) ENVIANDO ACK DE GRUPO final cumulativo para Seq={last_seq_received}.")
                        ack_packet = f"TIPO:ACK|SEQ:{last_seq_received}".encode('utf-8')
                        conn.sendall(ack_packet)
                
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