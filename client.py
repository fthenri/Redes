import socket
import random
import time
import math

# --- Funções de Suporte (caesar_cipher, calculate_checksum, create_packet) - Sem alterações ---

def caesar_cipher(text, shift, encrypt=True):
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

def create_packet(seq_num, data_chunk_encrypted):
    checksum = calculate_checksum(data_chunk_encrypted)
    return f"TIPO:DATA|SEQ:{seq_num}|CHK:{checksum}|DATA:{data_chunk_encrypted}"

# --- Configurações do Cliente ---
HOST = '127.0.0.1'
PORT = 65432
CHAVE_CIFRA = 5
TIMEOUT = 4

# --- MUDANÇA PRINCIPAL: Loop para enviar múltiplas mensagens ---
while True:
    # --- Interação com o Usuário para cada nova mensagem ---
    print("\n--- Configuração da Nova Mensagem ---")
    MSG_SIZE = int(input("Tamanho dos caracteres por mensagem/pacote (ex: 10): "))
    WINDOW_SIZE = int(input("Tamanho da janela de envio (ex: 4): "))
    RECOVERY_MODE = input("Modo de recuperação (gbn / sr): ").lower()
    OP_MODE = input("Modo de operação (integro / perda / erro): ").lower()

    if RECOVERY_MODE not in ['gbn', 'sr']:
        RECOVERY_MODE = 'gbn'
        print("Modo de recuperação inválido, usando 'gbn'.")
    if OP_MODE not in ['integro', 'perda', 'erro']:
        OP_MODE = 'integro'
        print("Modo de operação inválido, usando 'integro'.")

    PROB_PERDA = 0.3 if OP_MODE == 'perda' else 0
    PROB_ERRO = 0.3 if OP_MODE == 'erro' else 0

    MESSAGE_TO_SEND = input("Digite a mensagem longa a ser enviada: \n")
    print("-" * 30)

    # --- Lógica de Conexão e Envio (agora dentro do loop) ---
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        try:
            print("Conectando ao servidor...")
            s.connect((HOST, PORT))
            
            handshake_msg = f"WINDOW={WINDOW_SIZE};RECOVERY={RECOVERY_MODE}"
            s.sendall(handshake_msg.encode('utf-8'))
            s.recv(1024)

            packets = []
            num_packets = math.ceil(len(MESSAGE_TO_SEND) / MSG_SIZE)
            for i in range(num_packets):
                chunk = MESSAGE_TO_SEND[i*MSG_SIZE : (i+1)*MSG_SIZE]
                encrypted_chunk = caesar_cipher(chunk, CHAVE_CIFRA, encrypt=True)
                packets.append(create_packet(i, encrypted_chunk))

            send_base = 0
            next_seq_num = 0
            acks_received = [False] * num_packets
            recv_buffer = ""

            while send_base < num_packets:
                while next_seq_num < send_base + WINDOW_SIZE and next_seq_num < num_packets:
                    packet_to_send = packets[next_seq_num]
                    if OP_MODE == 'perda' and random.random() < PROB_PERDA:
                        print(f"[CLIENT] SIMULANDO PERDA do pacote Seq={next_seq_num}.")
                    elif OP_MODE == 'erro' and random.random() < PROB_ERRO:
                        parts = dict(item.split(":", 1) for item in packet_to_send.split("|"))
                        bad_checksum = int(parts['CHK']) + 1
                        bad_packet = f"TIPO:DATA|SEQ:{parts['SEQ']}|CHK:{bad_checksum}|DATA:{parts['DATA']}"
                        s.sendall(bad_packet.encode('utf-8'))
                        print(f"[CLIENT] SIMULANDO ERRO no pacote Seq={next_seq_num}.")
                    else:
                        s.sendall(packet_to_send.encode('utf-8'))
                        print(f"[CLIENT] Enviando pacote Seq={next_seq_num}.")
                    next_seq_num += 1
                    time.sleep(0.1)

                timeout_start = time.time()
                retransmit = False

                while time.time() - timeout_start < TIMEOUT:
                    try:
                        s.setblocking(False)
                        data_received = s.recv(4096).decode('utf-8')
                        if data_received:
                            recv_buffer += data_received
                        
                        while 'TIPO:ACK' in recv_buffer:
                            try:
                                packet_end_idx = recv_buffer.find('TIPO:', 1)
                                if packet_end_idx != -1:
                                    single_ack_str = recv_buffer[:packet_end_idx]
                                    recv_buffer = recv_buffer[packet_end_idx:]
                                else:
                                    single_ack_str = recv_buffer
                                    recv_buffer = ""
                                
                                ack_parts = dict(item.split(":", 1) for item in single_ack_str.split("|"))
                                ack_seq = int(ack_parts.get("SEQ"))

                                if RECOVERY_MODE == 'gbn':
                                    print(f"[CLIENT] ACK cumulativo recebido: {ack_seq}.")
                                    for i in range(send_base, ack_seq):
                                        if i < len(acks_received): acks_received[i] = True
                                    send_base = ack_seq
                                
                                elif RECOVERY_MODE == 'sr':
                                    if ack_seq < len(acks_received) and not acks_received[ack_seq]:
                                        print(f"[CLIENT] ACK recebido para Seq={ack_seq}.")
                                        acks_received[ack_seq] = True
                                    while send_base < num_packets and acks_received[send_base]:
                                        send_base += 1
                            except (ValueError, IndexError):
                                break
                    except BlockingIOError:
                        time.sleep(0.001)
                    
                    if send_base >= next_seq_num:
                        break
                
                s.setblocking(True)

                if send_base < next_seq_num:
                    retransmit = True
                
                if retransmit:
                    print(f"[CLIENT] TIMEOUT! Ocorreu uma perda de pacote ou de ACK.")
                    if RECOVERY_MODE == 'gbn':
                        print(f"[CLIENT] GO-BACK-N: Retransmitindo pacotes a partir de Seq={send_base}.")
                        next_seq_num = send_base
                    elif RECOVERY_MODE == 'sr':
                        print(f"[CLIENT] SELECTIVE REPEAT: Retransmitindo pacotes perdidos.")
                        for i in range(send_base, next_seq_num):
                            if not acks_received[i]:
                                print(f"[CLIENT] Retransmitindo pacote perdido Seq={i}.")
                                s.sendall(packets[i].encode('utf-8'))
                                time.sleep(0.1)

            s.sendall(b"FIN")
            print("\n[CLIENT] Mensagem enviada completamente.")

        except ConnectionRefusedError:
            print("Conexão recusada. Verifique se o servidor está rodando e tente novamente.")
        except Exception as e:
            print(f"Ocorreu um erro: {e}")

    # --- Pergunta ao usuário se deseja continuar ---
    if input("Deseja enviar outra mensagem? (s/n): ").lower() != 's':
        print("Encerrando cliente.")
        break