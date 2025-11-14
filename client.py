import socket
import random
import time
import math

def caesar_cipher(text, shift, encrypt=True):
    if not encrypt:
        shift = -shift
    result = ""
    for char in text:
        if char.isalpha():
            start = ord('a') if char.islower() else ord('A')
            shifted = (ord(char) - start + shift) % 26
            result += chr(start + shifted)
        elif char.isdigit():
            start = ord('0')
            shifted = (ord(char) - start + shift) % 10 
            result += chr(start + shifted)
        else:
            result += char
    return result

def calculate_checksum(data):
    return sum(ord(char) for char in data)

def create_packet(seq_num, data_chunk_encrypted):
    checksum = calculate_checksum(data_chunk_encrypted)
    return f"TIPO:DATA|SEQ:{seq_num}|CHK:{checksum}|DATA:{data_chunk_encrypted}"

HOST = '127.0.0.1'
PORT = 65432
CHAVE_CIFRA = 5
TIMEOUT = 4

while True:
    print("\n--- Configuração da Nova Mensagem ---")
    
    while True:
        try:
            MSG_SIZE = int(input("Tamanho dos caracteres por mensagem/pacote (MÁXIMO 4): "))
            if 0 < MSG_SIZE <= 4:
                break
            else:
                print("[ERRO] O tamanho da carga útil deve ser um número entre 1 e 4.")
        except ValueError:
            print("[ERRO] Entrada inválida. Por favor, digite um número.")
    
    RECOVERY_MODE = input("Modo de recuperação (gbn / sr): ").lower()

    if RECOVERY_MODE == 'sr':
        ACK_MODE = input("Modo de confirmação (individual / grupo): ").lower()
        if ACK_MODE not in ['individual', 'grupo']:
            ACK_MODE = 'individual'
            print("Modo de confirmação inválido, usando 'individual'.")
    else:
        ACK_MODE = 'individual'
        if RECOVERY_MODE == 'gbn':
            print("Modo GBN usará ACKs individuais/cumulativos por padrão.")

    OP_MODE = input("Modo de operação (integro / perda / erro): ").lower()
    
    while True:
        try:
            CLIENT_WINDOW_SIZE = int(input("Tamanho da janela do cliente (1-5): "))
            if 1 <= CLIENT_WINDOW_SIZE <= 5:
                break
            else:
                print("[ERRO] O tamanho da janela deve ser entre 1 e 5.")
        except ValueError:
            print("[ERRO] Entrada inválida. Por favor, digite um número.")

    SEND_MODE = input("Modo de envio (lote / isolado): ").lower()
    if SEND_MODE not in ['lote', 'isolado']:
        SEND_MODE = 'lote'
        print("Modo de envio inválido, usando 'lote'.")

    if RECOVERY_MODE not in ['gbn', 'sr']:
        RECOVERY_MODE = 'gbn'
        print("Modo de recuperação inválido, usando 'gbn'.")
    if OP_MODE not in ['integro', 'perda', 'erro']:
        OP_MODE = 'integro'
        print("Modo de operação inválido, usando 'integro'.")

    PROB_PERDA = 0.3 if OP_MODE == 'perda' else 0
    PROB_ERRO = 0.3 if OP_MODE == 'erro' else 0

    print("-" * 30)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        try:
            print("Conectando ao servidor...")
            s.connect((HOST, PORT))
            
            handshake_msg = f"RECOVERY={RECOVERY_MODE};WINDOW={CLIENT_WINDOW_SIZE};ACK_MODE={ACK_MODE}"
            s.sendall(handshake_msg.encode('utf-8'))
            print(f"[CLIENT] Handshake enviado: {handshake_msg}")
            
            handshake_response = s.recv(1024).decode('utf-8')
            params = dict(item.split("=") for item in handshake_response.split(";"))
            WINDOW_SIZE = int(params.get("WINDOW"))
            
            print(f"[HANDSHAKE] Servidor definiu a janela como: {WINDOW_SIZE}")

            
            if SEND_MODE == 'lote':
                MESSAGE_TO_SEND = input("Digite a mensagem longa a ser enviada: \n")
                if not MESSAGE_TO_SEND:
                    print("Nenhuma mensagem para enviar.")
                else:
                    packets = []
                    original_chunks = []
                    num_packets = math.ceil(len(MESSAGE_TO_SEND) / MSG_SIZE)
                    
                    if num_packets == 0:
                        print("Nenhuma mensagem para enviar.")
                        s.sendall(b"FIN")
                        continue

                    for i in range(num_packets):
                        seq_num = i + 1 
                        chunk = MESSAGE_TO_SEND[i*MSG_SIZE : (i+1)*MSG_SIZE]
                        encrypted_chunk = caesar_cipher(chunk, CHAVE_CIFRA, encrypt=True)
                        packets.append(create_packet(seq_num, encrypted_chunk))
                        original_chunks.append(chunk)

                    send_base = 1
                    next_seq_num = 1
                    acks_received = [False] * (num_packets + 1)
                    nacks_received = set()
                    recv_buffer = ""

                    while send_base <= num_packets:
                        while next_seq_num < send_base + WINDOW_SIZE and next_seq_num <= num_packets:
                            packet_index = next_seq_num - 1
                            packet_to_send = packets[packet_index]
                            original_data = original_chunks[packet_index]
                            encrypted_data = caesar_cipher(original_data, CHAVE_CIFRA, encrypt=True)
                            
                            if OP_MODE == 'perda' and random.random() < PROB_PERDA:
                                print(f"[CLIENT] SIMULANDO PERDA do pacote Seq={next_seq_num}. Conteúdo: '{original_data}' -> '{encrypted_data}'")
                            elif OP_MODE == 'erro' and random.random() < PROB_ERRO:
                                parts = dict(item.split(":", 1) for item in packet_to_send.split("|"))
                                bad_checksum = int(parts['CHK']) + 1
                                bad_packet = f"TIPO:DATA|SEQ:{parts['SEQ']}|CHK:{bad_checksum}|DATA:{parts['DATA']}"
                                s.sendall(bad_packet.encode('utf-8'))
                                print(f"[CLIENT] SIMULANDO ERRO no pacote Seq={next_seq_num}. Conteúdo: '{original_data}' -> '{encrypted_data}' (Checksum errado: {bad_checksum})")
                            else:
                                s.sendall(packet_to_send.encode('utf-8'))
                                checksum = calculate_checksum(encrypted_data)
                                print(f"[CLIENT] Enviando pacote Seq={next_seq_num}. Conteúdo: '{original_data}' -> '{encrypted_data}' (Checksum: {checksum})")
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
                                
                                while 'TIPO:' in recv_buffer:
                                    try:
                                        packet_end_idx = recv_buffer.find('TIPO:', 1)
                                        if packet_end_idx != -1:
                                            single_packet_str = recv_buffer[:packet_end_idx]
                                            recv_buffer = recv_buffer[packet_end_idx:]
                                        else:
                                            single_packet_str = recv_buffer
                                            recv_buffer = ""
                                        
                                        packet_parts = dict(item.split(":", 1) for item in single_packet_str.split("|"))
                                        packet_type = packet_parts.get("TIPO")
                                        seq_num = int(packet_parts.get("SEQ"))

                                        if packet_type == 'ACK':
                                            if RECOVERY_MODE == 'gbn':
                                                print(f"[CLIENT] ACK recebido para Pacote={seq_num}.")
                                                if (seq_num + 1) > send_base:
                                                    send_base = seq_num + 1
                                                    timeout_start = time.time()
                                            elif RECOVERY_MODE == 'sr':
                                                if seq_num <= num_packets and not acks_received[seq_num]:
                                                    print(f"[CLIENT] ACK recebido para Seq={seq_num}.")
                                                    acks_received[seq_num] = True
                                                    if seq_num in nacks_received:
                                                        nacks_received.remove(seq_num)
                                                while send_base <= num_packets and acks_received[send_base]:
                                                    send_base += 1
                                        
                                        elif packet_type == 'NACK':
                                            print(f"[CLIENT] NACK recebido para Seq={seq_num}.")
                                            if RECOVERY_MODE == 'sr':
                                                packet_index_nack = seq_num - 1
                                                if seq_num <= num_packets and not acks_received[seq_num]:
                                                    nacks_received.add(seq_num)
                                                    original_data = original_chunks[packet_index_nack]
                                                    encrypted_data = caesar_cipher(original_data, CHAVE_CIFRA, encrypt=True)
                                                    print(f"[CLIENT] Retransmitindo pacote NACKado Seq={seq_num}. Conteúdo: '{original_data}' -> '{encrypted_data}'")
                                                    s.sendall(packets[packet_index_nack].encode('utf-8'))
                                                    time.sleep(0.1)
                                                
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
                                    if not acks_received[i] or i in nacks_received:
                                        packet_index_sr = i - 1
                                        original_data = original_chunks[packet_index_sr]
                                        encrypted_data = caesar_cipher(original_data, CHAVE_CIFRA, encrypt=True)
                                        print(f"[CLIENT] Retransmitindo pacote perdido Seq={i}. Conteúdo: '{original_data}' -> '{encrypted_data}'")
                                        s.sendall(packets[packet_index_sr].encode('utf-8'))
                                        time.sleep(0.1)
                                nacks_received.clear()

                s.sendall(b"FIN")
                print(f"[CLIENT] FIN enviado.")
                print("\n[CLIENT] Mensagem em lote enviada completamente.")

            
            elif SEND_MODE == 'isolado':
                print(f"Modo de envio ISOLADO. Digite 'sair' para finalizar a sessão.")
                
                base_seq = 1 
                
                while True:
                    MESSAGE_TO_SEND = input(f"Digite a msg (Próx Seq={base_seq}) (ou 'sair'): ")
                    if MESSAGE_TO_SEND.lower() == 'sair':
                        break
                    
                    if not MESSAGE_TO_SEND:
                        print("Nenhuma mensagem para enviar.")
                        continue
                    
                    packets = []
                    original_chunks = []
                    num_packets_batch = math.ceil(len(MESSAGE_TO_SEND) / MSG_SIZE)
                    
                    if num_packets_batch == 0:
                        continue

                    for i in range(num_packets_batch):
                        seq_num = i + base_seq 
                        chunk = MESSAGE_TO_SEND[i*MSG_SIZE : (i+1)*MSG_SIZE]
                        encrypted_chunk = caesar_cipher(chunk, CHAVE_CIFRA, encrypt=True)
                        packets.append(create_packet(seq_num, encrypted_chunk))
                        original_chunks.append(chunk)

                    end_seq_for_batch = base_seq + num_packets_batch
                    
                    acks_received = [False] * (end_seq_for_batch) 
                    nacks_received = set()
                    recv_buffer = ""

                    send_base = base_seq
                    next_seq_num = base_seq

                    while send_base < end_seq_for_batch:
                        while next_seq_num < send_base + WINDOW_SIZE and next_seq_num < end_seq_for_batch:
                            packet_index = next_seq_num - base_seq 
                            
                            packet_to_send = packets[packet_index]
                            original_data = original_chunks[packet_index]
                            encrypted_data = caesar_cipher(original_data, CHAVE_CIFRA, encrypt=True)
                            
                            if OP_MODE == 'perda' and random.random() < PROB_PERDA:
                                print(f"[CLIENT] SIMULANDO PERDA do pacote Seq={next_seq_num}. Conteúdo: '{original_data}' -> '{encrypted_data}'")
                            elif OP_MODE == 'erro' and random.random() < PROB_ERRO:
                                parts = dict(item.split(":", 1) for item in packet_to_send.split("|"))
                                bad_checksum = int(parts['CHK']) + 1
                                bad_packet = f"TIPO:DATA|SEQ:{parts['SEQ']}|CHK:{bad_checksum}|DATA:{parts['DATA']}"
                                s.sendall(bad_packet.encode('utf-8'))
                                print(f"[CLIENT] SIMULANDO ERRO no pacote Seq={next_seq_num}. Conteúdo: '{original_data}' -> '{encrypted_data}' (Checksum errado: {bad_checksum})")
                            else:
                                s.sendall(packet_to_send.encode('utf-8'))
                                checksum = calculate_checksum(encrypted_data)
                                print(f"[CLIENT] Enviando pacote Seq={next_seq_num}. Conteúdo: '{original_data}' -> '{encrypted_data}' (Checksum: {checksum})")
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
                                
                                while 'TIPO:' in recv_buffer:
                                    try:
                                        packet_end_idx = recv_buffer.find('TIPO:', 1)
                                        if packet_end_idx != -1:
                                            single_packet_str = recv_buffer[:packet_end_idx]
                                            recv_buffer = recv_buffer[packet_end_idx:]
                                        else:
                                            single_packet_str = recv_buffer
                                            recv_buffer = ""
                                        
                                        packet_parts = dict(item.split(":", 1) for item in single_packet_str.split("|"))
                                        packet_type = packet_parts.get("TIPO")
                                        seq_num = int(packet_parts.get("SEQ"))

                                        if packet_type == 'ACK':
                                            if RECOVERY_MODE == 'gbn':
                                                print(f"[CLIENT] ACK recebido para Pacote={seq_num}.")
                                                if (seq_num + 1) > send_base:
                                                    send_base = seq_num + 1
                                                    timeout_start = time.time()
                                            elif RECOVERY_MODE == 'sr':
                                                if seq_num < end_seq_for_batch and not acks_received[seq_num]:
                                                    print(f"[CLIENT] ACK recebido para Seq={seq_num}.")
                                                    acks_received[seq_num] = True
                                                    if seq_num in nacks_received:
                                                        nacks_received.remove(seq_num)
                                                while send_base < end_seq_for_batch and acks_received[send_base]:
                                                    send_base += 1
                                        
                                        elif packet_type == 'NACK':
                                            print(f"[CLIENT] NACK recebido para Seq={seq_num}.")
                                            if RECOVERY_MODE == 'sr':
                                                packet_index_nack = seq_num - base_seq
                                                
                                                if seq_num < end_seq_for_batch and not acks_received[seq_num]:
                                                    nacks_received.add(seq_num)
                                                    original_data = original_chunks[packet_index_nack]
                                                    encrypted_data = caesar_cipher(original_data, CHAVE_CIFRA, encrypt=True)
                                                    print(f"[CLIENT] Retransmitindo pacote NACKado Seq={seq_num}. Conteúdo: '{original_data}' -> '{encrypted_data}'")
                                                    s.sendall(packets[packet_index_nack].encode('utf-8'))
                                                    time.sleep(0.1)
                                                
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
                                    if not acks_received[i] or i in nacks_received:
                                        packet_index_sr = i - base_seq
                                        original_data = original_chunks[packet_index_sr]
                                        encrypted_data = caesar_cipher(original_data, CHAVE_CIFRA, encrypt=True)
                                        print(f"[CLIENT] Retransmitindo pacote perdido Seq={i}. Conteúdo: '{original_data}' -> '{encrypted_data}'")
                                        s.sendall(packets[packet_index_sr].encode('utf-8'))
                                        time.sleep(0.1)
                                nacks_received.clear()

                    print(f"[CLIENT] Pacote(s) isolado(s) (Seq {base_seq} a {end_seq_for_batch - 1}) enviados.")
                    
                    base_seq = end_seq_for_batch
                    
                s.sendall(b"FIN")
                print(f"[CLIENT] FIN enviado.")
                print("\n[CLIENT] Mensagem(ns) isolada(s) enviada(s) completamente.")
            
        except ConnectionRefusedError:
            print("Conexão recusada. Verifique se o servidor está rodando e tente novamente.")
        except Exception as e:
            print(f"Ocorreu um erro: {e}")

    if input("Deseja enviar outra mensagem? (s/n): ").lower() != 's':
        print("Encerrando cliente.")
        break