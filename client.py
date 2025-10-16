import socket
import random
import time
import math

# --- Funções de Suporte ---

def caesar_cipher(text, shift, encrypt=True):
    """Criptografa ou descriptografa um texto usando a Cifra de César."""
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
    """Calcula um checksum simples somando os valores ordinais dos caracteres."""
    return sum(ord(char) for char in data)

def create_packet(seq_num, data_chunk_encrypted):
    """Cria uma string de pacote formatada."""
    checksum = calculate_checksum(data_chunk_encrypted)
    return f"TIPO:DATA|SEQ:{seq_num}|CHK:{checksum}|DATA:{data_chunk_encrypted}"

# --- Configurações do Cliente ---
HOST = '127.0.0.1'
PORT = 65432
CHAVE_CIFRA = 5
TIMEOUT = 10    # segundos  

# --- Interação com o Usuário ---
print("--- Configuração do Cliente ---")
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

# --- Lógica Principal ---
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        s.connect((HOST, PORT))
        
        # 1. ---------- HANDSHAKE APRIMORADO ----------
        handshake_msg = f"WINDOW={WINDOW_SIZE};RECOVERY={RECOVERY_MODE}"
        s.sendall(handshake_msg.encode('utf-8'))
        s.recv(1024) # Espera o OK do servidor

        # 2. ---------- PREPARAÇÃO DOS PACOTES ----------
        packets = []
        num_packets = math.ceil(len(MESSAGE_TO_SEND) / MSG_SIZE)
        for i in range(num_packets):
            chunk = MESSAGE_TO_SEND[i*MSG_SIZE : (i+1)*MSG_SIZE]
            encrypted_chunk = caesar_cipher(chunk, CHAVE_CIFRA, encrypt=True)
            packets.append(create_packet(i, encrypted_chunk))

        # 3. ---------- LÓGICA DE ENVIO COM JANELA DESLIZANTE ----------
        send_base = 0
        next_seq_num = 0
        
        # Para SR, precisamos saber quais ACKs recebemos
        acks_received = [False] * num_packets

        while send_base < num_packets:
            # Envia pacotes dentro da janela
            # Envia pacotes dentro da janela
            while next_seq_num < send_base + WINDOW_SIZE and next_seq_num < num_packets:
                # O código de envio de pacotes (com simulação de erro/perda) permanece o mesmo
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

            # --- MUDANÇA PRINCIPAL: LÓGICA DE ESPERA NÃO-BLOQUEANTE ---
            
            # MUDANÇA 1: Inicia um cronômetro manual
            timeout_start = time.time()
            retransmit = False

            # MUDANÇA 2: Loop principal que respeita o cronômetro
            while time.time() - timeout_start < TIMEOUT:
                try:
                    # MUDANÇA 3: Configura o socket para não bloquear
                    s.setblocking(False)
                    
                    ack_data = s.recv(1024).decode('utf-8')
                    ack_parts = dict(item.split(":", 1) for item in ack_data.split("|"))
                    ack_seq = int(ack_parts.get("SEQ"))

                    # Lógica de processamento de ACK para GBN
                    if RECOVERY_MODE == 'gbn':
                        print(f"[CLIENT] ACK cumulativo recebido: {ack_seq}.")
                        # Marca todos os pacotes até o ack_seq como recebidos
                        for i in range(send_base, ack_seq):
                            if i < len(acks_received):
                                acks_received[i] = True
                        send_base = ack_seq
                    
                    # Lógica de processamento de ACK para SR
                    elif RECOVERY_MODE == 'sr':
                        print(f"[CLIENT] ACK recebido para Seq={ack_seq}.")
                        if ack_seq >= send_base and ack_seq < len(acks_received):
                            acks_received[ack_seq] = True
                        # Avança a base se possível
                        while send_base < num_packets and acks_received[send_base]:
                            send_base += 1
                
                except BlockingIOError:
                    # Isso é esperado! Significa "não há dados para ler agora".
                    # Apenas continuamos o loop, verificando o tempo.
                    time.sleep(0.001)
                    pass
                
                except Exception as e:
                    # Outros erros
                    print(f"Erro ao receber ACK: {e}")
                    break
                
                # Verifica se a janela inteira já foi confirmada para sair mais cedo
                if send_base >= next_seq_num:
                    break
            
            # MUDANÇA 4: Restaura o socket para o modo bloqueante
            s.setblocking(True)

            # Verifica se o timeout ocorreu de verdade (se a base não avançou como deveria)
            if send_base < next_seq_num:
                retransmit = True
            
            if retransmit:
                print(f"[CLIENT] TIMEOUT! Ocorreu uma perda de pacote ou de ACK.")
                
                if RECOVERY_MODE == 'gbn':
                    print(f"[CLIENT] GO-BACK-N: Retransmitindo todos os pacotes a partir de Seq={send_base}.")
                    next_seq_num = send_base

                elif RECOVERY_MODE == 'sr':
                    print(f"[CLIENT] SELECTIVE REPEAT: Retransmitindo apenas os pacotes perdidos.")
                    for i in range(send_base, next_seq_num):
                        if not acks_received[i]:
                            print(f"[CLIENT] Retransmitindo pacote perdido Seq={i}.")
                            s.sendall(packets[i].encode('utf-8'))
                            time.sleep(0.1)
                
                if RECOVERY_MODE == 'gbn':
                    print(f"[CLIENT] GO-BACK-N: Retransmitindo todos os pacotes a partir de Seq={send_base}.")
                    # Volta o 'next_seq_num' para a base da janela para reenviar tudo
                    next_seq_num = send_base

                elif RECOVERY_MODE == 'sr':
                    print(f"[CLIENT] SELECTIVE REPEAT: Retransmitindo apenas os pacotes perdidos.")
                    # Reenvia apenas os pacotes da janela atual que não receberam ACK
                    for i in range(send_base, next_seq_num):
                        if not acks_received[i]:
                            print(f"[CLIENT] Retransmitindo pacote perdido Seq={i}.")
                            s.sendall(packets[i].encode('utf-8'))
                            time.sleep(0.1)


        # 4. ---------- FINALIZAÇÃO ----------
        s.sendall(b"FIN") # Envia sinal de finalização
        print("\n[CLIENT] Mensagem enviada completamente. Encerrando.")

    except ConnectionRefusedError:
        print("Conexão recusada. Verifique se o servidor está rodando.")
    except Exception as e:
        print(f"Ocorreu um erro: {e}")