import socket
import random

# --- Funções de Suporte ---

def caesar_cipher(text, shift, encrypt=False):
    """Descriptografa um texto usando a Cifra de César."""
    # Para descriptografar, usamos o shift negativo
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

# --- Configurações do Servidor ---
HOST = '127.0.0.1'
PORT = 65432
CHAVE_CIFRA = 5 # Chave fixa para a Cifra de César

print("Iniciando servidor...")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Servidor escutando em {HOST}:{PORT}")

    conn, addr = s.accept()
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    with conn:
        print(f"Conexão estabelecida por {addr}")

        # 1. ---------- HANDSHAKE APRIMORADO ----------
        handshake_data = conn.recv(1024).decode('utf-8')
        params = dict(item.split("=") for item in handshake_data.split(";"))
        
        WINDOW_SIZE = int(params.get("WINDOW", "4"))
        RECOVERY_MODE = params.get("RECOVERY", "gbn")
        
        print(f"[HANDSHAKE] Cliente configurado com:")
        print(f"  - Modo de Recuperação: {RECOVERY_MODE.upper()}")
        print(f"  - Tamanho da Janela: {WINDOW_SIZE}")
        
        conn.sendall(b"OK")

        # 2. ---------- RECEBIMENTO E PROCESSAMENTO DE MENSAGENS ----------
        reconstructed_message = {}
        expected_seq_num = 0
        selective_repeat_buffer = {}
        # Variável para controlar quando enviar o ACK atrasado
        ack_is_pending = False
        
        # **NOVO**: Adiciona um timeout para detectar pausas
        conn.settimeout(0.5) # Timeout de meio segundo

        while True:
            try:
                packet_data = conn.recv(1024)
                if not packet_data:
                    print(f"Cliente {addr} desconectou.")
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

                # --- LÓGICA GBN COM DELAYED ACK ---
                if RECOVERY_MODE == 'gbn':
                    if seq_num == expected_seq_num:
                        # Pacote em ordem. APENAS RECEBE, NÃO ENVIA ACK AINDA.
                        print(f"[SERVER] Pacote Seq={seq_num} recebido em ordem. Aguardando próximos...")
                        data_decrypted = caesar_cipher(data_encrypted, CHAVE_CIFRA, encrypt=False)
                        reconstructed_message[seq_num] = data_decrypted
                        expected_seq_num += 1
                        ack_is_pending = True # Marca que temos um ACK para enviar
                    else:
                        # Pacote fora de ordem. ENVIA O ACK IMEDIATAMENTE.
                        print(f"[SERVER] Pacote Seq={seq_num} fora de ordem (esperando {expected_seq_num}). Descartado.")
                        ack_packet = f"TIPO:ACK|SEQ:{expected_seq_num}".encode('utf-8')
                        conn.sendall(ack_packet)
                        print(f"[SERVER] ENVIANDO ACK IMEDIATO: ACK={expected_seq_num} para forçar retransmissão.")
                        ack_is_pending = False # O ACK pendente foi enviado

                # Lógica de Repetição Seletiva
                elif RECOVERY_MODE == 'sr':
                    # Aceita pacotes dentro da janela de recepção
                    # (Embora a lógica principal de janela esteja no cliente, o servidor aceita fora de ordem)
                    if seq_num >= expected_seq_num:
                        data_decrypted = caesar_cipher(data_encrypted, CHAVE_CIFRA, encrypt=False)
                        selective_repeat_buffer[seq_num] = data_decrypted
                        
                        # Envia ACK para o pacote recebido, mesmo que fora de ordem
                        ack_packet = f"TIPO:ACK|SEQ:{seq_num}".encode('utf-8')
                        conn.sendall(ack_packet)
                        print(f"[SERVER] Enviando ACK para Seq={seq_num}.")
                        
                        # Avança a base da janela se possível
                        while expected_seq_num in selective_repeat_buffer:
                            reconstructed_message[expected_seq_num] = selective_repeat_buffer.pop(expected_seq_num)
                            expected_seq_num += 1
                    else:
                        # Se for um pacote antigo já confirmado, apenas envia o ACK novamente
                        ack_packet = f"TIPO:ACK|SEQ:{seq_num}".encode('utf-8')
                        conn.sendall(ack_packet)
            except socket.timeout:
                # O timeout ocorreu! Isso significa que a "rajada" de pacotes terminou.
                # Se houver um ACK pendente, envie-o agora.
                if ack_is_pending:
                    ack_packet = f"TIPO:ACK|SEQ:{expected_seq_num}".encode('utf-8')
                    conn.sendall(ack_packet)
                    print(f"[SERVER] Pausa detectada. ENVIANDO ACK CUMULATIVO: ACK={expected_seq_num} (confirmando tudo até {expected_seq_num-1}).")
                    ack_is_pending = False

            except Exception as e:
                print(f"Ocorreu um erro: {e}")
                break
        
        # 3. ---------- RECONSTRUÇÃO FINAL DA MENSAGEM ----------
        print("\n" + "="*40)
        print("TRANSMISSÃO FINALIZADA. RECONSTRUINDO MENSAGEM...")
        if not reconstructed_message:
            print("Nenhuma mensagem foi recebida corretamente.")
        else:
            final_message = ""
            # Ordena as chaves do dicionário para garantir a ordem correta
            sorted_keys = sorted(reconstructed_message.keys())
            for key in sorted_keys:
                final_message += reconstructed_message[key]
            
            print("Mensagem Original Reconstruída:")
            print(final_message)
        print("="*40)

print("Servidor finalizado.")