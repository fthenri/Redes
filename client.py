# cliente.py

import socket

HOST = '127.0.0.1'  # O mesmo host usado pelo servidor
PORT = 65432        # A mesma porta usada pelo servidor

# Cria o socket (IPv4, TCP)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    try:
        # Tenta se conectar ao servidor
        print(f"Tentando conectar a {HOST}:{PORT}...")
        s.connect((HOST, PORT))
        print("Conectado ao servidor!")
        
        # Prepara a mensagem para enviar
        mensagem = "Ola, servidor! Tudo bem?"
        
        # Envia a mensagem codificada em bytes
        print(f"Enviando: {mensagem}")
        s.sendall(mensagem.encode('utf-8'))
        
        # Espera e recebe a resposta do servidor (buffer de 1024 bytes)
        data = s.recv(1024)
        
        # Decodifica e imprime a resposta
        print(f"Servidor respondeu: {data.decode('utf-8')}")
        
    except ConnectionRefusedError:
        print(f"Não foi possível conectar a {HOST}:{PORT}. O servidor está rodando?")
    except Exception as e:
        print(f"Ocorreu um erro: {e}")

print("Conexão fechada.")