# servidor.py

import socket

# Define o host e a porta
HOST = '127.0.0.1'  # Endereço IP do Servidor (localhost)
PORT = 65432        # Porta que o Servidor vai escutar

print("Iniciando servidor...")

# socket.AF_INET especifica que estamos usando IPv4
# socket.SOCK_STREAM especifica que estamos usando TCP
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # Vincula o socket ao host e porta especificados
    s.bind((HOST, PORT))
    
    # Coloca o socket em modo de escuta
    s.listen()
    
    print(f"Servidor escutando em {HOST}:{PORT}")
    
    # Aceita uma nova conexão
    # s.accept() bloqueia a execução até que uma conexão seja recebida
    # Retorna um novo objeto socket (conn) para a conexão e o endereço (addr) do cliente
    conn, addr = s.accept()
    
    # Usa um 'with' para garantir que o socket da conexão (conn) seja fechado no final
    with conn:
        print(f"Conexão estabelecida por {addr}")
        
        while True:
            # Recebe dados do cliente (buffer de 1024 bytes)
            data = conn.recv(1024)
            
            # Se não receber dados (data vazio), o cliente desconectou
            if not data:
                print("Cliente desconectou.")
                break
                
            # Decodifica os bytes recebidos para string (usando utf-8)
            mensagem_cliente = data.decode('utf-8')
            print(f"Cliente: {mensagem_cliente}")
            
            # Prepara e envia uma resposta de volta para o cliente
            # A resposta deve ser codificada para bytes (usando utf-8)
            resposta = f"Servidor recebeu sua mensagem: '{mensagem_cliente}'"
            conn.sendall(resposta.encode('utf-8'))
            print("Resposta enviada ao cliente.")

print("Servidor finalizado.")