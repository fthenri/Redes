# Redes

Henrique Gueiros
Lucas Calabria
Felipe Barros
Samuel Gouveia
Miguel Arcanjo
Artur Barros
Henrique Figueiredo Tefile


# Redes

Henrique Gueiros
Lucas Calabria
Felipe Barros
Samuel Gouveia
Miguel Arcanjo
Artur Barros
Henrique Figueiredo Tefile



📡 Projeto de Redes: Comunicação Confiável TCP
Um sistema completo de comunicação cliente-servidor com controle de erros e recuperação de pacotes.

🚀 Começo Rápido
1️⃣ Inicie o Servidor
bash
python servidor.py
2️⃣ Execute o Cliente
bash
python cliente.py
📋 Pré-requisitos
Python 3.6+

Nenhuma biblioteca externa necessária

🛠️ Configuração
Salve os arquivos:
cliente.py - Programa do cliente

servidor.py - Programa do servidor

⚙️ Como Usar
No Cliente, configure:
Tamanho do Pacote (1-4 caracteres)

Modo de Recuperação:

gbn - Go-Back-N

sr - Selective Repeat

Modo de Operação:

integro - Sem problemas

perda - 30% de perda de pacotes

erro - 30% de erros de checksum

Digite sua mensagem

🎯 Exemplo de Uso
text
--- Configuração da Nova Mensagem ---
Tamanho dos caracteres por mensagem/pacote (MÁXIMO 4): 3
Modo de recuperação (gbn / sr): gbn
Modo de operação (integro / perda / erro): integro
Digite a mensagem longa a ser enviada: 
Olá, este é um teste do sistema!
🔧 Funcionalidades
✅ Cifra de César para criptografia

✅ Checksum para detecção de erros

✅ Controle de fluxo com janela deslizante

✅ Retransmissão inteligente (GBN ou SR)

✅ Simulação de perdas e erros

✅ Reconexão automática

📊 Saída Esperada
Servidor:

text
🟢 Iniciando servidor...
🔊 Servidor escutando em 127.0.0.1:65432
✅ Conexão estabelecida com ('127.0.0.1', 65432)
📦 Pacote Seq=0 recebido. Conteúdo: 'Olá' -> 'Tqá'
Cliente:

text
🔗 Conectando ao servidor...
📤 Enviando pacote Seq=0. Conteúdo: 'Olá' -> 'Tqá'
✅ ACK recebido para Seq=0
🎉 Mensagem enviada completamente!
🐛 Solução de Problemas
Problema: "Conexão recusada"

✅ Verifique se o servidor está rodando

Problema: Mensagem incompleta

✅ Use modo integro para testes

✅ Aumente o timeout se necessário

Problema: Lentidão

✅ Reduza tamanho dos pacotes

✅ Use janela maior no servidor

🔄 Reiniciar
O cliente pergunta automaticamente:

text
Deseja enviar outra mensagem? (s/n):
Digite s para nova mensagem ou n para sair.

✨ Dica: Comece com modo integro para testar, depois experimente com perda ou erro para ver a recuperação em ação!
