# Otimizador de Sistema Windows

Este projeto é um utilitário desenvolvido em Python para otimizar o sistema operacional Windows, oferecendo uma interface gráfica (GUI) baseada no Tkinter. O software permite a realização de várias tarefas de manutenção do sistema, como otimização de memória, limpeza de arquivos temporários, verificação de disco e desfragmentação. Além disso, inclui ferramentas de rede, como teste de velocidade de conexão, análise de conexões de rede e escaneamento de IPs.

## Funcionalidades

### 1. **Utilitários do Sistema Operacional**
- **Otimizar Memória RAM**: Realiza a limpeza da memória RAM, liberando recursos do sistema.
- **Limpar Arquivos Temporários**: Remove arquivos temporários em diretórios como `%TEMP%`, `%TMP%` e `C:\Windows\Temp`.
- **Verificar Disco (chkdsk)**: Executa a verificação de disco no drive C: usando a ferramenta `chkdsk`.
- **Desfragmentar Disco**: Realiza a desfragmentação do disco rígido na partição C:.

### 2. **Ferramentas de Rede**
- **Teste de Velocidade**: Verifica o tempo de resposta de servidores como Google, Cloudflare e OpenAI para avaliar a velocidade da conexão.
- **Estado das Conexões**: Exibe as conexões de rede ativas no sistema, incluindo IPs locais e remotos e o status das conexões.
- **Scanner de IPs (porta 80)**: Realiza um escaneamento de IPs na rede local para verificar quais dispositivos estão respondendo na porta 80.
- **Testar DNS**: Testa a resolução DNS para servidores como Google (8.8.8.8) e Cloudflare (1.1.1.1).

## Pré-Requisitos

- Python 3.x
- Bibliotecas Python:
  - `psutil`: Para verificar as conexões de rede.
  - `scapy` (opcional): Para realizar o escaneamento de IPs. Caso não esteja instalado, o scanner de IPs não funcionará.

Para instalar as dependências, execute:

```bash
pip install psutil scapy
