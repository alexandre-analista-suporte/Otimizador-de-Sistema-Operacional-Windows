import ctypes
import os
import subprocess
import psutil
import socket
import threading
import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext
import sys
import time

try:
    from scapy.all import sr1, IP, TCP
except ImportError:
    sr1 = IP = TCP = None  # Tratamento se scapy não estiver instalado


# Verifica se está sendo executado como administrador
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# ------------------ FUNÇÕES SISTEMA OPERACIONAL ------------------

def otimizar_memoria():
    try:
        os.system("powershell -command \"[System.GC]::Collect()\"")
        messagebox.showinfo("Memória", "Memória otimizada com sucesso.")
    except Exception as e:
        messagebox.showerror("Erro", f"Erro ao otimizar memória: {e}")

def limpar_arquivos_temporarios():
    try:
        pastas = [os.getenv('TEMP'), os.getenv('TMP'), r'C:\Windows\Temp']
        removidos = 0
        for pasta in pastas:
            for raiz, dirs, arquivos in os.walk(pasta):
                for arquivo in arquivos:
                    caminho = os.path.join(raiz, arquivo)
                    try:
                        os.remove(caminho)
                        removidos += 1
                    except:
                        pass
                for dir in dirs:
                    try:
                        os.rmdir(os.path.join(raiz, dir))
                    except:
                        pass
        messagebox.showinfo("Limpeza", f"Arquivos temporários limpos: {removidos}")
    except Exception as e:
        messagebox.showerror("Erro", f"Erro na limpeza: {e}")

def verificar_disco():
    try:
        subprocess.run("chkdsk C:", shell=True)
        messagebox.showinfo("Verificação", "Verificação de disco finalizada.")
    except Exception as e:
        messagebox.showerror("Erro", f"Erro ao verificar disco: {e}")

def desfragmentar_disco():
    try:
        subprocess.run("defrag C: /O", shell=True)
        messagebox.showinfo("Desfragmentação", "Desfragmentação concluída.")
    except Exception as e:
        messagebox.showerror("Erro", f"Erro ao desfragmentar: {e}")

# ------------------ FUNÇÕES FERRAMENTAS DE REDE ------------------

def exibir_saida(output_widget, texto):
    output_widget.configure(state="normal")
    output_widget.insert(tk.END, texto + "\n")
    output_widget.configure(state="disabled")
    output_widget.see(tk.END)

def teste_de_velocidade(output_widget):
    def ping(host):
        try:
            inicio = time.time()
            socket.gethostbyname(host)
            fim = time.time()
            return round((fim - inicio) * 1000, 2)
        except:
            return None

    exibir_saida(output_widget, "[*] Testando velocidade de conexão...")
    servidores = ["google.com", "cloudflare.com", "openai.com"]
    for servidor in servidores:
        tempo = ping(servidor)
        if tempo:
            exibir_saida(output_widget, f"[✓] {servidor} respondeu em {tempo} ms")
        else:
            exibir_saida(output_widget, f"[✗] {servidor} não respondeu")

def estado_conexoes(output_widget):
    exibir_saida(output_widget, "[*] Verificando conexões de rede...")
    conexoes = psutil.net_connections()
    for conn in conexoes[:50]:  # Limite de 50 conexões exibidas
        try:
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            status = conn.status
            exibir_saida(output_widget, f"{laddr} -> {raddr} [{status}]")
        except:
            continue

def scanner_de_ip(output_widget, rede):
    if sr1 is None:
        exibir_saida(output_widget, "[!] Scapy não está instalado.")
        return

    exibir_saida(output_widget, f"[*] Iniciando scanner na rede {rede}x (portas 21,22,23,80,443)...")
    for i in range(1, 255):
        ip = f"{rede}{i}"
        pkt = IP(dst=ip)/TCP(dport=[21, 22, 23, 80, 443], flags="S")
        resp = sr1(pkt, timeout=0.5, verbose=0)
        if resp:
            exibir_saida(output_widget, f"[✓] {ip} respondeu em alguma porta")

def testar_dns(output_widget, ips_str):
    servidores = [ip.strip() for ip in ips_str.split(",")]
    exibir_saida(output_widget, "[*] Testando resolução DNS...")
    for servidor in servidores:
        try:
            nome = socket.gethostbyaddr(servidor)
            exibir_saida(output_widget, f"[✓] {servidor} resolve para {nome[0]}")
        except:
            exibir_saida(output_widget, f"[✗] {servidor} não respondeu")

def ping_tracert(output_widget, destinos_str):
    destinos = [d.strip() for d in destinos_str.split(",")]
    for destino in destinos:
        exibir_saida(output_widget, f"[*] Pingando {destino}...")
        try:
            resposta = subprocess.run(["ping", "-n", "4", destino], capture_output=True, text=True, timeout=10)
            exibir_saida(output_widget, resposta.stdout)
        except Exception as e:
            exibir_saida(output_widget, f"[✗] Erro no ping: {e}")

        exibir_saida(output_widget, f"[*] Executando tracert para {destino}...")
        try:
            resposta = subprocess.run(["tracert", destino], capture_output=True, text=True, timeout=30)
            exibir_saida(output_widget, resposta.stdout)
        except Exception as e:
            exibir_saida(output_widget, f"[✗] Erro no tracert: {e}")

# ------------------ JANELAS DE CONFIGURAÇÃO ------------------

def janela_scanner_ip(output_widget):
    def executar():
        rede = entrada_rede.get()
        if not rede:
            messagebox.showwarning("Atenção", "Rede não informada.")
            return
        janela.destroy()
        executar_em_thread(lambda: scanner_de_ip(output_widget, rede))

    janela = tk.Toplevel()
    janela.title("Configurar Scanner de IPs")
    janela.geometry("300x150")
    tk.Label(janela, text="Informe a rede base (ex: 192.168.1.):").pack(pady=10)
    entrada_rede = tk.Entry(janela, width=30)
    entrada_rede.pack(pady=5)
    tk.Button(janela, text="Executar Scanner", command=executar).pack(pady=10)
    tk.Button(janela, text="Cancelar", command=janela.destroy).pack()

def janela_teste_dns(output_widget):
    def executar():
        ips = entrada_ips.get()
        if not ips:
            messagebox.showwarning("Atenção", "IPs não informados.")
            return
        janela.destroy()
        executar_em_thread(lambda: testar_dns(output_widget, ips))

    janela = tk.Toplevel()
    janela.title("Configurar Teste de DNS")
    janela.geometry("300x150")
    tk.Label(janela, text="Informe IPs separados por vírgula:").pack(pady=10)
    entrada_ips = tk.Entry(janela, width=30)
    entrada_ips.pack(pady=5)
    tk.Button(janela, text="Executar Teste", command=executar).pack(pady=10)
    tk.Button(janela, text="Cancelar", command=janela.destroy).pack()

def janela_ping_tracert(output_widget):
    def executar():
        destinos = entrada_destinos.get()
        if not destinos:
            messagebox.showwarning("Atenção", "Destinos não informados.")
            return
        janela.destroy()
        executar_em_thread(lambda: ping_tracert(output_widget, destinos))

    janela = tk.Toplevel()
    janela.title("Configurar Ping e Traceroute")
    janela.geometry("300x150")
    tk.Label(janela, text="Informe IPs/Domínios separados por vírgula:").pack(pady=10)
    entrada_destinos = tk.Entry(janela, width=30)
    entrada_destinos.pack(pady=5)
    tk.Button(janela, text="Executar Teste", command=executar).pack(pady=10)
    tk.Button(janela, text="Cancelar", command=janela.destroy).pack()

# ------------------ INTERFACE PRINCIPAL ------------------

def executar_em_thread(func, output_widget=None):
    if output_widget:
        threading.Thread(target=func, args=(output_widget,)).start()
    else:
        threading.Thread(target=func).start()

def iniciar_interface():
    root = tk.Tk()
    root.title("Otimizador de Sistema Windows")
    root.geometry("750x550")
    root.resizable(False, False)

    notebook = ttk.Notebook(root)
    notebook.pack(expand=True, fill="both", padx=10, pady=10)

    # Aba Sistema Operacional
    aba_sistema = ttk.Frame(notebook)
    notebook.add(aba_sistema, text="Sistema Operacional")

    tk.Label(aba_sistema, text="Utilitários do Sistema Operacional", font=("Arial", 14, "bold")).pack(pady=10)

    botoes = [
        ("Otimizar Memória RAM", otimizar_memoria),
        ("Limpar Arquivos Temporários", limpar_arquivos_temporarios),
        ("Verificar Disco (chkdsk)", verificar_disco),
        ("Desfragmentar Disco", desfragmentar_disco),
    ]

    for texto, funcao in botoes:
        tk.Button(aba_sistema, text=texto, width=40, height=2, command=lambda f=funcao: executar_em_thread(f)).pack(pady=5)

    # Aba Ferramentas de Rede
    aba_rede = ttk.Frame(notebook)
    notebook.add(aba_rede, text="Ferramentas de Rede")

    output = scrolledtext.ScrolledText(aba_rede, width=90, height=20, state="disabled", font=("Consolas", 10))
    output.pack(pady=10)

    botoes_rede = [
        ("Teste de Velocidade", teste_de_velocidade),
        ("Estado das Conexões", estado_conexoes),
        ("Scanner de IPs (Configurar)", janela_scanner_ip),
        ("Testar DNS (Configurar)", janela_teste_dns),
        ("Ping e Traceroute (Configurar)", janela_ping_tracert),
    ]

    for texto, funcao in botoes_rede:
        tk.Button(aba_rede, text=texto, width=35, command=lambda f=funcao: executar_em_thread(f, output)).pack(pady=3)

    tk.Button(root, text="Sair", width=30, command=root.quit).pack(pady=10)

    root.mainloop()

# ------------------ Execução Principal ------------------

if __name__ == "__main__":
    if not is_admin():
        try:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{__file__}"', None, 1)
        except Exception as e:
            messagebox.showerror("Erro", f"Não foi possível executar como administrador: {e}")
    else:
        iniciar_interface()
