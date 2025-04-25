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

def scanner_de_ip(output_widget):
    if sr1 is None:
        exibir_saida(output_widget, "[!] Scapy não está instalado.")
        return

    exibir_saida(output_widget, "[*] Iniciando scanner de IPs e portas (porta 80)...")
    rede = "192.168.0."  # Ajuste conforme sua rede
    for i in range(1, 10):
        ip = f"{rede}{i}"
        pkt = IP(dst=ip)/TCP(dport=80, flags="S")
        resp = sr1(pkt, timeout=0.5, verbose=0)
        if resp:
            exibir_saida(output_widget, f"[✓] {ip} está ativo e respondeu na porta 80")

def testar_dns(output_widget):
    exibir_saida(output_widget, "[*] Testando resolução DNS...")
    servidores = ["8.8.8.8", "1.1.1.1"]
    for servidor in servidores:
        try:
            nome = socket.gethostbyaddr(servidor)
            exibir_saida(output_widget, f"[✓] {servidor} resolve para {nome[0]}")
        except:
            exibir_saida(output_widget, f"[✗] {servidor} não respondeu")

# ------------------ INTERFACE ------------------

def executar_em_thread(func, output_widget=None):
    if output_widget:
        threading.Thread(target=func, args=(output_widget,)).start()
    else:
        threading.Thread(target=func).start()

def iniciar_interface():
    root = tk.Tk()
    root.title("Otimizador de Sistema Windows")
    root.geometry("700x500")
    root.resizable(False, False)

    notebook = ttk.Notebook(root)
    notebook.pack(expand=True, fill="both", padx=10, pady=10)

    # ------------------ Aba Sistema Operacional ------------------
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

    # ------------------ Aba Ferramentas de Rede ------------------
    aba_rede = ttk.Frame(notebook)
    notebook.add(aba_rede, text="Ferramentas de Rede")

    output = scrolledtext.ScrolledText(aba_rede, width=80, height=20, state="disabled", font=("Consolas", 10))
    output.pack(pady=10)

    botoes_rede = [
        ("Teste de Velocidade", teste_de_velocidade),
        ("Estado das Conexões", estado_conexoes),
        ("Scanner de IPs (porta 80)", scanner_de_ip),
        ("Testar DNS", testar_dns),
    ]

    for texto, funcao in botoes_rede:
        tk.Button(aba_rede, text=texto, width=30, command=lambda f=funcao: executar_em_thread(f, output)).pack(pady=3)

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
