import subprocess
import requests
import threading
import time
import urllib3
import re
import webbrowser
import atexit
import signal
import sys
import os
import sqlite3
import json
import logging
import shutil
import pandas as pd
import warnings #silenciar completamente o warning
warnings.filterwarnings("ignore", category=RuntimeWarning, module="mac_vendor_lookup")#silenciar completamente o warning
from datetime import datetime, timedelta
from flask import Flask, render_template_string, send_from_directory, request, jsonify, send_file
from flask_socketio import SocketIO, emit
from mac_vendor_lookup import MacLookup
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

# get_linux_neighbors() é responsável por ler a "tabela de vizinhos" do Kernel do Linux.
def get_linux_neighbors():
    """Captura TODOS os dispositivos da tabela ARP do Kernel Linux sem restrições"""
    vizinhos = {}
    try:
        # Usamos 'ip neigh show' para pegar a tabela atual do Kernel
        saida = subprocess.check_output(["ip", "neigh", "show"]).decode()
        for linha in saida.split('\n'):
            partes = linha.split()
            # Precisamos garantir que a linha tenha um IP e um MAC válido (lladdr)
            if len(partes) >= 4 and "lladdr" in partes:
                ip = partes[0]
                mac = partes[partes.index("lladdr") + 1].upper()
                # Filtramos apenas para o seu range, mas sem descartar por status
                if ip.startswith(RANGE_SCAN) and ":" in mac:
                    vizinhos[ip] = mac
    except Exception as e:
        print(f"[LINUX-ERROR] Erro ao acessar tabela ARP: {e}")
    return vizinhos

# Desativa avisos de certificados SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================= CONFIGURAÇÃO =================
TELEGRAM_TOKEN = "8500111206:AAGXPGWSMyogpP57-iBdpxKQq-mg54kAwHw"
TELEGRAM_CHAT_ID = "7041868424"
PORTA_WEB = 8080  # Portas recomendadas: 5000, 8000, 8080 ou 8888
IP_SERVIDOR = "192.168.0.22"
LINK_ACESSO = f"http://{IP_SERVIDOR}:{PORTA_WEB}"
DB_NAME = "monitor_roteadores.db"
INTERVALO_VARREDURA = 30
LIMITE_ALERTA_DB_MB = 1024
RANGE_SCAN = "192.168.0."

try:
    mac_identificador = MacLookup()
    mac_identificador.update_servers = ["https://standards-oui.ieee.org/oui/oui.txt"]
except:
    mac_identificador = None

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
lock = threading.Lock()

status_atual = {}
historico_falhas_python = {}
historico_mac_alerta = {}
# NOVO: Registry de MACs para inteligência DHCP (evita falsos positivos)
mac_registry = {}  # {mac: {'nome': str, 'ip_atual': str, 'ultimo_visto': datetime, 'visto_em_ips': []}}
historico_mac_alerta_real = {}  # {ip_mac_antigo_mac_novo: timestamp} - Alertas de troca REAL (não DHCP)
status_sistema_global = {"uso_db_ms": 0, "risco_percent": 0}

# ================= BANCO DE DADOS =================

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # ATIVAR WAL MODE - Permite leitura simultânea durante escritas
    cursor.execute('PRAGMA journal_mode=WAL;')
    cursor.execute('PRAGMA synchronous=NORMAL;')
    cursor.execute('PRAGMA cache_size=10000;')
    cursor.execute('PRAGMA temp_store=MEMORY;')

    # Tabela principal de dispositivos
    cursor.execute('''CREATE TABLE IF NOT EXISTS config_dispositivos (
        ip TEXT PRIMARY KEY,
        nome TEXT,
        fabricante TEXT,
        marca TEXT,
        modelo TEXT,
        especificacoes TEXT,
        mac_oficial TEXT,
        ignorar INTEGER DEFAULT 0,
        tipo TEXT DEFAULT 'Outros'
    )''')

    # Tenta adicionar a coluna tipo caso ela não exista (Migration)
    try:
        cursor.execute("ALTER TABLE config_dispositivos ADD COLUMN tipo TEXT DEFAULT 'Outros'")
    except:
        pass

    # Tabela de logs de status
    cursor.execute('''CREATE TABLE IF NOT EXISTS logs_status (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME,
        ip TEXT,
        nome TEXT,
        status TEXT,
        web TEXT,
        mac TEXT,
        mac_status TEXT
    )''')

    # Tabela de auditoria de hardware
    cursor.execute('''CREATE TABLE IF NOT EXISTS auditoria_hardware (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME,
        ip TEXT,
        nome_setor TEXT,
        fabricante_antigo TEXT,
        modelo_antigo TEXT,
        mac_antigo TEXT,
        mac_novo TEXT
    )''')

    # NOVO: Tenta adicionar coluna tipo_evento se não existir (Migration)
    try:
        cursor.execute("ALTER TABLE auditoria_hardware ADD COLUMN tipo_evento TEXT DEFAULT 'TROCA_HARDWARE'")
    except:
        pass

    # NOVO: Tabela de registry de MACs (inteligência anti-falso positivo DHCP)
    cursor.execute('''CREATE TABLE IF NOT EXISTS mac_registry (
        mac TEXT PRIMARY KEY,
        nome_dispositivo TEXT,
        ip_atual TEXT,
        primeiro_visto DATETIME,
        ultimo_visto DATETIME,
        contador_movimentacoes INTEGER DEFAULT 0,
        status TEXT DEFAULT 'ATIVO'
    )''')

    # NOVO: Tabela de tipos de dispositivos (dinâmica)
    cursor.execute('''CREATE TABLE IF NOT EXISTS tipos_dispositivos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT UNIQUE NOT NULL,
        descricao TEXT,
        cor TEXT DEFAULT '#1a237e',
        ativo INTEGER DEFAULT 1,
        ordem INTEGER DEFAULT 0
    )''')

    # Inserir tipos padrão se a tabela estiver vazia
    cursor.execute("SELECT COUNT(*) FROM tipos_dispositivos")
    if cursor.fetchone()[0] == 0:
        tipos_padrao = [
            ('Roteador', 'Dispositivos de roteamento de rede', '#1a237e', 1),
            ('Switch', 'Switches e hubs de rede', '#2e7d32', 2),
            ('Desktop', 'Computadores desktop', '#1565c0', 3),
            ('Celular', 'Smartphones e tablets', '#ef6c00', 4),
            ('Relógio Ponto', 'Relógios de ponto eletrônico', '#6a1b9a', 5),
            ('Impressora', 'Impressoras e multifuncionais', '#c62828', 6),
            ('Smart TV', 'Televisões smart e displays', '#00796b', 7),
            ('Outros', 'Outros dispositivos diversos', '#455a64', 99)
        ]
        cursor.executemany(
            "INSERT INTO tipos_dispositivos (nome, descricao, cor, ordem) VALUES (?, ?, ?, ?)",
            tipos_padrao
        )

    # Tabela de controle do sistema
    cursor.execute('''CREATE TABLE IF NOT EXISTS controle_sistema (
        chave TEXT PRIMARY KEY,
        valor TEXT
    )''')

    cursor.execute("INSERT OR IGNORE INTO controle_sistema (chave, valor) VALUES (?, ?)",
                   ('ultima_atualizacao_mac', 'Nunca atualizada'))

    conn.commit()
    conn.close()

def atualizar_mac_registry(mac, nome_dispositivo, ip_atual):
    """
    Atualiza o registry de MACs com inteligência anti-falso positivo DHCP.
    Retorna: ('movimentacao', ip_anterior) se MAC mudou de IP, ('normal', None) caso contrário
    """
    global mac_registry

    if not mac or mac == "---":
        return ('normal', None)

    agora = datetime.now()
    ip_anterior = None

    # Usar timeout maior e modo WAL para evitar locks
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME, timeout=10.0)
        cursor = conn.cursor()

        # Verifica se MAC já existe no registry
        cursor.execute("SELECT ip_atual, contador_movimentacoes FROM mac_registry WHERE mac = ?", (mac,))
        registro = cursor.fetchone()

        if registro:
            ip_anterior = registro[0]
            contador = registro[1]

            # Se mudou de IP, é movimentação DHCP (não troca de hardware)
            if ip_anterior != ip_atual:
                cursor.execute("""UPDATE mac_registry
                                  SET ip_atual = ?, ultimo_visto = ?, contador_movimentacoes = ?, status = ?
                                  WHERE mac = ?""",
                               (ip_atual, agora, contador + 1, 'MOVIMENTADO', mac))
                conn.commit()
                conn.close()
                return ('movimentacao', ip_anterior)
            else:
                # Mesmo IP, só atualiza timestamp
                cursor.execute("UPDATE mac_registry SET ultimo_visto = ? WHERE mac = ?",
                               (agora, mac))
                conn.commit()
                conn.close()
                return ('normal', None)
        else:
            # MAC completamente novo - adicionar ao registry
            cursor.execute("""INSERT INTO mac_registry
                              (mac, nome_dispositivo, ip_atual, primeiro_visto, ultimo_visto, contador_movimentacoes, status)
                              VALUES (?, ?, ?, ?, ?, ?, ?)""",
                           (mac, nome_dispositivo, ip_atual, agora, agora, 0, 'NOVO'))
            conn.commit()
            conn.close()
            return ('novo', None)

    except sqlite3.OperationalError as e:
        if 'database is locked' in str(e):
            print(f"[MAC-REGISTRY-WARN] Banco ocupado, tentando novamente...", flush=True)
            # Retorna normal para não quebrar o fluxo, tenta na próxima varredura
            return ('normal', None)
        print(f"[MAC-REGISTRY-ERROR] Erro operacional: {e}", flush=True)
        return ('normal', None)
    except Exception as e:
        print(f"[MAC-REGISTRY-ERROR] Erro ao atualizar registry: {e}", flush=True)
        return ('normal', None)
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass

def avaliar_situacao_mac(ip, mac_atual, mac_oficial_db, nome_dispositivo):
    """
    Avalia se a situação é:
    - 'ok': Tudo normal
    - 'movimentacao_dhcp': MAC conhecido mudou de IP (não alertar)
    - 'novo_dispositivo': MAC novo ocupou IP vazio (não alertar, só registrar)
    - 'troca_suspeita': MAC antigo sumiu, novo MAC desconhecido apareceu (ALERTAR 1x)
    - 'troca_confirmada': MAC antigo está offline há tempo, novo MAC é permanente (ALERTAR)

    Retorna: (status_str, mac_antigo_suspeito, detalhes_dict)
    """
    global mac_registry, historico_mac_alerta_real

    if mac_atual == "---" or not mac_atual:
        return ('ok', None, {})

    # Atualiza registry e verifica se é movimentação conhecida
    tipo_atualizacao, ip_anterior = atualizar_mac_registry(mac_atual, nome_dispositivo, ip)

    # CASO 1: MAC atual é o mesmo do cadastro = OK
    if mac_oficial_db and mac_oficial_db != "---" and mac_atual.upper() == mac_oficial_db.upper():
        return ('ok', None, {'motivo': 'MAC corresponde ao cadastro'})

    # CASO 2: MAC atual é conhecido (já vimos em outro IP) = Movimentação DHCP
    if tipo_atualizacao == 'movimentacao':
        return ('movimentacao_dhcp', mac_oficial_db, {
            'motivo': f'MAC {mac_atual} mudou de {ip_anterior} para {ip}',
            'ip_anterior': ip_anterior,
            'alertar': False
        })

    # CASO 3: MAC atual é novo (nunca visto), mas IP tem MAC oficial cadastrado
    if mac_oficial_db and mac_oficial_db != "---" and mac_atual.upper() != mac_oficial_db.upper():
        # Verificar se MAC oficial (antigo) está ativo em outro IP
        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT ip_atual FROM mac_registry WHERE mac = ?", (mac_oficial_db,))
            registro_antigo = cursor.fetchone()
            conn.close()

            if registro_antigo:
                ip_atual_do_antigo = registro_antigo[0]
                if ip_atual_do_antigo and ip_atual_do_antigo != ip:
                    # MAC antigo está vivo em outro lugar = DHCP normal
                    return ('novo_dispositivo', mac_oficial_db, {
                        'motivo': f'MAC antigo {mac_oficial_db} está ativo em {ip_atual_do_antigo}',
                        'mac_antigo_online': True,
                        'alertar': False
                    })
        except Exception as e:
            print(f"[AVALIACAO-ERROR] Erro ao verificar MAC antigo: {e}", flush=True)

        # Verificar se já alertamos sobre esta combinação recentemente (24h)
        chave_alerta = f"{ip}_{mac_oficial_db}_{mac_atual}"
        ultimo_alerta = historico_mac_alerta_real.get(chave_alerta)

        if ultimo_alerta:
            tempo_desde_alerta = datetime.now() - ultimo_alerta
            if tempo_desde_alerta < timedelta(hours=24):
                return ('troca_suspeita_silenciosa', mac_oficial_db, {
                    'motivo': 'Troca suspeita, mas já alertamos nas últimas 24h',
                    'alertar': False
                })

        # CASO 4: Troca suspeita de hardware (alertar 1x)
        historico_mac_alerta_real[chave_alerta] = datetime.now()
        return ('troca_suspeita', mac_oficial_db, {
            'motivo': f'MAC antigo {mac_oficial_db} sumiu do IP {ip}, novo MAC {mac_atual} detectado',
            'mac_antigo': mac_oficial_db,
            'mac_novo': mac_atual,
            'alertar': True,
            'severidade': 'ALTA'
        })

    # CASO 5: MAC novo em IP sem cadastro anterior = Novo dispositivo
    return ('novo_dispositivo', None, {
        'motivo': 'Novo MAC em IP sem cadastro anterior',
        'alertar': False
    })

def deve_alertar_troca_hardware(ip, mac_novo, mac_antigo):
    """
    Verifica se deve enviar alerta de troca de hardware (evita spam).
    Retorna True apenas se não alertamos nas últimas 24h para esta combinação.
    """
    global historico_mac_alerta_real

    chave = f"{ip}_{mac_antigo}_{mac_novo}"
    agora = datetime.now()
    ultimo_alerta = historico_mac_alerta_real.get(chave)

    if ultimo_alerta:
        diferenca = agora - ultimo_alerta
        if diferenca < timedelta(hours=24):
            return False  # Já alertamos recentemente

    historico_mac_alerta_real[chave] = agora
    return True

def obter_dispositivos_db():
    max_retries = 3
    for attempt in range(max_retries):
        conn = None
        try:
            # Timeout de 5 segundos para evitar bloqueio indefinido
            conn = sqlite3.connect(DB_NAME, timeout=5.0)
            conn.execute('PRAGMA query_only = ON;')  # Modo somente leitura
            cursor = conn.cursor()
            cursor.execute("""SELECT ip, nome, fabricante, marca, modelo, especificacoes, mac_oficial, tipo
                              FROM config_dispositivos WHERE ignorar = 0""")
            rows = cursor.fetchall()
            conn.close()
            sorted_rows = sorted(rows, key=lambda x: int(x[0].split('.')[-1]))
            return {r[0]: [r[1], r[2], r[3], r[4], r[5], r[6], r[7]] for r in sorted_rows}
        except sqlite3.OperationalError as e:
            if 'database is locked' in str(e) and attempt < max_retries - 1:
                print(f"[DB-RETRY] Tentativa {attempt + 1} falhou, aguardando...", flush=True)
                time.sleep(0.5 * (attempt + 1))  # Backoff exponencial
                continue
            print(f"[DB-ERROR] obter_dispositivos_db: {e}", flush=True)
            return {}  # Retorna dicionário vazio em caso de falha persistente
        except Exception as e:
            print(f"[DB-ERROR] obter_dispositivos_db: {e}", flush=True)
            return {}
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass
    return {}

def identificar_fabricante(mac):
    """
    Identifica o fabricante a partir do MAC address.
    Compatível com versões síncronas e assíncronas da biblioteca mac_vendor_lookup.
    """
    if not mac_identificador or mac == "---":
        return "Desconhecido"

    try:
        resultado = mac_identificador.lookup(mac)

        # Verifica se é uma coroutine (versão async da biblioteca)
        import inspect
        if inspect.iscoroutine(resultado):
            # Executa de forma síncrona
            import asyncio
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # Cria novo loop se necessário
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                return loop.run_until_complete(resultado)
            except Exception:
                return "Fabricante Novo"

        # Versão síncrona retorna string diretamente
        return resultado

    except Exception:
        return "Fabricante Novo"

def varredura_inicial():
    """Varredura Forçada: Obriga todos os dispositivos a se revelarem ao Linux"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM config_dispositivos")
    if cursor.fetchone()[0] <= 18: # Se tiver só os roteadores ou vazio, força busca
        print("\n[SYSTEM] 🛡️ INICIANDO VARREDURA HARDCORE (MODO SCANNER)...", flush=True)

        # Dispara pings em massa (background) para preencher a tabela ARP do Linux
        processos = []
        for i in range(1, 255):
            ip = f"{RANGE_SCAN}{i}"
            # Ping ultra rápido (0.2s de espera) só para o Linux registrar o MAC
            p = subprocess.Popen(["ping", "-c", "1", "-W", "0.2", ip], stdout=subprocess.DEVNULL)
            processos.append(p)

        # Aguarda os pings terminarem
        for p in processos: p.wait()

        # Agora lê a tabela que acabamos de preencher
        vizinhos = get_linux_neighbors()

        for ip, mac in vizinhos.items():
            fab = identificar_fabricante(mac)
            cursor.execute("INSERT OR IGNORE INTO config_dispositivos (ip, nome, fabricante, mac_oficial, ignorar, tipo) VALUES (?,?,?,?,?,?)",
                         (ip, f"Descoberto {ip.split('.')[-1]}", fab, mac, 0, "Outros"))
            print(f"[ACHADO] {ip} -> {fab}")

        conn.commit()
    conn.close()

# ================= FUNÇÕES DE SISTEMA =================

@app.route('/audio/<path:filename>')
def serve_audio(filename):
    return send_from_directory(os.getcwd(), filename)

def enviar_telegram(mensagem):
    msg_final = f"{mensagem}\n\n🔗 [Abrir Sistema]({LINK_ACESSO})"
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": msg_final, "parse_mode": "Markdown"}
    try: requests.post(url, data=payload, timeout=5)
    except: pass

def aviso_desligamento():
    agora = datetime.now().strftime('%d/%m/%Y %H:%M:%S.%f')[:-4]
    enviar_telegram(f"⚠️ **ALERTA: Monitoramento Interrompido!**\nO sistema de Monitoramento de Dispositivos 4.0 em `{IP_SERVIDOR}` parou.\n🗓️ {agora}")

atexit.register(aviso_desligamento)
def signal_handler(sig, frame): sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def get_mac_address(ip):
    try:
        saida = subprocess.check_output(["ip", "neigh", "show", ip] if sys.platform != "win32" else ["arp", "-a", ip], stderr=subprocess.STDOUT).decode()
        mac = re.search(r"(([a-fA-F0-9]{2}[:-]){5}[a-fA-F0-9]{2})", saida)
        return mac.group(0).upper() if mac else "---"
    except: return "---"

def check_dispositivo(ip):
    """Checagem híbrida: Ping + Tabela ARP do Linux"""
    # 1. Tenta o Ping tradicional
    cmd = ["ping", "-c", "1", "-W", "1", ip]
    online = subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    web_ok = False

    # 2. Se o ping falhou, verifica se o IP está na tabela ARP (comum em celulares)
    if not online:
        vizinhos_ativos = get_linux_neighbors()
        if ip in vizinhos_ativos:
            online = True # O dispositivo está na rede, mas bloqueou o ping

    # 3. Se estiver online, tenta checagem Web
    if online:
        try:
            r = requests.get(f"http://{ip}", timeout=2, verify=False)
            if r.status_code: web_ok = True
        except: pass

    return online, web_ok

def tarefa_dispositivo(ip, info_db, resultados):
    # info_db: [nome, fabricante, marca, modelo, espec, mac_oficial, tipo]
    try:
        nome_disp = info_db[0]
        fabricante_db = info_db[1] if len(info_db) > 1 else ""
        tipo_disp = info_db[6] if len(info_db) > 6 else "Outros"
        mac_oficial = info_db[5] if len(info_db) > 5 else "---"
    except Exception as e:
        nome_disp = "Desconhecido"
        fabricante_db = ""
        tipo_disp = "Outros"
        mac_oficial = "---"

    status_rede, web_ok = check_dispositivo(ip)
    vizinhos = get_linux_neighbors()
    mac_atual = vizinhos.get(ip, "---")

    # Usa fabricante do banco se existir, senão identifica pelo MAC atual
    if fabricante_db and fabricante_db.strip():
        fabricante = fabricante_db
    else:
        fabricante = identificar_fabricante(mac_atual) if mac_atual != "---" else "---"

    # NOVO: Lógica inteligente de avaliação de MAC (anti-falso positivo DHCP)
    situacao_mac, mac_antigo_suspeito, detalhes = avaliar_situacao_mac(ip, mac_atual, mac_oficial, nome_disp)

    # Define mac_status baseado na situação (preserva compatibilidade com frontend)
    if situacao_mac == 'ok':
        mac_status = "OK"
    elif situacao_mac == 'movimentacao_dhcp':
        mac_status = "DHCP_NORMAL"  # Novo status: MAC mudou de IP (não é troca)
    elif situacao_mac == 'novo_dispositivo':
        mac_status = "NOVO"  # Novo status: Dispositivo novo na rede
    elif situacao_mac in ('troca_suspeita', 'troca_suspeita_silenciosa'):
        mac_status = "TROCA_SUSPEITA"  # Alterado de "ALTERADO" para mais específico
    else:
        mac_status = "OK"

    # HORA ATUAL - ADICIONADO PARA CORRIGIR "undefined"
    hora_atual = datetime.now().strftime("%H:%M:%S")

    res = {
        "status": "ONLINE" if status_rede else "OFFLINE",
        "web": "OK" if web_ok else "FALHA",
        "nome": nome_disp,
        "tipo": tipo_disp,
        "fabricante": fabricante,
        "mac": mac_atual,
        "mac_oficial": mac_oficial,
        "mac_status": mac_status,
        "latencia": "---",
        "erro": not status_rede,
        "hora": hora_atual,
        # NOVOS CAMPOS (não afetam frontend existente):
        "_situacao_mac": situacao_mac,
        "_mac_antigo_suspeito": mac_antigo_suspeito,
        "_detalhes_mac": detalhes
    }

    with lock:
        status_atual[ip] = res
        resultados[ip] = res

def verificar_rede():
    global status_atual
    agora_timestamp = datetime.now().strftime('%d/%m/%Y %H:%M:%S')

    print(f"\n{'='*80}\n[VARREDURA ATIVA] Iniciando busca hardcore (Paridade Advanced IP Scanner)\n{'='*80}", flush=True)
    socketio.emit('status_varredura', {'msg': 'Escaneando rede...'})

    # Varredura de Ping para popular tabela ARP
    processos_ping = []
    for i in range(1, 255):
        ip_teste = f"{RANGE_SCAN}{i}"
        p = subprocess.Popen(["ping", "-c", "1", "-W", "0.2", ip_teste],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processos_ping.append(p)

    for p in processos_ping: p.wait()

    # Captura vizinhos da tabela ARP
    vizinhos_detectados = get_linux_neighbors()

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        for ip_v, mac_v in vizinhos_detectados.items():
            fab_v = identificar_fabricante(mac_v)
            cursor.execute("""INSERT OR IGNORE INTO config_dispositivos
                              (ip, nome, fabricante, mac_oficial, ignorar, tipo)
                              VALUES (?, ?, ?, ?, 0, 'Outros')""",
                           (ip_v, f"Descoberto {ip_v.split('.')[-1]}", fab_v, mac_v))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB-ERROR] Erro ao atualizar novos dispositivos: {e}")

    dispositivos_para_monitorar = obter_dispositivos_db()

    with lock:
        ips_atuais = list(status_atual.keys())
        for ip in ips_atuais:
            if ip not in dispositivos_para_monitorar:
                del status_atual[ip]

    resultados_agora = {}
    threads = []
    for ip, info in dispositivos_para_monitorar.items():
        t = threading.Thread(target=tarefa_dispositivo, args=(ip, info, resultados_agora))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # Lógica de Notificação e Histórico
    falhas, voltaram, alertas_mac = [], [], []
    for ip in dispositivos_para_monitorar:
        if ip in resultados_agora:
            erro_agora = resultados_agora[ip]["erro"]
            erro_antes = historico_falhas_python.get(ip, False)

            if erro_agora and not erro_antes:
                falhas.append(f"🔴 {dispositivos_para_monitorar[ip][0]} ({ip})")
            elif not erro_agora and erro_antes:
                voltaram.append(f"✅ {dispositivos_para_monitorar[ip][0]} ({ip})")

            historico_falhas_python[ip] = erro_agora

            # Lógica de alerta MAC inteligente (anti-spam DHCP)
            situacao = resultados_agora[ip].get("_situacao_mac", "ok")
            detalhes = resultados_agora[ip].get("_detalhes_mac", {})

            if situacao == "troca_suspeita" and detalhes.get("alertar", False):
                mac_antigo = detalhes.get("mac_antigo", "desconhecido")
                mac_novo = detalhes.get("mac_novo", resultados_agora[ip]["mac"])

                if deve_alertar_troca_hardware(ip, mac_novo, mac_antigo):
                    alertas_mac.append(
                        f"⚠️ **TROCA DE HARDWARE DETECTADA:** {dispositivos_para_monitorar[ip][0]} ({ip})\n"
                        f"   MAC anterior: `{mac_antigo}`\n"
                        f"   MAC novo: `{mac_novo}`\n"
                        f"   Motivo: {detalhes.get('motivo', 'Troca suspeita')}"
                    )
                    historico_mac_alerta[ip] = True
            elif situacao == "movimentacao_dhcp":
                # Movimentação DHCP normal - não alertar, só log silencioso
                historico_mac_alerta[ip] = False
            elif situacao == "novo_dispositivo":
                # Novo dispositivo - não alertar como troca de hardware
                historico_mac_alerta[ip] = False
            else:
                historico_mac_alerta[ip] = False


    #if falhas: enviar_telegram(f"🚨 **FALHA** - {agora_timestamp}\n" + "\n".join(falhas))
    #if voltaram: enviar_telegram(f"🟢 **OK** - {agora_timestamp}\n" + "\n".join(voltaram))
    #if alertas_mac: enviar_telegram(f"🛡️ **AUDITORIA** - {agora_timestamp}\n" + "\n".join(alertas_mac))

    # Mantendo suas funções de Log e Saúde intactas
    salvar_log_completo(status_atual, dispositivos_para_monitorar)
    dados_saude = analisar_saude_sistema()
    # Garante que o Socket emita o valor correto para o Front-end
    socketio.emit('atualizar_saude', dados_saude)

    # ADIÇÃO DA REGRA DE ORDENAÇÃO (SEM COMPACTAR O QUE JÁ EXISTIA)
    def criterio_prioridade(ip_chave):
        info = status_atual[ip_chave]
        # Peso 1: OFFLINE/FALHA (Topo)
        if info['status'] == 'OFFLINE':
            prio = 1
        # Peso 2: ONLINE/FALHA (Meio)
        elif info['web'] == 'FALHA':
            prio = 2
        # Peso 3: ONLINE/OK (Base)
        else:
            prio = 3

        # IP para ordenação secundária (zfill garante que 192.168.0.2 venha antes de 10)
        ip_ordenavel = "".join(part.zfill(3) for part in ip_chave.split('.'))
        return (prio, ip_ordenavel)

    lista_ips_ordenados = sorted(status_atual.keys(), key=criterio_prioridade)

    # Convertendo para lista de dicionários para preservar a ordem no SocketIO
    dados_ordenados_lista = []
    for ip_ord in lista_ips_ordenados:
        dict_item = status_atual[ip_ord].copy()
        dict_item['ip'] = ip_ord
        dados_ordenados_lista.append(dict_item)

    socketio.emit('atualizar_dados', {
        'dados': dados_ordenados_lista,
        'total_ips': len(dispositivos_para_monitorar),
        'total_ips_cadastrados': len(dispositivos_para_monitorar),
        'saude': status_sistema_global
    })

    print(f"{'='*80}\n[VARREDURA CONCLUÍDA] Status: {len(dispositivos_para_monitorar)} monitorados.\n{'='*80}\n", flush=True)

def salvar_log_completo(dados_loop, config_db):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        agora = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        for ip, info in dados_loop.items():
            # Grava o log de status normal
            cursor.execute("""INSERT INTO logs_status
                            (timestamp, ip, nome, status, web, mac, mac_status)
                            VALUES (?, ?, ?, ?, ?, ?, ?)""",
                         (agora, ip, info['nome'], info['status'], info['web'], info['mac'], info['mac_status']))

            # GRAVAÇÃO NA AUDITORIA: Apenas para situações reais de troca ou novos dispositivos
            situacao = info.get("_situacao_mac", "ok")
            deve_gravar_auditoria = False
            mac_antigo_auditoria = info['mac_oficial']
            mac_novo_auditoria = info['mac']

            if situacao == "troca_suspeita":
                deve_gravar_auditoria = True
            elif situacao == "movimentacao_dhcp":
                # Gravar como movimentação (não é troca de hardware)
                deve_gravar_auditoria = True
                mac_antigo_auditoria = info.get("_mac_antigo_suspeito", info['mac_oficial'])
            elif situacao == "novo_dispositivo" and info['mac'] != "---":
                # Novo dispositivo detectado
                deve_gravar_auditoria = True
                mac_antigo_auditoria = None  # Não tinha MAC anterior

            if deve_gravar_auditoria and info['mac'] != "---":
                # Verifica se já não registramos este evento exato recentemente (evita duplicatas)
                cursor.execute("""SELECT mac_novo FROM auditoria_hardware
                                  WHERE ip = ? AND mac_novo = ? AND timestamp > datetime('now', '-1 hour')
                                  ORDER BY id DESC LIMIT 1""",
                               (ip, info['mac']))
                ultimo_evento = cursor.fetchone()

                if not ultimo_evento:
                    # Busca dados do banco para auditoria
                    cursor.execute("SELECT nome, fabricante, modelo FROM config_dispositivos WHERE ip = ?", (ip,))
                    db_row = cursor.fetchone()
                    if db_row:
                        nome_setor = db_row[0]
                        fab_antigo = db_row[1]
                        modelo_antigo = db_row[2]
                    else:
                        nome_setor = info['nome']
                        fab_antigo = info['fabricante']
                        modelo_antigo = ""

                    # INSERE SEM tipo_evento (compatibilidade com banco existente)
                    cursor.execute("""INSERT INTO auditoria_hardware
                                    (timestamp, ip, nome_setor, fabricante_antigo, modelo_antigo, mac_antigo, mac_novo)
                                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                                  (agora, ip, nome_setor, fab_antigo, modelo_antigo,
                                   mac_antigo_auditoria if mac_antigo_auditoria else "N/A",
                                   mac_novo_auditoria))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[AUDITORIA-ERROR] ❌ Erro ao gravar: {e}", flush=True)

def analisar_saude_sistema():
    """
    Analisa a saúde do sistema v5.2 - Refletindo o espaço real do SSD.
    """
    try:
        caminho_projeto = os.path.dirname(os.path.abspath(__file__))
        total, usado, livre = shutil.disk_usage(caminho_projeto)

        # Agora a saúde será EXATAMENTE a porcentagem livre do disco
        percentual_livre = float((livre / total) * 100)
        livre_gb = float(livre / (1024**3))
        tamanho_db_mb = float(os.path.getsize(DB_NAME) / (1024 * 1024)) if os.path.exists(DB_NAME) else 0.0

        # A saúde reflete o hardware. Se o banco passar do limite, tiramos uma penalidade pequena.
        saude_final = percentual_livre

        if tamanho_db_mb > float(LIMITE_ALERTA_DB_MB):
            saude_final -= 5.0 # Penalidade fixa por banco grande

        saude_final = max(0.0, min(100.0, saude_final))

        global status_sistema_global
        status_sistema_global["risco_percent"] = round(saude_final, 2)
        status_sistema_global["uso_db_ms"] = round(tamanho_db_mb, 2)

        return {
            "saude_percentual": round(saude_final, 2),
            "risco_percent": round(saude_final, 2),
            "tamanho_db_mb": round(tamanho_db_mb, 2),
            "percentual_disco_livre": round(percentual_livre, 2)
        }
    except Exception as e:
        print(f"[ERRO-SAUDE] {e}")
        return {"saude_percentual": 0.0, "risco_percent": 0.0}

@app.route('/exportar/<formato>')
def exportar_dados(formato):
    df_dados = []
    with lock:
        for ip, info in status_atual.items():
            df_dados.append({
                "IP": ip,
                "Setor": info.get('nome', '---'),
                "Tipo": info.get('tipo', '---'),
                "Fabricante": info.get('fabricante', '---'),
                "Status": info.get('status', '---'),
                "Web": info.get('web', '---'),
                "MAC": info.get('mac', '---')
            })

    df = pd.DataFrame(df_dados)
    data_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"monitor_rede_{data_str}"

    if formato == "json":
        return jsonify(df_dados)

    if formato == "txt":
        path = f"{filename}.txt"
        df.to_csv(path, sep='\t', index=False)
        return send_file(path, as_attachment=True)

    if formato == "excel":
        path = f"{filename}.xlsx"
        df.to_excel(path, index=False)
        return send_file(path, as_attachment=True)

    if formato == "pdf":
        path = f"{filename}.pdf"
        doc = SimpleDocTemplate(path, pagesize=landscape(letter))
        elements = []
        # Converte DataFrame para lista de listas para a tabela do PDF
        data = [df.columns.tolist()] + df.values.tolist()
        t = Table(data)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.blue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(t)
        doc.build(elements)
        return send_file(path, as_attachment=True)

    return "Formato Inválido", 400

# ================= TEMPLATES HTML =================

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <title>Monitor de Rede Profissional 4.0</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
<style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f0f2f5; margin: 0; padding: 20px; }
        .container { max-width: 1400px; margin: auto; background: white; padding: 20px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #eee; padding-bottom: 15px; margin-bottom: 20px; }
        .live-status { display: flex; align-items: center; gap: 10px; font-weight: bold; color: #2e7d32; }
        .dot { height: 10px; width: 10px; background-color: #2e7d32; border-radius: 50%; display: inline-block; animation: blink 1s infinite; }
        @keyframes blink { 0% { opacity: 1; } 50% { opacity: 0.3; } 100% { opacity: 1; } }
        .cronometro-box { color: #d32f2f; font-size: 14px; margin-left: 5px; }
        .menu-links { display: flex; gap: 10px; margin-bottom: 20px; }
        .menu-links a { text-decoration: none; color: white; background: #1a237e; padding: 10px 15px; border-radius: 6px; font-size: 13px; font-weight: bold; transition: 0.3s; }
        .menu-links a:hover { background: #303f9f; }

/* Estilos dos Filtros */
        .filter-group { display: flex; gap: 10px; margin-bottom: 5px; background: #e8eaf6; padding: 12px; border-radius: 8px; align-items: center; }
        .btn-filter { padding: 10px 15px; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; color: white; font-size: 12px; transition: 0.3s; opacity: 0.6; }
        .btn-filter.active { opacity: 1; box-shadow: 0 4px 10px rgba(0,0,0,0.3); transform: scale(1.05); }
        .btn-ok { background-color: #2e7d32 !important; }
        .btn-aviso { background-color: #fbc02d !important; color: black !important; }
        .btn-offline { background-color: #d32f2f !important; }
        .btn-todos { background-color: #1a237e !important; }

        /* ESTILO DO SELECT - CONTRASTE MÁXIMO */
        .label-filtro { font-weight: bold; color: #1a237e; font-size: 13px; margin-right: 5px; }
        .select-tipo {
            padding: 10px 15px;
            border: 2px solid #1a237e;
            border-radius: 6px;
            background-color: #1a237e; /* Fundo Azul Escuro */
            color: #ffffff;            /* Texto Branco */
            font-weight: bold;
            font-size: 12px;
            cursor: pointer;
            outline: none;
            min-width: 250px;
        }
        .select-tipo option {
            background-color: #ffffff;
            color: #333333;
        }

        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th { background-color: #1a237e; color: white; padding: 12px; text-align: left; font-size: 14px; position: sticky; top: 0; cursor: pointer; }
        td { padding: 10px; border-bottom: 1px solid #eee; font-size: 13px; }
        tr:hover { background-color: #f5f5f5; }
        .ONLINE { color: #2e7d32; font-weight: bold; }
        .OFFLINE { color: #d32f2f; font-weight: bold; }
        .status-badge { padding: 4px 8px; border-radius: 4px; font-size: 11px; text-transform: uppercase; }
        .bg-ok { background: #e8f5e9; color: #2e7d32; }
        .bg-error { background: #ffebee; color: #c62828; }
        .mac-alert { background: #d32f2f; color: white; padding: 2px 5px; border-radius: 3px; font-weight: bold; }
        .footer-info { margin-top: 20px; padding-top: 15px; border-top: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; font-size: 12px; color: #666; }
        .export-buttons { display: flex; gap: 5px; align-items: center; }
        .btn-export { background: #455a64; color: white; padding: 6px 12px; border-radius: 4px; text-decoration: none; font-weight: bold; font-size: 11px; }
        .btn-export:hover { background: #37474f; }

        #Compatibilizar com a versão do monitor_rede_v2.py
        /* CLASSES PARA ALERTA DE MAC ALTERADO - COPIADAS DO V2 */
        .MAC-ALERTA {
            color: #ffffff;
            background-color: #d32f2f;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            display: inline-block;
        }
        .btn-fix {
            background: #fff;
            color: #d32f2f;
            border: 1px solid #d32f2f;
            padding: 2px 5px;
            cursor: pointer;
            border-radius: 3px;
            font-size: 10px;
            margin-left: 5px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .btn-fix:hover {
            background: #d32f2f;
            color: #fff;
        }
        .linha-critica {
            background-color: #fff5f5 !important;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1 style="margin:0; color:#1a237e;">Monitor de Rede Profissional 3.0</h1>
                <div class="live-status">
                    <span class="dot"></span>
                    MONITORAMENTO EM TEMPO REAL
                    <span class="cronometro-box">(Próxima atualização em: <span id="tempo-restante">30</span>s)</span>
                </div>
            </div>
            <div style="text-align: right;">
                <div id="relogio" style="font-size: 18px; font-weight: bold; color: #333;">00:00:00</div>
                <div id="info-sistema" style="font-size: 11px; color: #7f8c8d;">Sincronizando...</div>
            </div>
        </div>

        <div class="menu-links">
            <a href="/">DASHBOARD</a>
            <a href="/relatorios">RELATÓRIOS BI</a>
            <a href="/config">CONFIGURAÇÕES</a>
            <a href="/auditoria_detalhada">AUDITORIA MAC</a>
            <a href="/manutencao_logs">MANUTENÇÃO</a>
        </div>

        <div class="filter-group">
            <button class="btn-filter btn-todos active" onclick="setFiltroStatus('TODOS', this)">TODOS</button>
            <button class="btn-filter btn-ok" onclick="setFiltroStatus('OK', this)">🟢 ONLINE & OK</button>
            <button class="btn-filter btn-aviso" onclick="setFiltroStatus('AVISO', this)">🟡 ONLINE & FALHA</button>
            <button class="btn-filter btn-offline" onclick="setFiltroStatus('OFFLINE', this)">🔴 OFFLINE</button>
        </div>

        <div class="filter-group" style="margin-top: 10px;">
            <span class="label-filtro">FILTRAR POR TIPO:</span>
            <select id="select-filtro-tipo" class="select-tipo" onchange="setFiltroTipo(this.value)">
                <option value="Todos">Exibir Todos os Tipos</option>
                {% for tipo in tipos %}
                <option value="{{tipo}}">{{tipo}}</option>
                {% endfor %}
            </select>
        </div>

        <table id="tabela-dispositivos">
            <thead>
                <tr>
                    <th onclick="sortTable(0)">IP</th>
                    <th onclick="sortTable(1)">Setor / Nome</th>
                    <th onclick="sortTable(2)">Tipo</th>
                    <th onclick="sortTable(3)">Fabricante</th>
                    <th onclick="sortTable(4)">Status</th>
                    <th onclick="sortTable(5)">Web (80/443)</th>
                    <th onclick="sortTable(6)">Endereço MAC</th>
                    <th onclick="sortTable(7)">Última Atualização</th>
                </tr>
            </thead>
            <tbody id="corpo-tabela">
                </tbody>
        </table>

        <div class="footer-info">
            <div class="export-buttons">
                <span style="margin-right:10px; font-weight:bold;">EXPORTAR:</span>
                <a href="/exportar/txt" class="btn-export">TXT</a>
                <a href="/exportar/excel" class="btn-export">EXCEL</a>
                <a href="/exportar/pdf" class="btn-export">PDF</a>
                <a href="/exportar/json" class="btn-export">JSON</a>
            </div>
            <div id="estatisticas">
                Dispositivos: <span id="total-ips">0</span> | Saúde do Banco: <span id="db-saude">0%</span>
            </div>
        </div>
    </div>

    <script>
        var socket = io();
        var filtroStatusAtual = 'TODOS';
        var filtroTipoAtual = 'Todos';
        var dadosUltimos = [];
        var contagemRegressiva = 30;
        window.totalIpsCadastrados = 0;

        // Função de Filtro por Status
        function setFiltroStatus(status, btn) {
            filtroStatusAtual = status;
            btn.parentElement.querySelectorAll('.btn-filter').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            renderizarTabela();
        }

        // Função de Filtro por Tipo (Adaptada para Select)
        function setFiltroTipo(valor) {
            filtroTipoAtual = valor;
            // Como é um select, não precisamos gerenciar classe 'active' em botões aqui
            renderizarTabela();
        }

        // Sincronização do Cronômetro com o Backend
        socket.on('reset_cronometro', function(msg) {
            contagemRegressiva = msg.segundos;
            document.getElementById('tempo-restante').innerText = contagemRegressiva;
        });

        // Lógica do Cronômetro Visual (1 segundo)
        setInterval(function() {
            if (contagemRegressiva > 0) {
                contagemRegressiva--;
                document.getElementById('tempo-restante').innerText = contagemRegressiva;
            }
        }, 1000);

        // Atualização dos dados e renderização
        socket.on('atualizar_dados', function(msg) {
            dadosUltimos = msg.dados;
            window.totalIpsCadastrados = msg.total_ips_cadastrados || msg.total_ips;
            document.getElementById('db-saude').innerText = msg.saude.risco_percent + '%';
            document.getElementById('info-sistema').innerText = 'Tamanho DB: ' + msg.saude.tamanho_mb + 'MB | Resposta: ' + msg.saude.uso_db_ms + 'ms';
            renderizarTabela();
        });

        function renderizarTabela() {
            const corpo = document.getElementById('corpo-tabela');
            corpo.innerHTML = '';

            var contadorVisiveis = 0;

            dadosUltimos.forEach(function(info) {
                var ip = info.ip;

                var atendeStatus = false;
                if (filtroStatusAtual === 'TODOS') atendeStatus = true;
                else if (filtroStatusAtual === 'OK' && info.status === 'ONLINE' && info.web === 'OK') atendeStatus = true;
                else if (filtroStatusAtual === 'AVISO' && info.status === 'ONLINE' && info.web === 'FALHA') atendeStatus = true;
                else if (filtroStatusAtual === 'OFFLINE' && info.status === 'OFFLINE') atendeStatus = true;

                var atendeTipo = (filtroTipoAtual === 'Todos' || info.tipo === filtroTipoAtual);

                if (atendeStatus && atendeTipo) {
                    contadorVisiveis++;

                    // LÓGICA DO MAC COM BOTÃO "TORNAR PADRÃO" - ADAPTADA DO V2
                    let displayMac = info.mac;
                    if(info.mac_status === 'ALTERADO') {
                        displayMac = `<div class="MAC-ALERTA">⚠️ TROCADO: ${info.mac} <button class="btn-fix" onclick="tornarPadrao('${ip}', '${info.mac}')">Tornar Padrão</button></div>`;
                    }

                    // DESTACAR LINHA CRÍTICA (OFFLINE) - ADAPTADO DO V2
                    let classeLinha = '';
                    if(info.status === 'OFFLINE') {
                        classeLinha = 'class="linha-critica"';
                    }

                    var row = `<tr ${classeLinha}>` +
                        '<td><a href="http://' + ip + '" target="_blank" style="color:#1a237e; font-weight:bold; text-decoration:none;">' + ip + '</a></td>' +
                        '<td>' + info.nome + '</td>' +
                        '<td>' + info.tipo + '</td>' +
                        '<td>' + info.fabricante + '</td>' +
                        '<td class="' + info.status + '">' + info.status + '</td>' +
                        '<td><span class="status-badge ' + (info.web === 'OK' ? 'bg-ok' : 'bg-error') + '">' + info.web + '</span></td>' +
                        '<td>' + displayMac + '</td>' +
                        '<td>' + info.hora + '</td>' +
                    '</tr>';
                    corpo.innerHTML += row;
                }
            });

            // ATUALIZAR CONTADOR NO RODAPÉ COM FORMATO "X de Y"
            var totalCadastrados = window.totalIpsCadastrados || dadosUltimos.length;
            document.getElementById('total-ips').innerText = contadorVisiveis + ' de ' + totalCadastrados;
        }

        setInterval(function() {
            document.getElementById('relogio').innerText = new Date().toLocaleTimeString();
        }, 1000);

        function sortTable(n) {
            var table, rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
            table = document.getElementById("tabela-dispositivos");
            switching = true; dir = "asc";
            while (switching) {
                switching = false; rows = table.rows;
                for (i = 1; i < (rows.length - 1); i++) {
                    shouldSwitch = false;
                    x = rows[i].getElementsByTagName("TD")[n];
                    y = rows[i+1].getElementsByTagName("TD")[n];
                    if (dir == "asc") {
                        if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) { shouldSwitch = true; break; }
                    } else {
                        if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) { shouldSwitch = true; break; }
                    }
                }
                if (shouldSwitch) { rows[i].parentNode.insertBefore(rows[i + 1], rows[i]); switching = true; switchcount ++; }
                else { if (switchcount == 0 && dir == "asc") { dir = "desc"; switching = true; } }
            }
        }

        function tornarPadrao(ip, novoMac) {
            if(confirm("Deseja tornar " + novoMac + " o novo padrão para o IP " + ip + "?")) {
                fetch('/api/fix_mac', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ip: ip, mac: novoMac})
                }).then(r => r.json()).then(d => {
                    alert(d.msg);
                });
            }
        }

    </script>
</body>
</html>
"""

@app.route('/relatorios')
def relatorios():
    """Menu principal de relatórios - Apresentação dos 12 gráficos disponíveis"""
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="pt-br">
    <head>
        <title>BI: Menu de Relatórios - 12 Indicadores Estratégicos</title>
        <style>
            body {
                font-family: 'Segoe UI', sans-serif;
                background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
                padding: 20px;
                color: #333;
                margin: 0;
                min-height: 100vh;
            }
            .dashboard-header {
                text-align: center;
                margin-bottom: 40px;
                padding: 30px;
                background: linear-gradient(135deg, #1a237e 0%, #283593 100%);
                color: white;
                border-radius: 15px;
                box-shadow: 0 10px 30px rgba(26,35,126,0.3);
            }
            .dashboard-header h1 {
                margin: 0;
                font-size: 2.5em;
                text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
            }
            .dashboard-header p {
                margin: 15px 0 0 0;
                opacity: 0.9;
                font-size: 1.1em;
            }
            .btn-back {
                text-decoration: none;
                color: white;
                background: #d32f2f;
                padding: 12px 25px;
                border-radius: 25px;
                font-weight: bold;
                display: inline-block;
                margin-bottom: 30px;
                transition: 0.3s;
                box-shadow: 0 4px 15px rgba(211,47,47,0.3);
            }
            .btn-back:hover {
                background: #b71c1c;
                transform: translateY(-2px);
            }
            .grid-menu {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
                gap: 25px;
                max-width: 1400px;
                margin: 0 auto;
            }
            .card-menu {
                background: white;
                padding: 25px;
                border-radius: 12px;
                box-shadow: 0 5px 20px rgba(0,0,0,0.08);
                transition: all 0.3s ease;
                border-left: 5px solid #1a237e;
                position: relative;
                overflow: hidden;
            }
            .card-menu:hover {
                transform: translateY(-5px);
                box-shadow: 0 15px 40px rgba(0,0,0,0.15);
            }
            .card-menu::before {
                content: attr(data-num);
                position: absolute;
                top: -10px;
                right: -10px;
                width: 60px;
                height: 60px;
                background: #e8eaf6;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 1.5em;
                font-weight: bold;
                color: #1a237e;
                opacity: 0.3;
            }
            .card-menu h3 {
                color: #1a237e;
                margin: 0 0 15px 0;
                font-size: 1.3em;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .icon { font-size: 1.5em; }
            .descricao {
                color: #555;
                font-size: 0.95em;
                line-height: 1.6;
                margin-bottom: 15px;
            }
            .tecnico {
                background: #f5f5f5;
                padding: 12px;
                border-radius: 8px;
                font-size: 0.85em;
                color: #666;
                margin-bottom: 15px;
                border-left: 3px solid #fbc02d;
            }
            .tecnico strong { color: #1a237e; }
            .dica {
                background: #e8f5e9;
                padding: 10px;
                border-radius: 6px;
                font-size: 0.8em;
                color: #2e7d32;
                margin-bottom: 15px;
                display: flex;
                align-items: center;
                gap: 8px;
            }
            .btn-grafico {
                text-decoration: none;
                color: white;
                background: linear-gradient(135deg, #2e7d32 0%, #1b5e20 100%);
                padding: 12px 20px;
                border-radius: 8px;
                font-weight: bold;
                display: inline-block;
                transition: 0.3s;
                text-align: center;
                width: 100%;
                box-sizing: border-box;
                border: none;
                cursor: pointer;
                font-size: 1em;
            }
            .btn-grafico:hover {
                background: linear-gradient(135deg, #1b5e20 0%, #2e7d32 100%);
                transform: scale(1.02);
            }
            .categoria {
                grid-column: 1 / -1;
                background: #1a237e;
                color: white;
                padding: 15px 25px;
                border-radius: 10px;
                margin-top: 20px;
                font-weight: bold;
                font-size: 1.2em;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            @media (max-width: 768px) {
                .grid-menu { grid-template-columns: 1fr; }
                .dashboard-header h1 { font-size: 1.8em; }
            }
        </style>
    </head>
    <body>
        <div class="dashboard-header">
            <h1>📊 Business Intelligence - Infraestrutura</h1>
            <p>Selecione um dos 12 indicadores estratégicos para visualização detalhada</p>
        </div>

        <div style="text-align: center;">
            <a href="/" class="btn-back">⬅ Voltar ao Painel Operacional</a>
        </div>

        <div class="grid-menu">

            <div class="categoria">🎯 Visão Geral de Disponibilidade (SLA)</div>

            <div class="card-menu" data-num="01">
                <h3><span class="icon">📈</span> 1. Disponibilidade por Dispositivo (SLA %)</h3>
                <div class="descricao">
                    Mostra o percentual de tempo que cada dispositivo permaneceu online nos últimos dias.
                    Fundamental para identificar equipamentos críticos que precisam de atenção imediata.
                </div>
                <div class="tecnico">
                    <strong>Cálculo:</strong> <code>SUM(ONLINE) / COUNT(*) * 100</code> agrupado por IP.<br>
                    <strong>Fonte:</strong> Tabela <code>logs_status</code> JOIN <code>config_dispositivos</code>.
                </div>
                <div class="dica">💡 <strong>Dica:</strong> Dispositivos abaixo de 95% devem ser priorizados para manutenção.</div>
                <a href="/grafico_sla" class="btn-grafico">📊 Ir Para o Gráfico</a>
            </div>

            <div class="card-menu" data-num="04">
                <h3><span class="icon">🏷️</span> 4. Distribuição de Marcas no Inventário</h3>
                <div class="descricao">
                    Visualização da diversidade de fabricantes na sua rede.
                    Ajuda a identificar dependência excessiva de determinadas marcas.
                </div>
                <div class="tecnico">
                    <strong>Cálculo:</strong> Contagem de dispositivos agrupada por <code>fabricante</code>.<br>
                    <strong>Fonte:</strong> Tabela <code>config_dispositivos</code> (exclui ignorados).
                </div>
                <div class="dica">💡 <strong>Dica:</strong> Diversificar fabricantes reduz riscos de falhas em cascata por bugs específicos.</div>
                <a href="/grafico_fabricantes" class="btn-grafico">📊 Ir Para o Gráfico</a>
            </div>

            <div class="card-menu" data-num="09">
                <h3><span class="icon">🎯</span> 9. Disponibilidade por Tipo de Equipamento</h3>
                <div class="descricao">
                    Análise de SLA agrupada por categoria (Roteador, Switch, Desktop, etc).
                    Permite identificar se problemas são generalizados ou específicos de tipos.
                </div>
                <div class="tecnico">
                    <strong>Cálculo:</strong> Média de uptime por <code>tipo</code> de dispositivo.<br>
                    <strong>Fonte:</strong> JOIN entre <code>logs_status</code> e <code>config_dispositivos</code>.
                </div>
                <div class="dica">💡 <strong>Dica:</strong> Se "Desktops" têm SLA baixo, pode indicar problema elétrico localizado.</div>
                <a href="/grafico_sla_tipo" class="btn-grafico">📊 Ir Para o Gráfico</a>
            </div>

            <div class="categoria">⚡ Análise de Desempenho e Confiabilidade</div>

            <div class="card-menu" data-num="07">
                <h3><span class="icon">⏱️</span> 7. Ranking de Falhas por Dispositivo</h3>
                <div class="descricao">
                    Lista os dispositivos que mais falharam (ficaram OFFLINE) no período.
                    Prioriza investimentos em substituição preventiva.
                </div>
                <div class="tecnico">
                    <strong>Cálculo:</strong> Contagem de registros <code>status='OFFLINE'</code> por IP.<br>
                    <strong>Fonte:</strong> Tabela <code>logs_status</code> com <code>LIMIT 15</code>.
                </div>
                <div class="dica">💡 <strong>Dica:</strong> Equipamentos no topo desta lista devem ser substituídos prioritariamente.</div>
                <a href="/grafico_falhas" class="btn-grafico">📊 Ir Para o Gráfico</a>
            </div>

            <div class="card-menu" data-num="08">
                <h3><span class="icon">⚡</span> 8. Top 10 - Dispositivos com Mais Falhas</h3>
                <div class="descricao">
                    Versão concentrada do ranking anterior, mostrando apenas os 10 piores.
                    Ideal para apresentações executivas rápidas.
                </div>
                <div class="tecnico">
                    <strong>Cálculo:</strong> Mesmo do item 7, mas com <code>LIMIT 10</code>.<br>
                    <strong>Visual:</strong> Gráfico de barras verticais para impacto visual imediato.
                </div>
                <div class="dica">💡 <strong>Dica:</strong> Use este gráfico em relatórios gerenciais mensais.</div>
                <a href="/grafico_top10_falhas" class="btn-grafico">📊 Ir Para o Gráfico</a>
            </div>

            <div class="card-menu" data-num="11">
                <h3><span class="icon">🏭</span> 11. Comparativo de Confiabilidade por Fabricante</h3>
                <div class="descricao">
                    Ranking de SLA por marca.
                    Suporte crucial para decisões de compra e negociação com fornecedores.
                </div>
                <div class="tecnico">
                    <strong>Cálculo:</strong> Média de uptime por <code>fabricante</code> com contagem de dispositivos.<br>
                    <strong>Cor:</strong> Vermelho (&lt;90%), Amarelo (90-95%), Verde (&gt;95%).
                </div>
                <div class="dica">💡 <strong>Dica:</strong> Use dados deste gráfico para renegociar contratos ou justificar mudança de fornecedor.</div>
                <a href="/grafico_sla_fabricante" class="btn-grafico">📊 Ir Para o Gráfico</a>
            </div>

            <div class="categoria">🔥 Padrões de Falha e Incidentes</div>

            <div class="card-menu" data-num="12">
                <h3><span class="icon">🔥</span> 12. Matriz de Indisponibilidade - Heatmap</h3>
                <div class="descricao">
                    Mapa de calor cruzando dia da semana vs hora do dia.
                    Revela padrões ocultos de instabilidade (ex: "sextas às 18h").
                </div>
                <div class="tecnico">
                    <strong>Cálculo:</strong> Contagem de falhas <code>GROUP BY dia_semana, hora</code>.<br>
                    <strong>Visual:</strong> Scatter plot com intensidade de cor = volume de falhas.
                </div>
                <div class="dica">💡 <strong>Dica:</strong> Padrões horários indicam problemas de carga (ex: horário de pico) ou automações agendadas.</div>
                <a href="/grafico_heatmap" class="btn-grafico">📊 Ir Para o Gráfico</a>
            </div>

            <div class="card-menu" data-num="10">
                <h3><span class="icon">⚠️</span> 10. Falhas em Cascata (Incidentes de Infraestrutura)</h3>
                <div class="descricao">
                    Detecta momentos onde 3+ dispositivos caíram simultaneamente.
                    Indica problemas de infraestrutura (energia, switch core) vs falhas isoladas.
                </div>
                <div class="tecnico">
                    <strong>Cálculo:</strong> Agrupamento por minuto com <code>HAVING COUNT(DISTINCT ip) >= 3</code>.<br>
                    <strong>Severidade:</strong> Crítico (10+), Alto (5-9), Médio (3-4).
                </div>
                <div class="dica">💡 <strong>Dica:</strong> Incidentes frequentes no mesmo horário sugerem necessidade de nobreak/estabilizador.</div>
                <a href="/grafico_cascata" class="btn-grafico">📊 Ir Para o Gráfico</a>
            </div>

            <div class="card-menu" data-num="03">
                <h3><span class="icon">📊</span> 3. Estabilidade da Rede (Volume de Logs/Dia)</h3>
                <div class="descricao">
                    Linha do tempo mostrando quantidade de registros gerados por dia.
                    Picos indicam instabilidade generalizada na rede.
                </div>
                <div class="tecnico">
                    <strong>Cálculo:</strong> <code>COUNT(*)</code> agrupado por <code>DATE(timestamp)</code>.<br>
                    <strong>Limit:</strong> Últimos 7 dias para foco em tendência recente.
                </div>
                <div class="dica">💡 <strong>Dica:</strong> Pico súbito pode indicar ataque de rede ou loop de broadcast.</div>
                <a href="/grafico_volume" class="btn-grafico">📊 Ir Para o Gráfico</a>
            </div>

            <div class="categoria">🛡️ Governança de Ativos e Auditoria</div>

            <div class="card-menu" data-num="05">
                <h3><span class="icon">📈</span> 5. Evolução do Inventário (Dispositivos/Mês)</h3>
                <div class="descricao">
                    Mostra crescimento da rede ao longo do tempo.
                    Essencial para planejamento de capacidade e orçamento.
                </div>
                <div class="tecnico">
                    <strong>Cálculo:</strong> Contagem de IPs únicos primeiro vistos em cada mês.<br>
                    <strong>Fonte:</strong> <code>MIN(timestamp)</code> por IP na tabela <code>logs_status</code>.
                </div>
                <div class="dica">💡 <strong>Dica:</strong> Crescimento acelerado sem planejamento pode degradar performance da rede.</div>
                <a href="/grafico_crescimento" class="btn-grafico">📊 Ir Para o Gráfico</a>
            </div>

            <div class="card-menu" data-num="06">
                <h3><span class="icon">👻</span> 6. Dispositivos "Fantasmas" (Sem atividade 7+ dias)</h3>
                <div class="descricao">
                    Lista IPs cadastrados que não aparecem há mais de 7 dias.
                    Indica equipamentos desmobilizados sem processo formal ou falha de monitoramento.
                </div>
                <div class="tecnico">
                    <strong>Cálculo:</strong> <code>MAX(timestamp) < DATE('now', '-7 days')</code> ou NULL.<br>
                    <strong>Ordenação:</strong> Nunca logados primeiro, depois mais antigos.
                </div>
                <div class="dica">💡 <strong>Dica:</strong> Revise mensalmente para manter inventário atualizado e liberar IPs para reuso.</div>
                <a href="/grafico_fantasmas" class="btn-grafico">📊 Ir Para o Gráfico</a>
            </div>

            <div class="card-menu" data-num="02">
                <h3><span class="icon">🔄</span> 2. Ranking de Trocas de Hardware (Audit)</h3>
                <div class="descricao">
                    Histórico de alterações de MAC address detectadas.
                    Indica substituições não documentadas de equipamentos.
                </div>
                <div class="tecnico">
                    <strong>Cálculo:</strong> Contagem de registros na tabela <code>auditoria_hardware</code>.<br>
                    <strong>Histórico:</strong> Mantém nome do setor no momento da troca para rastreabilidade.
                </div>
                <div class="dica">💡 <strong>Dica:</strong> Muitas trocas no mesmo setor podem indicar problema de energia ou má gestão de ativos.</div>
                <a href="/grafico_trocas" class="btn-grafico">📊 Ir Para o Gráfico</a>
            </div>
            <div class="categoria">🔧 Análise Técnica Avançada</div>

            <div class="card-menu" data-num="13" style="border-left-color: #6a1b9a;">
                <h3><span class="icon">🔬</span> 13. Análise de Camadas de Disponibilidade</h3>
                <div class="descricao">
                    <strong>GRÁFICO TÉCNICO:</strong> Separa as 3 condições reais de monitoramento:
                    ONLINE & OK (ping + web), ONLINE & FALHA (ping sem web) e OFFLINE (sem ping).
                    Essencial para diagnóstico técnico diferenciado entre falhas de rede e falhas de serviço.
                </div>
                <div class="tecnico">
                    <strong>Métricas Calculadas:</strong><br>
                    • <strong>SLA Rede:</strong> <code>Ping OK / Total</code> - Conectividade IP<br>
                    • <strong>SLA Serviço:</strong> <code>Web OK / Total</code> - Interface web funcional<br>
                    • <strong>Gap Técnico:</strong> <code>(Ping OK - Web OK) / Total</code> - Equipamentos "meio funcionando"
                </div>
                <div class="dica" style="background: #f3e5f5; color: #6a1b9a;">
                    💡 <strong>Uso:</strong> Ideal para equipe de TI identificar se problema é infraestrutura (rede) ou aplicação (serviço web).
                    Diferente dos outros gráficos que mostram apenas "funciona/não funciona" para diretoria.
                </div>
                <a href="/grafico_camadas" class="btn-grafico" style="background: linear-gradient(135deg, #6a1b9a 0%, #4a148c 100%);">📊 Ir Para o Gráfico Técnico</a>
            </div>
        </div>
    </body>
    </html>
    """)
# =============================================================================
# ROTAS INDIVIDUAIS DOS 12 GRÁFICOS
# =============================================================================

def query_db(query, params=(), timeout=10.0):
    """Função auxiliar para queries seguras com timeout"""
    conn = sqlite3.connect(DB_NAME, timeout=timeout)
    try:
        conn.execute('PRAGMA query_only = ON;')
        cursor = conn.cursor()
        cursor.execute(query, params)
        result = cursor.fetchall()
        return result
    finally:
        conn.close()


def obter_periodo_dados(dias=30):
    """Retorna string formatada do período de dados (últimos X dias)"""
    try:
        # Busca data mais recente e mais antiga nos últimos X dias
        conn = sqlite3.connect(DB_NAME, timeout=5.0)
        conn.execute('PRAGMA query_only = ON;')
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                MIN(DATE(timestamp)) as inicio,
                MAX(DATE(timestamp)) as fim,
                COUNT(DISTINCT DATE(timestamp)) as dias_com_dados
            FROM logs_status
            WHERE DATE(timestamp) >= DATE('now', '-{} days')
        """.format(dias))

        row = cursor.fetchone()
        conn.close()

        if row and row[0] and row[1]:
            # Formata datas brasileiro
            data_inicio = datetime.strptime(row[0], '%Y-%m-%d').strftime('%d/%m/%Y')
            data_fim = datetime.strptime(row[1], '%Y-%m-%d').strftime('%d/%m/%Y')
            return f"{data_inicio} até {data_fim} ({row[2]} dias com dados)"
        return "Período não determinado"
    except Exception as e:
        print(f"[PERIODO-ERROR] {e}", flush=True)
        return "Período não disponível"


@app.route('/grafico_sla')
def grafico_sla():
    """Gráfico 1: Disponibilidade por Dispositivo (SLA %) - Últimos 30 dias"""
    periodo_str = obter_periodo_dados(30)

    try:
        dados = query_db("""
            SELECT
                l.ip,
                c.nome as nome_atual,
                ROUND(SUM(CASE WHEN l.status = 'ONLINE' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) as sla_percent
            FROM logs_status l
            LEFT JOIN config_dispositivos c ON l.ip = c.ip
            WHERE DATE(l.timestamp) >= DATE('now', '-30 days')
            GROUP BY l.ip
            HAVING COUNT(*) > 0
            ORDER BY sla_percent ASC
        """)
    except Exception as e:
        print(f"[GRAFICO-SLA-ERROR] {e}", flush=True)
        dados = []

    if not dados:
        dados = [('192.168.0.1', 'Sem Dados no Período', 0)]

    labels = json.dumps([f"{(d[1] or 'Desconhecido')} ({d[0]})" for d in dados])
    valores = json.dumps([float(d[2]) if d[2] else 0 for d in dados])

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>1. Disponibilidade por Dispositivo (SLA %)</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: 'Segoe UI', sans-serif; background: #f0f2f5; padding: 20px; margin: 0; }
            .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
            h1 { color: #1a237e; margin-bottom: 5px; }
            .btn-back { text-decoration: none; color: white; background: #d32f2f; padding: 10px 20px; border-radius: 20px; font-weight: bold; display: inline-block; margin-bottom: 20px; }
            .chart-container { position: relative; height: 500px; margin-top: 20px; }
            .periodo-box {
                background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%);
                padding: 15px 20px;
                border-radius: 8px;
                margin-bottom: 20px;
                border-left: 4px solid #1976d2;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .periodo-label { font-weight: bold; color: #1565c0; }
            .periodo-valor { color: #1976d2; font-size: 1.1em; }
            .info { background: #e8eaf6; padding: 15px; border-radius: 8px; margin-bottom: 20px; color: #555; }
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/relatorios" class="btn-back">⬅ Voltar ao Menu</a>
            <h1>📈 1. Disponibilidade por Dispositivo (SLA %)</h1>

            <div class="periodo-box">
                <span class="periodo-label">📅 Período de Análise:</span>
                <span class="periodo-valor">{{ periodo }}</span>
            </div>

            <div class="info">
                <strong>Fórmula:</strong> SUM(ONLINE) / TOTAL * 100 |
                <strong>Mostrando:</strong> Dispositivos com atividade nos últimos 30 dias
            </div>

            <div class="chart-container">
                <canvas id="chart"></canvas>
            </div>
        </div>
        <script>
            new Chart(document.getElementById('chart'), {
                type: 'bar',
                data: {
                    labels: {{ labels|safe }},
                    datasets: [{
                        label: 'SLA %',
                        data: {{ valores|safe }},
                        backgroundColor: function(c) {
                            const v = c.raw;
                            return v < 90 ? '#d32f2f' : v < 95 ? '#fbc02d' : '#2e7d32';
                        },
                        borderWidth: 1
                    }]
                },
                options: {
                    indexAxis: 'y',
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            callbacks: {
                                label: function(c) {
                                    return 'SLA: ' + c.raw.toFixed(2) + '% (últimos 30 dias)';
                                }
                            }
                        }
                    },
                    scales: {
                        x: { min: 0, max: 100, title: { display: true, text: 'Percentual de Uptime (%)' } }
                    }
                }
            });
        </script>
    </body>
    </html>
    """, labels=labels, valores=valores, periodo=periodo_str)

@app.route('/grafico_fabricantes')
def grafico_fabricantes():
    """Gráfico 4: Distribuição de Marcas no Inventário - Snapshot Atual"""
    data_atual = datetime.now().strftime('%d/%m/%Y %H:%M')

    try:
        dados = query_db("""
            SELECT COALESCE(fabricante, 'Desconhecido'), COUNT(*)
            FROM config_dispositivos
            WHERE ignorar = 0
            GROUP BY fabricante
            ORDER BY COUNT(*) DESC
        """)
    except Exception as e:
        print(f"[GRAFICO-FAB-ERROR] {e}", flush=True)
        dados = [('Desconhecido', 0)]

    labels = json.dumps([str(d[0]) for d in dados])
    valores = json.dumps([d[1] for d in dados])

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>4. Distribuição de Marcas no Inventário</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: 'Segoe UI', sans-serif; background: #f0f2f5; padding: 20px; margin: 0; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); text-align: center; }
            h1 { color: #1a237e; margin-bottom: 5px; }
            .btn-back { text-decoration: none; color: white; background: #d32f2f; padding: 10px 20px; border-radius: 20px; font-weight: bold; display: inline-block; margin-bottom: 20px; }
            .chart-container { position: relative; height: 500px; margin-top: 20px; }
            .periodo-box {
                background: linear-gradient(135deg, #f3e5f5 0%, #e1bee7 100%);
                padding: 15px 20px;
                border-radius: 8px;
                margin-bottom: 20px;
                border-left: 4px solid #7b1fa2;
            }
            .periodo-label { font-weight: bold; color: #6a1b9a; }
            .snapshot { color: #7b1fa2; font-size: 1.1em; }
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/relatorios" class="btn-back">⬅ Voltar ao Menu</a>
            <h1>🏷️ 4. Distribuição de Marcas no Inventário</h1>

            <div class="periodo-box">
                <span class="periodo-label">📸 Snapshot do Inventário:</span><br>
                <span class="snapshot">{{ periodo }}</span><br>
                <small style="color: #8e24aa;">Mostra todos os dispositivos cadastrados atualmente (não excluídos)</small>
            </div>

            <div class="chart-container">
                <canvas id="chart"></canvas>
            </div>
        </div>
        <script>
            new Chart(document.getElementById('chart'), {
                type: 'pie',
                data: {
                    labels: {{ labels|safe }},
                    datasets: [{
                        data: {{ valores|safe }},
                        backgroundColor: ['#1a237e', '#2e7d32', '#ef6c00', '#d32f2f', '#9c27b0', '#0097a7', '#795548', '#607d8b']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'right' },
                        tooltip: {
                            callbacks: {
                                label: function(c) {
                                    const total = c.dataset.data.reduce((a, b) => a + b, 0);
                                    const pct = ((c.raw / total) * 100).toFixed(1);
                                    return c.label + ': ' + c.raw + ' dispositivos (' + pct + '%)';
                                }
                            }
                        }
                    }
                }
            });
        </script>
    </body>
    </html>
    """, labels=labels, valores=valores, periodo=f"Inventário em {data_atual}")

@app.route('/grafico_sla_tipo')
def grafico_sla_tipo():
    """Gráfico 9: Disponibilidade por Tipo de Equipamento - Últimos 30 dias"""
    periodo_str = obter_periodo_dados(30)

    try:
        dados = query_db("""
            SELECT
                COALESCE(c.tipo, 'Outros') as tipo,
                ROUND(SUM(CASE WHEN l.status = 'ONLINE' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) as sla
            FROM logs_status l
            JOIN config_dispositivos c ON l.ip = c.ip
            WHERE c.ignorar = 0 AND DATE(l.timestamp) >= DATE('now', '-30 days')
            GROUP BY c.tipo
            HAVING COUNT(*) > 0
            ORDER BY sla ASC
        """)
    except Exception as e:
        print(f"[GRAFICO-SLA-TIPO-ERROR] {e}", flush=True)
        dados = [('Outros', 0)]

    labels = json.dumps([str(d[0]) for d in dados])
    valores = json.dumps([float(d[1]) if d[1] else 0 for d in dados])

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>9. Disponibilidade por Tipo de Equipamento</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: 'Segoe UI', sans-serif; background: #f0f2f5; padding: 20px; margin: 0; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); text-align: center; }
            h1 { color: #1a237e; margin-bottom: 5px; }
            .btn-back { text-decoration: none; color: white; background: #d32f2f; padding: 10px 20px; border-radius: 20px; font-weight: bold; display: inline-block; margin-bottom: 20px; }
            .chart-container { position: relative; height: 500px; margin-top: 20px; }
            .periodo-box {
                background: linear-gradient(135deg, #e8f5e9 0%, #c8e6c9 100%);
                padding: 15px 20px;
                border-radius: 8px;
                margin-bottom: 20px;
                border-left: 4px solid #388e3c;
            }
            .periodo-label { font-weight: bold; color: #2e7d32; }
            .periodo-valor { color: #388e3c; font-size: 1.1em; }
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/relatorios" class="btn-back">⬅ Voltar ao Menu</a>
            <h1>🎯 9. Disponibilidade por Tipo de Equipamento</h1>

            <div class="periodo-box">
                <span class="periodo-label">📅 Período de Análise:</span>
                <span class="periodo-valor">{{ periodo }}</span>
            </div>

            <div class="chart-container">
                <canvas id="chart"></canvas>
            </div>
        </div>
        <script>
            new Chart(document.getElementById('chart'), {
                type: 'radar',
                data: {
                    labels: {{ labels|safe }},
                    datasets: [{
                        label: 'SLA % (últimos 30 dias)',
                        data: {{ valores|safe }},
                        backgroundColor: 'rgba(26, 35, 126, 0.2)',
                        borderColor: '#1a237e',
                        pointBackgroundColor: '#1a237e',
                        pointBorderColor: '#fff',
                        pointHoverBackgroundColor: '#fff',
                        pointHoverBorderColor: '#1a237e'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: true, position: 'top' }
                    },
                    scales: {
                        r: {
                            min: 0,
                            max: 100,
                            ticks: { stepSize: 20 }
                        }
                    }
                }
            });
        </script>
    </body>
    </html>
    """, labels=labels, valores=valores, periodo=periodo_str)

@app.route('/grafico_falhas')
def grafico_falhas():
    """Gráfico 7: Ranking de Falhas por Dispositivo - Últimos 30 dias"""
    periodo_str = obter_periodo_dados(30)

    try:
        dados = query_db("""
            SELECT ip, COUNT(*) as total_falhas
            FROM logs_status
            WHERE status = 'OFFLINE' AND DATE(timestamp) >= DATE('now', '-30 days')
            GROUP BY ip
            HAVING total_falhas > 0
            ORDER BY total_falhas DESC
            LIMIT 15
        """)
    except Exception as e:
        print(f"[GRAFICO-FALHAS-ERROR] {e}", flush=True)
        dados = []

    labels = json.dumps([str(d[0]) for d in dados])
    valores = json.dumps([d[1] for d in dados])

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>7. Ranking de Falhas por Dispositivo</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: 'Segoe UI', sans-serif; background: #f0f2f5; padding: 20px; margin: 0; }
            .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
            h1 { color: #1a237e; margin-bottom: 5px; }
            .btn-back { text-decoration: none; color: white; background: #d32f2f; padding: 10px 20px; border-radius: 20px; font-weight: bold; display: inline-block; margin-bottom: 20px; }
            .chart-container { position: relative; height: 500px; margin-top: 20px; }
            .periodo-box {
                background: linear-gradient(135deg, #fff3e0 0%, #ffe0b2 100%);
                padding: 15px 20px;
                border-radius: 8px;
                margin-bottom: 20px;
                border-left: 4px solid #ef6c00;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .periodo-label { font-weight: bold; color: #e65100; }
            .periodo-valor { color: #ef6c00; font-size: 1.1em; }
            .alerta { background: #ffebee; border-left: 4px solid #d32f2f; padding: 15px; margin-bottom: 20px; color: #c62828; }
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/relatorios" class="btn-back">⬅ Voltar ao Menu</a>
            <h1>⏱️ 7. Ranking de Falhas por Dispositivo</h1>

            <div class="periodo-box">
                <span class="periodo-label">📅 Período de Análise:</span>
                <span class="periodo-valor">{{ periodo }}</span>
            </div>

            <div class="alerta">
                <strong>⚠️ Atenção:</strong> Mostrando apenas falhas (status OFFLINE) dos últimos 30 dias.
                Dispositivos no topo requerem atenção imediata.
            </div>

            <div class="chart-container">
                <canvas id="chart"></canvas>
            </div>
        </div>
        <script>
            new Chart(document.getElementById('chart'), {
                type: 'bar',
                data: {
                    labels: {{ labels|safe }},
                    datasets: [{
                        label: 'Falhas (OFFLINE)',
                        data: {{ valores|safe }},
                        backgroundColor: '#ef6c00',
                        borderColor: '#e65100',
                        borderWidth: 1
                    }]
                },
                options: {
                    indexAxis: 'y',
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            callbacks: {
                                label: function(c) {
                                    return c.raw + ' falhas no período';
                                }
                            }
                        }
                    },
                    scales: {
                        x: { beginAtZero: true, title: { display: true, text: 'Número de Falhas' } }
                    }
                }
            });
        </script>
    </body>
    </html>
    """, labels=labels, valores=valores, periodo=periodo_str)

@app.route('/grafico_top10_falhas')
def grafico_top10_falhas():
    """Gráfico 8: Top 10 - Dispositivos com Mais Falhas - Últimos 30 dias"""
    periodo_str = obter_periodo_dados(30)

    try:
        dados = query_db("""
            SELECT ip, COUNT(*) as total
            FROM logs_status
            WHERE status = 'OFFLINE' AND DATE(timestamp) >= DATE('now', '-30 days')
            GROUP BY ip
            HAVING total > 0
            ORDER BY total DESC
            LIMIT 10
        """)
    except Exception as e:
        print(f"[GRAFICO-TOP10-ERROR] {e}", flush=True)
        dados = []

    labels = json.dumps([str(d[0]) for d in dados])
    valores = json.dumps([d[1] for d in dados])

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>8. Top 10 - Dispositivos com Mais Falhas</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: 'Segoe UI', sans-serif; background: #f0f2f5; padding: 20px; margin: 0; }
            .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); text-align: center; }
            h1 { color: #1a237e; margin-bottom: 5px; }
            .btn-back { text-decoration: none; color: white; background: #d32f2f; padding: 10px 20px; border-radius: 20px; font-weight: bold; display: inline-block; margin-bottom: 20px; }
            .chart-container { position: relative; height: 500px; margin-top: 20px; }
            .periodo-box {
                background: linear-gradient(135deg, #ffebee 0%, #ffcdd2 100%);
                padding: 15px 20px;
                border-radius: 8px;
                margin-bottom: 20px;
                border-left: 4px solid #c62828;
            }
            .periodo-label { font-weight: bold; color: #c62828; }
            .periodo-valor { color: #d32f2f; font-size: 1.1em; }
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/relatorios" class="btn-back">⬅ Voltar ao Menu</a>
            <h1>⚡ 8. Top 10 - Dispositivos com Mais Falhas</h1>

            <div class="periodo-box">
                <span class="periodo-label">📅 Período de Análise:</span>
                <span class="periodo-valor">{{ periodo }}</span>
            </div>

            <div class="chart-container">
                <canvas id="chart"></canvas>
            </div>
        </div>
        <script>
            new Chart(document.getElementById('chart'), {
                type: 'bar',
                data: {
                    labels: {{ labels|safe }},
                    datasets: [{
                        label: 'Falhas',
                        data: {{ valores|safe }},
                        backgroundColor: ['#d32f2f', '#e53935', '#f44336', '#ef5350', '#e57373',
                                        '#ef9a9a', '#ffebee', '#ffcdd2', '#ef9a9a', '#e57373'],
                        borderWidth: 2,
                        borderColor: '#b71c1c'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            callbacks: {
                                title: function(c) {
                                    return 'IP: ' + c[0].label;
                                },
                                label: function(c) {
                                    return 'Total de falhas: ' + c.raw;
                                }
                            }
                        }
                    },
                    scales: {
                        y: { beginAtZero: true, title: { display: true, text: 'Falhas Registradas' } }
                    }
                }
            });
        </script>
    </body>
    </html>
    """, labels=labels, valores=valores, periodo=periodo_str)

@app.route('/grafico_sla_fabricante')
def grafico_sla_fabricante():
    """Gráfico 11: Comparativo de Confiabilidade por Fabricante - Últimos 30 dias"""
    periodo_str = obter_periodo_dados(30)

    try:
        dados = query_db("""
            SELECT
                COALESCE(NULLIF(fabricante, ''), 'Desconhecido') as fabricante,
                ROUND(SUM(CASE WHEN l.status = 'ONLINE' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) as sla,
                COUNT(DISTINCT l.ip) as qtd
            FROM logs_status l
            JOIN config_dispositivos c ON l.ip = c.ip
            WHERE c.ignorar = 0 AND DATE(l.timestamp) >= DATE('now', '-30 days')
            GROUP BY c.fabricante
            HAVING COUNT(*) > 0
            ORDER BY sla ASC
        """)
    except Exception as e:
        print(f"[GRAFICO-SLA-FAB-ERROR] {e}", flush=True)
        dados = [('Desconhecido', 0, 0)]

    labels = json.dumps([str(d[0]) for d in dados])
    valores = json.dumps([float(d[1]) if d[1] else 0 for d in dados])
    qtd = json.dumps([d[2] for d in dados])

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>11. Comparativo de Confiabilidade por Fabricante</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: 'Segoe UI', sans-serif; background: #f0f2f5; padding: 20px; margin: 0; }
            .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
            h1 { color: #1a237e; margin-bottom: 5px; }
            .btn-back { text-decoration: none; color: white; background: #d32f2f; padding: 10px 20px; border-radius: 20px; font-weight: bold; display: inline-block; margin-bottom: 20px; }
            .chart-container { position: relative; height: 500px; margin-top: 20px; }
            .periodo-box {
                background: linear-gradient(135deg, #e0f2f1 0%, #b2dfdb 100%);
                padding: 15px 20px;
                border-radius: 8px;
                margin-bottom: 20px;
                border-left: 4px solid #00796b;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .periodo-label { font-weight: bold; color: #00695c; }
            .periodo-valor { color: #00796b; font-size: 1.1em; }
            .legenda { background: #fff3e0; border-left: 4px solid #ef6c00; padding: 15px; margin-bottom: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/relatorios" class="btn-back">⬅ Voltar ao Menu</a>
            <h1>🏭 11. Comparativo de Confiabilidade por Fabricante</h1>

            <div class="periodo-box">
                <span class="periodo-label">📅 Período de Análise:</span>
                <span class="periodo-valor">{{ periodo }}</span>
            </div>

            <div class="legenda">
                <strong>Legenda de Cores:</strong> 🟥 Vermelho (&lt;90%) | 🟨 Amarelo (90-95%) | 🟩 Verde (&gt;95%)
            </div>

            <div class="chart-container">
                <canvas id="chart"></canvas>
            </div>
        </div>
        <script>
            const qtd = {{ qtd|safe }};
            new Chart(document.getElementById('chart'), {
                type: 'bar',
                data: {
                    labels: {{ labels|safe }},
                    datasets: [{
                        label: 'SLA %',
                        data: {{ valores|safe }},
                        backgroundColor: function(c) {
                            const v = c.raw;
                            return v < 90 ? '#d32f2f' : v < 95 ? '#fbc02d' : '#2e7d32';
                        }
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            callbacks: {
                                afterLabel: function(c) {
                                    return 'Dispositivos monitorados: ' + (qtd[c.dataIndex] || 0);
                                }
                            }
                        }
                    },
                    scales: {
                        y: { min: 0, max: 100, title: { display: true, text: 'SLA %' } }
                    }
                }
            });
        </script>
    </body>
    </html>
    """, labels=labels, valores=valores, qtd=qtd, periodo=periodo_str)

@app.route('/grafico_heatmap')
def grafico_heatmap():
    """Gráfico 12: Matriz de Indisponibilidade - Heatmap - Últimos 30 dias"""
    periodo_str = obter_periodo_dados(30)

    try:
        dados = query_db("""
            SELECT
                CASE strftime('%w', timestamp)
                    WHEN '0' THEN 'Dom' WHEN '1' THEN 'Seg' WHEN '2' THEN 'Ter'
                    WHEN '3' THEN 'Qua' WHEN '4' THEN 'Qui' WHEN '5' THEN 'Sex' WHEN '6' THEN 'Sáb'
                END as dia,
                CAST(strftime('%H', timestamp) as INTEGER) as hora,
                COUNT(DISTINCT ip) as falhas
            FROM logs_status
            WHERE status = 'OFFLINE' AND DATE(timestamp) >= DATE('now', '-30 days')
            GROUP BY dia, hora
        """)
    except Exception as e:
        print(f"[GRAFICO-HEATMAP-ERROR] {e}", flush=True)
        dados = []

    dias_ordem = ['Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sáb', 'Dom']
    heatmap_matrix = {d: [0]*24 for d in dias_ordem}

    for d in dados:
        if len(d) >= 3:
            dia, hora, val = str(d[0]), int(d[1]) if d[1] else 0, d[2]
            if dia in heatmap_matrix and 0 <= hora < 24:
                heatmap_matrix[dia][hora] = val

    heatmap_data = [heatmap_matrix[d] for d in dias_ordem]
    max_val = max([max(row) for row in heatmap_data]) if any(max(row) > 0 for row in heatmap_data) else 1

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>12. Matriz de Indisponibilidade - Heatmap</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: 'Segoe UI', sans-serif; background: #f0f2f5; padding: 20px; margin: 0; }
            .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
            h1 { color: #1a237e; margin-bottom: 5px; }
            .btn-back { text-decoration: none; color: white; background: #d32f2f; padding: 10px 20px; border-radius: 20px; font-weight: bold; display: inline-block; margin-bottom: 20px; }
            .chart-container { position: relative; height: 500px; margin-top: 20px; }
            .periodo-box {
                background: linear-gradient(135deg, #fce4ec 0%, #f8bbd9 100%);
                padding: 15px 20px;
                border-radius: 8px;
                margin-bottom: 20px;
                border-left: 4px solid #c2185b;
            }
            .periodo-label { font-weight: bold; color: #ad1457; }
            .periodo-valor { color: #c2185b; font-size: 1.1em; }
            .legenda { display: flex; align-items: center; justify-content: center; gap: 20px; margin-top: 20px; font-size: 0.9em; }
            .legenda-item { display: flex; align-items: center; gap: 5px; }
            .cor { width: 20px; height: 20px; border-radius: 3px; }
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/relatorios" class="btn-back">⬅ Voltar ao Menu</a>
            <h1>🔥 12. Matriz de Indisponibilidade - Heatmap</h1>

            <div class="periodo-box">
                <span class="periodo-label">📅 Período de Análise:</span>
                <span class="periodo-valor">{{ periodo }}</span>
            </div>

            <div class="chart-container">
                <canvas id="chart"></canvas>
            </div>

            <div class="legenda">
                <span>Intensidade de Falhas:</span>
                <div class="legenda-item"><div class="cor" style="background: #ffebee;"></div> Baixa</div>
                <div class="legenda-item"><div class="cor" style="background: #ffcdd2;"></div> Média</div>
                <div class="legenda-item"><div class="cor" style="background: #ef5350;"></div> Alta</div>
                <div class="legenda-item"><div class="cor" style="background: #c62828;"></div> Crítica</div>
            </div>
        </div>
        <script>
            const heatData = {{ heatmap_data|safe }};
            const dias = {{ dias|safe }};
            const horas = {{ horas|safe }};
            const maxVal = {{ max_val }};

            const scatter = [];
            const colors = [];
            const cores = ['#ffebee', '#ffcdd2', '#ef9a9a', '#e57373', '#ef5350', '#f44336', '#e53935', '#c62828'];

            for (let d = 0; d < dias.length; d++) {
                for (let h = 0; h < 24; h++) {
                    const v = heatData[d][h];
                    if (v > 0) {
                        scatter.push({ x: h, y: d, v: v });
                        const idx = Math.min(Math.floor((v / maxVal) * (cores.length - 1)), cores.length - 1);
                        colors.push(cores[idx]);
                    }
                }
            }

            new Chart(document.getElementById('chart'), {
                type: 'scatter',
                data: {
                    datasets: [{
                        data: scatter,
                        backgroundColor: colors,
                        pointRadius: function(c) { return 8 + (c.raw.v / maxVal) * 15; },
                        pointHoverRadius: 25
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            callbacks: {
                                title: function(c) {
                                    const r = c[0].raw;
                                    return dias[r.y] + ' às ' + horas[r.x] + 'h';
                                },
                                label: function(c) {
                                    return 'Falhas: ' + c.raw.v + ' dispositivos';
                                }
                            }
                        }
                    },
                    scales: {
                        x: {
                            min: -0.5, max: 23.5,
                            ticks: { callback: function(v) { return (v % 3 === 0) ? v + 'h' : ''; }, stepSize: 1 },
                            title: { display: true, text: 'Hora do Dia' }
                        },
                        y: {
                            min: -0.5, max: 6.5,
                            ticks: { callback: function(v) { return dias[v] || ''; }, stepSize: 1 },
                            title: { display: true, text: 'Dia da Semana' }
                        }
                    }
                }
            });
        </script>
    </body>
    </html>
    """, heatmap_data=json.dumps(heatmap_data), dias=json.dumps(dias_ordem),
         horas=json.dumps(list(range(24))), max_val=max_val, periodo=periodo_str)

@app.route('/grafico_cascata')
def grafico_cascata():
    """Gráfico 10: Falhas em Cascata - Últimos 30 dias"""
    periodo_str = obter_periodo_dados(30)

    try:
        dados = query_db("""
            SELECT
                DATE(timestamp) as dia,
                TIME(timestamp) as hora,
                COUNT(DISTINCT ip) as afetados
            FROM logs_status
            WHERE status = 'OFFLINE' AND DATE(timestamp) >= DATE('now', '-30 days')
            GROUP BY strftime('%Y-%m-%d %H:%M', timestamp)
            HAVING afetados >= 3
            ORDER BY dia DESC, hora DESC
            LIMIT 20
        """)
    except Exception as e:
        print(f"[GRAFICO-CASCATA-ERROR] {e}", flush=True)
        dados = []

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>10. Falhas em Cascata (Incidentes de Infraestrutura)</title>
        <style>
            body { font-family: 'Segoe UI', sans-serif; background: #f0f2f5; padding: 20px; margin: 0; }
            .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
            h1 { color: #1a237e; margin-bottom: 5px; }
            .btn-back { text-decoration: none; color: white; background: #d32f2f; padding: 10px 20px; border-radius: 20px; font-weight: bold; display: inline-block; margin-bottom: 20px; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
            th { background: #1a237e; color: white; position: sticky; top: 0; }
            tr:hover { background: #f5f5f5; }
            .badge { padding: 6px 12px; border-radius: 12px; font-size: 0.85em; font-weight: bold; }
            .critico { background: #ffebee; color: #c62828; }
            .alto { background: #fff3e0; color: #ef6c00; }
            .medio { background: #e8f5e9; color: #2e7d32; }
            .empty { text-align: center; padding: 40px; color: #2e7d32; font-size: 1.2em; }
            .periodo-box {
                background: linear-gradient(135deg, #e8eaf6 0%, #c5cae9 100%);
                padding: 15px 20px;
                border-radius: 8px;
                margin-bottom: 20px;
                border-left: 4px solid #3f51b5;
            }
            .periodo-label { font-weight: bold; color: #283593; }
            .periodo-valor { color: #3f51b5; font-size: 1.1em; }
            .info { background: #e3f2fd; padding: 15px; border-radius: 8px; margin-bottom: 20px; color: #1565c0; }
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/relatorios" class="btn-back">⬅ Voltar ao Menu</a>
            <h1>⚠️ 10. Falhas em Cascata (Incidentes de Infraestrutura)</h1>

            <div class="periodo-box">
                <span class="periodo-label">📅 Período de Análise:</span>
                <span class="periodo-valor">{{ periodo }}</span>
            </div>

            <div class="info">
                <strong>Definição:</strong> Momentos onde 3+ dispositivos caíram simultaneamente (mesmo minuto).
                Indicam problemas de infraestrutura (energia, switch core).
            </div>

            <table>
                <thead>
                    <tr>
                        <th>Data</th>
                        <th>Hora</th>
                        <th>Dispositivos Afetados</th>
                        <th>Severidade</th>
                        <th>Possível Causa</th>
                    </tr>
                </thead>
                <tbody>
                    {% for d in dados %}
                    <tr>
                        <td><b>{{ d[0] }}</b></td>
                        <td>{{ d[1] }}</td>
                        <td style="font-size: 1.2em; font-weight: bold; color: {% if d[2] >= 10 %}#c62828{% elif d[2] >= 5 %}#ef6c00{% else %}#2e7d32{% endif %};">
                            {{ d[2] }} dispositivos
                        </td>
                        <td>
                            {% if d[2] >= 10 %}
                            <span class="badge critico">🔴 CRÍTICO</span>
                            {% elif d[2] >= 5 %}
                            <span class="badge alto">🟠 ALTO</span>
                            {% else %}
                            <span class="badge medio">🟢 MÉDIO</span>
                            {% endif %}
                        </td>
                        <td style="color: #666; font-size: 0.9em;">
                            {% if d[2] >= 10 %}Queda de energia geral ou falha core{% elif d[2] >= 5 %}Possível problema no rack/switch{% else %}Sobrecarga momentânea{% endif %}
                        </td>
                    </tr>
                    {% else %}
                    <tr><td colspan="5" class="empty">✅ Nenhum incidente de cascata detectado no período!<br>Isso indica boa estabilidade de infraestrutura.</td></tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """, dados=dados, periodo=periodo_str)

@app.route('/grafico_volume')
def grafico_volume():
    """Gráfico 3: Estabilidade da Rede (Volume de Logs/Dia) - Últimos 14 dias"""
    try:
        dados = query_db("""
            SELECT DATE(timestamp) as dia, COUNT(*) as total
            FROM logs_status
            GROUP BY dia
            ORDER BY dia DESC
            LIMIT 14
        """)
    except Exception as e:
        print(f"[GRAFICO-VOLUME-ERROR] {e}", flush=True)
        dados = []

    if not dados:
        dados = [(datetime.now().strftime('%Y-%m-%d'), 0)]

    # Calcula período real dos dados
    if dados:
        data_inicio = datetime.strptime(dados[-1][0], '%Y-%m-%d').strftime('%d/%m/%Y')
        data_fim = datetime.strptime(dados[0][0], '%Y-%m-%d').strftime('%d/%m/%Y')
        periodo_str = f"{data_inicio} até {data_fim} ({len(dados)} dias)"
    else:
        periodo_str = "Sem dados disponíveis"

    labels = json.dumps([str(d[0]) for d in reversed(dados)])
    valores = json.dumps([d[1] for d in reversed(dados)])

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>3. Estabilidade da Rede (Volume de Logs/Dia)</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: 'Segoe UI', sans-serif; background: #f0f2f5; padding: 20px; margin: 0; }
            .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); text-align: center; }
            h1 { color: #1a237e; margin-bottom: 5px; }
            .btn-back { text-decoration: none; color: white; background: #d32f2f; padding: 10px 20px; border-radius: 20px; font-weight: bold; display: inline-block; margin-bottom: 20px; }
            .chart-container { position: relative; height: 400px; margin-top: 20px; }
            .periodo-box {
                background: linear-gradient(135deg, #e0f7fa 0%, #b2ebf2 100%);
                padding: 15px 20px;
                border-radius: 8px;
                margin-bottom: 20px;
                border-left: 4px solid #0097a7;
            }
            .periodo-label { font-weight: bold; color: #00838f; }
            .periodo-valor { color: #0097a7; font-size: 1.1em; }
            .alerta { background: #fff3e0; border-left: 4px solid #ef6c00; padding: 15px; margin: 20px 0; text-align: left; }
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/relatorios" class="btn-back">⬅ Voltar ao Menu</a>
            <h1>📊 3. Estabilidade da Rede (Volume de Logs/Dia)</h1>

            <div class="periodo-box">
                <span class="periodo-label">📅 Período de Análise:</span>
                <span class="periodo-valor">{{ periodo }}</span>
            </div>

            <div class="alerta">
                <strong>📈 Interpretação:</strong> Picos indicam instabilidade (muitas mudanças de status).
                Linha plana sugere rede estável ou monitoramento parado.
            </div>

            <div class="chart-container">
                <canvas id="chart"></canvas>
            </div>
        </div>
        <script>
            new Chart(document.getElementById('chart'), {
                type: 'line',
                data: {
                    labels: {{ labels|safe }},
                    datasets: [{
                        label: 'Registros/Dia',
                        data: {{ valores|safe }},
                        borderColor: '#1a237e',
                        backgroundColor: 'rgba(26, 35, 126, 0.1)',
                        fill: true,
                        tension: 0.4,
                        pointRadius: 5,
                        pointBackgroundColor: '#1a237e',
                        pointBorderColor: '#fff',
                        pointBorderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        y: { beginAtZero: true, title: { display: true, text: 'Quantidade de Registros' } }
                    }
                }
            });
        </script>
    </body>
    </html>
    """, labels=labels, valores=valores, periodo=periodo_str)

@app.route('/grafico_crescimento')
def grafico_crescimento():
    """Gráfico 5: Evolução do Inventário (Dispositivos/Mês) - Últimos 12 meses"""
    try:
        dados = query_db("""
            SELECT
                strftime('%Y-%m', MIN(timestamp)) as mes,
                COUNT(DISTINCT ip) as total
            FROM logs_status
            GROUP BY strftime('%Y-%m', timestamp)
            ORDER BY mes DESC
            LIMIT 12
        """)
    except Exception as e:
        print(f"[GRAFICO-CRESCIMENTO-ERROR] {e}", flush=True)
        dados = []

    if not dados:
        dados = [(datetime.now().strftime('%Y-%m'), 0)]

    # Calcula período
    if len(dados) > 1:
        mes_inicio = dados[-1][0]
        mes_fim = dados[0][0]
        periodo_str = f"{mes_inicio} até {mes_fim} ({len(dados)} meses)"
    else:
        periodo_str = f"Mês: {dados[0][0] if dados else 'atual'}"

    labels = json.dumps([str(d[0]) for d in reversed(dados)])
    valores = json.dumps([d[1] for d in reversed(dados)])

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>5. Evolução do Inventário (Dispositivos/Mês)</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: 'Segoe UI', sans-serif; background: #f0f2f5; padding: 20px; margin: 0; }
            .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); text-align: center; }
            h1 { color: #1a237e; margin-bottom: 5px; }
            .btn-back { text-decoration: none; color: white; background: #d32f2f; padding: 10px 20px; border-radius: 20px; font-weight: bold; display: inline-block; margin-bottom: 20px; }
            .chart-container { position: relative; height: 400px; margin-top: 20px; }
            .periodo-box {
                background: linear-gradient(135deg, #f3e5f5 0%, #e1bee7 100%);
                padding: 15px 20px;
                border-radius: 8px;
                margin-bottom: 20px;
                border-left: 4px solid #7b1fa2;
            }
            .periodo-label { font-weight: bold; color: #6a1b9a; }
            .periodo-valor { color: #7b1fa2; font-size: 1.1em; }
            .info { background: #e8f5e9; padding: 15px; border-radius: 8px; margin-bottom: 20px; color: #2e7d32; }
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/relatorios" class="btn-back">⬅ Voltar ao Menu</a>
            <h1>📈 5. Evolução do Inventário (Dispositivos/Mês)</h1>

            <div class="periodo-box">
                <span class="periodo-label">📅 Período de Análise:</span>
                <span class="periodo-valor">{{ periodo }}</span>
            </div>

            <div class="info">
                Mostra a quantidade de dispositivos únicos detectados pela primeira vez em cada mês.
                Útil para planejamento de capacidade de rede.
            </div>

            <div class="chart-container">
                <canvas id="chart"></canvas>
            </div>
        </div>
        <script>
            new Chart(document.getElementById('chart'), {
                type: 'bar',
                data: {
                    labels: {{ labels|safe }},
                    datasets: [{
                        label: 'Novos Dispositivos',
                        data: {{ valores|safe }},
                        backgroundColor: '#667eea',
                        borderColor: '#5a67d8',
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        y: { beginAtZero: true, ticks: { stepSize: 1 }, title: { display: true, text: 'Quantidade de Dispositivos' } }
                    }
                }
            });
        </script>
    </body>
    </html>
    """, labels=labels, valores=valores, periodo=periodo_str)

@app.route('/grafico_fantasmas')
def grafico_fantasmas():
    """Gráfico 6: Dispositivos "Fantasmas" (Sem atividade 7+ dias) - Status Atual"""
    data_atual = datetime.now().strftime('%d/%m/%Y %H:%M')

    try:
        dados = query_db("""
            SELECT
                c.ip,
                c.nome,
                c.tipo,
                c.fabricante,
                MAX(l.timestamp) as ultimo_log
            FROM config_dispositivos c
            LEFT JOIN logs_status l ON c.ip = l.ip
            WHERE c.ignorar = 0
            GROUP BY c.ip
            HAVING ultimo_log IS NULL OR DATE(ultimo_log) < DATE('now', '-7 days')
            ORDER BY
                CASE WHEN ultimo_log IS NULL THEN 0 ELSE 1 END,
                ultimo_log ASC
            LIMIT 50
        """)
    except Exception as e:
        print(f"[GRAFICO-FANTASMAS-ERROR] {e}", flush=True)
        dados = []

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>6. Dispositivos "Fantasmas" (Sem atividade 7+ dias)</title>
        <style>
            body { font-family: 'Segoe UI', sans-serif; background: #f0f2f5; padding: 20px; margin: 0; }
            .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
            h1 { color: #1a237e; margin-bottom: 5px; }
            .btn-back { text-decoration: none; color: white; background: #d32f2f; padding: 10px 20px; border-radius: 20px; font-weight: bold; display: inline-block; margin-bottom: 20px; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
            th { background: #1a237e; color: white; position: sticky; top: 0; }
            tr:hover { background: #f5f5f5; }
            .nunca { color: #d32f2f; font-weight: bold; }
            .antigo { color: #ef6c00; }
            .badge { padding: 4px 10px; border-radius: 12px; font-size: 0.8em; background: #e8eaf6; color: #1a237e; }
            .empty { text-align: center; padding: 40px; color: #2e7d32; font-size: 1.2em; }
            .stats { display: flex; gap: 20px; margin-bottom: 20px; }
            .stat-box { background: #f5f5f5; padding: 15px; border-radius: 8px; text-align: center; flex: 1; }
            .stat-num { font-size: 2em; font-weight: bold; color: #1a237e; }
            .stat-label { color: #666; font-size: 0.9em; }
            .periodo-box {
                background: linear-gradient(135deg, #fafafa 0%, #f5f5f5 100%);
                padding: 15px 20px;
                border-radius: 8px;
                margin-bottom: 20px;
                border-left: 4px solid #616161;
            }
            .periodo-label { font-weight: bold; color: #424242; }
            .periodo-valor { color: #616161; font-size: 1.1em; }
            .criterio { background: #fff3e0; padding: 10px; border-radius: 6px; margin-bottom: 20px; color: #ef6c00; font-size: 0.9em; }
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/relatorios" class="btn-back">⬅ Voltar ao Menu</a>
            <h1>👻 6. Dispositivos "Fantasmas" (Sem atividade 7+ dias)</h1>

            <div class="periodo-box">
                <span class="periodo-label">📸 Status do Inventário em:</span>
                <span class="periodo-valor">{{ periodo }}</span>
            </div>

            <div class="criterio">
                <strong>🔍 Critério:</strong> Dispositivos cadastrados sem logs nos últimos 7 dias ou que nunca foram detectados.
            </div>

            <div class="stats">
                <div class="stat-box">
                    <div class="stat-num">{{ dados|length }}</div>
                    <div class="stat-label">Dispositivos Inativos</div>
                </div>
                <div class="stat-box">
                    <div class="stat-num">{{ dados|selectattr("4", "equalto", None)|list|length }}</div>
                    <div class="stat-label">Nunca Logados</div>
                </div>
            </div>

            <table>
                <thead>
                    <tr>
                        <th>IP</th>
                        <th>Nome</th>
                        <th>Tipo</th>
                        <th>Fabricante</th>
                        <th>Última Atividade</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {% for d in dados %}
                    <tr>
                        <td><b>{{ d[0] }}</b></td>
                        <td>{{ d[1] or 'N/A' }}</td>
                        <td><span class="badge">{{ d[2] or 'Outros' }}</span></td>
                        <td>{{ d[3] or 'N/A' }}</td>
                        <td class="{% if not d[4] %}nunca{% else %}antigo{% endif %}">
                            {% if d[4] %}{{ d[4] }}{% else %}Nunca logado{% endif %}
                        </td>
                        <td>
                            {% if not d[4] %}
                            <span style="color: #d32f2f; font-weight: bold;">🔴 Nunca visto</span>
                            {% else %}
                            <span style="color: #ef6c00;">🟠 Inativo 7+ dias</span>
                            {% endif %}
                        </td>
                    </tr>
                    {% else %}
                    <tr><td colspan="6" class="empty">✅ Nenhum dispositivo fantasma detectado!<br>Todos os equipamentos estão ativos na rede.</td></tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """, dados=dados, periodo=f"{data_atual} (Snapshot atual)")

@app.route('/grafico_trocas')
def grafico_trocas():
    """Gráfico 2: Ranking de Trocas de Hardware (Audit) - Histórico Completo"""

    # Busca período das trocas
    try:
        periodo_dados = query_db("""
            SELECT
                MIN(DATE(timestamp)) as inicio,
                MAX(DATE(timestamp)) as fim,
                COUNT(*) as total_registros
            FROM auditoria_hardware
        """)
        if periodo_dados and periodo_dados[0][0]:
            p = periodo_dados[0]
            data_inicio = datetime.strptime(p[0], '%Y-%m-%d').strftime('%d/%m/%Y')
            data_fim = datetime.strptime(p[1], '%Y-%m-%d').strftime('%d/%m/%Y')
            periodo_str = f"{data_inicio} até {data_fim} ({p[2]} registros)"
        else:
            periodo_str = "Sem dados de auditoria"
    except Exception as e:
        periodo_str = "Período indeterminado"

    try:
        dados = query_db("""
            SELECT ip, nome_setor, fabricante_antigo, modelo_antigo, COUNT(*) as total
            FROM auditoria_hardware
            GROUP BY ip, nome_setor, fabricante_antigo, modelo_antigo
            ORDER BY total DESC
            LIMIT 20
        """)
    except Exception as e:
        print(f"[GRAFICO-TROCAS-ERROR] {e}", flush=True)
        dados = []

    labels = json.dumps([f"{d[2]} {d[3]}" for d in dados])
    sublabels = json.dumps([f"IP: {d[0]} | Local: {d[1]}" for d in dados])
    valores = json.dumps([d[4] for d in dados])

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>2. Ranking de Trocas de Hardware (Audit)</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: 'Segoe UI', sans-serif; background: #f0f2f5; padding: 20px; margin: 0; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); text-align: center; }
            h1 { color: #1a237e; margin-bottom: 5px; }
            .btn-back { text-decoration: none; color: white; background: #d32f2f; padding: 10px 20px; border-radius: 20px; font-weight: bold; display: inline-block; margin-bottom: 20px; }
            .chart-container { position: relative; height: 500px; margin-top: 20px; }
            .periodo-box {
                background: linear-gradient(135deg, #ffebee 0%, #ffcdd2 100%);
                padding: 15px 20px;
                border-radius: 8px;
                margin-bottom: 20px;
                border-left: 4px solid #c62828;
            }
            .periodo-label { font-weight: bold; color: #b71c1c; }
            .periodo-valor { color: #c62828; font-size: 1.1em; }
            .alerta { background: #ffebee; border-left: 4px solid #d32f2f; padding: 15px; margin-bottom: 20px; text-align: left; }
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/relatorios" class="btn-back">⬅ Voltar ao Menu</a>
            <h1>🔄 2. Ranking de Trocas de Hardware (Audit)</h1>

            <div class="periodo-box">
                <span class="periodo-label">📅 Período de Auditoria:</span>
                <span class="periodo-valor">{{ periodo }}</span>
            </div>

            <div class="alerta">
                <strong>⚠️ Auditoria de Hardware:</strong> Registra quando um MAC diferente do cadastrado é detectado em um IP.
                Indica substituição não documentada de equipamentos.
            </div>

            <div class="chart-container">
                <canvas id="chart"></canvas>
            </div>
        </div>
        <script>
            const subLabels = {{ sublabels|safe }};
            new Chart(document.getElementById('chart'), {
                type: 'doughnut',
                data: {
                    labels: {{ labels|safe }},
                    datasets: [{
                        data: {{ valores|safe }},
                        backgroundColor: ['#d32f2f', '#1a237e', '#fbc02d', '#455a64', '#2e7d32',
                                        '#ef6c00', '#0097a7', '#7b1fa2', '#5d4037', '#607d8b',
                                        '#c62828', '#283593', '#f9a825', '#37474f', '#1b5e20']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'right' },
                        tooltip: {
                            callbacks: {
                                afterLabel: function(c) {
                                    return subLabels[c.dataIndex] || '';
                                }
                            }
                        }
                    }
                }
            });
        </script>
    </body>
    </html>
    """, labels=labels, sublabels=sublabels, valores=valores, periodo=periodo_str)

@app.route('/grafico_camadas')
def grafico_camadas():
    """Gráfico 13: Análise de Camadas de Disponibilidade (3 estados) - Últimos 30 dias"""
    periodo_str = obter_periodo_dados(30)

    # BUSCAR QUANTIDADE REAL DE DISPOSITIVOS NO SISTEMA (igual a rota /)
    total_dispositivos_sistema = 0
    try:
        conn_total = sqlite3.connect(DB_NAME, timeout=5.0)
        conn_total.execute('PRAGMA query_only = ON;')
        cursor_total = conn_total.cursor()
        cursor_total.execute("""
            SELECT COUNT(*)
            FROM config_dispositivos
            WHERE ignorar = 0
        """)
        resultado_total = cursor_total.fetchone()
        if resultado_total:
            total_dispositivos_sistema = resultado_total[0]
        conn_total.close()
    except Exception as e:
        print(f"[GRAFICO-CAMADAS-TOTAL-ERROR] {e}", flush=True)
        total_dispositivos_sistema = 0

    # Verificar se usuário quer ver todos (modo expandido)
    modo_expandido = request.args.get('modo', 'filtro') == 'todos'

    dados = []

    # Bloco principal de queries
    try:
        if modo_expandido:
            # MODO TODOS: Retorna todos os IPs que apareceram nos logs
            dados = query_db("""
                SELECT
                    ip,
                    nome,
                    SUM(CASE WHEN status = 'ONLINE' AND web = 'OK' THEN 1 ELSE 0 END) as online_ok,
                    SUM(CASE WHEN status = 'ONLINE' AND web = 'FALHA' THEN 1 ELSE 0 END) as online_falha,
                    SUM(CASE WHEN status = 'OFFLINE' THEN 1 ELSE 0 END) as offline,
                    COUNT(*) as total
                FROM logs_status
                WHERE DATE(timestamp) >= DATE('now', '-30 days')
                GROUP BY ip
                HAVING total > 0
                ORDER BY
                    (online_falha + offline) DESC,
                    offline DESC,
                    ip ASC
            """, timeout=15.0)

            # Converter para lista mutável
            dados = list(dados) if dados else []

            # Buscar IPs cadastrados que não aparecem nos logs (nunca logados)
            ips_com_logs = [d[0] for d in dados if len(d) > 0]

            try:
                conn_faltantes = sqlite3.connect(DB_NAME, timeout=5.0)
                conn_faltantes.execute('PRAGMA query_only = ON;')
                cursor_faltantes = conn_faltantes.cursor()

                if ips_com_logs:
                    placeholders = ','.join(['?' for _ in ips_com_logs])
                    cursor_faltantes.execute(f"""
                        SELECT ip, nome
                        FROM config_dispositivos
                        WHERE ignorar = 0 AND ip NOT IN ({placeholders})
                    """, ips_com_logs)
                else:
                    cursor_faltantes.execute("""
                        SELECT ip, nome
                        FROM config_dispositivos
                        WHERE ignorar = 0
                    """)

                faltantes = cursor_faltantes.fetchall()
                conn_faltantes.close()

                # Adiciona IPs nunca logados com contagem zero
                for ip, nome in faltantes:
                    dados.append((ip, nome, 0, 0, 0, 0))

                # Reordena: problemáticos primeiro, depois por IP
                dados = sorted(dados, key=lambda x: (x[3] + x[4] if len(x) > 4 else 0, x[4] if len(x) > 4 else 0), reverse=True)

            except Exception as e2:
                print(f"[GRAFICO-CAMADAS-FALTANTES-ERROR] {e2}", flush=True)

            modo_texto = f"TODOS OS DISPOSITIVOS ({len(dados)} de {total_dispositivos_sistema})"

        else:
            # MODO FILTRO INTELIGENTE: Mostra apenas IPs com problemas ou variação
            dados = query_db("""
                SELECT
                    ip,
                    nome,
                    SUM(CASE WHEN status = 'ONLINE' AND web = 'OK' THEN 1 ELSE 0 END) as online_ok,
                    SUM(CASE WHEN status = 'ONLINE' AND web = 'FALHA' THEN 1 ELSE 0 END) as online_falha,
                    SUM(CASE WHEN status = 'OFFLINE' THEN 1 ELSE 0 END) as offline,
                    COUNT(*) as total
                FROM logs_status
                WHERE DATE(timestamp) >= DATE('now', '-30 days')
                GROUP BY ip
                HAVING
                    total > 0
                    AND (
                        online_falha > 0
                        OR offline > 0
                        OR (online_ok < total)
                    )
                ORDER BY
                    (online_falha + offline) DESC,
                    offline DESC,
                    ip ASC
                LIMIT 50
            """, timeout=10.0)

            dados = list(dados) if dados else []
            modo_texto = f"DISPOSITIVOS COM VARIAÇÃO ({len(dados)} de {total_dispositivos_sistema})"

    except Exception as e:
        print(f"[GRAFICO-CAMADAS-ERROR] {e}", flush=True)
        dados = []
        modo_texto = "ERRO AO CARREGAR"

    if not dados:
        dados = [('192.168.0.1', 'Sem Dados', 0, 0, 0, 0)]

    # Calcular estatísticas
    total_ips_analisados = len(dados)
    total_online_ok = sum([int(d[2]) if len(d) > 2 and d[2] else 0 for d in dados])
    total_online_falha = sum([int(d[3]) if len(d) > 3 and d[3] else 0 for d in dados])
    total_offline = sum([int(d[4]) if len(d) > 4 and d[4] else 0 for d in dados])
    total_geral = total_online_ok + total_online_falha + total_offline

    # Contar IPs por categoria de saúde
    ips_perfeitos = sum([1 for d in dados if len(d) > 4 and d[3] == 0 and d[4] == 0 and d[2] > 0])
    ips_com_falha_web = sum([1 for d in dados if len(d) > 3 and d[3] > 0])
    ips_offline = sum([1 for d in dados if len(d) > 4 and d[4] > 0])

    sla_rede = round((total_online_ok + total_online_falha) / total_geral * 100, 2) if total_geral > 0 else 0
    sla_servico = round(total_online_ok / total_geral * 100, 2) if total_geral > 0 else 0
    gap_tecnico = round(total_online_falha / total_geral * 100, 2) if total_geral > 0 else 0

    # Preparar dados para o gráfico
    labels = json.dumps([f"{(d[1] if len(d) > 1 and d[1] else 'Desconhecido')} ({d[0]})" for d in dados])
    valores_online_ok = json.dumps([int(d[2]) if len(d) > 2 and d[2] else 0 for d in dados])
    valores_online_falha = json.dumps([int(d[3]) if len(d) > 3 and d[3] else 0 for d in dados])
    valores_offline = json.dumps([int(d[4]) if len(d) > 4 and d[4] else 0 for d in dados])

    # URL para alternar modo
    url_alternativa = "/grafico_camadas?modo=todos" if not modo_expandido else "/grafico_camadas?modo=filtro"
    texto_botao = f"📊 Ver Todos os Dispositivos ({total_dispositivos_sistema})" if not modo_expandido else "🔍 Voltar ao Filtro Inteligente"
    cor_botao = "#6a1b9a" if not modo_expandido else "#2e7d32"

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>13. Análise de Camadas de Disponibilidade (3 Estados)</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: 'Segoe UI', sans-serif; background: #f0f2f5; padding: 20px; margin: 0; }
            .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
            h1 { color: #6a1b9a; margin-bottom: 5px; }
            .btn-back { text-decoration: none; color: white; background: #d32f2f; padding: 10px 20px; border-radius: 20px; font-weight: bold; display: inline-block; margin-bottom: 20px; }
            .chart-container { position: relative; height: {% if modo_expandido %}800px{% else %}600px{% endif %}; margin-top: 20px; }
            .periodo-box {
                background: linear-gradient(135deg, #f3e5f5 0%, #e1bee7 100%);
                padding: 15px 20px;
                border-radius: 8px;
                margin-bottom: 20px;
                border-left: 4px solid #6a1b9a;
                display: flex;
                align-items: center;
                justify-content: space-between;
                flex-wrap: wrap;
                gap: 10px;
            }
            .periodo-label { font-weight: bold; color: #4a148c; }
            .periodo-valor { color: #6a1b9a; font-size: 1.1em; }
            .modo-atual {
                background: #6a1b9a;
                color: white;
                padding: 5px 12px;
                border-radius: 15px;
                font-size: 0.85em;
                font-weight: bold;
            }
            .btn-alternar {
                text-decoration: none;
                color: white;
                padding: 12px 25px;
                border-radius: 25px;
                font-weight: bold;
                display: inline-block;
                transition: 0.3s;
                box-shadow: 0 4px 10px rgba(0,0,0,0.2);
            }
            .btn-alternar:hover { transform: translateY(-2px); box-shadow: 0 6px 15px rgba(0,0,0,0.3); }
            .metricas-gerais {
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 15px;
                margin-bottom: 25px;
            }
            .metrica-box {
                padding: 15px;
                border-radius: 10px;
                text-align: center;
                color: white;
            }
            .metrica-rede { background: linear-gradient(135deg, #2e7d32 0%, #1b5e20 100%); }
            .metrica-servico { background: linear-gradient(135deg, #1565c0 0%, #0d47a1 100%); }
            .metrica-gap { background: linear-gradient(135deg, #ef6c00 0%, #e65100 100%); }
            .metrica-ips { background: linear-gradient(135deg, #6a1b9a 0%, #4a148c 100%); }
            .metrica-valor { font-size: 2em; font-weight: bold; margin: 8px 0; }
            .metrica-label { font-size: 0.8em; opacity: 0.9; text-transform: uppercase; letter-spacing: 0.5px; }
            .resumo-categorias {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 15px;
                margin-bottom: 25px;
                background: #fafafa;
                padding: 20px;
                border-radius: 10px;
                border: 2px solid #e0e0e0;
            }
            .categoria-box {
                text-align: center;
                padding: 15px;
                border-radius: 8px;
                border-left: 4px solid;
            }
            .cat-perfeito { border-color: #2e7d32; background: #e8f5e9; }
            .cat-falhaweb { border-color: #fbc02d; background: #fffde7; }
            .cat-offline { border-color: #d32f2f; background: #ffebee; }
            .cat-numero { font-size: 1.8em; font-weight: bold; margin-bottom: 5px; }
            .cat-label { font-size: 0.85em; color: #555; }
            .explicacao {
                background: #fafafa;
                padding: 20px;
                border-radius: 8px;
                margin-bottom: 20px;
                border: 1px solid #e0e0e0;
            }
            .explicacao h3 { color: #6a1b9a; margin-top: 0; }
            .legenda-cor { display: inline-block; width: 20px; height: 20px; border-radius: 4px; margin-right: 8px; vertical-align: middle; }
            .cor-ok { background: #2e7d32; }
            .cor-falha { background: #fbc02d; }
            .cor-offline { background: #d32f2f; }
            .aviso-modo {
                background: {% if modo_expandido %}#fff3e0{% else %}#e8f5e9{% endif %};
                border-left: 4px solid {% if modo_expandido %}#ef6c00{% else %}#2e7d32{% endif %};
                padding: 12px 15px;
                margin-bottom: 20px;
                border-radius: 6px;
                color: {% if modo_expandido %}#e65100{% else %}#1b5e20{% endif %};
                font-size: 0.95em;
            }
            @media (max-width: 768px) {
                .metricas-gerais { grid-template-columns: repeat(2, 1fr); }
                .resumo-categorias { grid-template-columns: 1fr; }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/relatorios" class="btn-back">⬅ Voltar ao Menu</a>
            <h1>🔬 13. Análise de Camadas de Disponibilidade (3 Estados)</h1>

            <div class="periodo-box">
                <div>
                    <span class="periodo-label">📅 Período de Análise:</span>
                    <span class="periodo-valor">{{ periodo }}</span>
                </div>
                <span class="modo-atual">{{ modo_texto }}</span>
            </div>

            <div class="aviso-modo">
                {% if modo_expandido %}
                <strong>⚠️ Modo Completo Ativo:</strong> Mostrando todos os {{ total_ips }} dispositivos cadastrados no sistema.
                O carregamento pode ser lento e o gráfico extenso. Use o botão abaixo para voltar ao filtro inteligente.
                {% else %}
                <strong>✅ Filtro Inteligente Ativo:</strong> Mostrando {{ total_ips }} dispositivos que apresentaram variação
                (tiveram pelo menos uma falha ou indisponibilidade). IPs 100% saudáveis estão ocultos para focar nos problemas.
                {% endif %}
            </div>

            <div style="text-align: center; margin-bottom: 25px;">
                <a href="{{ url_alternativa }}" class="btn-alternar" style="background: {{ cor_botao }};">
                    {{ texto_botao }}
                </a>
            </div>

            <div class="metricas-gerais">
                <div class="metrica-box metrica-rede">
                    <div class="metrica-label">SLA Rede</div>
                    <div class="metrica-valor">{{ sla_rede }}%</div>
                    <small>Ping respondendo</small>
                </div>
                <div class="metrica-box metrica-servico">
                    <div class="metrica-label">SLA Serviço</div>
                    <div class="metrica-valor">{{ sla_servico }}%</div>
                    <small>Web acessível</small>
                </div>
                <div class="metrica-box metrica-gap">
                    <div class="metrica-label">Gap Técnico</div>
                    <div class="metrica-valor">{{ gap_tecnico }}%</div>
                    <small>Sem web, com ping</small>
                </div>
                <div class="metrica-box metrica-ips">
                    <div class="metrica-label">IPs Visíveis</div>
                    <div class="metrica-valor">{{ total_ips }}</div>
                    <small>{% if modo_expandido %}de 184+ total{% else %}com problemas{% endif %}</small>
                </div>
            </div>

            <div class="resumo-categorias">
                <div class="categoria-box cat-perfeito">
                    <div class="cat-numero" style="color: #2e7d32;">{{ ips_perfeitos }}</div>
                    <div class="cat-label">✅ 100% ONLINE & OK<br><small>(Sem nenhuma falha)</small></div>
                </div>
                <div class="categoria-box cat-falhaweb">
                    <div class="cat-numero" style="color: #f57f17;">{{ ips_com_falha_web }}</div>
                    <div class="cat-label">⚠️ Com Falha de Web<br><small>(Ping OK, sem interface)</small></div>
                </div>
                <div class="categoria-box cat-offline">
                    <div class="cat-numero" style="color: #c62828;">{{ ips_offline }}</div>
                    <div class="cat-label">❌ Com OFFLINEs<br><small>(Quedas de rede)</small></div>
                </div>
            </div>

            <div class="explicacao">
                <h3>📊 Como interpretar este gráfico:</h3>
                <p>
                    <span class="legenda-cor cor-ok"></span> <strong>ONLINE & OK (Verde):</strong> Ping responde E interface web abre. 100% funcional.<br>
                    <span class="legenda-cor cor-falha"></span> <strong>ONLINE & FALHA (Amarelo):</strong> Ping responde, mas web não abre. Problema de serviço.<br>
                    <span class="legenda-cor cor-offline"></span> <strong>OFFLINE (Vermelho):</strong> Ping não responde. Problema de rede/energia/hardware.
                </p>
                <p><strong>Dica:</strong> No modo filtro, você vê apenas dispositivos que precisam de atenção.
                No modo completo, vê todos incluindo os perfeitos (que só aparecem na barra verde).</p>
            </div>

            <div class="chart-container">
                <canvas id="chart"></canvas>
            </div>
        </div>
        <script>
            new Chart(document.getElementById('chart'), {
                type: 'bar',
                data: {
                    labels: {{ labels|safe }},
                    datasets: [
                        {
                            label: 'ONLINE & OK (Ping + Web)',
                            data: {{ valores_online_ok|safe }},
                            backgroundColor: '#2e7d32',
                            stack: 'Stack 0'
                        },
                        {
                            label: 'ONLINE & FALHA (Ping sem Web)',
                            data: {{ valores_online_falha|safe }},
                            backgroundColor: '#fbc02d',
                            stack: 'Stack 0'
                        },
                        {
                            label: 'OFFLINE (Sem Ping)',
                            data: {{ valores_offline|safe }},
                            backgroundColor: '#d32f2f',
                            stack: 'Stack 0'
                        }
                    ]
                },
                options: {
                    indexAxis: 'y',
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        title: {
                            display: true,
                            text: '{% if modo_expandido %}Todos os Dispositivos{% else %}Dispositivos com Variação (Filtro Inteligente){% endif %} - Empilhado por Estado',
                            font: { size: 16 }
                        },
                        tooltip: {
                            callbacks: {
                                footer: function(tooltipItems) {
                                    let total = 0;
                                    tooltipItems.forEach(function(tooltipItem) {
                                        total += tooltipItem.raw;
                                    });
                                    return 'Total de checagens: ' + total;
                                }
                            }
                        }
                    },
                    scales: {
                        x: {
                            stacked: true,
                            title: { display: true, text: 'Quantidade de Checagens (últimos 30 dias)' }
                        },
                        y: {
                            stacked: true,
                            title: { display: true, text: 'Dispositivos' },
                            ticks: {
                                font: {
                                    size: {% if modo_expandido %}9{% else %}11{% endif %}
                                }
                            }
                        }
                    }
                }
            });
        </script>
    </body>
    </html>
    """,
    labels=labels,
    valores_online_ok=valores_online_ok,
    valores_online_falha=valores_online_falha,
    valores_offline=valores_offline,
    sla_rede=sla_rede,
    sla_servico=sla_servico,
    gap_tecnico=gap_tecnico,
    total_ips=total_ips_analisados,
    ips_perfeitos=ips_perfeitos,
    ips_com_falha_web=ips_com_falha_web,
    ips_offline=ips_offline,
    periodo=periodo_str,
    modo_expandido=modo_expandido,
    modo_texto=modo_texto,
    url_alternativa=url_alternativa,
    texto_botao=texto_botao,
    cor_botao=cor_botao
)


@app.route('/auditoria_detalhada')
def auditoria_detalhada():
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        # Seleciona os dados da tabela de auditoria
        cursor.execute("SELECT id, timestamp, ip, nome_setor, fabricante_antigo, modelo_antigo, mac_antigo, mac_novo FROM auditoria_hardware ORDER BY timestamp DESC LIMIT 200")
        logs = cursor.fetchall()
        conn.close()
    except Exception as e:
        return f"Erro ao acessar banco de dados: {e}"

    return render_template_string("""
    <!DOCTYPE html><html><head><title>Log de Auditoria</title>
    <style>
        body{font-family:sans-serif;padding:20px;background:#f4f7f6;}
        table{width:100%;border-collapse:collapse;background:white;box-shadow: 0 2px 5px rgba(0,0,0,0.1);}
        th,td{padding:12px;border:1px solid #ddd;font-size:13px;text-align:left;}
        th{background:#1a237e;color:white;}
        tr:nth-child(even){background-color: #f9f9f9;}
        .filter-container{background:white;padding:15px;border-radius:8px;margin-bottom:15px;display:flex;gap:10px;align-items:center;}
        .no-data{padding:20px; text-align:center; color:#666; font-style:italic;}
    </style></head>
    <body>
        <h2>🛡️ Histórico de Auditoria de Hardware (Mundo Real)</h2>
        <div style="margin-bottom:20px;">
            <a href="/" style="text-decoration:none; background:#1a237e; color:white; padding:8px 15px; border-radius:5px;">⬅ Voltar ao Painel</a>
        </div>
        <div class="filter-container">
            <strong>Filtros rápidos:</strong>
            <input type="text" id="fIP" placeholder="Filtrar por IP..." onkeyup="filtrar()" style="padding:8px; width:200px;">
            <input type="text" id="fSetor" placeholder="Filtrar por Setor/Nome..." onkeyup="filtrar()" style="padding:8px; width:200px;">
        </div>
        <table id="tab">
            <thead>
                <tr>
                    <th>Data/Hora</th>
                    <th>Endereço IP</th>
                    <th>Setor/Dispositivo</th>
                    <th>MAC Oficial (Esperado)</th>
                    <th>MAC Detectado (Novo)</th>
                </tr>
            </thead>
            <tbody>
            {% for log in logs %}
                <tr>
                    <td>{{log[1]}}</td>
                    <td><b>{{log[2]}}</b></td>
                    <td>{{log[3]}}</td>
                    <td><code style="color:#2e7d32">{{log[6]}}</code></td>
                    <td><code style="color:#d32f2f; font-weight:bold;">{{log[7]}}</code></td>
                </tr>
            {% else %}
                <tr><td colspan="5" class="no-data">Nenhuma troca de hardware registrada até o momento.</td></tr>
            {% endfor %}
            </tbody>
        </table>
        <script>
            function filtrar() {
                let ip = document.getElementById('fIP').value.toLowerCase();
                let setor = document.getElementById('fSetor').value.toLowerCase();
                let rows = document.querySelectorAll('#tab tbody tr');
                rows.forEach(r => {
                    let textoIP = r.cells[1] ? r.cells[1].innerText.toLowerCase() : '';
                    let textoSetor = r.cells[2] ? r.cells[2].innerText.toLowerCase() : '';
                    r.style.display = (textoIP.includes(ip) && textoSetor.includes(setor)) ? '' : 'none';
                });
            }
        </script>
    </body></html>""", logs=logs)
# ================= ROTA: MANUTENÇÃO DE LOGS =================

@app.route('/manutencao_logs')
def manutencao_logs():
    return render_template_string("""
    <!DOCTYPE html><html><head><title>Manutenção de Logs</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
        body { font-family: sans-serif; background: #f4f7f6; padding: 20px; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); max-width: 600px; margin: auto; }
        .danger { background: #d32f2f; color: white; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        input, select { padding: 8px; margin: 5px 0; width: 100%; box-sizing: border-box; }
        .btn { padding: 10px; border: none; border-radius: 5px; cursor: pointer; font-weight: bold; width: 100%; margin-top: 10px; color: white; }
        .btn-backup { background: #2e7d32; }
        .btn-del { background: #c62828; }
        .btn-back { background: #1a237e; display: block; text-align: center; text-decoration: none; margin-bottom: 10px; }
        .saude-box-extra { text-align: center; font-size: 1.2em; font-weight: bold; margin: 15px 0; padding: 10px; border: 1px dashed #ccc; border-radius: 5px; }
        .cor-saudavel { color: #2e7d32; }
        .cor-alerta { color: #fbc02d; }
        .cor-perigosa { color: #d32f2f; animation: blink 0.5s infinite; }
        .info-nota { font-size: 0.85em; color: #555; background: #fff9c4; padding: 10px; border-left: 4px solid #fbc02d; margin: 10px 0; }
        @keyframes blink { 0% { opacity: 1; } 50% { opacity: 0.3; } 100% { opacity: 1; } }
    </style></head>
    <body>
        <div class="card">
            <a href="/" class="btn btn-back">⬅ Voltar</a>
            <h2>🧹 Manutenção e Backup de Dados</h2>
            <div id="saude-sistema-manut" class="saude-box-extra">Saúde do Sistema: Aguardando...</div>
            <div class="danger"><b>CUIDADO:</b> A deleção é permanente. Sempre faça um backup externo antes de limpar o banco de dados.</div>

            <h3>1. Backup de Segurança (Via Navegador)</h3>
            <div class="info-nota">
                💡 <b>Dica:</b> Para escolher o local de destino, certifique-se de que a opção "Perguntar onde salvar cada arquivo" esteja ativada nas configurações do seu navegador.
            </div>
            <p>Ao clicar abaixo, o navegador receberá o fluxo direto de dados para download.</p>
            <button class="btn btn-backup" onclick="baixarDB()">📥 Iniciar Download de Segurança</button>
            <hr>

            <h3>2. Deleção Seletiva</h3>
            <p>Selecione a data limite. Todos os logs <b>ANTERIORES</b> a esta data serão removidos.</p>
            <label>Data e Hora Limite:</label>
            <input type="datetime-local" id="data_limite">
            <button class="btn btn-del" onclick="deletarLogs()">🗑️ Deletar Logs Antigos</button>
        </div>
        <audio id="somAlertaManut" src="/audio/perigo.mp3" preload="auto"></audio>
        <script>
            var socket = io();
            function baixarDB() {
                window.location.href = '/api/download_db';
            }
            function deletarLogs() {
                const data = document.getElementById('data_limite').value;
                if(!data) { alert("Selecione uma data!"); return; }
                if(confirm("TEM CERTEZA? Isso apagará todos os logs anteriores a " + data)) {
                    fetch('/api/limpar_logs_manual', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({data: data.replace('T', ' ') + ':00'})
                    }).then(r => r.json()).then(d => alert(d.msg));
                }
            }
            socket.on('atualizar_dados', function(msg) {
                const saude = msg.saude;
                const div = document.getElementById('saude-sistema-manut');
                let classeCor = "cor-saudavel";
                if (msg.saude) {
                    let saudeElement = document.getElementById('saude-valor');
                    let percentual = msg.saude.risco_percent; // ou msg.saude.saude_percentual

                    saudeElement.innerHTML = percentual + '%';

                    // LIMPEZA E AJUSTE DE CORES:
                    saudeElement.classList.remove('saude-bom', 'saude-alerta', 'saude-critica');

                    if (percentual >= 85) {
                        saudeElement.style.color = "#2ecc71"; // Verde para 90%
                        saudeElement.style.animation = "none"; // Garante que não pisca
                    } else if (percentual >= 50) {
                        saudeElement.style.color = "#f1c40f"; // Amarelo
                        saudeElement.style.animation = "none";
                    } else {
                        saudeElement.style.color = "#e74c3c"; // Vermelho apenas abaixo de 50%
                        saudeElement.style.animation = "blinker 1.5s linear infinite";
                    }
                }                div.innerHTML = `🛡️ Saúde do Sistema: <span class="${classeCor}">${saude.risco_percent}%</span>`;
            });
        </script>
    </body></html>
    """)

@app.route('/api/download_db')
def download_db():
    try:
        nome_arquivo_download = f"backup_rede_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        return send_file(
            DB_NAME,
            as_attachment=True,
            download_name=nome_arquivo_download,
            mimetype='application/octet-stream'
        )
    except Exception as e:
        return f"Erro ao gerar stream de download: {e}", 500

@app.route('/api/limpar_logs_manual', methods=['POST'])
def limpar_logs_manual():
    data_limite = request.json.get('data')
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM logs_status WHERE timestamp < ?", (data_limite,))
        cursor.execute("DELETE FROM auditoria_hardware WHERE timestamp < ?", (data_limite,))
        removidos = cursor.rowcount
        conn.commit()
        cursor.execute("VACUUM")
        conn.close()
        return jsonify({"status": "sucesso", "msg": f"Sucesso! {removidos} registros removidos. O banco foi otimizado."})
    except Exception as e:
        return jsonify({"status": "erro", "msg": f"Erro: {str(e)}"})

# ================= CONFIGURAÇÃO E APIS =================

@app.route('/config')
def config_page():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM config_dispositivos")
    dispositivos = cursor.fetchall()
    cursor.execute("SELECT valor FROM controle_sistema WHERE chave = 'ultima_atualizacao_mac'")
    res = cursor.fetchone()
    v_mac = res[0] if res else "Nunca atualizada"

    # NOVO: Buscar tipos dinâmicos do banco (apenas ativos)
    cursor.execute("SELECT nome FROM tipos_dispositivos WHERE ativo=1 ORDER BY ordem, nome")
    tipos_dinamicos = [row[0] for row in cursor.fetchall()]

    conn.close()

    # Obtém a versão da biblioteca mac-vendor-lookup
    versao_biblioteca_mac = "Não instalada"
    try:
        import pkg_resources
        versao_biblioteca_mac = pkg_resources.get_distribution("mac-vendor-lookup").version
    except Exception:
        try:
            import subprocess
            resultado = subprocess.check_output(["pip", "show", "mac-vendor-lookup"], universal_newlines=True)
            for linha in resultado.split('\n'):
                if linha.startswith('Version:'):
                    versao_biblioteca_mac = linha.split(':')[1].strip()
                    break
        except Exception:
            versao_biblioteca_mac = "Desconhecida"

    dispositivos_ordenados = sorted(dispositivos, key=lambda x: int(x[0].split('.')[-1]))

    # NOVO: Passar tipos dinâmicos para o template
    return render_template_string(HTML_CONFIG,
                                  dispositivos=dispositivos_ordenados,
                                  versao_mac=v_mac,
                                  versao_lib_mac=versao_biblioteca_mac,
                                  tipos_disponiveis=tipos_dinamicos)

@app.route('/api/config_update', methods=['POST'])
def config_update():
    """
    Atualiza as configurações de um dispositivo no banco de dados.
    Adaptada do monitor_rede_v2.py para compatibilidade com nomenclaturas do v3.
    """
    try:
        dados = request.json
        ip = dados.get('ip')

        # Coleta de dados preservando todas as colunas de hardware solicitadas
        nome = dados.get('nome')
        fabricante = dados.get('fabricante')
        marca = dados.get('marca')
        modelo = dados.get('modelo')
        especificacoes = dados.get('especificacoes')
        mac_oficial = dados.get('mac')  # No v2 é 'mac', no v3 é 'mac_oficial'
        tipo = dados.get('tipo', 'Outros')
        ignorar = dados.get('ignorar', 0)

        if not ip:
            return jsonify({"status": "erro", "msg": "IP não fornecido"}), 400

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        # Update completo garantindo a integridade das colunas originais
        cursor.execute("""
            UPDATE config_dispositivos
            SET nome=?, fabricante=?, marca=?, modelo=?, especificacoes=?, mac_oficial=?, tipo=?, ignorar=?
            WHERE ip=?
        """, (nome, fabricante, marca, modelo, especificacoes, mac_oficial, tipo, ignorar, ip))

        conn.commit()
        conn.close()

        print(f"[CONFIG] Alterações salvas para o IP: {ip}", flush=True)
        return jsonify({"status": "sucesso", "msg": f"Configurações de {ip} atualizadas!"})
    except Exception as e:
        print(f"[ERROR] Falha ao salvar configurações: {e}", flush=True)
        return jsonify({"status": "erro", "msg": str(e)}), 500

@app.route('/api/save_all_devices', methods=['POST'])
def save_all_devices():
    """
    Atualiza múltiplos dispositivos de uma vez.
    Adaptada do monitor_rede_v2.py para compatibilidade com nomenclaturas do v3.
    """
    devices = request.json.get('devices', [])
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        for d in devices:
            cursor.execute("""UPDATE config_dispositivos
                              SET nome=?, fabricante=?, marca=?, modelo=?, especificacoes=?, mac_oficial=?, ignorar=?, tipo=?
                              WHERE ip=?""",
                         (d['nome'], d.get('fabricante',''), d.get('marca',''), d.get('modelo',''),
                          d.get('especificacoes',''), d['mac'], d.get('ignorar', 0), d.get('tipo', 'Outros'), d['ip']))
        conn.commit()
        conn.close()
        return jsonify({"status": "sucesso", "msg": f"Sucesso! {len(devices)} IPs foram atualizados simultaneamente."})
    except Exception as e:
        return jsonify({"status": "erro", "msg": str(e)}), 500

@app.route('/api/fix_mac', methods=['POST'])
def fix_mac():
    d = request.json
    ip = d.get('ip')
    novo_mac = d.get('mac')
    novo_fabricante = identificar_fabricante(novo_mac)
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("UPDATE config_dispositivos SET mac_oficial=?, fabricante=? WHERE ip=?", (novo_mac, novo_fabricante, ip))
    conn.commit()
    conn.close()
    with lock:
        if ip in status_atual:
            status_atual[ip]['mac_oficial'] = novo_mac
            status_atual[ip]['fabricante'] = novo_fabricante
            status_atual[ip]['mac_status'] = "OK"
    global historico_mac_alerta
    historico_mac_alerta[ip] = False
    return jsonify({"status": "sucesso", "msg": f"Hardware do IP {ip} atualizado para {novo_mac}!"})

@app.route('/api/update_mac_library')
def update_mac_library():
    try:
        if mac_identificador:
            if hasattr(mac_identificador, 'cache_path'):
                os.makedirs(os.path.dirname(mac_identificador.cache_path), exist_ok=True)
            mac_identificador.update_servers = ["https://standards-oui.ieee.org/oui/oui.txt"]
            if hasattr(mac_identificador, 'refresh'):
                mac_identificador.refresh()
            agora = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("UPDATE controle_sistema SET valor = ? WHERE chave = 'ultima_atualizacao_mac'", (agora,))
            conn.commit()
            conn.close()
            return jsonify({"status": "sucesso", "msg": f"Base de Fabricantes atualizada em: {agora}"})
        return jsonify({"status": "erro", "msg": "Objeto MacLookup não inicializado."})
    except Exception as e:
        return jsonify({"status": "erro", "msg": f"Erro ao atualizar: {str(e)}"})

@app.route('/api/backup')
def backup_api():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM config_dispositivos")
    colunas = [desc[0] for desc in cursor.description]
    dados = [dict(zip(colunas, row)) for row in cursor.fetchall()]
    conn.close()
    nome_arquivo = datetime.now().strftime("backup_roteadores_%d-%m-%Y_%H-%M-%S.json")
    with open(nome_arquivo, 'w', encoding='utf-8') as f:
        json.dump(dados, f, indent=4, ensure_ascii=False)
    return jsonify({"msg": f"Backup '{nome_arquivo}' gerado com sucesso!"})

HTML_CONFIG = """
<!DOCTYPE html><html><head><title>Configurações</title>
<style>
    body{font-family:sans-serif; background:#f0f2f5; padding:20px;}
    .card{background:white; padding:20px; border-radius:8px; box-shadow:0 2px 10px rgba(0,0,0,0.1);}
    table{width:100%; border-collapse:collapse; font-size:12px; margin-top:20px;}
    th,td{padding:8px; border:1px solid #ddd; text-align:left;}
    th{background:#1a237e; color:white;}
    .btn{padding:8px 12px; border:none; border-radius:4px; cursor:pointer; color:white; font-weight:bold; margin-right:5px;}
    .footer-cfg { margin-top: 15px; font-weight: bold; color: #1a237e; }
</style></head>
<body>
    <div class="card">
        <a href="/" style="text-decoration:none; color:#1a237e; font-weight:bold;">⬅ Voltar</a>
        <h2 style="color:#1a237e;">⚙️ Configurações de Inventário</h2>

        <div style="margin-bottom:15px;">
            <button onclick="selecionarTodosIgnorar()" class="btn" style="background:#455a64;">✅ Selecionar Todos p/ Ignorar</button>
            <button onclick="deselecionarTodosIgnorar()" class="btn" style="background:#455a64;">🚫 Desselecionar Todos p/ Ignorar</button>
            <button onclick="salvarTudo()" class="btn" style="background:#2e7d32;">💾 Salvar Tudo</button>
            <button onclick="gerarBackupJSON()" class="btn" style="background:#f57f17;">📥 Gerar Backup JSON</button>
            <button onclick="atualizarBaseMAC()" class="btn" style="background:#0288d1;">🔄 Atualizar Base MAC</button>
            <a href="/tipos" class="btn" style="background:#6a1b9a; text-decoration:none; display:inline-block;">🏷️ Gerenciar Tipos</a>
            <span style="font-size:12px; margin-left:10px;">
                Última atualização: <span id="last_upd">{{ versao_mac }}</span>
                <span style="color:#666; margin-left:15px;">|</span>
                <span style="color:#0288d1; font-weight:bold;">Lib MAC: {{ versao_lib_mac }}</span>
            </span>
        </div>

        <table>
            <thead>
                <tr>
                    <th>IP</th><th>Tipo</th><th>Dispositivo (Label)</th><th>Fabricante</th>
                    <th>Marca</th><th>Modelo</th><th>Especificações</th><th>MAC Oficial</th>
                    <th>Ignorar?</th><th>Ação</th>
                </tr>
            </thead>
            <tbody id="corpo">
                {% for d in dispositivos %}
                <tr data-ip="{{ d[0] }}">
                    <td><b>{{ d[0] }}</b></td>
                    <td>
                        <select class="tipo" id="t-{{ d[0]|replace('.','_') }}">
                            {% for tipo in tipos_disponiveis %}
                            <option value="{{ tipo }}" {% if d[8]==tipo %}selected{% endif %}>{{ tipo }}</option>
                            {% endfor %}
                        </select>
                    </td>
                    <td><input type="text" class="nome" id="n-{{ d[0]|replace('.','_') }}" value="{{ d[1] }}"></td>
                    <td><input type="text" class="fab" id="f-{{ d[0]|replace('.','_') }}" value="{{ d[2] }}"></td>
                    <td><input type="text" class="mar" id="mar-{{ d[0]|replace('.','_') }}" value="{{ d[3] }}"></td>
                    <td><input type="text" class="mod" id="mod-{{ d[0]|replace('.','_') }}" value="{{ d[4] }}"></td>
                    <td><input type="text" class="esp" id="esp-{{ d[0]|replace('.','_') }}" value="{{ d[5] }}"></td>
                    <td><input type="text" class="mac" id="mac-{{ d[0]|replace('.','_') }}" value="{{ d[6] }}"></td>
                    <td style="text-align:center;"><input type="checkbox" id="ign-{{ d[0]|replace('.','_') }}" class="check-ignorar" {% if d[7]==1 %}checked{% endif %}></td>
                    <td><button onclick="salvar('{{ d[0] }}')" style="background:#2e7d32; color:white; border:none; padding:5px; border-radius:3px; cursor:pointer;">💾</button></td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        <div class="footer-cfg">Total de IPs listados no Inventário: {{ dispositivos|length }}</div>
    </div>
    <script>
        function selecionarTodosIgnorar() {
            const checks = document.querySelectorAll('.check-ignorar');
            checks.forEach(c => c.checked = true);
        }

        function deselecionarTodosIgnorar() {
            const checks = document.querySelectorAll('.check-ignorar');
            checks.forEach(c => c.checked = false);
        }

        function salvarTudo() {
            if(!confirm("Deseja salvar as alterações de TODOS os dispositivos de uma vez?")) return;
            const rows = document.querySelectorAll('#corpo tr');
            const devices = [];

            rows.forEach(row => {
                const ip = row.getAttribute('data-ip');
                const id = ip.replace(/\\./g, '_');

                devices.push({
                    ip: ip,
                    nome: document.getElementById('n-'+id).value,
                    tipo: document.getElementById('t-'+id).value,
                    fabricante: document.getElementById('f-'+id).value,
                    marca: document.getElementById('mar-'+id).value,
                    modelo: document.getElementById('mod-'+id).value,
                    especificacoes: document.getElementById('esp-'+id).value,
                    mac: document.getElementById('mac-'+id).value,
                    ignorar: document.getElementById('ign-'+id).checked ? 1 : 0
                });
            });

            console.log("[DEBUG] Enviando todos os dados:", devices);

            fetch('/api/save_all_devices', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({devices: devices})
            }).then(r => r.json()).then(d => {
                if(d.status === 'sucesso') {
                    alert('✅ ' + d.msg);
                    location.reload();
                } else {
                    alert('❌ Erro: ' + d.msg);
                }
            }).catch(err => alert('Erro crítico: ' + err));
        }

        function salvar(ip) {
            const id = ip.replace(/\\./g, '_');

            const data = {
                ip: ip,
                nome: document.getElementById('n-' + id).value,
                fabricante: document.getElementById('f-' + id).value,
                marca: document.getElementById('mar-' + id).value,
                modelo: document.getElementById('mod-' + id).value,
                especificacoes: document.getElementById('esp-' + id).value,
                mac: document.getElementById('mac-' + id).value,
                ignorar: document.getElementById('ign-' + id).checked ? 1 : 0,
                tipo: document.getElementById('t-' + id).value
            };

            console.log("[DEBUG] Salvando dispositivo:", ip, data);

            fetch('/api/config_update', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            })
            .then(response => response.json())
            .then(result => {
                if (result.status === 'sucesso') {
                    alert('✅ Dispositivo ' + ip + ' atualizado com sucesso!');
                } else {
                    alert('❌ Erro ao salvar: ' + result.msg);
                }
            })
            .catch(error => {
                console.error('Erro:', error);
                alert('❌ Erro de comunicação com o servidor.');
            });
        }

        function atualizarBaseMAC() {
            if(confirm("Deseja baixar a lista de fabricantes atualizada da IEEE?")) {
                fetch('/api/update_mac_library')
                .then(r => r.json())
                .then(d => {
                    alert(d.msg);
                    if(d.status === 'sucesso') location.reload();
                });
            }
        }

        function gerarBackupJSON() {
    fetch('/api/backup')
    .then(r => r.json())
    .then(d => {
        alert('✅ ' + d.msg);
    })
    .catch(err => {
        alert('❌ Erro ao gerar backup: ' + err);
    });
}
    </script>
</body></html>
"""

def loop_monitor():
    enviar_telegram("🚀 **Monitoramento de Dispositivos 4.0 Ativo**")
    while True:
        verificar_rede()
        tempo_espera = 30

        # Avisa o frontend que a varredura terminou e o contador de 30s deve iniciar
        socketio.emit('reset_cronometro', {'segundos': tempo_espera})

        for i in range(tempo_espera):
            progresso = (i + 1) / tempo_espera
            barras = int(progresso * 20)
            espacos = 20 - barras
            sys.stdout.write(f"\rAguardando próxima varredura: [{'#' * barras}{'-' * espacos}] {tempo_espera - i}s  ")
            sys.stdout.flush()
            time.sleep(1)
        print("\r" + " " * 60 + "\r", end="")

@app.route('/')
def index():
    # Busca os tipos únicos cadastrados no banco de dados para popular o select
    tipos_disponiveis = []
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT tipo FROM config_dispositivos WHERE ignorar = 0 AND tipo IS NOT NULL")
        tipos_disponiveis = [row[0] for row in cursor.fetchall() if row[0]]
        conn.close()
    except Exception as e:
        print(f"[ERROR] Falha ao carregar tipos para o filtro: {e}")

    return render_template_string(HTML_TEMPLATE, tipos=tipos_disponiveis)

@app.route('/tipos')
def rota_tipos():
    """Página para gerenciar tipos de dispositivos dinamicamente"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, nome, descricao, cor, ativo, ordem FROM tipos_dispositivos ORDER BY ordem, nome")
    tipos = cursor.fetchall()
    conn.close()

    return render_template_string("""
    <!DOCTYPE html><html><head><title>Gerenciar Tipos de Dispositivos</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
        body{font-family:sans-serif; background:#f0f2f5; padding:20px;}
        .card{background:white; padding:20px; border-radius:8px; box-shadow:0 2px 10px rgba(0,0,0,0.1); max-width: 900px; margin: auto;}
        h2{color:#1a237e;}
        table{width:100%; border-collapse:collapse; font-size:13px; margin-top:15px;}
        th,td{padding:10px; border:1px solid #ddd; text-align:left;}
        th{background:#1a237e; color:white;}
        tr:nth-child(even){background-color: #f9f9f9;}
        .btn{padding:8px 15px; border:none; border-radius:4px; cursor:pointer; color:white; font-weight:bold; margin-right:5px;}
        .btn-add{background:#2e7d32;}
        .btn-edit{background:#0288d1;}
        .btn-del{background:#d32f2f;}
        .btn-back{background:#455a64; text-decoration:none; display:inline-block;}
        .form-row{display:flex; gap:10px; margin-bottom:10px; align-items:flex-end;}
        .form-group{flex:1;}
        .form-group label{display:block; margin-bottom:5px; font-weight:bold; color:#333; font-size:12px;}
        .form-group input, .form-group select{width:100%; padding:8px; border:1px solid #ccc; border-radius:4px; box-sizing:border-box;}
        .cor-preview{display:inline-block; width:20px; height:20px; border-radius:3px; vertical-align:middle; margin-left:5px; border:1px solid #ccc;}
        .ativo-sim{color:#2e7d32; font-weight:bold;}
        .ativo-nao{color:#d32f2f;}
        .info-box{background:#e3f2fd; padding:15px; border-radius:8px; margin-bottom:20px; border-left:4px solid #0288d1;}
    </style></head>
    <body>
        <div class="card">
            <a href="/config" class="btn btn-back">⬅ Voltar à Configuração</a>
            <h2>🏷️ Gerenciar Tipos de Dispositivos</h2>

            <div class="info-box">
                <strong>ℹ️ Informação:</strong> Os tipos cadastrados aqui aparecerão automaticamente no dropdown
                "Tipo" da página de configuração de dispositivos. Você pode adicionar, editar ou remover tipos conforme necessário.
            </div>

            <h3>➕ Adicionar Novo Tipo</h3>
            <div class="form-row">
                <div class="form-group">
                    <label>Nome do Tipo</label>
                    <input type="text" id="novo_nome" placeholder="Ex: Notebook">
                </div>
                <div class="form-group">
                    <label>Descrição (opcional)</label>
                    <input type="text" id="novo_desc" placeholder="Ex: Laptops e notebooks corporativos">
                </div>
                <div class="form-group" style="flex:0.5;">
                    <label>Cor</label>
                    <input type="color" id="novo_cor" value="#1a237e">
                </div>
                <div class="form-group" style="flex:0.3;">
                    <label>Ordem</label>
                    <input type="number" id="novo_ordem" value="0" min="0">
                </div>
                <button class="btn btn-add" onclick="adicionarTipo()">➕ Adicionar</button>
            </div>

            <h3>📋 Tipos Cadastrados</h3>
            <table>
                <thead>
                    <tr>
                        <th>Ordem</th>
                        <th>Nome</th>
                        <th>Descrição</th>
                        <th>Cor</th>
                        <th>Status</th>
                        <th>Ações</th>
                    </tr>
                </thead>
                <tbody>
                    {% for t in tipos %}
                    <tr data-id="{{ t[0] }}">
                        <td>{{ t[5] }}</td>
                        <td><strong>{{ t[1] }}</strong></td>
                        <td>{{ t[2] or '-' }}</td>
                        <td><span class="cor-preview" style="background:{{ t[3] }};"></span> {{ t[3] }}</td>
                        <td class="{{ 'ativo-sim' if t[4] == 1 else 'ativo-nao' }}">
                            {{ '✅ Ativo' if t[4] == 1 else '❌ Inativo' }}
                        </td>
                        <td>
                            <button class="btn btn-edit" onclick="editarTipo({{ t[0] }}, '{{ t[1] }}', '{{ t[2] or '' }}', '{{ t[3] }}', {{ t[4] }}, {{ t[5] }})" style="padding:5px 10px; font-size:11px;">✏️ Editar</button>
                            {% if t[1] != 'Outros' %}
                            <button class="btn btn-del" onclick="excluirTipo({{ t[0] }}, '{{ t[1] }}')" style="padding:5px 10px; font-size:11px;">🗑️ Excluir</button>
                            {% endif %}
                        </td>
                    </tr>
                    {% else %}
                    <tr><td colspan="6" style="text-align:center; padding:20px; color:#666;">Nenhum tipo cadastrado.</td></tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <!-- Modal de Edição -->
        <div id="modalEditar" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.5); z-index:1000;">
            <div style="background:white; max-width:500px; margin:100px auto; padding:20px; border-radius:8px; box-shadow:0 4px 20px rgba(0,0,0,0.3);">
                <h3>✏️ Editar Tipo</h3>
                <input type="hidden" id="edit_id">
                <div class="form-group" style="margin-bottom:10px;">
                    <label>Nome</label>
                    <input type="text" id="edit_nome">
                </div>
                <div class="form-group" style="margin-bottom:10px;">
                    <label>Descrição</label>
                    <input type="text" id="edit_desc">
                </div>
                <div class="form-group" style="margin-bottom:10px;">
                    <label>Cor</label>
                    <input type="color" id="edit_cor">
                </div>
                <div class="form-group" style="margin-bottom:10px;">
                    <label>Ordem</label>
                    <input type="number" id="edit_ordem" min="0">
                </div>
                <div class="form-group" style="margin-bottom:15px;">
                    <label><input type="checkbox" id="edit_ativo"> Ativo</label>
                </div>
                <div style="text-align:right;">
                    <button class="btn btn-back" onclick="fecharModal()" style="margin-right:10px;">Cancelar</button>
                    <button class="btn btn-edit" onclick="salvarEdicao()">Salvar Alterações</button>
                </div>
            </div>
        </div>

        <script>
            function adicionarTipo() {
                const nome = document.getElementById('novo_nome').value.trim();
                const desc = document.getElementById('novo_desc').value.trim();
                const cor = document.getElementById('novo_cor').value;
                const ordem = document.getElementById('novo_ordem').value;

                if(!nome) { alert('Digite um nome para o tipo!'); return; }

                fetch('/api/tipos', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({nome: nome, descricao: desc, cor: cor, ordem: ordem})
                }).then(r => r.json()).then(d => {
                    if(d.status === 'sucesso') {
                        alert('✅ ' + d.msg);
                        location.reload();
                    } else {
                        alert('❌ Erro: ' + d.msg);
                    }
                });
            }

            function editarTipo(id, nome, desc, cor, ativo, ordem) {
                document.getElementById('edit_id').value = id;
                document.getElementById('edit_nome').value = nome;
                document.getElementById('edit_desc').value = desc;
                document.getElementById('edit_cor').value = cor;
                document.getElementById('edit_ordem').value = ordem;
                document.getElementById('edit_ativo').checked = ativo === 1;
                document.getElementById('modalEditar').style.display = 'block';
            }

            function fecharModal() {
                document.getElementById('modalEditar').style.display = 'none';
            }

            function salvarEdicao() {
                const id = document.getElementById('edit_id').value;
                const dados = {
                    nome: document.getElementById('edit_nome').value.trim(),
                    descricao: document.getElementById('edit_desc').value.trim(),
                    cor: document.getElementById('edit_cor').value,
                    ordem: document.getElementById('edit_ordem').value,
                    ativo: document.getElementById('edit_ativo').checked ? 1 : 0
                };

                fetch('/api/tipos/' + id, {
                    method: 'PUT',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(dados)
                }).then(r => r.json()).then(d => {
                    if(d.status === 'sucesso') {
                        alert('✅ ' + d.msg);
                        location.reload();
                    } else {
                        alert('❌ Erro: ' + d.msg);
                    }
                });
            }

            function excluirTipo(id, nome) {
                if(!confirm('Tem certeza que deseja excluir o tipo "' + nome + '"?\\n\\n⚠️ Atenção: Dispositivos que usam este tipo continuarão funcionando, mas o tipo não aparecerá mais nas opções.')) return;

                fetch('/api/tipos/' + id, {
                    method: 'DELETE'
                }).then(r => r.json()).then(d => {
                    if(d.status === 'sucesso') {
                        alert('✅ ' + d.msg);
                        location.reload();
                    } else {
                        alert('❌ Erro: ' + d.msg);
                    }
                });
            }
        </script>
    </body></html>
    """, tipos=tipos)

@app.route('/api/tipos', methods=['POST'])
def api_tipos_create():
    """Cria um novo tipo de dispositivo"""
    try:
        dados = request.json
        nome = dados.get('nome', '').strip()
        descricao = dados.get('descricao', '').strip()
        cor = dados.get('cor', '#1a237e')
        ordem = dados.get('ordem', 0)

        if not nome:
            return jsonify({"status": "erro", "msg": "Nome do tipo é obrigatório"}), 400

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO tipos_dispositivos (nome, descricao, cor, ordem) VALUES (?, ?, ?, ?)",
            (nome, descricao, cor, ordem)
        )
        conn.commit()
        conn.close()

        return jsonify({"status": "sucesso", "msg": f"Tipo '{nome}' criado com sucesso!"})
    except sqlite3.IntegrityError:
        return jsonify({"status": "erro", "msg": f"Já existe um tipo com o nome '{nome}'"}), 400
    except Exception as e:
        return jsonify({"status": "erro", "msg": str(e)}), 500


@app.route('/api/tipos/<int:id>', methods=['PUT'])
def api_tipos_update(id):
    """Atualiza um tipo de dispositivo existente"""
    try:
        dados = request.json
        nome = dados.get('nome', '').strip()
        descricao = dados.get('descricao', '').strip()
        cor = dados.get('cor', '#1a237e')
        ordem = dados.get('ordem', 0)
        ativo = dados.get('ativo', 1)

        if not nome:
            return jsonify({"status": "erro", "msg": "Nome do tipo é obrigatório"}), 400

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute(
            """UPDATE tipos_dispositivos
               SET nome=?, descricao=?, cor=?, ordem=?, ativo=?
               WHERE id=?""",
            (nome, descricao, cor, ordem, ativo, id)
        )
        conn.commit()
        conn.close()

        return jsonify({"status": "sucesso", "msg": f"Tipo '{nome}' atualizado com sucesso!"})
    except sqlite3.IntegrityError:
        return jsonify({"status": "erro", "msg": f"Já existe outro tipo com o nome '{nome}'"}), 400
    except Exception as e:
        return jsonify({"status": "erro", "msg": str(e)}), 500

@app.route('/api/tipos/<int:id>', methods=['DELETE'])
def api_tipos_delete(id):
    """Remove um tipo de dispositivo"""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        # Verificar se é o tipo "Outros" (protegido)
        cursor.execute("SELECT nome FROM tipos_dispositivos WHERE id=?", (id,))
        resultado = cursor.fetchone()
        if resultado and resultado[0] == 'Outros':
            conn.close()
            return jsonify({"status": "erro", "msg": "O tipo 'Outros' não pode ser excluído (proteção do sistema)"}), 400

        cursor.execute("DELETE FROM tipos_dispositivos WHERE id=?", (id,))
        conn.commit()
        conn.close()

        return jsonify({"status": "sucesso", "msg": "Tipo excluído com sucesso!"})
    except Exception as e:
        return jsonify({"status": "erro", "msg": str(e)}), 500

if __name__ == "__main__":
    init_db()

    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

    print("\n[SYSTEM] Iniciando serviços v5.0...", flush=True)
    varredura_inicial()

    threading.Thread(target=loop_monitor, daemon=True).start()
    threading.Thread(target=lambda: (time.sleep(3), webbrowser.open(LINK_ACESSO)), daemon=True).start()

    print(f"[INFO] Monitoramento de Saúde: Ativado (SSD + Trava DB {LIMITE_ALERTA_DB_MB}MB)", flush=True)
    socketio.run(app, host='0.0.0.0', port=PORTA_WEB, debug=False, allow_unsafe_werkzeug=True)

# FINAL DO ARQUIVO: TOTAL DE LINHAS EXPANDIDO PARA SUPORTAR BI E RESPONSIVIDADE.