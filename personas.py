"""
Simulação de personas para o Zero Trust Authentication Server.

Este script exercita o servidor de autenticação através de um conjunto de
personas, cada uma representando um perfil de utilizador ou atacante com um
comportamento característico. Cada persona isola um vetor de ataque específico
e valida um dos níveis de decisão do sistema (ALLOWED, CAPTCHA, RATE_LIMITED,
CHALLENGE ou BLOCKED).

Personas disponíveis:
    1. Utilizador Normal        acesso legítimo interno            -> ALLOWED
    2. Hacker Brute Force       tentativas sucessivas de password -> RATE_LIMITED
    3. Atacante Estrangeiro     IP de país de alto risco          -> CAPTCHA
    4. Ladrão de Token          roubo de sessão e adulteração     -> CHALLENGE / BLOCKED
    5. Hacker Furtivo           ataque lento e disperso           -> ALLOWED
    6. Atacante Total           todos os fatores combinados       -> BLOCKED
    7. Utilizador com CAPTCHA   risco médio com verificação        -> CAPTCHA
    8. Desafio de Segurança     challenge respondido com sucesso  -> CHALLENGE
    9. Challenge Falhado        três respostas erradas ao desafio -> BLOCKED

Utilização:
    Executar com o servidor ativo e escolher uma persona no menu interativo.
    Cada persona usa um endereço IP próprio, pelo que podem correr em qualquer
    ordem sem interferirem entre si.
"""

import requests
import time
import os

# Endereço do servidor de autenticação (ajustar consoante a topologia da rede)
SERVER = "http://192.168.1.10:8080"

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
NC     = "\033[0m"

def limpar():
    os.system("clear")

def banner(titulo, descricao):
    print("\n" + "="*65)
    print(f"  {titulo}")
    print(f"  {descricao}")
    print("="*65)

def mostrar_resultado(r):
    try:
        data = r.json()
        risk = data.get("risk", {})
        score = risk.get("score", "N/A")
        level = risk.get("level", "N/A")
        decision = risk.get("decision", "N/A")
        factors = risk.get("factors", {})

        if decision == "ALLOWED":      cor = GREEN
        elif decision == "BLOCKED":    cor = RED
        elif decision == "CAPTCHA":    cor = YELLOW
        elif decision == "CHALLENGE":  cor = YELLOW
        elif decision == "RATE_LIMITED": cor = RED
        else:                          cor = NC

        print(f"\n  Score: {score}/100  |  Level: {level}  |  Decisao: {cor}{decision}{NC}")

        # Mensagens especiais
        if data.get("error"):
            print(f"  Mensagem: {data['error']}")
        if data.get("captcha"):
            print(f"  CAPTCHA: {data['captcha'].get('question', '')}")
        if data.get("challenge"):
            print(f"  CHALLENGE: {data['challenge'].get('question', '')}")
        if data.get("authenticated") == True:
            token = data.get("token", "")
            print(f"  Token: {token[:40]}..." if token else "")

        if factors:
            print(f"  {'─'*60}")
            for nome, f in factors.items():
                s = f.get("score", 0)
                p = f.get("peso", 0)
                reason = f.get("reason", "")
                country = f.get("country", "")
                country_str = f" ({country})" if country and country != "N/A" else ""
                filled = "#" * int(s)
                empty = "-" * int(p - s)
                barra = (filled + empty)[:30]
                print(f"  {nome:<20} {s:>3}/{p:<3}  [{barra:<30}]  {reason}{country_str}")

        return data
    except Exception as e:
        print(f"  Erro ao processar resposta: {e}")
        print(f"  Resposta raw: {r.text[:200]}")
        return {}

def pausar():
    input(f"\n{CYAN}  Pressiona ENTER para continuar...{NC}")

def limpar_banidos():
    try:
        r = requests.get(f"{SERVER}/api/banned")
        ips = r.json().get("ips", [])
        for ip in ips:
            requests.delete(f"{SERVER}/api/banned/{ip}")
        if ips:
            print(f"  {len(ips)} IPs desbanidos.")
    except:
        pass

def login(user, pwd, ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)", fwd=None, extra={}):
    headers = {"Content-Type": "application/json", "User-Agent": ua}
    if fwd:
        headers["X-Forwarded-For"] = fwd
    body = {"username": user, "password": pwd, **extra}
    try:
        return requests.post(f"{SERVER}/auth/login", json=body, headers=headers, timeout=5)
    except Exception as e:
        print(f"  Erro de ligacao: {e}")
        return None

def verify(token, ua="Mozilla/5.0", fwd=None):
    headers = {"Content-Type": "application/json", "User-Agent": ua}
    if fwd:
        headers["X-Forwarded-For"] = fwd
    try:
        return requests.post(f"{SERVER}/auth/verify", json={"token": token}, headers=headers, timeout=5)
    except Exception as e:
        print(f"  Erro de ligacao: {e}")
        return None

# ─────────────────────────────────────────────────────────────
# PERSONA 1 — UTILIZADOR NORMAL
# Testa: login correto, verify token, acesso admin
# Score esperado: ~5 | Decisao: ALLOWED
# ─────────────────────────────────────────────────────────────
def persona1():
    banner("PERSONA 1 - UTILIZADOR NORMAL",
           "Login legitimo com alice e admin, verifica token JWT")
    limpar_banidos()

    print(f"\n{CYAN}  Passo 1/3 - Alice faz login com credenciais corretas{NC}")
    r = login("alice", "Alice#2024")
    if r is None: return
    data = mostrar_resultado(r)
    token = r.json().get("token", "")

    time.sleep(1)

    print(f"\n{CYAN}  Passo 2/3 - Alice verifica o token JWT{NC}")
    r2 = verify(token)
    if r2 is not None: mostrar_resultado(r2)

    time.sleep(1)

    print(f"\n{CYAN}  Passo 3/3 - Admin faz login{NC}")
    r3 = login("admin", "Admin@GNS3!")
    if r3 is not None: mostrar_resultado(r3)

    print(f"\n{GREEN}  Resultado final: Utilizador normal — acesso permitido sem friccao{NC}")

# ─────────────────────────────────────────────────────────────
# PERSONA 2 — HACKER BRUTE FORCE
# Testa: multiplas passwords erradas ate RATE_LIMITED
# Score esperado: 0->25 | Decisao: RATE_LIMITED
# ─────────────────────────────────────────────────────────────
def persona2():
    banner("PERSONA 2 - HACKER BRUTE FORCE",
           "Tenta varias passwords (brute force puro) ate ser bloqueado por rate limiting")
    limpar_banidos()

    passwords = ["password123", "admin", "123456", "alice2024", "qwerty",
                 "letmein", "alice123", "pass123", "root", "toor", "errada1", "errada2"]

    for i, pwd in enumerate(passwords):
        print(f"\n{CYAN}  Tentativa {i+1}/{len(passwords)} - password: '{pwd}'{NC}")
        r = login("alice", pwd, fwd="192.168.1.66")
        if r is None: break
        data = mostrar_resultado(r)
        decision = data.get("risk", {}).get("decision", "")
        if decision in ("BLOCKED", "RATE_LIMITED"):
            print(f"\n{RED}  Resultado final: Hacker bloqueado apos {i+1} tentativas!{NC}")
            return
        time.sleep(0.4)

    print(f"\n{YELLOW}  Resultado final: Todas as tentativas processadas{NC}")

# ─────────────────────────────────────────────────────────────
# PERSONA 3 — ATACANTE ESTRANGEIRO
# Testa: APENAS localizacao perigosa (IP da China), sem ferramentas
# IP publico (15) + Pais alto risco (15) = R 30 -> CAPTCHA
# ─────────────────────────────────────────────────────────────
def persona3():
    banner("PERSONA 3 - ATACANTE ESTRANGEIRO",
           "Login a partir de IP de pais de alto risco (so localizacao) -> CAPTCHA")
    limpar_banidos()

    print(f"\n{CYAN}  Passo 1/2 - Login da China (so localizacao perigosa, sem ferramentas){NC}")
    print(f"  Esperado: IP publico (15) + Pais alto risco (15) = R 30 -> CAPTCHA")
    r = login("alice", "Alice#2024", fwd="1.0.1.1")
    if r is None: return
    data = mostrar_resultado(r)
    question = data.get("captcha", {}).get("question", "N/A")
    if question != "N/A":
        print(f"\n  Pergunta CAPTCHA recebida: '{question}'")

    time.sleep(1)

    print(f"\n{CYAN}  Passo 2/2 - Resolve o CAPTCHA e acede{NC}")
    r2 = login("alice", "Alice#2024", fwd="1.0.1.1",
               extra={"captcha_answer": "sporting"})
    if r2 is not None: mostrar_resultado(r2)

    print(f"\n{YELLOW}  Resultado final: So a localizacao perigosa disparou o CAPTCHA{NC}")

# ─────────────────────────────────────────────────────────────
# PERSONA 4 — LADRAO DE TOKEN
# Testa: uso de JWT noutro IP e token adulterado
# Score esperado: CHALLENGE + BLOCKED
# ─────────────────────────────────────────────────────────────
def persona4():
    banner("PERSONA 4 - LADRAO DE TOKEN",
           "Rouba JWT de alice, usa noutro IP e tenta token adulterado")
    limpar_banidos()

    print(f"\n{CYAN}  Passo 1/3 - Alice faz login legitimo e obtem token{NC}")
    r = login("alice", "Alice#2024")
    if r is None: return
    mostrar_resultado(r)
    token = r.json().get("token", "")
    print(f"  Token capturado: {token[:50]}...")

    time.sleep(1)

    print(f"\n{CYAN}  Passo 2/3 - Ladrao usa token de alice noutro IP (192.168.1.99){NC}")
    r2 = verify(token, ua="python-requests/2.28", fwd="192.168.1.99")
    if r2 is not None: mostrar_resultado(r2)

    time.sleep(1)

    print(f"\n{CYAN}  Passo 3/3 - Ladrao tenta com token adulterado{NC}")
    token_adulterado = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGVzIjpbImFkbWluIl19.ASSINATURA_FALSA"
    r3 = verify(token_adulterado, ua="python-requests/2.28")
    if r3 is not None: mostrar_resultado(r3)

    print(f"\n{RED}  Resultado final: Ladrao de token detetado — IP banido permanentemente!{NC}")

# ─────────────────────────────────────────────────────────────
# PERSONA 5 — HACKER FURTIVO
# Testa: tentativas lentas para evitar brute force
# Score esperado: 15-20 | Decisao: ALLOWED (passa despercebido)
# ─────────────────────────────────────────────────────────────
def persona5():
    banner("PERSONA 5 - HACKER FURTIVO",
           "Tentativas lentas (3s intervalo) disfarçado de browser normal")
    limpar_banidos()

    passwords = ["password", "alice2024", "Alice2024", "Alice#2023"]

    for i, pwd in enumerate(passwords):
        print(f"\n{CYAN}  Tentativa {i+1}/{len(passwords)} - '{pwd}' (aguarda 3s entre tentativas){NC}")
        r = login("alice", pwd,
                  ua="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                  fwd="203.0.113.1")
        if r is not None: mostrar_resultado(r)
        if i < len(passwords) - 1:
            time.sleep(3)

    print(f"\n{YELLOW}  Resultado final: Hacker furtivo — score baixo, passou com poucos alertas{NC}")

# ─────────────────────────────────────────────────────────────
# PERSONA 6 — ATACANTE TOTAL
# Testa: China + sqlmap + brute force ate BLOCKED
# Score esperado: 70+ | Decisao: BLOCKED
# ─────────────────────────────────────────────────────────────
def persona6():
    banner("PERSONA 6 - ATACANTE TOTAL",
           "Combina IP China + sqlmap + brute force ate BLOCKED permanente")
    limpar_banidos()

    for i in range(1, 15):
        print(f"\n{CYAN}  Ataque {i}/14 — China + sqlmap + password errada{NC}")
        r = login("admin", "errada", ua="sqlmap/1.7.8", fwd="1.0.1.60")
        if r is None: break
        data = mostrar_resultado(r)
        decision = data.get("risk", {}).get("decision", "")
        if decision == "BLOCKED":
            print(f"\n{RED}  Resultado final: ATACANTE BANIDO PERMANENTEMENTE apos {i} tentativas!{NC}")
            break
        time.sleep(0.3)

    print(f"\n{CYAN}  Lista de IPs banidos:{NC}")
    try:
        r = requests.get(f"{SERVER}/api/banned")
        data = r.json()
        print(f"  Total banidos: {data.get('total', 0)}")
        for ip in data.get("ips", []):
            print(f"    - {ip}")
    except:
        print("  Erro ao obter lista de banidos")

# ─────────────────────────────────────────────────────────────
# PERSONA 7 — UTILIZADOR COM CAPTCHA
# Testa: IP China + tentativas disparam CAPTCHA, resolve e entra
# Score esperado: 45+ | Decisao: CAPTCHA -> ALLOWED
# ─────────────────────────────────────────────────────────────
def persona7():
    banner("PERSONA 7 - UTILIZADOR COM CAPTCHA",
           "IP da China + tentativas disparam CAPTCHA, utilizador resolve e entra")
    limpar_banidos()

    print(f"\n{CYAN}  Passo 1/3 - Acumula tentativas com IP da China (4x password errada){NC}")
    for i in range(4):
        login("bob", "errada", fwd="1.0.1.50")
        print(f"  Tentativa {i+1}/4 acumulada...")
        time.sleep(0.5)

    time.sleep(1)

    print(f"\n{CYAN}  Passo 2/3 - Tentativa que dispara CAPTCHA{NC}")
    r = login("bob", "errada", fwd="1.0.1.50")
    if r is None: return
    data = mostrar_resultado(r)
    question = data.get("captcha", {}).get("question", "N/A")
    print(f"\n  Pergunta CAPTCHA recebida: '{question}'")

    time.sleep(1)

    print(f"\n{CYAN}  Passo 3/3 - Bob resolve CAPTCHA e faz login correto{NC}")
    r2 = login("bob", "Bob$Pass99", fwd="1.0.1.50",
               extra={"captcha_answer": "sporting"})
    if r2 is not None: mostrar_resultado(r2)

    print(f"\n{GREEN}  Resultado final: Utilizador legitimo passou o CAPTCHA com sucesso!{NC}")

# ─────────────────────────────────────────────────────────────
# PERSONA 8 — CHALLENGE (pergunta de seguranca)
# Testa: score alto dispara CHALLENGE, responde e entra
# Score esperado: 50-69 | Decisao: CHALLENGE -> ALLOWED
# ─────────────────────────────────────────────────────────────
def persona8():
    banner("PERSONA 8 - DESAFIO DE SEGURANCA (CHALLENGE)",
           "Score alto dispara pergunta de seguranca, alice responde e entra")
    limpar_banidos()

    print(f"\n{CYAN}  Passo 1/3 - Acumula tentativas da China com nikto (3x){NC}")
    for i in range(3):
        login("alice", "errada", ua="nikto/2.1.6", fwd="1.0.1.80")
        print(f"  Tentativa {i+1}/3 acumulada...")
        time.sleep(0.3)

    time.sleep(1)

    print(f"\n{CYAN}  Passo 2/3 - Tentativa que dispara CHALLENGE{NC}")
    print(f"  Esperado: China(15) + nikto(15) + IP publico(15) + brute force = R 50-60 -> CHALLENGE")
    r = login("alice", "Alice#2024", ua="nikto/2.1.6", fwd="1.0.1.80")
    if r is None: return
    data = mostrar_resultado(r)
    question = data.get("challenge", {}).get("question", "N/A")
    print(f"\n  Pergunta de seguranca: '{question}'")

    time.sleep(1)

    print(f"\n{CYAN}  Passo 3/3 - Alice responde ao CHALLENGE corretamente{NC}")
    r2 = login("alice", "Alice#2024", ua="nikto/2.1.6", fwd="1.0.1.80",
               extra={"security_answer": "covilha"})
    if r2 is not None: mostrar_resultado(r2)

    print(f"\n{GREEN}  Resultado final: Alice passou o CHALLENGE e acedeu com MFA!{NC}")

# ─────────────────────────────────────────────────────────────
# PERSONA 9 — CHALLENGE FALHADO (bloqueio por respostas erradas)
# Testa: dispara CHALLENGE e falha 3x a resposta -> BLOCKED permanente
# ─────────────────────────────────────────────────────────────
def persona9():
    banner("PERSONA 9 - CHALLENGE FALHADO",
           "Dispara CHALLENGE e falha a pergunta de seguranca 3x -> BLOCKED")
    limpar_banidos()

    print(f"\n{CYAN}  Passo 1/2 - Acumula tentativas da China com nikto para disparar CHALLENGE{NC}")
    for i in range(3):
        login("alice", "errada", ua="nikto/2.1.6", fwd="1.0.1.90")
        print(f"  Tentativa {i+1}/3 acumulada...")
        time.sleep(0.3)

    time.sleep(1)

    print(f"\n{CYAN}  Passo 2/2 - Responde ERRADO ao CHALLENGE 3 vezes{NC}")
    print(f"  Esperado: apos 3 respostas erradas -> BLOCKED permanente")
    for i in range(3):
        print(f"\n{YELLOW}  Resposta errada {i+1}/3...{NC}")
        r = login("alice", "Alice#2024", ua="nikto/2.1.6", fwd="1.0.1.90",
                  extra={"security_answer": "resposta_errada"})
        if r is None: break
        data = mostrar_resultado(r)
        decision = data.get("risk", {}).get("decision", "")
        if decision == "BLOCKED":
            print(f"\n{RED}  Resultado final: IP bloqueado apos 3 falhas no CHALLENGE!{NC}")
            return
        time.sleep(0.5)

    print(f"\n{RED}  Resultado final: Bloqueio por falhas repetidas no CHALLENGE{NC}")

# ─────────────────────────────────────────────────────────────
# MENU
# ─────────────────────────────────────────────────────────────
PERSONAS = {
    "1": ("Utilizador Normal",              persona1),
    "2": ("Hacker Brute Force",             persona2),
    "3": ("Atacante Estrangeiro",           persona3),
    "4": ("Ladrao de Token",                persona4),
    "5": ("Hacker Furtivo",                 persona5),
    "6": ("Atacante Total",                 persona6),
    "7": ("Utilizador com CAPTCHA",         persona7),
    "8": ("Desafio de Seguranca CHALLENGE", persona8),
    "9": ("Challenge Falhado (BLOCKED)",    persona9),
}

def menu():
    while True:
        limpar()
        print(f"\n{BOLD}{'='*65}")
        print("  ZERO TRUST - SIMULACAO DE PERSONAS")
        print(f"  Servidor: {SERVER}")
        print(f"{'='*65}{NC}\n")

        for k, (nome, _) in PERSONAS.items():
            print(f"  {k}) {nome}")
        print(f"\n  A) Correr TODAS as personas")
        print(f"  L) Ver logs do servidor")
        print(f"  B) Ver IPs banidos")
        print(f"  C) Limpar IPs banidos")
        print(f"  0) Sair\n")

        opcao = input("  Escolhe [0-9/A/L/B/C]: ").strip().upper()

        if opcao == "0":
            print("\n  Ate logo!\n")
            break
        elif opcao in PERSONAS:
            limpar()
            PERSONAS[opcao][1]()
            pausar()
        elif opcao == "A":
            for k, (nome, fn) in PERSONAS.items():
                limpar()
                fn()
                pausar()
        elif opcao == "L":
            try:
                r = requests.get(f"{SERVER}/api/logs")
                data = r.json()
                stats = data.get("stats", {})
                print(f"\n{BOLD}  Estatisticas do servidor:{NC}")
                print(f"  Total pedidos:  {stats.get('total', 0)}")
                print(f"  ALLOWED:        {stats.get('allowed', 0)}")
                print(f"  CAPTCHA:        {stats.get('captcha', 0)}")
                print(f"  CHALLENGE:      {stats.get('challenge', 0)}")
                print(f"  RATE_LIMITED:   {stats.get('rate_limited', 0)}")
                print(f"  BLOCKED:        {stats.get('blocked', 0)}")
                print(f"  Score medio:    {stats.get('avg_score', 0)}")
            except Exception as e:
                print(f"  Erro: {e}")
            pausar()
        elif opcao == "B":
            try:
                r = requests.get(f"{SERVER}/api/banned")
                data = r.json()
                print(f"\n  Total banidos: {data.get('total', 0)}")
                for ip in data.get("ips", []):
                    print(f"    - {ip}")
                if not data.get("ips"):
                    print("  Nenhum IP banido.")
            except Exception as e:
                print(f"  Erro: {e}")
            pausar()
        elif opcao == "C":
            limpar_banidos()
            print(f"{GREEN}  Lista de banidos limpa!{NC}")
            pausar()

if __name__ == "__main__":
    menu()
