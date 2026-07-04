"""
Risk Based Authentication Server.

Servidor de autenticação com análise de risco em tempo real. Cada pedido é
avaliado por seis fatores independentes que, combinados, geram um score de
risco (0-100) e uma decisão automática num de cinco níveis, de acordo com o
paradigma Zero Trust: "nunca confiar, verificar sempre".

Endpoints:
    POST /auth/login          Autenticação com avaliação de risco.
    POST /auth/verify         Validação de um token JWT existente.
    GET  /api/logs            Histórico e estatísticas de autenticação.
    GET  /api/banned          Lista de IPs banidos.
    POST /api/banned          Banimento manual de um IP.
    DELETE /api/banned/<ip>   Remoção de um IP da lista de banidos.
"""

import os
import json
import time
import hashlib
import ipaddress
from datetime import datetime, timezone, timedelta
from collections import defaultdict

from flask import Flask, request, jsonify
import jwt


#Geolocalização 

try:
    import geoip2.database

    GEOIP_DB = os.path.join(os.path.dirname(__file__), "GeoLite2-Country.mmdb")
    geoip_reader = (
        geoip2.database.Reader(GEOIP_DB) if os.path.exists(GEOIP_DB) else None
    )
    if geoip_reader:
        print("[INFO] GeoLite2 carregado com sucesso")
    else:
        print("[WARN] GeoLite2-Country.mmdb não encontrado — fator localização desativado")
except ImportError:
    geoip_reader = None
    print("[WARN] geoip2 não instalado — fator localização desativado")


# Configurações gerais

HOST = "0.0.0.0"
PORT = 8080

CACHE_FILE = "auth_log.json"          # histórico de autenticação persistido
BANNED_FILE = "banned_ips.json"       # lista de IPs banidos persistida

JWT_SECRET = "zero_trust_gns3_secret"
JWT_EXPIRY_MINUTES = 15               # validade do token emitido

# Limiares dos níveis de decisão (aplicados sobre o score total)
CRITICAL_RISK = 70                    # >= BLOCKED (banimento permanente)
HIGH_RISK = 50                        # >= CHALLENGE (pergunta de segurança)
MEDIUM_RISK = 30                      # >= CAPTCHA (verificação humana)

RATE_LIMIT_BLOCK_TIME = 30            # duração do bloqueio temporário (s)
BF_WINDOW = 300                       # janela de deteção de força bruta (s)
CHALLENGE_MAX_FAILS = 3               # falhas no challenge antes de banir

# CAPTCHA simples para verificação humana
CAPTCHA_QUESTION = "Qual e o melhor clube de Portugal?"
CAPTCHA_ANSWER = "sporting"

# User-Agents associados a ferramentas de ataque conhecidas
SUSPICIOUS_UA = [
    "sqlmap", "nikto", "nmap", "hydra",
    "medusa", "burpsuite", "python-requests", "masscan",
]

# Países classificados por nível de risco (códigos ISO 3166-1 alfa-2)
HIGH_RISK_COUNTRIES = {"CN", "RU", "KP", "IR", "SY", "CU"}
MEDIUM_RISK_COUNTRIES = {"BY", "VE", "MM", "SD", "AF"}


# Base de utilizadores (numa aplicação real proviria de uma base de dados)
USERS = {
    "admin": {
        "password": "Admin@GNS3!",
        "roles": ["admin"],
        "security_question": "Qual o nome do seu primeiro animal?",
        "security_answer": "pipoca",
    },
    "alice": {
        "password": "Alice#2024",
        "roles": ["user"],
        "security_question": "Qual a sua cidade natal?",
        "security_answer": "covilha",
    },
    "bob": {
        "password": "Bob$Pass99",
        "roles": ["user"],
        "security_question": "Qual o nome da sua mae?",
        "security_answer": "joana",
    },
}


# Estado em memória 
auth_log = []                          # histórico de todos os pedidos
ip_attempts = defaultdict(list)        # timestamps de tentativas por IP
ip_blocked_until = {}                  # bloqueios temporários (rate limit)
ip_permanently_banned = set()          # IPs banidos permanentemente
ip_challenge_fails = defaultdict(int)  # falhas no challenge por IP

app = Flask(__name__)



# Persistência em disco
def load_cache():
    """Carrega o histórico de autenticação a partir do ficheiro JSON."""
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE) as f:
                data = json.load(f)
                auth_log.extend(data if isinstance(data, list) else [])
            print(f"[INFO] {len(auth_log)} registos carregados")
        except Exception:
            pass


def save_cache():
    """Guarda os últimos 1000 registos de autenticação em disco."""
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(auth_log[-1000:], f, indent=2)
    except Exception:
        pass


def load_banned():
    """Carrega a lista de IPs banidos permanentemente."""
    if os.path.exists(BANNED_FILE):
        try:
            with open(BANNED_FILE) as f:
                data = json.load(f)
                ip_permanently_banned.update(data.get("ips", []))
            print(f"[INFO] {len(ip_permanently_banned)} IPs banidos carregados")
        except Exception:
            pass


def save_banned():
    """Persiste a lista de IPs banidos, com o instante da última atualização."""
    try:
        with open(BANNED_FILE, "w") as f:
            json.dump(
                {
                    "ips": list(ip_permanently_banned),
                    "updated": datetime.now(tz=timezone.utc).isoformat(),
                },
                f,
                indent=2,
            )
    except Exception:
        pass


# Funções utilitárias
def get_client_ip():
    """Devolve o IP de origem do cliente, respeitando o cabeçalho X-Forwarded-For."""
    return request.headers.get(
        "X-Forwarded-For", request.remote_addr
    ).split(",")[0].strip()


def get_country(ip):
    """Devolve o código ISO do país do IP (ex.: 'CN', 'PT'), ou None se indeterminável."""
    if not geoip_reader:
        return None
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback:
            return None
        return geoip_reader.country(ip).country.iso_code
    except Exception:
        return None


def print_log(risk, ip, user, endpoint):
    """Imprime no terminal uma linha colorida com o resultado da avaliação."""
    level_color = {
        "CRITICAL": "\033[91m", "HIGH": "\033[91m",
        "MEDIUM": "\033[93m", "LOW": "\033[92m",
    }.get(risk["level"], "")
    decision_tag = {
        "BLOCKED": " BLOCK", "CHALLENGE": " CHALL", "RATE_LIMITED": " LIMIT",
        "CAPTCHA": " CAPT ", "ALLOWED": " OK   ",
    }.get(risk["decision"], "")
    ts = datetime.now(tz=timezone.utc).strftime("%H:%M:%S")
    print(
        f"{level_color}[{ts}] {ip:>18} | {endpoint:<14} | "
        f"R={risk['score']:>3} {risk['level']:<8} | {decision_tag} | {user}\033[0m"
    )


def check_blocked(ip, now):
    """Indica se um IP está bloqueado (permanente ou temporariamente)."""
    if ip in ip_permanently_banned:
        return True, "IP permanentemente banido"
    if ip in ip_blocked_until:
        remaining = int(ip_blocked_until[ip] - now)
        if remaining > 0:
            return True, f"IP bloqueado. Tenta novamente em {remaining}s"
        del ip_blocked_until[ip]
    return False, None


def track_attempt(ip, now):
    """Regista uma tentativa e descarta as que caem fora da janela de análise."""
    ip_attempts[ip].append(now)
    ip_attempts[ip] = [t for t in ip_attempts[ip] if t > now - BF_WINDOW * 2]


# Motor de avaliação de risco
def compute_risk(ip, ua, now, jwt_payload=None, jwt_error=None):
    """
    Avalia o risco de um pedido combinando seis fatores independentes.

    Cada fator contribui com um valor até ao seu peso máximo. O score final é a
    soma de todos os fatores, limitada a 100, a partir da qual é determinada a
    decisão Zero Trust.

    Fatores e pesos máximos:
        1. IP de origem      (30)  tipo de IP e mudança de IP face ao token
        2. Força bruta       (25)  frequência de tentativas recentes
        3. User-Agent        (15)  deteção de ferramentas de ataque
        4. Hora do dia        (5)  acessos de madrugada são mais suspeitos
        5. Integridade JWT   (10)  token adulterado força bloqueio imediato
        6. Localização       (15)  país de origem do IP

    Returns:
        dict com o score total, o nível, a decisão e o detalhe de cada fator.
    """
    factors = {}
    token_stolen = False

    # Fator 1 — IP de origem
    s1, r1 = 0, "IP limpo"
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback:
            s1, r1 = 0, "Loopback"
        elif addr.is_private:
            s1, r1 = 5, "IP privado GNS3"
        else:
            s1, r1 = 15, "IP publico desconhecido"
    except ValueError:
        s1, r1 = 20, "IP invalido"

    # IP diferente do registado no token: possível roubo de sessão
    if (
        jwt_payload
        and jwt_payload.get("client_ip")
        and jwt_payload["client_ip"] != ip
        and ip not in ("127.0.0.1", "::1")
    ):
        s1 = min(30, s1 + 15)
        r1 += " + IP mudou (possivel roubo de token)"
        token_stolen = True
    factors["ip_origem"] = {"score": s1, "reason": r1, "peso": 30}

    # Fator 2 — Força bruta (frequência de tentativas na janela)
    recent = [t for t in ip_attempts[ip] if t > now - BF_WINDOW]
    n = len(recent)
    if n >= 10:
        s2, r2 = 25, f"Brute force severo: {n} em {BF_WINDOW}s"
    elif n >= 5:
        s2, r2 = 15, f"Multiplas tentativas: {n} em {BF_WINDOW}s"
    elif n >= 3:
        s2, r2 = 7, f"Algumas tentativas: {n} em {BF_WINDOW}s"
    else:
        s2, r2 = 0, f"Normal ({n} tentativa(s))"
    factors["brute_force"] = {"score": s2, "reason": r2, "tentativas": n, "peso": 25}

    # Fator 3 — User-Agent
    ual = (ua or "").lower()
    s3, r3 = 0, "User-Agent legitimo"
    if not ual.strip():
        s3, r3 = 10, "User-Agent ausente"
    else:
        for kw in SUSPICIOUS_UA:
            if kw in ual:
                s3, r3 = 15, f"Ferramenta de ataque: {kw}"
                break
    factors["user_agent"] = {"score": s3, "reason": r3, "peso": 15}

    # Fator 4 — Hora do dia
    hour = datetime.fromtimestamp(now, tz=timezone.utc).hour
    if hour < 5:
        s4, r4 = 5, f"Madrugada: {hour:02d}h UTC"
    elif hour < 7:
        s4, r4 = 3, f"Cedo: {hour:02d}h UTC"
    else:
        s4, r4 = 0, f"Horario normal: {hour:02d}h UTC"
    factors["hora_dia"] = {"score": s4, "reason": r4, "peso": 5}

    # Fator 5 — Integridade do token JWT
    if jwt_error:
        if "expirado" in jwt_error.lower():
            s5, r5 = 5, "Token expirado"
        else:
            s5, r5 = 100, "Token adulterado — BLOCKED imediato"
    elif jwt_payload:
        s5, r5 = 0, "JWT valido e integro"
    else:
        s5, r5 = 0, "Sem JWT (endpoint login)"
    factors["jwt_integridade"] = {"score": s5, "reason": r5, "peso": 10}

    # Fator 6 — Localização geográfica
    country = get_country(ip)
    if country is None:
        s6, r6 = 0, "Localizacao nao determinavel (IP privado ou GeoIP indisponivel)"
    elif country in HIGH_RISK_COUNTRIES:
        s6, r6 = 15, f"Pais de alto risco: {country}"
    elif country in MEDIUM_RISK_COUNTRIES:
        s6, r6 = 8, f"Pais suspeito: {country}"
    else:
        s6, r6 = 0, f"Pais sem risco: {country}"
    factors["localizacao"] = {
        "score": s6, "reason": r6, "country": country or "N/A", "peso": 15,
    }

    # Score final (limitado a 100)
    total = min(100, s1 + s2 + s3 + s4 + s5 + s6)

    # Decisão Zero Trust, do critério mais severo ao mais permissivo
    if s5 == 100:
        level, decision = "CRITICAL", "BLOCKED"        # token adulterado
    elif token_stolen:
        level, decision = "HIGH", "CHALLENGE"          # possível roubo de sessão
    elif total >= CRITICAL_RISK:
        level, decision = "CRITICAL", "BLOCKED"
    elif total >= HIGH_RISK:
        level, decision = "HIGH", "CHALLENGE"
    elif s2 >= 25:
        level, decision = "MEDIUM", "RATE_LIMITED"     # força bruta severa
    elif total >= MEDIUM_RISK:
        level, decision = "MEDIUM", "CAPTCHA"
    else:
        level, decision = "LOW", "ALLOWED"

    return {"score": total, "level": level, "decision": decision, "factors": factors}


# Geração de tokens JWT
def emit_jwt(username, ip):
    """Emite um JWT assinado com os dados do utilizador e o IP de emissão."""
    user = USERS[username]
    return jwt.encode(
        {
            "sub": username,
            "roles": user["roles"],
            "client_ip": ip,
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRY_MINUTES),
            "iss": "zero-trust-gns3",
        },
        JWT_SECRET,
        algorithm="HS256",
    )


@app.after_request
def add_headers(response):
    """Acrescenta o cabeçalho identificativo Zero Trust a todas as respostas."""
    response.headers["X-Zero-Trust"] = "never-trust-always-verify"
    return response



# Endpoint: consulta do histórico de autenticação
@app.route("/api/logs", methods=["GET"])
def get_logs():
    """Devolve estatísticas agregadas e os últimos 200 registos de autenticação."""
    total = len(auth_log)
    return jsonify(
        {
            "stats": {
                "total": total,
                "blocked": sum(1 for r in auth_log if r["decision"] == "BLOCKED"),
                "challenge": sum(1 for r in auth_log if r["decision"] == "CHALLENGE"),
                "rate_limited": sum(1 for r in auth_log if r["decision"] == "RATE_LIMITED"),
                "captcha": sum(1 for r in auth_log if r["decision"] == "CAPTCHA"),
                "allowed": sum(1 for r in auth_log if r["decision"] == "ALLOWED"),
                "avg_score": (
                    round(sum(r["risk_score"] for r in auth_log) / total, 1)
                    if total else 0
                ),
                "permanently_banned": list(ip_permanently_banned),
            },
            "records": list(reversed(auth_log[-200:])),
        }
    )



# Endpoint principal: login com avaliação de risco

@app.route("/auth/login", methods=["POST"])
def login():
    """Autentica um utilizador, aplicando a decisão adaptativa ao risco do pedido."""
    body = request.get_json() or {}
    ip = get_client_ip()
    ua = request.headers.get("User-Agent", "")
    now = time.time()

    # 1. Rejeitar de imediato IPs já bloqueados
    is_blocked, block_msg = check_blocked(ip, now)
    if is_blocked:
        status = 403 if ip in ip_permanently_banned else 429
        return jsonify({"authenticated": False, "error": block_msg}), status

    # 2. Registar a tentativa e calcular o risco
    track_attempt(ip, now)
    username = body.get("username", "")
    password = body.get("password", "")
    risk = compute_risk(ip, ua, now)

    # 3. Guardar o registo no histórico
    rec_id = hashlib.sha256(f"{ip}{now}".encode()).hexdigest()[:12]
    auth_log.append(
        {
            "id": rec_id,
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "endpoint": "/auth/login",
            "ip": ip,
            "user_agent": ua,
            "username": username,
            "risk_score": risk["score"],
            "risk_level": risk["level"],
            "decision": risk["decision"],
            "factors": risk["factors"],
        }
    )
    save_cache()
    print_log(risk, ip, username, "/auth/login")

    # 4. Aplicar a decisão Zero Trust
    # BLOCKED — risco crítico: banimento permanente
    if risk["decision"] == "BLOCKED":
        ip_permanently_banned.add(ip)
        save_banned()
        print(f"\033[91m[BAN] IP {ip} banido permanentemente!\033[0m")
        return jsonify(
            {
                "authenticated": False,
                "error": "IP banido permanentemente — risco critico",
                "risk": risk,
                "request_id": rec_id,
            }
        ), 403

    # CHALLENGE — risco alto: exige resposta a uma pergunta de segurança
    if risk["decision"] == "CHALLENGE":
        user = USERS.get(username)
        if not user:
            return jsonify(
                {"authenticated": False, "error": "Credenciais invalidas", "request_id": rec_id}
            ), 401

        security_answer = body.get("security_answer", "")

        # Ainda sem resposta: devolve a pergunta de segurança
        if not security_answer:
            return jsonify(
                {
                    "authenticated": False,
                    "error": "Verificacao adicional necessaria",
                    "challenge": {
                        "type": "security_question",
                        "question": user["security_question"],
                        "instruction": "Envia novamente com security_answer preenchido",
                        "attempts_remaining": CHALLENGE_MAX_FAILS - ip_challenge_fails[ip],
                    },
                    "risk": risk,
                    "request_id": rec_id,
                }
            ), 202

        # Resposta ou password incorreta: contabiliza a falha
        if (
            security_answer.lower().strip() != user["security_answer"]
            or user["password"] != password
        ):
            ip_challenge_fails[ip] += 1
            fails = ip_challenge_fails[ip]
            remaining = CHALLENGE_MAX_FAILS - fails

            # Esgotadas as tentativas: banimento permanente
            if fails >= CHALLENGE_MAX_FAILS:
                ip_permanently_banned.add(ip)
                save_banned()
                print(f"\033[91m[BAN] IP {ip} banido — {CHALLENGE_MAX_FAILS} falhas no CHALLENGE!\033[0m")
                return jsonify(
                    {
                        "authenticated": False,
                        "error": f"IP banido permanentemente — {CHALLENGE_MAX_FAILS} respostas erradas",
                        "risk": risk,
                        "request_id": rec_id,
                    }
                ), 403

            return jsonify(
                {
                    "authenticated": False,
                    "error": f"Resposta incorreta. Tentativas restantes: {remaining}",
                    "remaining_attempts": remaining,
                    "risk": risk,
                    "request_id": rec_id,
                }
            ), 401

        # Resposta correta: autenticação concluída com fator adicional (MFA)
        ip_challenge_fails[ip] = 0
        return jsonify(
            {
                "authenticated": True,
                "token": emit_jwt(username, ip),
                "username": username,
                "roles": user["roles"],
                "note": "Autenticado via pergunta de seguranca (MFA)",
                "risk": risk,
                "request_id": rec_id,
            }
        ), 200

    # RATE_LIMITED — força bruta severa: bloqueio temporário
    if risk["decision"] == "RATE_LIMITED":
        ip_blocked_until[ip] = now + RATE_LIMIT_BLOCK_TIME
        return jsonify(
            {
                "authenticated": False,
                "error": f"Rate limiting — IP bloqueado por {RATE_LIMIT_BLOCK_TIME}s (brute force detetado)",
                "remaining_seconds": RATE_LIMIT_BLOCK_TIME,
                "risk": risk,
                "request_id": rec_id,
            }
        ), 429

    # CAPTCHA — risco médio: exige verificação humana
    if risk["decision"] == "CAPTCHA":
        captcha_answer = body.get("captcha_answer", "")

        # Ainda sem resposta: devolve a pergunta do CAPTCHA
        if not captcha_answer:
            return jsonify(
                {
                    "authenticated": False,
                    "error": "Verificacao humana necessaria",
                    "captcha": {
                        "question": CAPTCHA_QUESTION,
                        "instruction": "Envia novamente com captcha_answer preenchido",
                    },
                    "risk": risk,
                    "request_id": rec_id,
                }
            ), 202

        # Resposta incorreta ao CAPTCHA
        if captcha_answer.lower().strip() != CAPTCHA_ANSWER:
            return jsonify(
                {
                    "authenticated": False,
                    "error": "Resposta incorreta ao CAPTCHA",
                    "risk": risk,
                    "request_id": rec_id,
                }
            ), 401

        # CAPTCHA correto: valida as credenciais normalmente
        user = USERS.get(username)
        if not user or user["password"] != password:
            return jsonify(
                {"authenticated": False, "error": "Credenciais invalidas", "request_id": rec_id}
            ), 401
        return jsonify(
            {
                "authenticated": True,
                "token": emit_jwt(username, ip),
                "username": username,
                "roles": user["roles"],
                "note": "Autenticado via CAPTCHA",
                "risk": risk,
                "request_id": rec_id,
            }
        ), 200

    # ALLOWED — risco baixo: autenticação normal
    user = USERS.get(username)
    if not user or user["password"] != password:
        return jsonify(
            {
                "authenticated": False,
                "error": "Credenciais invalidas",
                "risk": risk,
                "request_id": rec_id,
            }
        ), 401
    return jsonify(
        {
            "authenticated": True,
            "token": emit_jwt(username, ip),
            "username": username,
            "roles": user["roles"],
            "risk": risk,
            "request_id": rec_id,
        }
    ), 200


# Endpoint: validação de tokens JWT existentes
@app.route("/auth/verify", methods=["POST"])
def verify():
    """Valida um token JWT, reavaliando o risco do contexto de utilização."""
    body = request.get_json() or {}
    ip = get_client_ip()
    ua = request.headers.get("User-Agent", "")
    now = time.time()

    # 1. Rejeitar de imediato IPs já bloqueados
    is_blocked, block_msg = check_blocked(ip, now)
    if is_blocked:
        status = 403 if ip in ip_permanently_banned else 429
        return jsonify({"valid": False, "error": block_msg}), status

    # 2. Extrair e descodificar o token (corpo ou cabeçalho Authorization)
    token = body.get("token", "")
    auth_header = request.headers.get("Authorization", "")
    if not token and auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()

    jwt_payload, jwt_error, username = None, None, "<sem token>"
    if not token:
        jwt_error = "Token nao fornecido"
    else:
        try:
            jwt_payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            username = jwt_payload.get("sub", "?")
        except jwt.ExpiredSignatureError:
            jwt_error = "Token expirado"
        except jwt.InvalidTokenError:
            jwt_error = "Token adulterado ou invalido"

    # 3. Registar a tentativa e calcular o risco (incluindo os fatores do token)
    track_attempt(ip, now)
    risk = compute_risk(ip, ua, now, jwt_payload, jwt_error)

    # 4. Guardar o registo no histórico
    rec_id = hashlib.sha256(f"{ip}{now}v".encode()).hexdigest()[:12]
    auth_log.append(
        {
            "id": rec_id,
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "endpoint": "/auth/verify",
            "ip": ip,
            "user_agent": ua,
            "username": username,
            "risk_score": risk["score"],
            "risk_level": risk["level"],
            "decision": risk["decision"],
            "factors": risk["factors"],
            "jwt_valid": jwt_error is None,
        }
    )
    save_cache()
    print_log(risk, ip, username, "/auth/verify")

    # 5. Aplicar a decisão
    # Token inválido: rejeitar (e banir se tiver sido adulterado)
    if jwt_error:
        if "adulterado" in jwt_error:
            ip_permanently_banned.add(ip)
            save_banned()
            print(f"\033[91m[BAN] IP {ip} banido — token adulterado!\033[0m")
        return jsonify(
            {"valid": False, "error": jwt_error, "risk": risk, "request_id": rec_id}
        ), 401

    if risk["decision"] == "BLOCKED":
        ip_permanently_banned.add(ip)
        save_banned()
        return jsonify(
            {"valid": False, "error": "IP banido permanentemente", "risk": risk, "request_id": rec_id}
        ), 403

    if risk["decision"] == "CHALLENGE":
        return jsonify(
            {
                "valid": False,
                "error": "Re-autenticacao necessaria — possivel roubo de token",
                "risk": risk,
                "request_id": rec_id,
            }
        ), 202

    if risk["decision"] == "RATE_LIMITED":
        ip_blocked_until[ip] = now + RATE_LIMIT_BLOCK_TIME
        return jsonify(
            {
                "valid": False,
                "error": f"Rate limiting — bloqueado por {RATE_LIMIT_BLOCK_TIME}s",
                "risk": risk,
                "request_id": rec_id,
            }
        ), 429

    if risk["decision"] == "CAPTCHA":
        return jsonify(
            {
                "valid": False,
                "error": "Verificacao humana necessaria — re-autentica com captcha_answer",
                "captcha": {"question": CAPTCHA_QUESTION},
                "risk": risk,
                "request_id": rec_id,
            }
        ), 202

    # Token válido e risco baixo: acesso permitido
    return jsonify(
        {
            "valid": True,
            "username": username,
            "roles": jwt_payload.get("roles", []),
            "risk": risk,
            "risk_factors": risk["factors"],
            "request_id": rec_id,
        }
    ), 200


# Endpoints: gestão de IPs banidos
@app.route("/api/banned", methods=["GET"])
def get_banned():
    """Lista todos os IPs permanentemente banidos."""
    return jsonify(
        {"total": len(ip_permanently_banned), "ips": sorted(ip_permanently_banned)}
    )


@app.route("/api/banned", methods=["POST"])
def add_banned():
    """Adiciona manualmente um IP à lista de banidos."""
    body = request.get_json() or {}
    ip = body.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "Campo 'ip' obrigatorio"}), 400
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": "IP invalido"}), 400

    ip_permanently_banned.add(ip)
    save_banned()
    print(f"\033[91m[BAN] IP {ip} banido manualmente via API!\033[0m")
    return jsonify(
        {"message": f"IP {ip} banido com sucesso", "total": len(ip_permanently_banned)}
    ), 200


@app.route("/api/banned/<ip_addr>", methods=["DELETE"])
def remove_banned(ip_addr):
    """Remove um IP da lista de banidos."""
    if ip_addr not in ip_permanently_banned:
        return jsonify({"error": f"IP {ip_addr} nao esta na lista de banidos"}), 404

    ip_permanently_banned.discard(ip_addr)
    save_banned()
    print(f"\033[93m[UNBAN] IP {ip_addr} desbanido via API!\033[0m")
    return jsonify(
        {"message": f"IP {ip_addr} desbanido com sucesso", "total": len(ip_permanently_banned)}
    ), 200


# Arranque do servidor

if __name__ == "__main__":
    load_cache()
    load_banned()

    print("   ZERO TRUST AUTH SERVER ")
    print(f"  Servidor:    http://0.0.0.0:{PORT}")
    print(f"  Login:       POST /auth/login")
    print(f"  Verify:      POST /auth/verify")
    print(f"  Logs:        GET  /api/logs")
    print(f"  Banidos:     GET  /api/banned")
    print(f"  Banir:       POST /api/banned")
    print(f"  Desbanir:    DELETE /api/banned/<ip>\n")

    print(f"  5 Niveis de Decisao (R = soma wi*fi):")
    print(f"    R >= {CRITICAL_RISK}       BLOCKED      (403) banimento permanente")
    print(f"    R >= {HIGH_RISK}       CHALLENGE    (202) pergunta de seguranca ({CHALLENGE_MAX_FAILS} tentativas max)")
    print(f"    s2 >= 25      RATE_LIMITED (429) bloqueio {RATE_LIMIT_BLOCK_TIME}s (brute force severo)")
    print(f"    R >= {MEDIUM_RISK}       CAPTCHA      (202) verificacao humana")
    print(f"    R <  {MEDIUM_RISK}       ALLOWED      (200) acesso normal\n")

    print(f"  Sancoes especiais:")
    print(f"    Token adulterado              -> BLOCKED permanente")
    print(f"    Roubo de token                -> CHALLENGE imediato")
    print(f"    {CHALLENGE_MAX_FAILS}x resposta errada no CHALLENGE -> BLOCKED permanente\n")

    print(f"  Fatores (wi):")
    print(f"    IP de origem       0-30")
    print(f"    Brute force        0-25")
    print(f"    User-Agent         0-15")
    print(f"    Hora do dia        0-5")
    print(f"    Integridade JWT    0-10 (adulterado=100)")
    print(f"    Localizacao        0-15 (alto risco: CN/RU/KP/IR/SY/CU)\n")

    app.run(host=HOST, port=PORT, threaded=True)
