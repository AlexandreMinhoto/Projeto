import os, json, time, hashlib, ipaddress
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from flask import Flask, request, jsonify
import jwt

# Geolocalização
try:
    import geoip2.database
    GEOIP_DB = os.path.join(os.path.dirname(__file__), "GeoLite2-Country.mmdb")
    geoip_reader = geoip2.database.Reader(GEOIP_DB) if os.path.exists(GEOIP_DB) else None
    if geoip_reader:
        print("[INFO] GeoLite2 carregado com sucesso")
    else:
        print("[WARN] GeoLite2-Country.mmdb nao encontrado — fator localizacao desativado")
except ImportError:
    geoip_reader = None
    print("[WARN] geoip2 nao instalado — fator localizacao desativado")

HOST = "0.0.0.0"
PORT = 8080
CACHE_FILE = "auth_log.json"
JWT_SECRET = "zero_trust_gns3_secret"
JWT_EXPIRY_MINUTES = 15

# Thresholds dos 5 niveis
CRITICAL_RISK = 75   # BLOCKED permanente
HIGH_RISK     = 60   # CHALLENGE (pergunta de seguranca)
MEDIUM_RISK   = 40   # CAPTCHA ou RATE_LIMITED

RATE_LIMIT_BLOCK_TIME = 30
BF_WINDOW = 300

# CAPTCHA
CAPTCHA_QUESTION = "Qual e o melhor clube de Portugal?"
CAPTCHA_ANSWER   = "sporting"

# CHALLENGE — max tentativas antes de BLOCKED
CHALLENGE_MAX_FAILS = 3

BLACKLISTED_IPS = {"1.2.3.4", "10.0.0.99", "185.220.101.1"}
SUSPICIOUS_UA = ["sqlmap", "nikto", "nmap", "hydra", "medusa", "burpsuite", "python-requests", "masscan"]

# Paises de alto risco (score 20) e medio risco (score 10)
HIGH_RISK_COUNTRIES  = {"CN", "RU", "KP", "IR", "SY", "CU"}
MEDIUM_RISK_COUNTRIES = {"BY", "VE", "MM", "SD", "AF"}

USERS = {
    "admin": {"password": "Admin@GNS3!", "roles": ["admin"],
              "security_question": "Qual o nome do teu primeiro animal?",
              "security_answer": "pipoca"},
    "alice": {"password": "Alice#2024",  "roles": ["user"],
              "security_question": "Qual a tua cidade natal?",
              "security_answer": "covilha"},
    "bob":   {"password": "Bob$Pass99",  "roles": ["user"],
              "security_question": "Qual o nome da tua mae?",
              "security_answer": "joana"},
}

auth_log = []
ip_attempts = defaultdict(list)
ip_blocked_until = {}
ip_permanently_banned = set()
ip_challenge_fails = defaultdict(int)

app = Flask(__name__)

def load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE) as f:
                data = json.load(f)
                auth_log.extend(data if isinstance(data, list) else [])
            print(f"[INFO] {len(auth_log)} registos carregados")
        except: pass

def save_cache():
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(auth_log[-1000:], f, indent=2)
    except: pass

def get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()

def get_country(ip):
    """Devolve o codigo ISO do pais (ex: 'CN', 'PT') ou None."""
    if not geoip_reader:
        return None
    try:
        a = ipaddress.ip_address(ip)
        if a.is_private or a.is_loopback:
            return None
        response = geoip_reader.country(ip)
        return response.country.iso_code
    except Exception:
        return None

def print_log(risk, ip, user, ep):
    c = {"CRITICAL": "\033[91m", "HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[92m"}.get(risk["level"], "")
    i = {"BLOCKED": " BLOCK", "CHALLENGE": " CHALL", "RATE_LIMITED": " LIMIT",
         "CAPTCHA": " CAPT ", "ALLOWED": " OK   "}.get(risk["decision"], "")
    ts = datetime.now(tz=timezone.utc).strftime("%H:%M:%S")
    print(f"{c}[{ts}] {ip:>18} | {ep:<14} | R={risk['score']:>3} {risk['level']:<8} | {i} | {user}\033[0m")

def check_blocked(ip, now):
    if ip in ip_permanently_banned:
        return True, "IP permanentemente banido"
    if ip in ip_blocked_until:
        remaining = int(ip_blocked_until[ip] - now)
        if remaining > 0:
            return True, f"IP bloqueado. Tenta novamente em {remaining}s"
        else:
            del ip_blocked_until[ip]
    return False, None

def track_attempt(ip, now):
    ip_attempts[ip].append(now)
    ip_attempts[ip] = [t for t in ip_attempts[ip] if t > now - BF_WINDOW * 2]

def compute_risk(ip, ua, now, jwt_payload=None, jwt_error=None):
    f = {}
    token_stolen = False

    # Fator 1 - IP de origem (w=30, blacklist=100)
    s1, r1 = 0, "IP limpo"
    if ip in BLACKLISTED_IPS:
        s1, r1 = 100, "IP na blacklist"
    else:
        try:
            a = ipaddress.ip_address(ip)
            if a.is_loopback:  s1, r1 = 0,  "Loopback"
            elif a.is_private: s1, r1 = 5,  "IP privado GNS3"
            else:              s1, r1 = 15, "IP publico desconhecido"
        except: s1, r1 = 20, "IP invalido"
    if jwt_payload and jwt_payload.get("client_ip") and \
       jwt_payload["client_ip"] != ip and ip not in ("127.0.0.1", "::1"):
        s1 = min(30, s1 + 15)
        r1 += " + IP mudou (possivel roubo de token)"
        token_stolen = True
    f["ip_origem"] = {"score": s1, "reason": r1, "peso": 30}

    # Fator 2 - Brute force (w=25)
    recent = [t for t in ip_attempts[ip] if t > now - BF_WINDOW]
    n = len(recent) + 1
    if   n >= 10: s2, r2 = 25, f"Brute force severo: {n} em {BF_WINDOW}s"
    elif n >= 5:  s2, r2 = 15, f"Multiplas tentativas: {n} em {BF_WINDOW}s"
    elif n >= 3:  s2, r2 = 7,  f"Algumas tentativas: {n} em {BF_WINDOW}s"
    else:         s2, r2 = 0,  f"Normal ({n} tentativa(s))"
    f["brute_force"] = {"score": s2, "reason": r2, "tentativas": n, "peso": 25}

    # Fator 3 - User-Agent (w=15)
    ual = (ua or "").lower()
    s3, r3 = 0, "User-Agent legitimo"
    if not ual.strip(): s3, r3 = 10, "User-Agent ausente"
    else:
        for kw in SUSPICIOUS_UA:
            if kw in ual: s3, r3 = 15, f"Ferramenta de ataque: {kw}"; break
    f["user_agent"] = {"score": s3, "reason": r3, "peso": 15}

    # Fator 4 - Hora do dia (w=5)
    hour = datetime.fromtimestamp(now, tz=timezone.utc).hour
    if   hour < 5: s4, r4 = 5, f"Madrugada: {hour:02d}h UTC"
    elif hour < 7: s4, r4 = 3, f"Cedo: {hour:02d}h UTC"
    else:          s4, r4 = 0, f"Horario normal: {hour:02d}h UTC"
    f["hora_dia"] = {"score": s4, "reason": r4, "peso": 5}

    # Fator 5 - Integridade JWT (w=10, adulterado=BLOCKED imediato)
    if jwt_error:
        if "expirado" in jwt_error.lower(): s5, r5 = 5,   "Token expirado"
        else:                               s5, r5 = 100, "Token adulterado — BLOCKED imediato"
    elif jwt_payload: s5, r5 = 0, "JWT valido e integro"
    else:             s5, r5 = 0, "Sem JWT (endpoint login)"
    f["jwt_integridade"] = {"score": s5, "reason": r5, "peso": 10}

    # Fator 6 - Localizacao geografica (w=15)
    country = get_country(ip)
    if country is None:
        s6, r6 = 0, "Localizacao nao determinavel (IP privado ou GeoIP indisponivel)"
    elif country in HIGH_RISK_COUNTRIES:
        s6, r6 = 15, f"Pais de alto risco: {country}"
    elif country in MEDIUM_RISK_COUNTRIES:
        s6, r6 = 8, f"Pais suspeito: {country}"
    else:
        s6, r6 = 0, f"Pais sem risco: {country}"
    f["localizacao"] = {"score": s6, "reason": r6, "country": country or "N/A", "peso": 15}

    # R = soma(wi * fi)
    total = min(100, s1 + s2 + s3 + s4 + s5 + s6)

    # 5 niveis de decisao Zero Trust
    if s5 == 100:
        level, decision = "CRITICAL", "BLOCKED"
    elif token_stolen:
        level, decision = "HIGH", "CHALLENGE"
    elif total >= CRITICAL_RISK:
        level, decision = "CRITICAL", "BLOCKED"
    elif total >= HIGH_RISK:
        level, decision = "HIGH", "CHALLENGE"
    elif s2 >= 25:
        level, decision = "MEDIUM", "RATE_LIMITED"
    elif total >= MEDIUM_RISK:
        level, decision = "MEDIUM", "CAPTCHA"
    else:
        level, decision = "LOW", "ALLOWED"

    return {"score": total, "level": level, "decision": decision, "factors": f}


def emit_jwt(username, ip):
    user = USERS[username]
    return jwt.encode({
        "sub": username, "roles": user["roles"], "client_ip": ip,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRY_MINUTES),
        "iss": "zero-trust-gns3"
    }, JWT_SECRET, algorithm="HS256")


@app.after_request
def add_headers(response):
    response.headers["X-Zero-Trust"] = "never-trust-always-verify"
    return response


@app.route('/api/logs', methods=['GET'])
def get_logs():
    total = len(auth_log)
    return jsonify({
        "stats": {
            "total": total,
            "blocked":      sum(1 for r in auth_log if r["decision"] == "BLOCKED"),
            "challenge":    sum(1 for r in auth_log if r["decision"] == "CHALLENGE"),
            "rate_limited": sum(1 for r in auth_log if r["decision"] == "RATE_LIMITED"),
            "captcha":      sum(1 for r in auth_log if r["decision"] == "CAPTCHA"),
            "allowed":      sum(1 for r in auth_log if r["decision"] == "ALLOWED"),
            "avg_score":    round(sum(r["risk_score"] for r in auth_log) / total, 1) if total else 0,
            "permanently_banned": list(ip_permanently_banned),
        },
        "records": list(reversed(auth_log[-200:]))
    })


@app.route('/auth/login', methods=['POST'])
def login():
    body = request.get_json() or {}
    ip  = get_client_ip()
    ua  = request.headers.get("User-Agent", "")
    now = time.time()

    # 1. Verifica bloqueio
    is_blocked, block_msg = check_blocked(ip, now)
    if is_blocked:
        status = 403 if ip in ip_permanently_banned else 429
        return jsonify({"authenticated": False, "error": block_msg}), status

    # 2. Regista tentativa e calcula risco
    track_attempt(ip, now)
    username = body.get("username", "")
    password = body.get("password", "")
    risk = compute_risk(ip, ua, now)

    # 3. Guarda registo
    rec_id = hashlib.sha256(f"{ip}{now}".encode()).hexdigest()[:12]
    rec = {
        "id": rec_id, "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "endpoint": "/auth/login", "ip": ip, "user_agent": ua, "username": username,
        "risk_score": risk["score"], "risk_level": risk["level"],
        "decision": risk["decision"], "factors": risk["factors"]
    }
    auth_log.append(rec); save_cache()
    print_log(risk, ip, username, "/auth/login")

    # 4. Aplica decisao Zero Trust

    # BLOCKED
    if risk["decision"] == "BLOCKED":
        ip_permanently_banned.add(ip)
        print(f"\033[91m[BAN] IP {ip} banido permanentemente!\033[0m")
        return jsonify({
            "authenticated": False,
            "error": "IP banido permanentemente — risco critico",
            "risk": risk, "request_id": rec_id
        }), 403

    # CHALLENGE — pergunta de seguranca
    if risk["decision"] == "CHALLENGE":
        user = USERS.get(username)
        if not user:
            return jsonify({"authenticated": False,
                "error": "Credenciais invalidas", "request_id": rec_id}), 401
        security_answer = body.get("security_answer", "")
        if not security_answer:
            return jsonify({
                "authenticated": False,
                "error": "Verificacao adicional necessaria",
                "challenge": {
                    "type": "security_question",
                    "question": user["security_question"],
                    "instruction": "Envia novamente com security_answer preenchido",
                    "attempts_remaining": CHALLENGE_MAX_FAILS - ip_challenge_fails[ip]
                },
                "risk": risk, "request_id": rec_id
            }), 202
        if security_answer.lower().strip() != user["security_answer"] or user["password"] != password:
            ip_challenge_fails[ip] += 1
            fails = ip_challenge_fails[ip]
            remaining = CHALLENGE_MAX_FAILS - fails
            if fails >= CHALLENGE_MAX_FAILS:
                ip_permanently_banned.add(ip)
                print(f"\033[91m[BAN] IP {ip} banido — {CHALLENGE_MAX_FAILS} falhas no CHALLENGE!\033[0m")
                return jsonify({
                    "authenticated": False,
                    "error": f"IP banido permanentemente — {CHALLENGE_MAX_FAILS} respostas erradas",
                    "risk": risk, "request_id": rec_id
                }), 403
            return jsonify({
                "authenticated": False,
                "error": f"Resposta incorreta. Tentativas restantes: {remaining}",
                "remaining_attempts": remaining,
                "risk": risk, "request_id": rec_id
            }), 401
        # Resposta correta
        ip_challenge_fails[ip] = 0
        return jsonify({
            "authenticated": True, "token": emit_jwt(username, ip),
            "username": username, "roles": user["roles"],
            "note": "Autenticado via pergunta de seguranca (MFA)",
            "risk": risk, "request_id": rec_id
        }), 200

    # RATE_LIMITED — brute force severo
    if risk["decision"] == "RATE_LIMITED":
        ip_blocked_until[ip] = now + RATE_LIMIT_BLOCK_TIME
        return jsonify({
            "authenticated": False,
            "error": f"Rate limiting — IP bloqueado por {RATE_LIMIT_BLOCK_TIME}s (brute force detetado)",
            "remaining_seconds": RATE_LIMIT_BLOCK_TIME,
            "risk": risk, "request_id": rec_id
        }), 429

    # CAPTCHA — verificacao humana
    if risk["decision"] == "CAPTCHA":
        captcha_answer = body.get("captcha_answer", "")
        if not captcha_answer:
            return jsonify({
                "authenticated": False,
                "error": "Verificacao humana necessaria",
                "captcha": {
                    "question": CAPTCHA_QUESTION,
                    "instruction": "Envia novamente com captcha_answer preenchido"
                },
                "risk": risk, "request_id": rec_id
            }), 202
        if captcha_answer.lower().strip() != CAPTCHA_ANSWER:
            return jsonify({
                "authenticated": False,
                "error": "Resposta incorreta ao CAPTCHA",
                "risk": risk, "request_id": rec_id
            }), 401
        user = USERS.get(username)
        if not user or user["password"] != password:
            return jsonify({"authenticated": False,
                "error": "Credenciais invalidas", "request_id": rec_id}), 401
        return jsonify({
            "authenticated": True, "token": emit_jwt(username, ip),
            "username": username, "roles": user["roles"],
            "note": "Autenticado via CAPTCHA",
            "risk": risk, "request_id": rec_id
        }), 200

    # ALLOWED
    user = USERS.get(username)
    if not user or user["password"] != password:
        return jsonify({
            "authenticated": False, "error": "Credenciais invalidas",
            "risk": {"score": risk["score"], "level": risk["level"]},
            "request_id": rec_id
        }), 401
    return jsonify({
        "authenticated": True, "token": emit_jwt(username, ip),
        "username": username, "roles": user["roles"],
        "risk": risk, "request_id": rec_id
    }), 200


@app.route('/auth/verify', methods=['POST'])
def verify():
    body = request.get_json() or {}
    ip  = get_client_ip()
    ua  = request.headers.get("User-Agent", "")
    now = time.time()

    # 1. Verifica bloqueio
    is_blocked, block_msg = check_blocked(ip, now)
    if is_blocked:
        status = 403 if ip in ip_permanently_banned else 429
        return jsonify({"valid": False, "error": block_msg}), status

    # 2. Extrai e valida token
    token = body.get("token", "")
    ah = request.headers.get("Authorization", "")
    if not token and ah.startswith("Bearer "):
        token = ah[7:].strip()

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

    # 3. Regista tentativa e calcula risco
    track_attempt(ip, now)
    risk = compute_risk(ip, ua, now, jwt_payload, jwt_error)

    # 4. Guarda registo
    rec_id = hashlib.sha256(f"{ip}{now}v".encode()).hexdigest()[:12]
    rec = {
        "id": rec_id, "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "endpoint": "/auth/verify", "ip": ip, "user_agent": ua, "username": username,
        "risk_score": risk["score"], "risk_level": risk["level"],
        "decision": risk["decision"], "factors": risk["factors"],
        "jwt_valid": jwt_error is None
    }
    auth_log.append(rec); save_cache()
    print_log(risk, ip, username, "/auth/verify")

    # 5. Aplica decisao
    if jwt_error:
        if "adulterado" in jwt_error:
            ip_permanently_banned.add(ip)
            print(f"\033[91m[BAN] IP {ip} banido — token adulterado!\033[0m")
        return jsonify({
            "valid": False, "error": jwt_error,
            "risk": risk, "request_id": rec_id
        }), 401

    if risk["decision"] == "BLOCKED":
        ip_permanently_banned.add(ip)
        return jsonify({"valid": False, "error": "IP banido permanentemente",
            "risk": risk, "request_id": rec_id}), 403
    if risk["decision"] == "CHALLENGE":
        return jsonify({"valid": False,
            "error": "Re-autenticacao necessaria — possivel roubo de token",
            "risk": risk, "request_id": rec_id}), 202
    if risk["decision"] == "RATE_LIMITED":
        ip_blocked_until[ip] = now + RATE_LIMIT_BLOCK_TIME
        return jsonify({"valid": False,
            "error": f"Rate limiting — bloqueado por {RATE_LIMIT_BLOCK_TIME}s",
            "risk": risk, "request_id": rec_id}), 429
    if risk["decision"] == "CAPTCHA":
        return jsonify({"valid": False,
            "error": "Verificacao humana necessaria — re-autentica com captcha_answer",
            "captcha": {"question": CAPTCHA_QUESTION},
            "risk": risk, "request_id": rec_id}), 202

    return jsonify({
        "valid": True, "username": username,
        "roles": jwt_payload.get("roles", []),
        "risk": risk, "risk_factors": risk["factors"],
        "request_id": rec_id
    }), 200


if __name__ == "__main__":
    load_cache()
    print("   ZERO TRUST AUTH SERVER ")
    print(f"  Servidor:    http://0.0.0.0:{PORT}")
    print(f"  Login:       POST /auth/login")
    print(f"  Verify:      POST /auth/verify")
    print(f"  Logs:        GET  /api/logs\n")
    print(f"  5 Niveis de Decisao (R = soma wi*fi):")
    print(f"    R >= 75       BLOCKED      (403) banimento permanente")
    print(f"    R >= 60       CHALLENGE    (202) pergunta de seguranca ({CHALLENGE_MAX_FAILS} tentativas max)")
    print(f"    s2 >= 25      RATE_LIMITED (429) bloqueio {RATE_LIMIT_BLOCK_TIME}s (brute force severo)")
    print(f"    R >= 40       CAPTCHA      (202) verificacao humana")
    print(f"    R <  40       ALLOWED      (200) acesso normal\n")
    print(f"  Sancoes especiais:")
    print(f"    Token adulterado              -> BLOCKED permanente")
    print(f"    Roubo de token                -> CHALLENGE imediato")
    print(f"    {CHALLENGE_MAX_FAILS}x resposta errada no CHALLENGE -> BLOCKED permanente\n")
    print(f"  Fatores (wi):")
    print(f"    IP de origem       0-30 (blacklist=100)")
    print(f"    Brute force        0-25")
    print(f"    User-Agent         0-15")
    print(f"    Hora do dia        0-5")
    print(f"    Integridade JWT    0-10 (adulterado=100)")
    print(f"    Localizacao        0-15 (alto risco: CN/RU/KP/IR/SY/CU)\n")
    app.run(host=HOST, port=PORT, threaded=True)