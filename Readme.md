# Risk Based Authentication Server

Sistema de autenticação baseado em risco, fundamentado no paradigma **Zero Trust** ("nunca confiar, verificar sempre"). Cada pedido de autenticação é avaliado em tempo real por seis fatores contextuais independentes que, combinados, produzem um score de risco de 0 a 100, a partir do qual o sistema aplica automaticamente uma de cinco decisões adaptativas.

Projeto desenvolvido no âmbito da licenciatura em Engenharia Informática da Universidade da Beira Interior.

## Funcionalidades

- **Motor de avaliação de risco** determinístico e transparente, com seis fatores ponderados.
- **Cinco decisões adaptativas** proporcionais ao risco calculado.
- **Autenticação por token JWT** assinado (HS256), com o IP de origem embebido e validade de 15 minutos.
- **Deteção de anomalias no token**: roubo de sessão (mudança de IP) e adulteração da assinatura.
- **Persistência** do histórico de autenticação e da lista de endereços bloqueados.
- **API de auditoria** para consulta de registos e gestão de IPs banidos.

## Modelo de risco

O score final resulta da soma dos seis fatores, limitada a 100:

| Fator | Peso máximo | Descrição |
|---|---|---|
| IP de origem | 30 | Tipo de IP e mudança de IP face ao token |
| Força bruta | 25 | Frequência de tentativas recentes |
| User-Agent | 15 | Deteção de ferramentas de ataque conhecidas |
| Localização | 15 | País de origem do IP |
| Integridade JWT | 10 | Token adulterado força bloqueio imediato |
| Hora do dia | 5 | Acessos de madrugada são mais suspeitos |

## Decisões adaptativas

| Decisão | Condição | Resposta |
|---|---|---|
| `ALLOWED` | R < 30 | Acesso concedido |
| `CAPTCHA` | R ≥ 30 | Verificação humana |
| `RATE_LIMITED` | força bruta severa | Bloqueio temporário (30 s) |
| `CHALLENGE` | R ≥ 50 | Pergunta de segurança |
| `BLOCKED` | R ≥ 70 | Banimento permanente |

Sanções especiais: um token adulterado resulta em `BLOCKED` imediato; a utilização de um token a partir de um IP diferente do de emissão despoleta `CHALLENGE`; três respostas erradas ao desafio de segurança conduzem a `BLOCKED`.

## Instalação

Requer Python 3.10 ou superior.

```bash
# Clonar o repositório
git clone https://github.com/<utilizador>/<repositorio>.git
cd <repositorio>

# (Opcional) criar um ambiente virtual
python3 -m venv venv
source venv/bin/activate        # No Windows: venv\Scripts\activate

# Instalar as dependências
pip install -r requirements.txt
```

O fator de localização geográfica é opcional e requer a base de dados **GeoLite2-Country.mmdb** (da MaxMind), colocada na raiz do projeto. Sem este ficheiro, o servidor funciona normalmente, apenas com o fator de localização desativado.

## Utilização

Iniciar o servidor:

```bash
python3 server.py
```

O servidor fica disponível em `http://0.0.0.0:8080`.

Com o servidor ativo, executar o simulador de personas para testar os diferentes cenários:

```bash
python3 personas.py
```

## Endpoints

| Método | Rota | Descrição |
|---|---|---|
| `POST` | `/auth/login` | Autenticação com avaliação de risco |
| `POST` | `/auth/verify` | Validação de um token JWT existente |
| `GET` | `/api/logs` | Histórico e estatísticas de autenticação |
| `GET` | `/api/banned` | Lista de IPs banidos |
| `POST` | `/api/banned` | Banimento manual de um IP |
| `DELETE` | `/api/banned/<ip>` | Remoção de um IP da lista de banidos |

### Exemplo de pedido

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "Alice#2024"}'
```

## Personas de teste

O script `personas.py` inclui nove personas, cada uma isolando um vetor de ataque e validando um nível de decisão:

1. **Utilizador Normal** — acesso legítimo interno → `ALLOWED`
2. **Hacker Brute Force** — tentativas sucessivas de password → `RATE_LIMITED`
3. **Atacante Estrangeiro** — IP de país de alto risco → `CAPTCHA`
4. **Ladrão de Token** — roubo de sessão e adulteração → `CHALLENGE` / `BLOCKED`
5. **Hacker Furtivo** — ataque lento e disperso → `ALLOWED`
6. **Atacante Total** — todos os fatores combinados → `BLOCKED`
7. **Utilizador com CAPTCHA** — risco médio com verificação → `CAPTCHA`
8. **Desafio de Segurança** — challenge respondido com sucesso → `CHALLENGE`
9. **Challenge Falhado** — três respostas erradas ao desafio → `BLOCKED`

## Ambiente de teste

O sistema foi validado numa rede simulada com **GNS3**, integrando um router Cisco, um switch, um servidor (máquina virtual) e um cliente em contentor Docker, permitindo reproduzir um cenário representativo de uma rede real.

## Estrutura do repositório

```
.
├── server.py          # Servidor de autenticação Zero Trust
├── personas.py        # Simulador de personas para teste
├── requirements.txt   # Dependências do projeto
├── .gitignore
└── README.md
```

## Aviso

Este é um projeto académico, concebido para fins educativos e de demonstração. As credenciais e a chave de assinatura JWT presentes no código são exemplos e não devem ser utilizados em ambientes de produção.

