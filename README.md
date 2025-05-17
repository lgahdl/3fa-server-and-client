# Sistema de Autenticação 3FA com TOTP e Criptografia

Este projeto implementa um sistema de autenticação de três fatores (3FA) que inclui:
1. Fator de localização (IP/país)
2. Fator de conhecimento (senha)
3. Fator de posse (código TOTP)

Após a autenticação bem-sucedida, o sistema permite o envio de mensagens criptografadas usando chaves derivadas de TOTP.

## Requisitos

- Node.js (v18 ou superior)
- Docker e Docker Compose
- npm ou yarn

## Estrutura do Projeto

- **src/**: Backend da aplicação com API REST
- **client/**: Cliente interativo para testar o sistema

## Configuração Inicial

### 1. Instalação das Dependências

```bash
cd server
npm install
```

### 2. Configuração do Ambiente

Crie um arquivo `.env` na raiz do diretório `server/` com as seguintes variáveis:

```
# Porta do servidor
PORT=3000

# Configuração PostgreSQL
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=app_db
POSTGRES_HOST=localhost
POSTGRES_PORT=5433

# URLs do Redis
REDIS_SERVER_URL=redis://localhost:6381
REDIS_CLIENT_URL=redis://localhost:6380

# Chave de API do IPInfo (obtenha em https://ipinfo.io/signup)
IPINFO_API_KEY=sua_chave_ipinfo_aqui
```

## Executando a Aplicação

### 1. Iniciando os Containers Docker

Primeiro, inicie os containers Docker que hospedam o PostgreSQL e os dois Redis (Redis do Cliente e Redis do Servidor):

```bash
cd server
docker-compose up -d
```

Este comando iniciará:
- PostgreSQL (porta 5433)
- PgAdmin (porta 8080)
- Redis do Servidor (porta 6381)
- Redis do Cliente (porta 6380)

Verifique se os containers estão rodando:

```bash
docker-compose ps
```

### 2. Iniciando o Servidor

Após os containers estarem em execução, inicie o servidor:

```bash
cd server
npm run dev
```

O servidor estará disponível em `http://localhost:3000`

### 3. Executando o Cliente Interativo

Em um novo terminal, execute o cliente interativo:

```bash
cd server
npm run client
```

## Utilizando o Cliente Interativo

O cliente interativo oferece um menu com as seguintes opções:

1. **Registrar novo usuário**: Cria um novo usuário no sistema
2. **Ver histórico de registros**: Visualiza os usuários registrados
3. **Testar conexão Redis**: Verifica a conexão com o Redis
4. **Verificar secret armazenado**: Consulta o secret TOTP de um usuário
5. **Solicitar código TOTP**: Gera códigos TOTP em tempo real
6. **Login completo (3FA)**: Realiza autenticação completa com 3 fatores
0. **Sair**: Encerra o cliente

### Fluxo de Uso Típico

1. Registre um novo usuário (opção 1)
2. Verifique se o secret foi armazenado corretamente (opção 4)
3. Gere um código TOTP (opção 5)
4. Realize o login completo (opção 6)
5. Envie uma mensagem criptografada quando solicitado

## Simulação de Diferentes Localizações

O cliente permite simular requisições de diferentes países usando IPs predefinidos:
- Brasil: 200.152.38.1
- EUA: 8.8.8.8
- UK: 176.32.103.205
- Japão: 203.104.153.1

Para testes mais realistas, recomenda-se o uso de uma VPN para alterar o IP real.

## Acesso ao PgAdmin

Para gerenciar o banco de dados PostgreSQL:
1. Acesse `http://localhost:8080`
2. Faça login com:
   - Email: admin@admin.com
   - Senha: admin
3. Adicione um novo servidor:
   - Host: postgres-db
   - Porta: 5432
   - Usuário: postgres
   - Senha: postgres
   - Database: app_db

## Parando a Aplicação

Para parar os containers Docker:

```bash
cd server
docker-compose down
```

## Detalhes Técnicos

- Autenticação de senha: Algoritmo Scrypt
- Geração TOTP: Biblioteca otplib
- Criptografia de mensagens: AES-256-GCM
- Armazenamento de secrets: Redis
- Detecção de país: API IPInfo 

## Fluxos do Sistema

### 1. Fluxo de Registro de Usuário

```mermaid
sequenceDiagram
    participant Cliente
    participant Servidor
    participant IPInfo
    participant Redis
    participant Postgres

    Cliente->>Servidor: POST /register (nome, número_celular, senha)
    Servidor->>IPInfo: Consulta país do IP
    IPInfo-->>Servidor: Retorna país
    
    Note over Servidor: Gera salt aleatório
    Note over Servidor: Hash da senha com Scrypt
    
    Servidor->>Postgres: Salva usuário (nome, número, país, hash, salt)
    Postgres-->>Servidor: Confirmação
    
    Note over Servidor: Gera secret = Hash(senha + salt)
    
    Servidor->>Redis: Armazena secret com chave = número_celular
    Redis-->>Servidor: Confirmação
    
    Servidor-->>Cliente: Sucesso (dados do usuário e secret)
    
    Cliente->>Redis Cliente: Armazena secret localmente
```

### 2. Fluxo de Login com TOTP

```mermaid
sequenceDiagram
    participant Cliente
    participant Servidor
    participant IPInfo
    participant Redis
    participant Postgres

    Note right of Cliente: Primeira Etapa - Verificar Credenciais e Localização

    Cliente->>Servidor: POST /login (número_celular, senha)
    Servidor->>Postgres: Busca usuário pelo número
    Postgres-->>Servidor: Dados do usuário

    Note over Servidor: Verifica senha com Scrypt
    
    Servidor->>IPInfo: Consulta país do IP
    IPInfo-->>Servidor: Retorna país
    
    Note over Servidor: Compara país do IP com país cadastrado
    
    Servidor-->>Cliente: Sucesso: "I'll wait for the 6-digit code"

    Note right of Cliente: Segunda Etapa - Verificação TOTP
    
    Note over Cliente: Recupera secret do Redis local
    Note over Cliente: Gera código TOTP usando o secret
    
    Cliente->>Servidor: POST /verify-totp (número_celular, código TOTP)
    Servidor->>Redis: Recupera secret do usuário
    Redis-->>Servidor: Secret do usuário
    
    Note over Servidor: Verifica código TOTP usando secret
    Note over Servidor: Gera chave simétrica e IV aleatório
    
    Servidor-->>Cliente: Autenticação 3FA completa (chave de sessão, IV)
```

### 3. Fluxo de Mensagem Criptografada

```mermaid
sequenceDiagram
    participant Cliente
    participant Servidor
    participant Redis

    Note right of Cliente: Após Login 3FA bem-sucedido

    Note over Servidor: Armazena código TOTP usado na verificação
    Servidor->>Redis: Salva {totp_code, iv, timestamp} com TTL de 5 min
    
    Note over Cliente: Possui chave de sessão e IV do servidor
    Note over Cliente: Usuário digita mensagem
    
    Note over Cliente: Criptografa mensagem com AES-256-GCM
    Note over Cliente: Obtém tag de autenticação
    
    Cliente->>Servidor: POST /send-message (mensagem cifrada, IV, número_celular)
    
    Servidor->>Redis: Recupera secret do usuário
    Redis-->>Servidor: Secret do usuário
    
    Servidor->>Redis: Recupera código TOTP salvo da sessão
    Redis-->>Servidor: Dados da sessão {totp_code, iv, timestamp}
    
    Note over Servidor: Deriva mesma chave simétrica usando TOTP salvo + secret
    
    Note over Servidor: Descriptografa a mensagem com AES-256-GCM
    Note over Servidor: Verifica tag de autenticação
    
    Servidor-->>Cliente: Confirmação e mensagem descriptografada
``` 