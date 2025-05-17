-- Arquivo de inicialização do banco de dados
-- Criar tabela de usuários com a estrutura solicitada
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  nome VARCHAR(100) NOT NULL,
  numero_celular VARCHAR(20) UNIQUE NOT NULL,
  local VARCHAR(50) NOT NULL, -- País
  senha VARCHAR(255) NOT NULL, -- Senha encriptada com SCRYPT
  salt VARCHAR(100) NOT NULL, -- Salt usado para encriptar a senha
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Criar tabela de posts
CREATE TABLE IF NOT EXISTS posts (
  id SERIAL PRIMARY KEY,
  title VARCHAR(100) NOT NULL,
  content TEXT NOT NULL,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);