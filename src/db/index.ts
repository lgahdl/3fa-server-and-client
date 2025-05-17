import { Pool } from 'pg';
import { drizzle } from 'drizzle-orm/node-postgres';
import * as schema from './schema';

// Configurações de conexão com o PostgreSQL
const pool = new Pool({
  host: process.env.POSTGRES_HOST || 'localhost',
  port: parseInt(process.env.POSTGRES_PORT || '5433'),
  database: process.env.POSTGRES_DB || 'app_db',
  user: process.env.POSTGRES_USER || 'postgres',
  password: process.env.POSTGRES_PASSWORD || 'postgres',
});

// Teste de conexão com o banco de dados
pool.connect((err, client, release) => {
  if (err) {
    return console.error('Erro ao conectar no PostgreSQL:', err);
  }
  console.log('Conexão com PostgreSQL estabelecida com sucesso!');
  release();
});

// Criar instância do DrizzleORM
export const db = drizzle(pool, { schema });

// Função legada para executar consultas SQL (manter para compatibilidade)
export const query = async (text: string, params?: any[]) => {
  try {
    const result = await pool.query(text, params);
    return result;
  } catch (error) {
    console.error('Erro ao executar consulta:', error);
    throw error;
  }
};

export default {
  query,
  pool,
  db
}; 