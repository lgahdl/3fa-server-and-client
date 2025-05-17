// server/src/index.ts
import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { logger } from 'hono/logger';
import dotenv from 'dotenv';
import db from './db';
import { UserController } from './controllers/user.controller';
import RedisService from './services/redis.service';

// Carregar variáveis de ambiente
dotenv.config();

// Inicializar conexões Redis
RedisService.initialize().catch(err => {
  console.error('Falha ao inicializar Redis:', err);
  // Continua a inicialização mesmo se o Redis falhar
});

// Criar uma nova instância do Hono
const app = new Hono();

// Middleware de logger para registrar requisições
app.use('*', logger());

// Rota raiz que retorna uma mensagem simples
app.get('/', (c) => {
  return c.json({
    message: 'Servidor Hono funcionando!',
    timestamp: new Date().toISOString()
  });
});

// Rota de exemplo
app.get('/api/hello', (c) => {
  return c.json({
    message: 'Olá, mundo!',
    timestamp: new Date().toISOString()
  });
});

// Rota para testar a conexão com o banco de dados
app.get('/api/db-test', async (c) => {
  try {
    const result = await db.query('SELECT NOW() as current_time');
    return c.json({
      message: 'Conexão com o banco de dados bem-sucedida!',
      data: result.rows[0],
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Erro ao testar o banco de dados:', error);
    return c.json({
      message: 'Erro ao conectar com o banco de dados',
      error: error instanceof Error ? error.message : String(error),
      timestamp: new Date().toISOString()
    }, 500);
  }
});

// Rota para testar o Redis
app.get('/api/redis-test', async (c) => {
  try {
    const testKey = 'test-key';
    const testValue = 'Test value: ' + new Date().toISOString();
    
    // Testar Redis do servidor
    await RedisService.set(testKey, testValue);
    const value = await RedisService.get(testKey);
    
    return c.json({
      message: 'Conexão com Redis do servidor bem-sucedida!',
      data: {
        key: testKey,
        value: value
      },
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Erro ao testar o Redis:', error);
    return c.json({
      message: 'Erro ao conectar com o Redis',
      error: error instanceof Error ? error.message : String(error),
      timestamp: new Date().toISOString()
    }, 500);
  }
});

// Endpoint de registro de usuário
app.post('/register', UserController.register);

// Endpoint para login (primeira etapa)
app.post('/login', UserController.login);

// Endpoint para verificação TOTP (segunda etapa)
app.post('/verify-totp', UserController.verifyTOTP);

// Endpoint para receber mensagem criptografada
app.post('/send-message', UserController.receiveMessage);

// Porta onde o servidor irá escutar
const PORT = parseInt(process.env.PORT || '3000');

console.log(`Servidor iniciando na porta ${PORT}...`);

// Iniciar o servidor
serve({
  fetch: app.fetch,
  port: PORT
}, (info) => {
  console.log(`Servidor rodando em http://localhost:${info.port}`);
}); 