import { createClient, RedisClientType } from 'redis';
import dotenv from 'dotenv';

dotenv.config();

class RedisService {
  private static client: RedisClientType | null = null;
  
  /**
   * Inicializa a conexão com o Redis do servidor
   */
  static async initialize() {
    try {
      const redisUrl = process.env.REDIS_SERVER_URL || 'redis://localhost:6379';
      
      // Inicializa o cliente do Redis do servidor
      this.client = createClient({
        url: redisUrl
      });
      
      // Lidar com eventos do Redis
      this.client.on('error', (err) => {
        console.error('Redis Server Error:', err);
      });
      
      this.client.on('connect', () => {
        console.log('Conectado ao Redis Server em', redisUrl);
      });
      
      // Conectar ao servidor Redis
      await this.client.connect();
      
      console.log('Conexão com Redis do servidor inicializada com sucesso');
    } catch (error) {
      console.error('Erro ao inicializar Redis do servidor:', error);
    }
  }
  
  /**
   * Obtém o cliente Redis
   */
  static getClient(): RedisClientType {
    if (!this.client) {
      throw new Error('Redis do servidor não está inicializado');
    }
    return this.client;
  }
  
  /**
   * Define um valor no Redis
   */
  static async set(key: string, value: string, expireSeconds?: number): Promise<void> {
    try {
      const client = this.getClient();
      await client.set(key, value);
      
      if (expireSeconds) {
        await client.expire(key, expireSeconds);
      }
    } catch (error) {
      console.error('Erro ao definir valor no Redis:', error);
      throw error;
    }
  }
  
  /**
   * Obtém um valor do Redis
   */
  static async get(key: string): Promise<string | null> {
    try {
      const client = this.getClient();
      return await client.get(key);
    } catch (error) {
      console.error('Erro ao obter valor do Redis:', error);
      throw error;
    }
  }
  
  /**
   * Fecha a conexão com o Redis
   */
  static async closeConnection(): Promise<void> {
    try {
      if (this.client) {
        await this.client.disconnect();
      }
      
      console.log('Conexão com Redis fechada com sucesso');
    } catch (error) {
      console.error('Erro ao fechar conexão com Redis:', error);
    }
  }
  
  // Métodos de compatibilidade para código existente
  
  /**
   * @deprecated Use set() instead
   */
  static async setServer(key: string, value: string, expireSeconds?: number): Promise<void> {
    return this.set(key, value, expireSeconds);
  }
  
  /**
   * @deprecated Use get() instead
   */
  static async getServer(key: string): Promise<string | null> {
    return this.get(key);
  }
}

export default RedisService; 