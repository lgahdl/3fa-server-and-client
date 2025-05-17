import { db } from '../db';
import { users, NewUser } from '../db/schema';
import { eq } from 'drizzle-orm';

export interface UserRegisterData {
  nome: string;
  numero_celular: string;
  senha: string;
  salt: string;
  local?: string; // Campo opcional para o país
}

export class UserService {
  /**
   * Registra um novo usuário no sistema
   */
  static async register(userData: UserRegisterData): Promise<{ success: boolean; user?: any; error?: string }> {
    try {
      // Verificar se o usuário já existe
      const existingUser = await db.select()
        .from(users)
        .where(eq(users.numero_celular, userData.numero_celular))
        .limit(1);

      if (existingUser.length > 0) {
        return {
          success: false,
          error: 'Usuário com este número de celular já existe'
        };
      }

      // Preparar os dados do usuário
      const newUser: NewUser = {
        nome: userData.nome,
        numero_celular: userData.numero_celular,
        local: userData.local || 'Brasil', // Usar o país fornecido ou o padrão
        senha: userData.senha,
        salt: userData.salt,
      };

      // Inserir o usuário no banco de dados
      const result = await db.insert(users).values(newUser).returning();

      return {
        success: true,
        user: result[0]
      };
    } catch (error) {
      console.error('Erro ao registrar usuário:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Erro desconhecido ao registrar usuário'
      };
    }
  }

  /**
   * Busca um usuário pelo número de celular
   */
  static async findByPhoneNumber(numeroCelular: string) {
    try {
      const result = await db.select()
        .from(users)
        .where(eq(users.numero_celular, numeroCelular))
        .limit(1);
        
      return result.length > 0 ? result[0] : null;
    } catch (error) {
      console.error('Erro ao buscar usuário:', error);
      throw error;
    }
  }
} 