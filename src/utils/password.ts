import crypto from 'crypto';

/**
 * Utilitário para gerenciar senhas com algoritmo Scrypt
 */
export class PasswordUtil {
  /**
   * Gera um salt aleatório para uso na criptografia
   * @returns string contendo o salt em formato hexadecimal
   */
  static generateSalt(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Criptografa uma senha usando o algoritmo scrypt
   * @param password Senha a ser criptografada
   * @param salt Salt a ser usado na criptografia
   * @returns String contendo o hash gerado em formato hexadecimal
   */
  static async hash(password: string, salt: string): Promise<string> {
    return new Promise((resolve, reject) => {
      // Parâmetros do scrypt:
      // N = 16384 = 2^14 (custo de CPU/memória)
      // r = 8 (tamanho do bloco)
      // p = 1 (paralelismo)
      // keylen = 64 (tamanho da chave de saída em bytes)
      crypto.scrypt(password, salt, 64, { 
        N: 16384, // 2^14
        r: 8,
        p: 1 
      }, (err, derivedKey) => {
        if (err) reject(err);
        resolve(derivedKey.toString('hex'));
      });
    });
  }

  /**
   * Verifica se uma senha corresponde a um hash armazenado
   * @param password Senha a ser verificada
   * @param hash Hash armazenado
   * @param salt Salt usado para gerar o hash
   * @returns Booleano indicando se a senha corresponde ao hash
   */
  static async verify(password: string, hash: string, salt: string): Promise<boolean> {
    const calculatedHash = await this.hash(password, salt);
    return calculatedHash === hash;
  }
} 