import crypto from 'crypto';

// Constantes para PBKDF2
export const PBKDF2_ITERATIONS = 100000; // Número recomendado de iterações para PBKDF2
export const PBKDF2_KEYLEN = 32; // Tamanho da chave em bytes (256 bits para AES-256)
export const PBKDF2_DIGEST = 'sha256'; // Algoritmo de hash para PBKDF2

/**
 * Utilitário para gerenciar senhas e criptografia
 */
export class EncryptUtils {
  /**
   * Gera um salt aleatório para uso na criptografia
   * @param length Tamanho do salt em bytes
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

  /**
   * Gera um secret usando PBKDF2 a partir de uma senha e um salt
   * @param password Senha ou entrada a ser usada
   * @param salt Salt para aumentar a segurança
   * @returns Promise com o secret gerado em formato hexadecimal
   */
  static async generateSecret(password: string, salt: string): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      crypto.pbkdf2(
        password,
        salt,
        PBKDF2_ITERATIONS,
        PBKDF2_KEYLEN,
        PBKDF2_DIGEST,
        (err, derivedKey) => {
          if (err) reject(err);
          else resolve(derivedKey.toString('hex'));
        }
      );
    });
  }

  /**
   * Deriva uma chave simétrica para criptografia usando PBKDF2
   * @param keyMaterial Material para derivação da chave (ex: TOTP + secret)
   * @param salt Salt para a derivação
   * @returns Promise com a chave derivada como Buffer
   */
  static async deriveSymmetricKey(keyMaterial: string, salt: Buffer): Promise<Buffer> {
    return new Promise<Buffer>((resolve, reject) => {
      crypto.pbkdf2(
        keyMaterial,
        salt,
        PBKDF2_ITERATIONS,
        PBKDF2_KEYLEN,
        PBKDF2_DIGEST,
        (err, derivedKey) => {
          if (err) reject(err);
          else resolve(derivedKey);
        }
      );
    });
  }

  /**
   * Gera um IV (Initialization Vector) aleatório para uso em criptografia
   * @param length Tamanho do IV em bytes (16 bytes para AES)
   * @returns Buffer contendo o IV gerado
   */
  static generateIV(length: number = 16): Buffer {
    return crypto.randomBytes(length);
  }

  /**
   * Criptografa uma mensagem usando AES-256-GCM
   * @param message Mensagem a ser criptografada
   * @param key Chave de criptografia
   * @param iv Vetor de inicialização
   * @returns Objeto contendo o texto cifrado e a tag de autenticação
   */
  static encrypt(message: string, key: Buffer, iv: Buffer): { ciphertext: Buffer, authTag: Buffer } {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(message, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    
    return { ciphertext: encrypted, authTag };
  }

  /**
   * Descriptografa uma mensagem usando AES-256-GCM
   * @param ciphertext Texto cifrado
   * @param authTag Tag de autenticação
   * @param key Chave de criptografia
   * @param iv Vetor de inicialização
   * @returns Mensagem descriptografada
   */
  static decrypt(ciphertext: Buffer, authTag: Buffer, key: Buffer, iv: Buffer): string {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString('utf8');
  }
} 