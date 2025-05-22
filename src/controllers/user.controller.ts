import { Context } from 'hono';
import { UserService } from '../services/user.service';
import { EncryptUtils } from '../utils/encrypt-utils';
import { IPInfoService } from '../services/ipinfo.service';
import RedisService from '../services/redis.service';
import crypto from 'crypto';
import { totp } from 'otplib';

// Configure TOTP settings
totp.options = { 
  digits: 6,       // 6-digit code
  step: 30,        // 30-second validity
  window: 1        // Allow small time window before/after
};

export class UserController {
  /**
   * Manipula o registro de um novo usuário
   */
  static async register(c: Context) {
    try {
      // Obter o IP do cliente
      const clientIP = UserController.getClientIP(c);
      console.log(`Requisição de registro recebida do IP local: ${clientIP}`);
      
      // Obter o país do IP
      let country = 'Brasil'; // Valor padrão
      
      // Se for um IP público válido, tenta obter o país
      if (clientIP !== '127.0.0.1' && !clientIP.startsWith('192.168.') && 
          !clientIP.startsWith('10.') && !clientIP.match(/^172\.(1[6-9]|2[0-9]|3[0-1])\./)) {
        try {
          country = await IPInfoService.getCountryFromIP(clientIP);
          console.log(`País detectado a partir do IP: ${country}`);
        } catch (err) {
          console.log('Não foi possível obter o país do IP, usando padrão:', err);
        }
      } else {
        console.log(`IP detectado é local/privado (${clientIP}), usando país padrão: ${country}`);
      }
      
      // Obter dados do corpo da requisição
      const body = await c.req.json();
      
      // Validar dados recebidos
      if (!body.nome || !body.numero_celular || !body.senha) {
        return c.json({
          success: false,
          message: 'Dados incompletos. Nome, número de celular e senha são obrigatórios.'
        }, 400);
      }
      
      // Gerar salt para a senha
      const salt = EncryptUtils.generateSalt();
      
      // Encriptar a senha usando SCRYPT
      const senhaEncriptada = await EncryptUtils.hash(body.senha, salt);
      
      // Registrar o usuário com o país detectado
      const result = await UserService.register({
        nome: body.nome,
        numero_celular: body.numero_celular,
        senha: senhaEncriptada,
        salt: salt,
        local: country // Usar o país detectado ou o padrão
      });
      
      if (!result.success) {
        return c.json({
          success: false,
          message: result.error
        }, 400);
      }
      
      // Gerar o "secret" usando PBKDF2
      const secretInput = `${body.senha}${salt}`;
      const secretHash = await EncryptUtils.generateSecret(secretInput, salt);
      
      // Armazenar o secret no Redis do servidor com a chave sendo o número de celular
      await RedisService.set(body.numero_celular, secretHash);
      console.log(`Secret armazenado no Redis para o celular: ${body.numero_celular}`);
      
      // Retorna sucesso, os dados do usuário (exceto senha e salt) e o secret
      const { senha, salt: userSalt, ...userWithoutSensitiveData } = result.user;
      
      return c.json({
        success: true,
        message: 'Usuário registrado com sucesso',
        user: userWithoutSensitiveData,
        secret: secretHash // Retornar o secret para o cliente
      }, 201);
    } catch (error) {
      console.error('Erro ao processar registro:', error);
      
      return c.json({
        success: false,
        message: 'Erro interno do servidor'
      }, 500);
    }
  }

  /**
   * Obtém o endereço IP do cliente a partir do contexto da requisição
   */
  private static getClientIP(c: Context): string {
    try {
      // Tenta obter do cabeçalho X-Forwarded-For (usado por proxies/load balancers)
      const forwardedFor = c.req.header('X-Forwarded-For');
      if (forwardedFor) {
        // O X-Forwarded-For pode conter múltiplos IPs separados por vírgula
        // O primeiro é geralmente o IP original do cliente
        return forwardedFor.split(',')[0].trim();
      }

      // Tenta obter do cabeçalho x-real-ip
      const realIP = c.req.header('x-real-ip');
      if (realIP) {
        return realIP;
      }

      // Tenta obter do cabeçalho cf-connecting-ip (Cloudflare)
      const cfIP = c.req.header('cf-connecting-ip');
      if (cfIP) {
        return cfIP;
      }

      // Em ambiente de desenvolvimento, podemos usar o host
      const host = c.req.header('host');
      if (host) {
        // O formato geralmente é IP:porta
        const parts = host.split(':');
        if (parts.length > 0 && parts[0]) {
          return parts[0];
        }
      }

      // Se nada mais funcionar, retorne um valor padrão
      return '127.0.0.1';
    } catch (error) {
      console.error('Erro ao obter IP do cliente:', error);
      return '127.0.0.1';
    }
  }

  /**
   * Obtém o IP público do servidor utilizando um serviço externo
   * Isso não fornece o IP do cliente, mas o IP do servidor!
   */
  private static async getPublicIP(): Promise<string> {
    try {
      const response = await fetch('https://api.ipify.org?format=json');
      if (!response.ok) {
        throw new Error(`Erro ao obter IP público: ${response.status}`);
      }
      const data = await response.json();
      return data.ip;
    } catch (error) {
      console.error('Erro ao buscar IP público:', error);
      throw error;
    }
  }
  
  /**
   * Realiza a verificação inicial de login
   * Verifica se o número de celular e senha estão corretos
   */
  static async login(c: Context) {
    try {
      // Obter dados do corpo da requisição
      const body = await c.req.json();
      
      // Validar dados recebidos
      if (!body.numero_celular || !body.senha) {
        return c.json({
          success: false,
          message: 'Dados incompletos. Número de celular e senha são obrigatórios.'
        }, 400);
      }
      
      // Obter o IP do cliente
      const clientIP = UserController.getClientIP(c);
      console.log(`Requisição de login recebida do IP: ${clientIP}`);
      
      // Buscar usuário pelo número de celular
      const usuario = await UserService.findByPhoneNumber(body.numero_celular);
      
      if (!usuario) {
        // Não informar especificamente que o usuário não existe (segurança)
        return c.json({
          success: false,
          message: 'Login information not right'
        }, 401);
      }
      
      // Verificar se a senha está correta
      const senhaCorreta = await EncryptUtils.verify(body.senha, usuario.senha, usuario.salt);
      
      if (!senhaCorreta) {
        return c.json({
          success: false,
          message: 'Login information not right'
        }, 401);
      }
      
      // Verificar o país do IP (primeiro fator - localização)
      let country = 'Desconhecido';
      try {
        country = await IPInfoService.getCountryFromIP(clientIP);
        console.log(`País do IP de login: ${country}, País do cadastro: ${usuario.local}`);
        
        // Se o país não corresponder, retornar erro
        if (country !== 'Desconhecido' && country !== usuario.local) {
          console.log(`ALERTA: Login rejeitado de um país diferente do cadastrado!`);
          return c.json({
            success: false,
            message: 'Acesso negado: Login de um país diferente do registrado.',
            login_country: country,
            registered_country: usuario.local
          }, 403);
        }
      } catch (err) {
        console.error('Erro ao verificar país do IP:', err);
      }
      
      // Se chegou aqui, é porque o número de celular e senha estão corretos
      return c.json({
        success: true,
        message: "I'll wait for the 6-digit code",
        user_id: usuario.id,
        country_match: country === usuario.local,
        login_country: country,
        registered_country: usuario.local
      });
      
    } catch (error) {
      console.error('Erro ao processar login:', error);
      
      return c.json({
        success: false,
        message: 'Erro interno do servidor'
      }, 500);
    }
  }

  /**
   * Verifica o código TOTP enviado pelo usuário (terceiro fator)
   * e retorna uma chave simétrica para criptografia da mensagem
   */
  static async verifyTOTP(c: Context) {
    try {
      // Obter dados do corpo da requisição
      const body = await c.req.json();
      
      // Validar dados recebidos
      if (!body.numero_celular || !body.totp_code) {
        return c.json({
          success: false,
          message: 'Dados incompletos. Número de celular e código TOTP são obrigatórios.'
        }, 400);
      }
      
      // Buscar o secret do usuário no Redis
      const secret = await RedisService.get(body.numero_celular);
      
      if (!secret) {
        return c.json({
          success: false,
          message: 'Erro de autenticação. Secret não encontrado.'
        }, 401);
      }
      
      console.log(`Verificando TOTP: código=${body.totp_code}, secret=${secret}`);
      
      // Verificar se o código TOTP é válido
      let isValid = false;
      try {
        // Para verificar o código TOTP, usamos o método check que suporta uma janela de validação
        isValid = totp.check(body.totp_code, secret);
        console.log(`Resultado da verificação TOTP: ${isValid}`);
      } catch (err: any) {
        console.error('Erro ao verificar TOTP:', err);
        return c.json({
          success: false,
          message: `Erro ao verificar TOTP: ${err.message || 'Erro desconhecido'}`
        }, 401);
      }
      
      if (!isValid) {
        return c.json({
          success: false,
          message: 'Código TOTP inválido ou expirado.'
        }, 401);
      }
      
      // Gerar um salt aleatório para PBKDF2
      const derivationSalt = crypto.randomBytes(16).toString('hex');
      
      // Armazenar o salt de derivação, o TOTP e o timestamp no Redis
      const sessionKey = `session:${body.numero_celular}`;
      const sessionData = {
        derivationSalt: derivationSalt,
        totpCode: body.totp_code,
        timestamp: Date.now()
      };
      
      // Armazenar os dados da sessão no Redis com TTL de 5 minutos (300 segundos)
      await RedisService.set(sessionKey, JSON.stringify(sessionData), 300);
      console.log(`Dados da sessão armazenados para ${body.numero_celular}:`, {
        ...sessionData,
        totpCode: '***'
      });
      
      // Retornar apenas o salt de derivação para o cliente
      return c.json({
        success: true,
        message: 'Autenticação completa! 3FA bem-sucedida.',
        derivation_salt: derivationSalt
      });
      
    } catch (error) {
      console.error('Erro ao verificar TOTP:', error);
      
      return c.json({
        success: false,
        message: 'Erro interno do servidor'
      }, 500);
    }
  }
  
  /**
   * Recebe e descriptografa uma mensagem enviada pelo cliente
   */
  static async receiveMessage(c: Context) {
    try {
      // Obter dados do corpo da requisição
      const body = await c.req.json();
      
      // LOG: Exibir corpo da requisição recebido
      console.log('--- [receiveMessage] Corpo da requisição recebido ---');
      console.log(body);
      
      // Validar dados recebidos (não precisamos mais do TOTP no corpo)
      if (!body.encrypted_message || !body.iv || !body.numero_celular) {
        return c.json({
          success: false,
          message: 'Dados incompletos. Mensagem criptografada, IV e número de celular são obrigatórios.'
        }, 400);
      }
      
      // LOG: Exibir número de celular recebido
      console.log(`[receiveMessage] Número de celular recebido: ${body.numero_celular}`);
      
      // Buscar o secret do usuário no Redis
      const secret = await RedisService.get(body.numero_celular);
      
      if (!secret) {
        return c.json({
          success: false,
          message: 'Erro ao descriptografar. Secret não encontrado.'
        }, 401);
      }
      
      // Buscar os dados da sessão armazenados
      const sessionKey = `session:${body.numero_celular}`;
      const sessionDataJson = await RedisService.get(sessionKey);
      
      // LOG: Exibir conteúdo bruto da sessão lida do Redis
      console.log(`[receiveMessage] Conteúdo bruto da sessão do Redis para ${sessionKey}:`);
      console.log(sessionDataJson);
      
      if (!sessionDataJson) {
        return c.json({
          success: false,
          message: 'Sessão expirada ou não encontrada. Faça login novamente.'
        }, 401);
      }
      
      // Converter os dados da sessão de JSON para objeto
      const sessionData = JSON.parse(sessionDataJson);
      
      // Verificar se temos o TOTP armazenado na sessão
      if (!sessionData.totpCode) {
        return c.json({
          success: false,
          message: 'Sessão inválida. Faça login novamente.'
        }, 401);
      }
      
      // Usar o TOTP armazenado na sessão e o salt de derivação
      const derivationSalt = Buffer.from(sessionData.derivationSalt, 'hex');
      const totpCode = sessionData.totpCode;
      
      console.log('Usando TOTP armazenado na sessão');
      
      // Derivar chave mestra usando o EncryptUtils (48 bytes: 32 para chave + 16 para IV)
      const keyMaterial = `${totpCode}${secret}`;
      const masterKey = await EncryptUtils.deriveSymmetricKey(keyMaterial, derivationSalt, 48);
      
      // Separar a chave mestra em chave de sessão (32 bytes) e IV (16 bytes)
      const symmetricKey = masterKey.slice(0, 32);
      const derivedIV = masterKey.slice(32, 48);
      
      console.log(`Tamanho da chave mestra: ${masterKey.length} bytes`);
      console.log(`Tamanho da chave de sessão: ${symmetricKey.length} bytes`);
      console.log(`Tamanho do IV derivado: ${derivedIV.length} bytes`);
      
      console.log(`[receiveMessage] symmetricKey (hex): ${symmetricKey.toString('hex')}`);
      console.log(`[receiveMessage] derivedIV (hex): ${derivedIV.toString('hex')}`);
      
      // Verificar se o IV derivado corresponde ao IV enviado pelo cliente
      const clientIV = Buffer.from(body.iv, 'hex');
      if (!derivedIV.equals(clientIV)) {
        console.error('IV derivado não corresponde ao IV enviado pelo cliente');
        return c.json({
          success: false,
          message: 'Falha na verificação do IV. Possível tentativa de manipulação.'
        }, 400);
      }
      
      // Descriptografar a mensagem
      try {
        // Separar o texto cifrado e a tag de autenticação
        const encryptedDataBuffer = Buffer.from(body.encrypted_message, 'hex');
        const ciphertext = encryptedDataBuffer.slice(0, -16); // Últimos 16 bytes são a tag de autenticação
        const authTag = encryptedDataBuffer.slice(-16);
        
        // Usar a função de descriptografia do EncryptUtils
        const message = EncryptUtils.decrypt(ciphertext, authTag, symmetricKey, derivedIV);
        
        return c.json({
          success: true,
          message: 'Mensagem recebida e descriptografada com sucesso',
          decrypted_message: message
        });
        
      } catch (decryptError) {
        console.error('Erro ao descriptografar mensagem:', decryptError);
        
        return c.json({
          success: false,
          message: 'Falha ao descriptografar a mensagem. Problema com a criptografia ou dados corrompidos.'
        }, 400);
      }
      
    } catch (error) {
      console.error('Erro ao processar mensagem criptografada:', error);
      
      return c.json({
        success: false,
        message: 'Erro interno do servidor'
      }, 500);
    }
  }
} 