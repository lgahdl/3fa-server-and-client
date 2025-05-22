#!/usr/bin/env node
/**
 * Cliente interativo para testar a API do servidor
 *
 * Este cliente permite registrar usuários através de um menu interativo,
 * se conecta ao Redis para armazenar dados do cliente,
 * e gerencia o secret gerado pelo servidor.
 */
const axios = require("axios");
const readline = require("readline");
const redis = require("redis");
const crypto = require("crypto");
const { totp } = require("otplib");

// Configuração da API
const BASE_URL = "http://127.0.0.1:3000";
const REDIS_CLIENT_URL =
  process.env.REDIS_CLIENT_URL || "redis://localhost:6380";

// IPs de teste para diferentes países
const TEST_IPS = {
  Brasil: "200.152.38.1", // São Paulo, Brasil
  EUA: "8.8.8.8", // Google DNS, EUA
  UK: "176.32.103.205", // Amazon UK
  Japão: "203.104.153.1", // Tóquio, Japão
  local: "127.0.0.1", // Localhost
};

// Cliente Redis
let redisClient = null;

// Criar interface de linha de comando interativa
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

// Configurações do TOTP
totp.options = {
  digits: 6, // Código de 6 dígitos
  step: 30, // Validade de 30 segundos
  window: 1, // Permitir uma pequena janela de tempo antes/depois
};


// Inicializar conexão com o Redis
async function initRedis() {
  try {
    console.log(`Conectando ao Redis em ${REDIS_CLIENT_URL}...`);
    redisClient = redis.createClient({
      url: REDIS_CLIENT_URL,
    });

    redisClient.on("error", (err) => {
      console.error("Erro no Redis:", err);
    });

    redisClient.on("connect", () => {
      console.log("Conectado ao Redis com sucesso!");
    });

    await redisClient.connect();
    return true;
  } catch (error) {
    console.error("Erro ao conectar ao Redis:", error);
    console.log("Continuando sem suporte a Redis...");
    return false;
  }
}

// Salvar secret no Redis usando número de celular como chave
async function salvarSecretRedis(numeroCelular, secret) {
  if (!redisClient) return;

  try {
    await redisClient.set(numeroCelular, secret);
    console.log(
      `Secret armazenado no Redis do cliente com chave: ${numeroCelular}`
    );
    return true;
  } catch (error) {
    console.error("Erro ao salvar secret no Redis:", error);
    return false;
  }
}

// Função para fazer perguntas ao usuário
function pergunta(pergunta) {
  return new Promise((resolve) => {
    rl.question(pergunta, (resposta) => {
      resolve(resposta);
    });
  });
}

// Função para obter o IP público real
async function getPublicIP() {
  try {
    const response = await axios.get("https://api.ipify.org?format=json");
    return response.data.ip;
  } catch (error) {
    console.error("Erro ao obter IP público:", error);
    return TEST_IPS.Brasil; // Fallback para IP do Brasil se falhar
  }
}

// Função para escolher um país/IP
async function escolherPais() {
  console.log("\nEscolha o país/IP para simular:");
  const paises = Object.keys(TEST_IPS);

  paises.forEach((pais, index) => {
    console.log(`${index + 1}. ${pais} (${TEST_IPS[pais]})`);
  });
  console.log(`${paises.length + 1}. IP real (detectar automaticamente)`);
  console.log(`${paises.length + 2}. Outro (digitar manualmente)`);

  let escolha;
  do {
    escolha = await pergunta("Digite o número da opção desejada: ");
    escolha = parseInt(escolha);
  } while (isNaN(escolha) || escolha < 1 || escolha > paises.length + 2);

  if (escolha <= paises.length) {
    const paisSelecionado = paises[escolha - 1];
    return { ip: TEST_IPS[paisSelecionado], pais: paisSelecionado };
  } else if (escolha === paises.length + 1) {
    // Usar IP real
    console.log("🌐 Obtendo seu IP público real...");
    const ip = await getPublicIP();
    return { ip, pais: "IP real" };
  } else {
    const ip = await pergunta("Digite o endereço IP desejado: ");
    return { ip, pais: "personalizado" };
  }
}

// Função para derivar chave de sessão e IV a partir do TOTP
async function deriveSessionKeys(totpCode, derivationSalt, numeroCelular) {
  // Recuperar o secret do Redis
  let secret;
  if (redisClient) {
    secret = await redisClient.get(numeroCelular);
    if (!secret) {
      throw new Error('Secret não encontrado no Redis');
    }
  } else {
    throw new Error('Redis não disponível para obter o secret');
  }

  // Usar o mesmo método de derivação do servidor: TOTP + secret
  const keyMaterial = `${totpCode}${secret}`;

  // Derivar chave mestra usando PBKDF2 (48 bytes: 32 para chave + 16 para IV)
  const masterKey = await new Promise((resolve, reject) => {
    crypto.pbkdf2(
      keyMaterial,
      Buffer.from(derivationSalt, 'hex'),
      100000, // 100.000 iterações
      48,     // 48 bytes (32 para chave + 16 para IV)
      'sha256',
      (err, derivedKey) => {
        if (err) reject(err);
        else resolve(derivedKey);
      }
    );
  });

  // Separar a chave mestra em chave de sessão (32 bytes) e IV (16 bytes)
  const sessionKey = masterKey.slice(0, 32);
  const iv = masterKey.slice(32, 48);

  // LOG: Mostrar as chaves derivadas no cliente
  console.log(`[CLIENT] sessionKey (hex): ${sessionKey.toString('hex')}`);
  console.log(`[CLIENT] iv (hex): ${iv.toString('hex')}`);

  return { sessionKey, iv };
}

// Função para registrar um usuário
async function registrarUsuario() {
  console.log("\n=== REGISTRO DE USUÁRIO ===");

  const nome = await pergunta("Nome: ");
  const numeroCelular = await pergunta(
    "Número de celular (ex: +5511999999999): "
  );
  const senha = await pergunta("Senha: ");
  const confirmacaoSenha = await pergunta("Confirme a senha: ");

  if (senha !== confirmacaoSenha) {
    console.log("\n❌ As senhas não coincidem. Tente novamente.");
    return await menuPrincipal();
  }

  const { ip, pais } = await escolherPais();

  const userData = {
    nome,
    numero_celular: numeroCelular,
    senha,
  };

  console.log("\nEnviando requisição de registro...");
  console.log(`IP simulado: ${ip} (${pais})`);

  // Log detalhado dos dados enviados
  console.log("\n📤 DADOS ENVIADOS PARA O SERVIDOR:");
  console.log(JSON.stringify(userData, null, 2));
  console.log(`Headers: X-Forwarded-For: ${ip}`);

  try {
    const response = await axios.post(`${BASE_URL}/register`, userData, {
      headers: {
        "Content-Type": "application/json",
        "X-Forwarded-For": ip,
      },
    });

    if (response.data.success) {
      console.log("\n✅ USUÁRIO REGISTRADO COM SUCESSO!");
      console.log("Detalhes:");
      console.log(`ID: ${response.data.user.id}`);
      console.log(`Nome: ${response.data.user.nome}`);
      console.log(`Número: ${response.data.user.numero_celular}`);
      console.log(`País detectado: ${response.data.user.local}`);
      console.log(
        `Criado em: ${new Date(response.data.user.created_at).toLocaleString()}`
      );

      // Verificar se o servidor retornou um secret
      if (response.data.secret) {
        console.log(
          `\n🔑 Secret recebido do servidor: ${response.data.secret}`
        );

        // Armazenar o secret no Redis do cliente usando o número de celular como chave
        if (redisClient) {
          const salvou = await salvarSecretRedis(
            numeroCelular,
            response.data.secret
          );
          if (salvou) {
            console.log(
              `✅ Secret armazenado com sucesso para o número ${numeroCelular}.`
            );
            console.log(
              "Para verificar o secret, utilize a opção 4 no menu principal."
            );
          }
        } else {
          console.log(
            "❌ Redis não disponível. Não foi possível armazenar o secret."
          );
          console.log(
            `🔒 IMPORTANTE: Guarde este secret: ${response.data.secret}`
          );
        }
      } else {
        console.log("⚠️ O servidor não retornou um secret.");
      }
    } else {
      console.log("\n❌ FALHA NO REGISTRO:");
      console.log(response.data.message);
    }
  } catch (error) {
    console.error("\n❌ ERRO AO REGISTRAR:");
    if (error.response) {
      console.error(`Status: ${error.response.status}`);
      console.error(
        "Mensagem:",
        error.response.data.message || JSON.stringify(error.response.data)
      );
    } else {
      console.error("Erro:", error.message);
    }
  }

  await menuPrincipal();
}

// Função para fazer login completo (3FA)
async function fazerLogin() {
  console.log("\n=== LOGIN DE USUÁRIO ===");

  const numeroCelular = await pergunta("Número de celular: ");
  const senha = await pergunta("Senha: ");

  const loginData = {
    numero_celular: numeroCelular,
    senha: senha,
  };

  const { ip, pais } = await escolherPais();

  console.log("\nEnviando requisição de login...");
  console.log(`IP simulado: ${ip} (${pais})`);

  try {
    // Primeira etapa: verificar credenciais e localização
    const loginResponse = await axios.post(`${BASE_URL}/login`, loginData, {
      headers: {
        "Content-Type": "application/json",
        "X-Forwarded-For": ip,
      },
    });

    if (!loginResponse.data.success) {
      console.log("\n❌ FALHA NO LOGIN:");
      console.log(loginResponse.data.message);
      if (loginResponse.data.login_country && loginResponse.data.registered_country) {
        console.log(`País de login: ${loginResponse.data.login_country}`);
        console.log(`País registrado: ${loginResponse.data.registered_country}`);
      }
      return await menuPrincipal();
    }

    console.log("\n✅ PRIMEIRA ETAPA CONCLUÍDA!");
    console.log(loginResponse.data.message);

    // Segunda etapa: verificação TOTP
    console.log("\n=== VERIFICAÇÃO TOTP ===");

    // Recuperar o secret do Redis
    let secret;
    if (redisClient) {
      secret = await redisClient.get(numeroCelular);
      if (!secret) {
        console.log("❌ Secret não encontrado no Redis. Verifique se você se registrou.");
        return await menuPrincipal();
      }
    } else {
      secret = await pergunta("Digite o secret (obtido no registro): ");
    }

    // Gerar código TOTP
    const totpCode = totp.generate(secret);
    console.log(`\n🔑 Código TOTP gerado: ${totpCode}`);

    // Perguntar se deseja usar o código gerado ou inserir manualmente
    const usarCodigoGerado = await pergunta("\nDeseja usar o código TOTP gerado? (s/n): ");
    let codigoTOTP;

    if (usarCodigoGerado.toLowerCase() === 's') {
      codigoTOTP = totpCode;
    } else {
      codigoTOTP = await pergunta("Digite o código TOTP: ");
    }

    // Enviar código TOTP para verificação
    const totpResponse = await axios.post(`${BASE_URL}/verify-totp`, {
      numero_celular: numeroCelular,
      totp_code: codigoTOTP,
    });

    if (!totpResponse.data.success) {
      console.log("\n❌ FALHA NA VERIFICAÇÃO TOTP:");
      console.log(totpResponse.data.message);
      return await menuPrincipal();
    }

    console.log("\n✅ VERIFICAÇÃO TOTP CONCLUÍDA!");
    console.log(totpResponse.data.message);

    // Derivar chave de sessão e IV usando o TOTP e o salt recebido
    const { sessionKey, iv } = await deriveSessionKeys(totpCode, totpResponse.data.derivation_salt, numeroCelular);

    // Armazenar as chaves no Redis do cliente
    if (redisClient) {
      await redisClient.set(
        `session:${numeroCelular}`,
        JSON.stringify({
          sessionKey: sessionKey.toString('hex'),
          iv: iv.toString('hex'),
          totpCode: totpCode, // Using camelCase consistently
          derivationSalt: totpResponse.data.derivation_salt, // Store the derivation salt from server
          timestamp: Date.now()
        }),
        { EX: 300 } // TTL de 5 minutos
      );
      console.log("\n✅ Chaves de sessão armazenadas no Redis do cliente.");
    } else {
      console.log("\n⚠️ Redis não disponível. As chaves não foram armazenadas.");
      console.log("Chave de sessão (hex):", sessionKey.toString('hex'));
      console.log("IV (hex):", iv.toString('hex'));
    }

    // Perguntar se deseja enviar uma mensagem criptografada
    const enviarMensagem = await pergunta("\nDeseja enviar uma mensagem criptografada? (s/n): ");
    if (enviarMensagem.toLowerCase() === 's') {
      await enviarMensagemCifrada(numeroCelular, sessionKey, iv);
    }

  } catch (error) {
    console.error("\n❌ ERRO DURANTE O LOGIN:");
    if (error.response) {
      console.error(`Status: ${error.response.status}`);
      console.error("Mensagem:", error.response.data.message || JSON.stringify(error.response.data));
    } else {
      console.error("Erro:", error.message);
    }
  }

  await menuPrincipal();
}

// Função para enviar mensagem criptografada
async function enviarMensagemCifrada(numeroCelular, sessionKey, iv) {
  console.log("\n=== ENVIAR MENSAGEM CRIPTOGRAFADA ===");

  // Recuperar dados da sessão do Redis
  let sessionData;
  if (redisClient) {
    const sessionJson = await redisClient.get(`session:${numeroCelular}`);
    if (sessionJson) {
      sessionData = JSON.parse(sessionJson);
      // Recuperar as chaves armazenadas
      sessionKey = Buffer.from(sessionData.sessionKey, 'hex');
      iv = Buffer.from(sessionData.iv, 'hex');
    } else {
      // Se não encontrou a sessão, tenta derivar as chaves novamente
      const totpCode = sessionData?.totpCode;
      const derivationSalt = sessionData?.derivationSalt;
      if (totpCode && derivationSalt) {
        const keys = await deriveSessionKeys(totpCode, derivationSalt, numeroCelular);
        sessionKey = keys.sessionKey;
        iv = keys.iv;
      } else {
        console.log("❌ Dados da sessão incompletos. Faça login novamente.");
        return;
      }
    }
  }

  // LOG: Mostrar as chaves que serão usadas para cifrar
  console.log(`[CLIENT] (enviarMensagemCifrada) sessionKey (hex): ${sessionKey.toString('hex')}`);
  console.log(`[CLIENT] (enviarMensagemCifrada) iv (hex): ${iv.toString('hex')}`);

  if (!sessionKey || !iv) {
    console.log("❌ Chaves de sessão não encontradas. Faça login novamente.");
    return;
  }

  const mensagem = await pergunta("Digite a mensagem a ser enviada: ");

  // Criptografar a mensagem
  const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey, iv);
  const encrypted = Buffer.concat([cipher.update(mensagem, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Concatenar o texto cifrado com a tag de autenticação
  const encryptedMessage = Buffer.concat([encrypted, authTag]).toString('hex');

  try {
    const response = await axios.post(`${BASE_URL}/send-message`, {
      numero_celular: numeroCelular,
      encrypted_message: encryptedMessage,
      iv: iv.toString('hex')
      // Não enviamos mais o TOTP, pois ele está armazenado no servidor
    });

    if (response.data.success) {
      console.log("\n✅ MENSAGEM ENVIADA E DESCRIPTOGRAFADA COM SUCESSO!");
      console.log("Mensagem original:", response.data.decrypted_message);
    } else {
      console.log("\n❌ ERRO AO ENVIAR MENSAGEM:");
      console.log(response.data.message);
    }
  } catch (error) {
    console.error("\n❌ ERRO AO ENVIAR MENSAGEM:");
    if (error.response) {
      console.error(`Status: ${error.response.status}`);
      console.error("Mensagem:", error.response.data.message || JSON.stringify(error.response.data));
    } else {
      console.error("Erro:", error.message);
    }
  }
}

// Função do menu principal
async function menuPrincipal() {
  console.log("\n==============================");
  console.log("🔐 SISTEMA DE AUTENTICAÇÃO 3FA");
  console.log("==============================");
  console.log("1. Registrar novo usuário");
  console.log("2. Login completo (3FA)");
  console.log("0. Sair");

  const opcao = await pergunta("\nEscolha uma opção: ");

  switch (opcao) {
    case "1":
      await registrarUsuario();
      break;
    case "2":
      await fazerLogin();
      break;
    case "0":
      console.log("\nEncerrando cliente...");
      if (redisClient) {
        await redisClient.disconnect();
      }
      rl.close();
      break;
    default:
      console.log("\n❌ Opção inválida. Tente novamente.");
      await menuPrincipal();
  }
}

// Função principal
async function main() {
  console.log("===================================");
  console.log("🌐 CLIENTE DE TESTE INTERATIVO 🌐");
  console.log("===================================");
  console.log(`Servidor conectado em: ${BASE_URL}`);

  // Tentar inicializar Redis
  await initRedis();

  await menuPrincipal();
}

// Iniciar o programa
main().catch((error) => {
  console.error("Erro não tratado:", error);
  if (redisClient) {
    redisClient.disconnect().catch(console.error);
  }
  rl.close();
});
