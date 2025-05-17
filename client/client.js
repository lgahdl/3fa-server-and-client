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

// Testar conexão com Redis
async function testarRedis() {
  console.log("\n=== TESTE DE CONEXÃO COM REDIS ===");

  try {
    const response = await axios.get(`${BASE_URL}/api/redis-test`);
    console.log("Resposta do servidor:");
    console.log(JSON.stringify(response.data, null, 2));
  } catch (error) {
    console.error("Erro ao testar Redis:", error.message);
    if (error.response) {
      console.error("Dados da resposta:", error.response.data);
    }
  }

  await menuPrincipal();
}

// Verificar secret armazenado
async function verificarSecret() {
  console.log("\n=== VERIFICAR SECRET ARMAZENADO ===");

  if (!redisClient) {
    console.log("❌ Conexão com Redis não está disponível.");
    return await menuPrincipal();
  }

  const numeroCelular = await pergunta(
    "Digite o número de celular para verificar o secret: "
  );

  try {
    const secret = await redisClient.get(numeroCelular);

    if (secret) {
      console.log(`\n✅ Secret encontrado para o número ${numeroCelular}:`);
      console.log(`🔑 ${secret}`);
    } else {
      console.log(
        `\n❌ Nenhum secret encontrado para o número ${numeroCelular}`
      );
    }
  } catch (error) {
    console.error("Erro ao verificar secret:", error);
  }

  await menuPrincipal();
}

// Função para solicitar código TOTP
async function solicitarTOTP() {
  console.log("\n=== GERAÇÃO DE CÓDIGO TOTP ===");
  console.log("Pressione ESC a qualquer momento para voltar ao menu principal");

  if (!redisClient) {
    console.log("❌ Conexão com Redis não está disponível.");
    console.log("Necessário para verificar o secret armazenado.");
    return await menuPrincipal();
  }

  const numeroCelular = await pergunta("Digite o número de celular: ");

  try {
    // Verificar se temos o secret armazenado para este número
    const secret = await redisClient.get(numeroCelular);

    if (!secret) {
      console.log(
        `\n❌ Nenhum secret encontrado para o número ${numeroCelular}`
      );
      console.log("É necessário registrar o usuário primeiro.");
      return await menuPrincipal();
    }

    console.log(`\n✅ Secret encontrado para o número ${numeroCelular}.`);

    // Loop para gerar e mostrar códigos TOTP continuamente até ESC ser pressionado
    while (!escPressed) {
      // Gerar um novo código TOTP
      const code = totp.generate(secret);

      // Obter tempo restante (arredondando para cima para evitar mostrar 0)
      const remainingTime = totp.timeRemaining();

      // Gerar chave para o Redis
      const redisKey = `${numeroCelular}-totp`;

      // Dados a serem armazenados
      const totpData = {
        code,
        timestamp: Date.now(),
        secret,
        expires_at: Date.now() + remainingTime * 1000,
      };

      // Armazenar no Redis
      await redisClient.set(redisKey, JSON.stringify(totpData));
      await redisClient.expire(redisKey, 30); // Sempre usar 30 segundos para o Redis

      console.log("\n✅ CÓDIGO TOTP GERADO:");
      console.log(`Código: ${code}`);
      console.log(`Válido por: ${remainingTime} segundos`);
      console.log("\nO código expirará em:");

      // Contagem regressiva
      for (let i = remainingTime; i > 0; i--) {
        if (escPressed) break;
        process.stdout.write(
          `\r${i} segundos restantes... (Pressione ESC para sair)`
        );
        // Esperar 1 segundo
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }

      if (!escPressed) {
        console.log("\n\n⏱️ Código expirado! Gerando novo código...");
      }
    }

    // Remover o listener e restaurar o modo do terminal
    stdin.removeListener("data", keyListener);
    stdin.setRawMode(false);
    stdin.pause();
  } catch (error) {
    console.error("\n❌ ERRO AO GERAR CÓDIGO TOTP:");
    console.error("Erro:", error.message);
    // Restaurar o modo do terminal em caso de erro
    stdin.setRawMode(false);
    stdin.pause();
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

  try {
    console.log("\nEnviando requisição de login (primeira etapa)...");

    // Log detalhado dos dados enviados
    console.log("\n📤 DADOS DE LOGIN ENVIADOS:");
    console.log(JSON.stringify(loginData, null, 2));

    // Primeira etapa: login com telefone e senha
    const response = await axios.post(`${BASE_URL}/login`, loginData);

    if (!response.data.success) {
      console.log("\n❌ FALHA NO LOGIN:");
      console.log(response.data.message);
      return await menuPrincipal();
    }

    console.log("\n✅ PRIMEIRA ETAPA DE LOGIN BEM-SUCEDIDA!");
    console.log(`Mensagem: ${response.data.message}`);

    // Verificar se o país do IP corresponde ao país registrado
    if (response.data.country_match === false) {
      console.log(
        `\n⚠️ ALERTA: Você está acessando de um país diferente do registrado!`
      );
      console.log(`País atual: ${response.data.login_country}`);
      console.log(`País registrado: ${response.data.registered_country}`);
    }

    // Segunda etapa: verificar TOTP
    console.log("\n=== SEGUNDA ETAPA: TOTP ===");

    // Buscar o secret armazenado no Redis do cliente
    const secret = await redisClient.get(numeroCelular);

    if (!secret) {
      console.log(
        `\n❌ Não foi possível encontrar o secret para o número ${numeroCelular}`
      );
      console.log(
        "É necessário registrar o usuário primeiro ou o secret expirou."
      );
      return await menuPrincipal();
    }

    // Gerar TOTP com base no secret
    const code = totp.generate(secret);
    console.log(`\n✅ Código TOTP gerado: ${code}`);

    // Perguntar ao usuário se deseja usar o código gerado ou digitar manualmente
    const useGerado = await pergunta("Usar o código gerado? (s/n): ");

    const totpCode =
      useGerado.toLowerCase() === "s"
        ? code
        : await pergunta("Digite o código TOTP: ");

    const totpData = {
      numero_celular: numeroCelular,
      totp_code: totpCode,
    };

    // Log detalhado dos dados TOTP
    console.log("\n📤 DADOS TOTP ENVIADOS:");
    console.log(JSON.stringify(totpData, null, 2));

    // Enviar requisição para verificar TOTP
    console.log("\nVerificando código TOTP...");

    const totpResponse = await axios.post(`${BASE_URL}/verify-totp`, totpData);

    if (!totpResponse.data.success) {
      console.log("\n❌ FALHA NA VERIFICAÇÃO DO TOTP:");
      console.log(totpResponse.data.message);
      return await menuPrincipal();
    }

    console.log("\n✅ AUTENTICAÇÃO 3FA COMPLETA!");
    console.log("Parabéns! Você completou a autenticação de 3 fatores:");
    console.log("1. Fator de localização (IP)");
    console.log("2. Fator de conhecimento (senha)");
    console.log("3. Fator de posse (TOTP)");

    // Armazenar a chave de sessão retornada pelo servidor para uso posterior
    const sessionKey = totpResponse.data.session_key;
    const iv = totpResponse.data.iv;

    console.log("\n📥 DADOS RECEBIDOS DO SERVIDOR:");
    console.log(
      `Session Key: ${sessionKey.slice(0, 10)}...${sessionKey.slice(-10)} (${
        sessionKey.length
      } caracteres)`
    );
    console.log(`IV: ${iv} (${iv.length} caracteres)`);

    // Permitir ao usuário enviar uma mensagem cifrada
    const enviarMsg = await pergunta(
      "\nDeseja enviar uma mensagem cifrada? (s/n): "
    );

    if (enviarMsg.toLowerCase() === "s") {
      await enviarMensagemCifrada(numeroCelular, sessionKey, iv);
    } else {
      console.log("\nVoltando ao menu principal...");
    }
  } catch (error) {
    console.error("\n❌ ERRO AO FAZER LOGIN:");
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

// Função para enviar mensagem cifrada
async function enviarMensagemCifrada(numeroCelular, chave, ivHex) {
  console.log("\n=== ENVIO DE MENSAGEM CIFRADA ===");

  try {
    // Solicitar a mensagem ao usuário
    const mensagem = await pergunta(
      "Digite a mensagem a ser enviada (cifrada): "
    );

    // Converter a chave e o IV para os formatos corretos
    // A chave para AES-256-GCM deve ter exatamente 32 bytes
    let chaveBuffer = Buffer.from(chave, "hex").slice(0, 32);

    // Se a chave é menor que 32 bytes, preenchemos com zeros
    if (chaveBuffer.length < 32) {
      const novaChave = Buffer.alloc(32);
      chaveBuffer.copy(novaChave);
      chaveBuffer = novaChave;
    }

    const ivBuffer = Buffer.from(ivHex, "hex");

    console.log(`Tamanho da chave: ${chaveBuffer.length} bytes`);
    console.log(`Tamanho do IV: ${ivBuffer.length} bytes`);

    // Criar o cipher para criptografia AES-GCM
    const cipher = crypto.createCipheriv("aes-256-gcm", chaveBuffer, ivBuffer);

    // Criptografar a mensagem
    let encrypted = cipher.update(mensagem, "utf8", "hex");
    encrypted += cipher.final("hex");

    // Obter a tag de autenticação
    const authTag = cipher.getAuthTag();

    // Combinar o texto cifrado e a tag de autenticação
    const encryptedMessage = encrypted + authTag.toString("hex");

    console.log("\nMensagem criptografada com sucesso!");
    console.log("Detalhes técnicos da criptografia:");
    console.log(`- Texto original (${mensagem.length} caracteres)`);
    console.log(
      `- Texto cifrado (${encrypted.length} caracteres hexadecimais)`
    );
    console.log(`- Tag de autenticação (${authTag.length} bytes)`);
    console.log(
      `- Total criptografado: ${encryptedMessage.length} caracteres hexadecimais`
    );

    const messageData = {
      encrypted_message: encryptedMessage,
      iv: ivHex,
      numero_celular: numeroCelular,
    };

    // Log detalhado dos dados enviados
    console.log("\n📤 DADOS CRIPTOGRAFADOS ENVIADOS:");
    console.log(
      `Message: ${encryptedMessage.slice(0, 30)}...${encryptedMessage.slice(
        -30
      )} (${encryptedMessage.length} caracteres)`
    );
    console.log(`IV: ${ivHex} (${ivHex.length} caracteres)`);
    console.log(`Número Celular: ${numeroCelular}`);

    console.log("Enviando para o servidor...");

    // Enviar a mensagem criptografada ao servidor
    const response = await axios.post(`${BASE_URL}/send-message`, messageData);

    if (response.data.success) {
      console.log("\n✅ MENSAGEM RECEBIDA PELO SERVIDOR!");
      console.log(`Resposta: ${response.data.message}`);
      console.log(
        `Mensagem descriptografada no servidor: ${response.data.decrypted_message}`
      );
    } else {
      console.log("\n❌ FALHA AO ENVIAR MENSAGEM:");
      console.log(response.data.message);
    }
  } catch (error) {
    console.error("\n❌ ERRO AO ENVIAR MENSAGEM CIFRADA:");
    if (error.response) {
      console.error(`Status: ${error.response.status}`);
      console.error(
        "Mensagem:",
        error.response.data.message || JSON.stringify(error.response.data)
      );
    } else {
      console.error("Erro:", error.message);
      console.error("Detalhes do erro:", error);
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
  console.log("3. Testar conexão Redis");
  console.log("4. Verificar secret armazenado");
  console.log("5. Solicitar código TOTP");
  console.log("0. Sair");

  const opcao = await pergunta("\nEscolha uma opção: ");

  switch (opcao) {
    case "1":
      await registrarUsuario();
      break;
    case "2":
      await fazerLogin();
      break;
    case "3":
      await verificarSecret();
      break;
    case "4":
      await solicitarTOTP();
      break;
    case "5":
      await testarRedis();
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
