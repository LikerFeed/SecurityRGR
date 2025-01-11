"use strict";

const crypto = require("crypto");
const net = require("net");
const fs = require("fs");

const rsaKeys = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
});

const privateRSAKey = rsaKeys.privateKey;
const publicRSAKey = rsaKeys.publicKey;

const server = net.createServer((socket) => {
  console.log("\nКлієнт успішно підключено до сервера!");
  let clientChallenge;
  let serverChallenge = crypto.randomBytes(16).toString("hex");

  let premasterKey;
  let encryptionKey;
  let clientReadyFlag = false;

  const sendServerHello = (socket) => {
    const publicRSAKeyPem = publicRSAKey.export({
      type: "spki",
      format: "pem",
    });

    socket.write(
      JSON.stringify({
        type: "serverHello",
        random: serverChallenge,
        publicKey: publicRSAKeyPem,
      })
    );

    console.log(
      `\nВідправлено serverHello клієнту з випадковим: ${serverChallenge}`
    );
    console.log(`Відправлено публічний ключ клієнту:\n${publicRSAKeyPem}`);
  };

  const decryptPremasterKey = (message) => {
    const decryptedKey = crypto.privateDecrypt(
      privateRSAKey,
      Buffer.from(message.premaster, "base64")
    );

    premasterKey = decryptedKey.toString("hex");
    console.log(`Розшифрований premasterKey: ${premasterKey}`);
  };

  const generateSessionKey = () => {
    encryptionKey = crypto
      .createHash("sha256")
      .update(clientChallenge + serverChallenge + premasterKey)
      .digest();

    console.log(
      `Згенеровано сесійний ключ: ${encryptionKey.toString("base64")}`
    );
  };

  const sendReady = (socket) => {
    const cipher = crypto.createCipheriv("aes-256-ecb", encryptionKey, null);

    const encryptedReady =
      cipher.update("ready", "utf8", "hex") + cipher.final("hex");

    socket.write(JSON.stringify({ type: "ready", message: encryptedReady }));
    console.log("Відправлено готовий статус клієнту");
  };

  const handleReady = (message) => {
    const decipher = crypto.createDecipheriv(
      "aes-256-ecb",
      encryptionKey,
      null
    );
    decipher.setAutoPadding(true);

    const decryptedReady =
      decipher.update(message.message, "hex", "utf8") + decipher.final("utf8");

    if (decryptedReady === "ready") {
      console.log("\nОтримано готовий статус від клієнта");
      clientReadyFlag = true;
    }
  };

  const handleText = (message, socket) => {
    const decipher = crypto.createDecipheriv(
      "aes-256-ecb",
      encryptionKey,
      null
    );
    const decryptedData =
      decipher.update(message.data, "hex", "utf8") + decipher.final("utf8");

    console.log(`\nОтримано зашифрований текст від клієнта: ${decryptedData}`);

    const cipher = crypto.createCipheriv("aes-256-ecb", encryptionKey, null);
    const encryptedData =
      cipher.update(
        "Secret message",
        "utf8",
        "hex"
      ) + cipher.final("hex");

    socket.write(JSON.stringify({ type: "text", data: encryptedData }));
    console.log("Відправлено зашифрований текст клієнту");
  };

  const handleFile = (message) => {
    const decipher = crypto.createDecipheriv(
      "aes-256-ecb",
      encryptionKey,
      null
    );
    const decryptedFileContent =
      decipher.update(message.data, "hex", "utf8") + decipher.final("utf8");

    fs.writeFileSync("../result.txt", decryptedFileContent, "utf8");
    console.log(
      "\nОтримано зашифрований файл від клієнта та збережено його у result.txt"
    );
  };

  socket.on("data", (data) => {
    try {
      const message = JSON.parse(data.toString());

      if (message.type === "hello") {
        clientChallenge = message.random;
        console.log(
          `\nОтримано hello від клієнта з випадковим: ${clientChallenge}`
        );

        sendServerHello(socket);
      } else if (message.type === "premasterKey") {
        console.log("Отримано зашифрований premasterKey від клієнта");

        decryptPremasterKey(message);
        generateSessionKey();
        sendReady(socket);
      } else if (message.type === "ready") {
        handleReady(message);
      } else if (message.type === "text") {
        handleText(message, socket);
      } else if (message.type === "file") {
        handleFile(message);
      }
    } catch (error) {
      console.error(err.message);
    }
  });
});

const PORT = 3000;
server.listen(PORT, () => {
  console.log(`Сервер запущено на порті ${PORT}`);
});

process.on("SIGINT", () => {
  console.log("\nСервер вимкнено");
  process.exit();
});
