"use strict";

const crypto = require("crypto");
const net = require("net");
const fs = require("fs");

const clientChallenge = crypto.randomBytes(16).toString("hex");
let serverChallenge;
let publlicRSAKey;
let premasterKey;
let encryptionKey;

const client = net.createConnection({ port: 3000 }, () => {
  console.log("\nКлієнт успішно підключено до сервера!");

  client.write(JSON.stringify({ type: "hello", random: clientChallenge }));
  console.log(
    `Відправлено hello повідомлення на сервер з випадковим: ${clientChallenge}`
  );
});

client.on("data", (data) => {
  const message = JSON.parse(data.toString());

  const handleServerHello = (message) => {
    serverChallenge = message.random;
    publlicRSAKey = message.publicKey;
    premasterKey = crypto.randomBytes(16).toString("hex");

    console.log(
      `\nОтримано serverHello від сервера з випадковим: ${serverChallenge}`
    );
    console.log(`Публічний ключ:\n${publlicRSAKey}`);
    console.log(`Premaster key без шифрування: ${premasterKey}`);
  };

  const handlePremasterKey = () => {
    const encryptedKey = crypto.publicEncrypt(
      publlicRSAKey,
      Buffer.from(premasterKey, "hex")
    );
    client.write(
      JSON.stringify({
        type: "premasterKey",
        premaster: encryptedKey.toString("base64"),
      })
    );
    console.log("\nВідправлено зашифрований premaster key на сервер");

    encryptionKey = crypto
      .createHash("sha256")
      .update(clientChallenge + serverChallenge + premasterKey)
      .digest();
    console.log(
      `Створено новий сесійний ключ у форматі Base64: ${encryptionKey.toString(
        "base64"
      )}`
    );
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
      console.log("\nОтримано готовий статус від сервера");

      const readyCipher = crypto.createCipheriv(
        "aes-256-ecb",
        encryptionKey,
        null
      );
      readyCipher.setAutoPadding(true);

      const encryptedReady =
        readyCipher.update("ready", "utf8", "hex") + readyCipher.final("hex");

      client.write(JSON.stringify({ type: "ready", message: encryptedReady }));
      console.log("Відправлено готовий статус на сервер");

      const cipher = crypto.createCipheriv("aes-256-ecb", encryptionKey, null);
      const encryptedData =
        cipher.update(
          "Secret message",
          "utf8",
          "hex"
        ) + cipher.final("hex");

      client.write(JSON.stringify({ type: "text", data: encryptedData }));
      console.log("Відправлено зашифрований текст на сервер");
    }
  };

  const handleText = (message) => {
    const decipher = crypto.createDecipheriv(
      "aes-256-ecb",
      encryptionKey,
      null
    );
    const decryptedData =
      decipher.update(message.data, "hex", "utf8") + decipher.final("utf8");

    console.log(`\nОтримано зашифрований текст від сервера: ${decryptedData}`);
  };

  const handleFile = () => {
    const fileContent = fs.readFileSync("../text.txt").toString("utf8");
    const fileCipher = crypto.createCipheriv(
      "aes-256-ecb",
      encryptionKey,
      null
    );

    fileCipher.setAutoPadding(true);
    const encryptedFileContent =
      fileCipher.update(fileContent, "utf8", "hex") + fileCipher.final("hex");
    client.write(JSON.stringify({ type: "file", data: encryptedFileContent }));

    console.log("Відправлено зашифрований текст з файлу text.txt на сервер");
  };

  try {
    if (message.type === "serverHello") {
      handleServerHello(message);
      handlePremasterKey();
    } else if (message.type === "ready") {
      handleReady(message);
    } else if (message.type === "text") {
      handleText(message);
      handleFile();
    }
  } catch (error) {
    console.error(err.message);
  }
});

process.on("SIGINT", () => {
  console.log("\nStopping the client...");
  process.exit();
});
