const crypto = require("crypto");

// Fonction pour calculer un HMAC-SHA256
function hmacSHA256(key, data) {
  // Convertir key et data en Buffer si ce ne sont pas déjà des Buffers
  if (typeof key === "string") key = Buffer.from(key, "utf-8");
  if (typeof data === "string") data = Buffer.from(data, "utf-8");

  const blockSize = 64; // Taille du bloc pour SHA-256
  let paddedKey = key;

  // Si la clé est plus grande que le bloc, la hacher
  if (key.length > blockSize) {
    paddedKey = crypto.createHash("sha256").update(key).digest();
  }

  // Compléter la clé pour atteindre la taille de 64 octets
  if (paddedKey.length < blockSize) {
    paddedKey = Buffer.concat([paddedKey, Buffer.alloc(blockSize - paddedKey.length)]);
  }

  // Calculer les paddings
  const oKeyPad = Buffer.alloc(blockSize, 0x5c).map((b, i) => b ^ paddedKey[i]);
  const iKeyPad = Buffer.alloc(blockSize, 0x36).map((b, i) => b ^ paddedKey[i]);

  // HMAC-SHA256
  const innerHash = crypto.createHash("sha256").update(Buffer.concat([iKeyPad, data])).digest();
  return crypto.createHash("sha256").update(Buffer.concat([oKeyPad, innerHash])).digest();
}

// Fonction PBKDF2 manuelle
function pbkdf2(password, salt, iterations, keyLength) {
  const passwordBuffer = Buffer.from(password, "utf-8");
  const saltBuffer = Buffer.from(salt, "utf-8");

  const blocks = Math.ceil(keyLength / 32); // SHA-256 produit 32 octets
  let derivedKey = Buffer.alloc(0);

  for (let block = 1; block <= blocks; block++) {
    const blockIndex = Buffer.alloc(4);
    blockIndex.writeUInt32BE(block, 0);

    // Initialisation de U1
    let u = hmacSHA256(passwordBuffer, Buffer.concat([saltBuffer, blockIndex]));

    // Accumuler U1
    let result = u;

    // Calculer U2 à Uc
    for (let i = 1; i < iterations; i++) {
      u = hmacSHA256(passwordBuffer, u);
      result = Buffer.from(result.map((b, j) => b ^ u[j]));
    }

    derivedKey = Buffer.concat([derivedKey, result]);
  }

  return derivedKey.slice(0, keyLength);
}

// Fonction pour générer une clé à partir d'un mot de passe
function generateKey(password, salt, iterations = 1000, keySize = 32) {
  return pbkdf2(password, salt, iterations, keySize);
}

// Fonction pour chiffrer les données avec AES et PBKDF2
function encryptAESWithPBKDF2(data, password) {
  const salt = crypto.randomBytes(16); // Génération du sel aléatoire (16 bytes)
  const iv = crypto.randomBytes(16);   // Génération de l'IV aléatoire (16 bytes)
  const key = generateKey(password, salt.toString("utf-8")); // Génération de la clé avec PBKDF2

  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv); // Mode AES-256-CBC
  let encrypted = cipher.update(
    typeof data === "string" ? data : JSON.stringify(data), 
    "utf8", 
    "base64"
  );
  encrypted += cipher.final("base64");

  return {
    ciphertext: encrypted,
    salt: salt.toString("hex"),
    iv: iv.toString("hex"),
  };
}

// Fonction pour déchiffrer les données avec AES et PBKDF2
function decryptAESWithPBKDF2(encryptedData, password) {
  const { ciphertext, salt, iv } = encryptedData;

  const saltBuffer = Buffer.from(salt, "hex");
  const ivBuffer = Buffer.from(iv, "hex");

  const key = generateKey(password, saltBuffer.toString("utf-8")); // Générer la clé avec PBKDF2

  const decipher = crypto.createDecipheriv("aes-256-cbc", key, ivBuffer);
  let decrypted = decipher.update(ciphertext, "base64", "utf8");
  decrypted += decipher.final("utf8");

  try {
    return JSON.parse(decrypted);
  } catch {
    return decrypted;
  }
}

// Exemple d'utilisation
const password = "my-secure-password";
const data = { message: "Données sensibles", date: new Date().toISOString() };
//const data = "Hello World !";

// Chiffrement
const encrypted = encryptAESWithPBKDF2(data, password);
console.log("Données chiffrées :", encrypted.ciphertext);

// Déchiffrement
const decrypted = decryptAESWithPBKDF2(encrypted, password);
console.log("Données déchiffrées :", decrypted);
console.log("Données déchiffrées :", decrypted.message);
console.log("Données déchiffrées :", decrypted.date);


// Exemple d'utilisation
const key1 = Buffer.from(["my-secure-password"]); // Clé en tant que Buffer
const data1 = "Hello"; // Données en tant que chaîne

console.log("Le Hach du mot Hello :", hmacSHA256(key1, data1).toString("hex"));


