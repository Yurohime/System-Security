const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("crypto");

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: "> "
});

// Hardcoded encryption key for AES-256-CBC (32 bytes)
const ENCRYPTION_KEY = Buffer.from('12345678901234567890123456789012'); 
const IV_LENGTH = 16; // AES block size

// Encrypt function
const encrypt = (text) => {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted; // Return IV and encrypted text
};

// Decrypt function
const decrypt = (text) => {
    let [iv, encryptedText] = text.split(':');
    iv = Buffer.from(iv, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
};

let username = "";

socket.on("connect", () => {
    console.log("Connected to the server");

    rl.question("Enter your Username: ", (input) => {
        username = input;
        console.log(`Welcome to the Server ${username}, please Enjoy`);
        rl.prompt();

        rl.on("line", (message) => {
            if (message.trim()) {
                // Encrypt the message before sending it to the server
                const encryptedMessage = encrypt(message);
                socket.emit("message", { username, message: encryptedMessage });
            }
            rl.prompt();
        });
    });
});

socket.on("message", (data) => {
    const { username: senderUsername, message: encryptedMessage } = data;

    try {
        // Decrypt the message received from the server
        const decryptedMessage = decrypt(encryptedMessage);

        if (senderUsername != username) {
            console.log(`${senderUsername}: ${decryptedMessage}`);
        }
    } catch (err) {
        console.error('Error decrypting message:', err);
    }
});

socket.on("disconnect", () => {
    console.log("Disconnecting, Exiting now....");
    rl.close();
    process.exit(0);
});

rl.on("SIGINT", () => {
    console.log("\nGoodbye :D...");
    socket.disconnect();
    rl.close();
    process.exit(0);
});
