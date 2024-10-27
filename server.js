const http = require("http");
const socketIo = require("socket.io");
const crypto = require("crypto");

const server = http.createServer();
const io = socketIo(server);

// Hardcoded encryption key for AES-256-CBC (32 bytes)
const ENCRYPTION_KEY = Buffer.from('12345678901234567890123456789012'); 
const IV_LENGTH = 16; // Bytes or 128 bits

// Encrypt function
const encrypt = (text) => {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted; 
    // Return IV and encrypted text
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

io.on("connection", (socket) => {
    console.log("A client connected:", socket.id);

    socket.on("disconnect", () => {
        console.log(`Client ${socket.id} disconnected`);
    });

    socket.on("message", (data) => {
        let { username, message } = data;

        try {
            // Decrypt message received from client
            const decryptedMessage = decrypt(message);

            // console.log(`Receiving Encrypted message from ${username}: ${message}`);
            console.log(`Receiving Decrypted message from ${username}: ${decryptedMessage}`);

            // Encrypt the modified message before emitting to other clients
            const encryptedMessage = encrypt(decryptedMessage + " (modified by server)");

            // Emit encrypted message
            io.emit("message", { username, message: encryptedMessage });

        } catch (err) {
            console.error('Error decrypting message:', err);
        }
    });
});

const port = 3000;
server.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
