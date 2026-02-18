
/*
 * RSAEncryptionDemo.java
 *
 * Implements asymmetric encryption using RSA.
 * The program:
 *  1. Generates a 2048-bit RSA key pair
 *  2. Accepts user plaintext input
 *  3. Encrypts with the public key
 *  4. Decrypts with the private key
 *  5. Displays Base64 ciphertext and recovered plaintext
 *
 * Satisfies: Key generation, encryption/decryption, error handling, and documentation.
 */

import java.security.*;
import javax.crypto.Cipher;
import java.util.Base64;
import java.util.Scanner;

public class RSAEncryptionDemo {

    private static final int KEY_SIZE = 2048;
    private static final String ALGORITHM = "RSA";

    private PublicKey publicKey;
    private PrivateKey privateKey;

    // ================= KEY GENERATION =================
    public void generateKeys() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(KEY_SIZE);

        KeyPair pair = keyGen.generateKeyPair();
        publicKey = pair.getPublic();
        privateKey = pair.getPrivate();

        System.out.println("RSA 2048-bit key pair generated successfully.\n");
    }

    // ================= ENCRYPTION =================
    public String encrypt(String message) throws Exception {

        if (message == null || message.trim().isEmpty()) {
            throw new IllegalArgumentException("Error: Message cannot be empty.");
        }

        // RSA size limit check
        // 2048-bit key → max ~245 bytes (with padding)
        if (message.getBytes().length > 245) {
            throw new IllegalArgumentException("Error: Message too large for RSA encryption.");
        }

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] encryptedBytes = cipher.doFinal(message.getBytes());

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // ================= DECRYPTION =================
    public String decrypt(String encryptedText) throws Exception {

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);

        return new String(decryptedBytes);
    }

    // ================= MAIN PROGRAM =================
    public static void main(String[] args) {

        RSAEncryptionDemo rsa = new RSAEncryptionDemo();
        Scanner scanner = new Scanner(System.in);

        try {
            // Step 1: Generate keys
            rsa.generateKeys();

            // Step 2: User input
            System.out.print("Enter a message to encrypt: ");
            String plaintext = scanner.nextLine();

            // Step 3: Encrypt
            String ciphertext = rsa.encrypt(plaintext);
            System.out.println("\nEncrypted Message (Base64):");
            System.out.println(ciphertext);

            // Step 4: Decrypt
            String decryptedText = rsa.decrypt(ciphertext);
            System.out.println("\nDecrypted Message:");
            System.out.println(decryptedText);

            // Verification
            if (plaintext.equals(decryptedText)) {
                System.out.println("\nVerification Successful: Decrypted text matches original message.");
            } else {
                System.out.println("\nVerification Failed: Messages do not match.");
            }

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

        scanner.close();
    }
}
