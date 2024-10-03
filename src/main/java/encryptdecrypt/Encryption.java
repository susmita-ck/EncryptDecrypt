package encryptdecrypt;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Encryption {

    private static SecureRandom random = new SecureRandom();

    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keygenerator = KeyGenerator.getInstance("AES");
        keygenerator.init(128);
        return keygenerator.generateKey();
    }

    /*
     * public static IvParameterSpec generateIv() {
     * byte[] initializationVector = new byte[16];
     * SecureRandom secureRandom = new SecureRandom();
     * secureRandom.nextBytes(initializationVector);
     * return new IvParameterSpec(initializationVector);
     * }
     */

    public static byte[] encrypt(String input, SecretKey key)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

        // Generate a new IV
        Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding");
        byte[] ivBytes = new byte[cipher.getBlockSize()];

        random.nextBytes(ivBytes); // Generate dynamic IV
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        // Initialize cipher with ENCRYPT_MODE, the key, and the dynamically generated
        // IV
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        // Encrypt the input and return the IV + ciphertext
        byte[] encryptedData = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));

        // Combine IV and ciphertext
        byte[] ivAndEncryptedData = new byte[ivBytes.length + encryptedData.length];
        System.arraycopy(ivBytes, 0, ivAndEncryptedData, 0, ivBytes.length); // Add IV at the start
        System.arraycopy(encryptedData, 0, ivAndEncryptedData, ivBytes.length, encryptedData.length); // Add ciphertext

        return ivAndEncryptedData; // Return IV + encrypted data combined
    }

    public static String decrypt(byte[] ivAndEncryptedData, SecretKey key)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

        // Extract the IV
        Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding");
        int blockSize = cipher.getBlockSize();
        byte[] ivBytes = new byte[blockSize];
        System.arraycopy(ivAndEncryptedData, 0, ivBytes, 0, blockSize);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        // Extract the ciphertext
        byte[] encryptedData = new byte[ivAndEncryptedData.length - blockSize];
        System.arraycopy(ivAndEncryptedData, blockSize, encryptedData, 0, encryptedData.length);

        // Initialize the cipher in DECRYPT_MODE with the extracted IV and key
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        // Decrypt and return the plaintext
        byte[] decryptedData = cipher.doFinal(encryptedData);
        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        SecretKey symmetricKey = generateKey();

        // Takes input from the keyboard
        Scanner message = new Scanner(System.in);
        String plainText = message.nextLine();
        message.close();

        // Encrypt the message using the symmetric key
        byte[] cipherText = encrypt(plainText, symmetricKey);
        Logger logger = Logger.getLogger(Encryption.class.getSimpleName());
        logger.log(Level.INFO, "The encrypted message is: " + cipherText);

        // Decrypt the encrypted message
        String decryptedText = decrypt(cipherText, symmetricKey);
        logger.log(Level.INFO, "Your original message is: " + decryptedText);
    }

}
