package encryptdecrypt;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.junit.Assert;
import org.junit.Test;

/**
 * Unit test for simple App.
 */
public class AppTest {

    @Test
    public void shouldAnswerWithTrue() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        SecretKey symmetricKey = Encryption.generateKey();

        // Takes input from the keyboard
        String plainText = "Sample Text";

        // Encrypt the message using the symmetric key
        byte[] cipherText = Encryption.encrypt(plainText, symmetricKey);
        Logger logger = Logger.getLogger(Encryption.class.getSimpleName());
        logger.log(Level.INFO, String.format("The encrypted message is: %s", cipherText));
        Assert.assertNotEquals(null, cipherText);

        // Decrypt the encrypted message
        String decryptedText = Encryption.decrypt(cipherText, symmetricKey);
        logger.log(Level.INFO, String.format("The original message is: %s", decryptedText));
        Assert.assertNotEquals(null, decryptedText);
    }
}
