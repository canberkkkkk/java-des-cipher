
/**
 * @author Canberk Aslan
 * ECB operation for DES Cipher
 */

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class CipherECB extends SimpleCipher {
  public byte[][] message;
  public byte[] key;

  /**
   * Responsible for creating dividing the block to 64 bit chunks and normalizing
   * the key to 64 or 192 bits
   * 
   * @param message
   * @param key
   * @param algorithm
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   */
  public CipherECB(byte[] message, byte[] key, String algorithm)
      throws NoSuchAlgorithmException, NoSuchPaddingException {
    super(algorithm);
    this.message = distributeMessage(message);
    this.key = normalizeToNBytes(key, algorithm == "TripleDES" ? DEFAULT_SIZE * 3 : DEFAULT_SIZE);
  }

  /**
   * Encryptes the blocks of message one by one using the key
   * Joins the blocks and constructs a whole message at the end
   * 
   * @return constructed message
   * @throws InvalidKeyException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   */
  public byte[] encrypt() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    int length = message.length;
    byte[][] ret = new byte[length][DEFAULT_SIZE];

    for (int i = 0; i < length; i++) {
      byte[] cipherText = encrypt(message[i], key);
      for (int j = 0; j < DEFAULT_SIZE; j++)
        ret[i][j] = cipherText[j];
    }

    return joinMessage(ret);
  }

  /**
   * Decryptes the blocks of message one by one using the key.
   * Joins the blocks and constructs a whole message at the end
   * 
   * @return constructed message
   * @throws InvalidKeyException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   */
  public byte[] decrypt() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    int length = message.length;
    byte[][] ret = new byte[length][DEFAULT_SIZE];

    for (int i = 0; i < length; i++) {
      byte[] cipherText = decrypt(message[i], key);
      for (int j = 0; j < DEFAULT_SIZE; j++)
        ret[i][j] = cipherText[j];
    }

    return joinMessage(ret);
  }
}
