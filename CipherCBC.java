
/**
 * @author Canberk Aslan
 * CBC operation for DES Cipher
 */

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class CipherCBC extends SimpleCipher {
  public byte[][] message;
  public byte[] key;
  public byte[] iv;

  /**
   * Responsible for creating dividing the block to 64 bit chunks and normalizing
   * the key to 64 or 192 bits, iv to 64 bits
   * 
   * @param message
   * @param key
   * @param iv
   * @param algorithm
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   */
  public CipherCBC(byte[] message, byte[] key, byte[] iv, String algorithm)
      throws NoSuchAlgorithmException, NoSuchPaddingException {
    super(algorithm);
    this.message = distributeMessage(message);
    this.iv = normalizeToNBytes(iv, DEFAULT_SIZE);
    this.key = normalizeToNBytes(key, algorithm == "TripleDES" ? DEFAULT_SIZE * 3 : DEFAULT_SIZE);
  }

  /**
   * Uses the iv for initializing the encryption process then uses ciphertext xor
   * plaintext
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
      byte[] cipherInput;

      /* First xor message with iv, then xor message with previous cipher text */
      if (i == 0)
        cipherInput = this.xorArrays(message[i], iv, DEFAULT_SIZE);
      else
        cipherInput = this.xorArrays(message[i], ret[i - 1], DEFAULT_SIZE);

      byte[] cipherText = encrypt(cipherInput, key);
      for (int j = 0; j < DEFAULT_SIZE; j++)
        ret[i][j] = cipherText[j];
    }

    return joinMessage(ret);
  }

  /**
   * Uses the iv for initializing the decryption process then uses ciphertext from
   * previous step xor
   * decrypted ciphertext
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
      byte[] plaintext;
      byte[] middlewareText = decrypt(message[i], key);

      /*
       * First xor decrypted message with iv then use ciphertext from previous step
       * with decrypted message
       */
      if (i == 0)
        plaintext = this.xorArrays(middlewareText, iv, DEFAULT_SIZE);
      else
        plaintext = this.xorArrays(middlewareText, message[i - 1], DEFAULT_SIZE);

      for (int j = 0; j < DEFAULT_SIZE; j++)
        ret[i][j] = plaintext[j];
    }

    return joinMessage(ret);
  }
}
