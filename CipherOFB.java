
/**
 * @author Canberk Aslan
 * OFB operation for DES Cipher
 */

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class CipherOFB extends SimpleCipher {
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
  public CipherOFB(byte[] message, byte[] key, byte[] iv, String algorithm)
      throws NoSuchAlgorithmException, NoSuchPaddingException {
    super(algorithm);
    this.message = distributeMessage(message);
    this.iv = normalizeToNBytes(iv, DEFAULT_SIZE);
    this.key = normalizeToNBytes(key, algorithm == "TripleDES" ? DEFAULT_SIZE * 3 : DEFAULT_SIZE);
  }

  /**
   * First use iv to encrypt, then xor it with plaintext.
   * For the next steps use previously encrypted text for encryption and xor with
   * plaintext after encryption
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
    byte[] middlewareText = new byte[DEFAULT_SIZE];

    for (int i = 0; i < length; i++) {
      /* if first step use iv if not use previous encrypted data */
      middlewareText = encrypt(i == 0 ? iv : middlewareText, key);
      byte[] cipherText = this.xorArrays(message[i], middlewareText, DEFAULT_SIZE);

      for (int j = 0; j < DEFAULT_SIZE; j++)
        ret[i][j] = cipherText[j];
    }

    return joinMessage(ret);
  }

  /**
   * First use iv to decrypt, then xor it with ciphertext.
   * For the next steps use previously decrypted text for decryption and xor with
   * ciphertext after decryption
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
    byte[] middlewareText = new byte[DEFAULT_SIZE];

    for (int i = 0; i < length; i++) {
      /* if first step use iv if not use previous decrypted data */
      middlewareText = encrypt(i == 0 ? iv : middlewareText, key);
      byte[] plainText = this.xorArrays(message[i], middlewareText, DEFAULT_SIZE);

      for (int j = 0; j < DEFAULT_SIZE; j++)
        ret[i][j] = plainText[j];
    }

    return joinMessage(ret);
  }
}
