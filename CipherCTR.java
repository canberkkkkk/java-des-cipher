
/**
 * @author Canberk Aslan
 * CTR operation for DES Cipher
 */

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class CipherCTR extends SimpleCipher {
  public byte[][] message;
  public byte[] key;
  public byte[] ctr;

  /**
   * Responsible for creating dividing the block to 64 bit chunks and normalizing
   * the key to 64 or 192 bits, creating the ctr with 32 bits of normalized nonce
   * value and 32 bits of counter
   * 
   * @param message
   * @param key
   * @param nonce
   * @param algorithm
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   */
  public CipherCTR(byte[] message, byte[] key, byte[] nonce, String algorithm)
      throws NoSuchAlgorithmException, NoSuchPaddingException {
    super(algorithm);
    this.ctr = new byte[DEFAULT_SIZE];
    this.message = distributeMessage(message);
    this.key = normalizeToNBytes(key, algorithm == "TripleDES" ? DEFAULT_SIZE * 3 : DEFAULT_SIZE);

    byte[] normalizedNonce = normalizeToNBytes(nonce, DEFAULT_SIZE / 2);
    for (int i = 0; i < DEFAULT_SIZE / 2; i++) {
      this.ctr[i] = normalizedNonce[i];
      this.ctr[i + (DEFAULT_SIZE / 2)] = (byte) 0;
    }
  }

  /* Encryption and decryption is basicly the same thing so use helper for both */
  public byte[] encrypt() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    return cryptHelper();
  }

  public byte[] decrypt() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    return cryptHelper();
  }

  /**
   * Uses nonce for giving additional protection and also counter.
   * Xors each block after encryption/decryption with plaintext/ciphertext
   * Joins the blocks and constructs a whole message at the end
   * 
   * @return constructed message
   * @throws InvalidKeyException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   */
  public byte[] cryptHelper() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    int length = message.length;
    byte[][] ret = new byte[length][DEFAULT_SIZE];

    for (int i = 0; i < length; i++) {
      /* use counter and nonce for encryption/decryption */
      byte[] middlewareText = encrypt(ctr, key);
      /* do xor operation with encrypted data and plaintext/ciphertext */
      byte[] cipherText = this.xorArrays(middlewareText, message[i], DEFAULT_SIZE);

      for (int j = 0; j < DEFAULT_SIZE; j++)
        ret[i][j] = cipherText[j];

      incrementCounter();
    }

    return joinMessage(ret);
  }

  /**
   * Increments the counter one by one
   * Note that the counter is default size over two which means it is 4 byte
   * 32 bits in total
   */
  public void incrementCounter() {
    for (int i = DEFAULT_SIZE - 1; i > (DEFAULT_SIZE / 2) - 1; i--) {
      if (ctr[i] == Byte.MAX_VALUE) {
        ctr[i] = (byte) 0;
        continue;
      }

      ctr[i]++;
      break;
    }
  }
}
