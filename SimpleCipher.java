
/**
 * @author Canberk Aslan
 * Simple Cipher for DES and TripleDES encryption/decryption
 * Take algorithm as a string in constructor then creates a cipher instance
 * with desired algorithm. Simple Cipher is responsible for setting the stage
 * for detailed block cipher mode of operations.
 */

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SimpleCipher {
  protected Cipher cipher;
  protected String algorithm;
  protected final int DEFAULT_SIZE = 8;

  SimpleCipher(String algorithm) throws NoSuchAlgorithmException, NoSuchPaddingException {
    this.algorithm = algorithm;
    this.cipher = Cipher.getInstance(this.algorithm + "/ECB/NoPadding");
  }

  public byte[] encrypt(byte[] message, byte[] key)
      throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    return crypt(message, key, Cipher.ENCRYPT_MODE);
  }

  public byte[] decrypt(byte[] message, byte[] key)
      throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    return crypt(message, key, Cipher.DECRYPT_MODE);
  }

  /**
   * Depending on the mode this method is capable of both doing encryption as well
   * as decryption
   * 
   * @return encrypted/decrypted block of message
   */
  public byte[] crypt(byte[] message, byte[] key, int mode)
      throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    SecretKey secretKey = new SecretKeySpec(key, 0, key.length, this.algorithm);
    cipher.init(mode, secretKey);
    return cipher.doFinal(message);
  }

  /**
   * If the key, iv, nonce or message is longer than expected it normalizes them
   * to given n value.
   * Also if the given array is shorter than n bytes, the method repeats the given
   * array
   * 
   * @return normalized byte array
   */
  public byte[] normalizeToNBytes(byte[] any, int n) {
    byte[] ret = new byte[n];

    if (any.length == n)
      return any;

    for (int i = 0; i < ret.length; i++)
      ret[i] = (i < any.length) ? any[i] : ((any.length == 0) ? (byte) 0 : any[i % any.length]);

    return ret;
  }

  /**
   * Since the message can be bigger than 64 bits, this method is responsible for
   * dividing them into 64
   * bit blocks, if any given block is shorter than 64 bits this method applies
   * padding.
   * 
   * @return distributed message
   */
  public byte[][] distributeMessage(byte[] message) {
    int predictedMessageBlockLength = (message.length % DEFAULT_SIZE == 0)
        ? (message.length / DEFAULT_SIZE)
        : ((message.length / DEFAULT_SIZE) + 1);

    byte[][] distributedMessage = new byte[predictedMessageBlockLength][DEFAULT_SIZE];
    for (int i = 0; i < predictedMessageBlockLength; i++)
      for (int j = 0; j < DEFAULT_SIZE; j++)
        distributedMessage[i][j] = ((i * DEFAULT_SIZE + j) < message.length) ? message[i * DEFAULT_SIZE + j] : (byte) 0;

    return distributedMessage;
  }

  /**
   * This method is responsible for joining 64 bit blocks together
   * 
   * @return byte array of joined message
   */
  public byte[] joinMessage(byte[][] message) {
    int length = message.length;
    byte[] ret = new byte[length * DEFAULT_SIZE];
    for (int i = 0; i < message.length; i++)
      for (int j = 0; j < DEFAULT_SIZE; j++)
        ret[(i * DEFAULT_SIZE) + j] = message[i][j];

    return ret;
  }

  /**
   * This method is responsible for applying xor operation for arr1 and arr2
   * 
   * @return new byte array, result of arr1 xor arr2
   */
  public byte[] xorArrays(byte[] arr1, byte[] arr2, int size) {
    byte[] ret = new byte[size];
    for (int i = 0; i < size; i++)
      ret[i] = (byte) (arr1[i] ^ arr2[i]);

    return ret;
  }
}
