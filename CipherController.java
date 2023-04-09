
/**
 * @author Canberk Aslan
 * Controls the operation mode division process in order to achieve cleaner code structure.
 */

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class CipherController {
  /**
   * Starts the encryption/decryption process with given values.
   * 
   * @param message
   * @param key
   * @param iv
   * @param nonce
   * @param algorithm
   * @param mode
   * @param type
   * @return encrypted/decrypted data
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   * @throws InvalidKeyException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   */
  public static byte[] run(byte[] message, byte[] key, byte[] iv, byte[] nonce, String algorithm, String mode,
      String type) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
      IllegalBlockSizeException, BadPaddingException {
    byte[] result = null;

    if (mode.equals("CBC")) {
      CipherCBC cipherCBC = new CipherCBC(message, key, iv, algorithm);
      result = type == "enc" ? cipherCBC.encrypt() : cipherCBC.decrypt();
    }

    else if (mode.equals("CFB")) {
      CipherCFB cipherCFB = new CipherCFB(message, key, iv, algorithm);
      result = type == "enc" ? cipherCFB.encrypt() : cipherCFB.decrypt();
    }

    else if (mode.equals("CTR")) {
      CipherCTR cipherCTR = new CipherCTR(message, key, nonce, algorithm);
      result = type == "enc" ? cipherCTR.encrypt() : cipherCTR.decrypt();
    }

    else if (mode.equals("OFB")) {
      CipherOFB cipherOFB = new CipherOFB(message, key, iv, algorithm);
      result = type == "enc" ? cipherOFB.encrypt() : cipherOFB.decrypt();
    }

    else {
      CipherECB cipherECB = new CipherECB(message, key, algorithm);
      result = type == "enc" ? cipherECB.encrypt() : cipherECB.decrypt();
    }

    return result;
  }
}
