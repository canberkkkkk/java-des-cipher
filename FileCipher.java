
/**
 * @author Canberk Aslan
 * Responsible for handling the arguments as well as starting the
 * encryption and decryption operations
 */

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class FileCipher {
  /**
   * Normalizes and validates arguments, starts the encryption / decryption cycle
   * 
   * @param args
   * @throws IOException
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   * @throws InvalidKeyException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   */
  public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException,
      InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    if (!validateArguments(args))
      throw new Error("Bad command line arguments");

    String algorithm = args[5],
        algorithmNormalized = algorithm.compareTo("DES") == 0 ? "DES" : "TripleDES",
        type = args[0].compareTo("-e") == 0 ? "enc" : "dec",
        mode = args[6],
        inputFile = args[2],
        outputFile = args[4],
        keyFile = args[7],
        keys[] = FileIO.readKeysFromFile(keyFile);

    byte[] iv = keys[0].getBytes(FileIO.ISO_8859_1),
        key = keys[1].getBytes(FileIO.ISO_8859_1),
        nonce = keys[2].getBytes(FileIO.ISO_8859_1),
        message = FileIO.readMessageFromFile(inputFile);

    long start = System.currentTimeMillis(), finish;
    byte[] result = CipherController.run(message, key, iv, nonce, algorithmNormalized, mode, type);
    finish = System.currentTimeMillis();

    FileIO.writeMessageToFile(outputFile, type == "enc" ? result : removePadding(result));
    FileIO.appendLog(inputFile + " " + outputFile + " " + type + " " + algorithm + " " + mode + " " + (finish - start));
  }

  /**
   * Validates arguments. Maybe this wasn't necessary but I felt like it is better
   * to have some validation than being sorry.
   * 
   * @param args
   * @return true if arguments are valid, false otherwise
   */
  public static boolean validateArguments(String[] args) {
    return (args.length == 8 && args[1].equals("-i") && args[3].equals("-o")
        && (args[0].equals("-e") || args[0].equals("-d"))
        && (args[5].equals("DES") || args[5].equals("3DES"))
        && (args[6].equals("CBC") || args[6].equals("CFB")
            || args[6].equals("CTR") || args[6].equals("ECB") || args[6].equals("OFB")));
  }

  /**
   * Since not all the blocks can be fit into 64 bit, we might use padding at the
   * end with 0's.
   * This method is responsible for removing them from the end of the plaintext
   * 
   * @param plainText
   * @return plaintext with removed paddings
   */
  public static byte[] removePadding(byte[] plainText) {
    int i = plainText.length - 1;
    for (; i >= 0; i--)
      if (plainText[i] != (byte) 0)
        break;

    byte[] ret = new byte[i + 1];
    for (i = 0; i < ret.length; i++)
      ret[i] = plainText[i];

    return ret;
  }
}
