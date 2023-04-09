
/**
 * @author Canberk Aslan
 * This class responsible for Input/Output operations
 * throught the lifecycle of the program. It handles, appending or creating new log,
 * writing/reading message from file as well as reading keys.
 */

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Scanner;

public class FileIO {
  public static Charset UTF_8 = StandardCharsets.UTF_8;

  /*
   * One-to-One mapping for byte array to string conversion thus usage of
   * ISO_88_59_1 was necessary. I have observed that UTF_8 wasn't able to encode
   * all the characters that was the result of encryption.
   */
  public static Charset ISO_8859_1 = StandardCharsets.ISO_8859_1;

  /**
   * If the run.log file doesn't exists, creates a new log file,
   * it it does, appends the log at the end of the file.
   * 
   * @param log
   * @throws IOException
   */
  public static void appendLog(String log) throws IOException {
    byte[] append = (log + System.lineSeparator()).getBytes(UTF_8);
    Files.write(Paths.get("run.log"), append, StandardOpenOption.APPEND, StandardOpenOption.CREATE);
  }

  /**
   * Writes the encrypted/decrypted message to the file
   * 
   * @param filename
   * @param message
   * @throws IOException
   */
  public static void writeMessageToFile(String filename, byte[] message) throws IOException {
    OutputStreamWriter writer = new OutputStreamWriter(new FileOutputStream(filename), ISO_8859_1);
    writer.write(new String(message, ISO_8859_1));
    writer.close();
  }

  /**
   * Reads the encrypted/decrypted message from the file
   * 
   * @param filename
   * @return
   * @throws IOException
   */
  public static byte[] readMessageFromFile(String filename) throws IOException {
    File file = new File(filename);
    return Files.readString(file.toPath(), ISO_8859_1).getBytes(ISO_8859_1);
  }

  /**
   * Reads keys from the file, if the key file structure is not as described,
   * throws an error
   * 
   * @param filename
   * @return
   * @throws FileNotFoundException
   */
  public static String[] readKeysFromFile(String filename) throws FileNotFoundException {
    File keyFile = new File(filename);
    Scanner scanner = new Scanner(keyFile);
    String[] keys = scanner.nextLine().split(" - ");
    scanner.close();

    if (keys.length < 3)
      throw new Error("ERROR :: Key file structure should be ${iv} - ${key} - ${none}");

    return keys;
  }
}
