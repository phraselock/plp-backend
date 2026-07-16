package plp.lib;

import java.security.SecureRandom;
import java.util.Base64;

public class PLTool {

  final protected static char[] hexArray = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

  public static byte[] generateRandom(int amount)
  {
    byte[] random = new byte[amount];
    SecureRandom srandom = new SecureRandom();
    byte[] seed = srandom.generateSeed(amount);
    srandom.setSeed(seed);
    for (int i = 0; i < amount; i++)
    {
      random[i] = (byte) srandom.nextInt();
    }
    return random;
  }

  public static String byteArrayToHexString(byte[] bytes)
  {
    char[] hexChars = new char[bytes.length * 2];
    int v;
    for (int j = 0; j < bytes.length; j++)
    {
      v = bytes[j] & 0xFF;
      hexChars[j * 2] = hexArray[v >>> 4];
      hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
  }

  public static String b64encode2String(byte[] input)
  {
    if (input != null)
    {
      return Base64.getUrlEncoder().withoutPadding().encodeToString(input);
    }
    return null;
  }

  public static byte[] hexStringToByteArray(String s)
  {
    s = s.toUpperCase();
    int len = s.length();
    byte[] data = new byte[len / 2];

    for (int i = 0; i < len; i += 2) {
      data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
    }

    return data;
  }

}
