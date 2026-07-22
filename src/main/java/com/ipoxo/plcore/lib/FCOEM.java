
package com.ipoxo.plcore.lib;

public class FCOEM
{
  private static class Range
  {
    final static public int NotFound = 0xFFFFFFFF;
    int location;
    int length;
    
    public Range()
    {
      location = NotFound;
      length = NotFound;
    }
  };
  
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
  
  final protected static char[] hexArray = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  
  public static String byteArrayToHexString(byte[] bytes)
  {
    char[] hexChars = new char[bytes.length * 2];
    int v;
    
    for (int j = 0; j < bytes.length; j++) {
      v = bytes[j] & 0xFF;
      hexChars[j * 2] = hexArray[v >>> 4];
      hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    
    return new String(hexChars);
  }

  public static byte[] revertByteArray(byte[] data)
  {
    byte[] tmp = new byte[data.length];
    for (int i = 0; i < data.length; i++) {
      tmp[i] = data[data.length - 1 - i];
    }
    return tmp;
  }

}
