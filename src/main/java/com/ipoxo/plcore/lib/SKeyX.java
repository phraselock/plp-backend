package com.ipoxo.plcore.lib;

public class SKeyX
{
  final private static String SKEY_KEY  = "key";
  final private static String SKEY_IV  = "iv";

  public static String getKey(DDXMLElement skey)
  {
    return skey.firstElementStringValue(SKEY_KEY,"");
  }

  public static String getIV(DDXMLElement skey)
  {
    return skey.firstElementStringValue(SKEY_IV,"");
  }

}
