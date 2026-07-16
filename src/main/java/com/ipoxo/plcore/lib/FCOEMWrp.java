package com.ipoxo.plcore.lib;

public class FCOEMWrp
{
  static {
    System.loadLibrary("pllibcpp");
  }
  
  public native byte[] keygenIV(int id);
  public native byte[] keygenAES(int id);
  
  public native String recoverKey(int id, byte[] encPwd);
  
}
