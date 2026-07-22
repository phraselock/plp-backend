package com.ipoxo.lib;

import com.ipoxo.plcore.lib.db.ksAnd;

public class AESPlnk extends ksAnd
{
  public AESPlnk(byte[] aesKey, byte[] iv)
  {
    super(aesKey, iv);
  }

}
