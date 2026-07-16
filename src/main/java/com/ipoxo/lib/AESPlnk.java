package com.ipoxo.lib;


import com.ipoxo.plcore.lib.db.ksAnd;

import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.naming.Context;

public class AESPlnk extends ksAnd
{
  public static final Boolean FORCE_STORED_KEY = true;

  private static AESPlnk TELKEY_NO_IV()
  {
    /*
    AESPlnk _tmp = APPDELEGATE().TKEY_OBJ;
    if(APPDELEGATE().TKEY_OBJ!=null)
    {
      byte[] rawAES = _tmp.getRawAES();
      if(rawAES!=null)
      {
        return new AESPlnk(rawAES);
      }
    }

     */
    return null;
  }

  public AESPlnk(byte[] aesKey)
  {
    super(aesKey);
  }

  public AESPlnk(byte[] aesKey, byte[] iv)
  {
    super(aesKey, iv);
  }

  public AESPlnk(SecretKey secretKey, byte[] iv)
  {
    super(secretKey, iv);
  }

  public AESPlnk(SecretKey secretKey)
  {
    super(secretKey);
  }

  public static AESPlnk getCorrectAesKeyForPhrase(Context ctx, String lidxPhrase, Boolean forceStoredKey)
  {
    AESPlnk aesKeyToUse = null;
    /*
    String usb_oi_pidx = db.getPhraseItemByLidx(lidxPhrase, "usb_oi_pidx");
    if(db.get_offline_mode(usb_oi_pidx))
    {
      byte[] aesStored = db.readUSBKeyFromKS(ctx, usb_oi_pidx);
      if (aesStored != null && aesStored.length == 32)
      {
        if (IS_OFFLINE(null) || forceStoredKey)
        {
          aesKeyToUse = new AESPlnk(aesStored);
        } else {
          if (!Arrays.equals(aesStored, TELKEY_NO_IV().getRawAES())) {
            aesKeyToUse = new AESPlnk(aesStored);
          } else {
            aesKeyToUse = new AESPlnk(TELKEY_NO_IV().getRawAES());
          }
        }
      }
    }
    if(aesKeyToUse==null)
    {
      aesKeyToUse = new AESPlnk(TELKEY_NO_IV().getRawAES());
    }
    */
    return aesKeyToUse;

  }

  public static AESPlnk getCorrectAesKeyForUSBKey(Context ctx, String usb_oi_pidx, Boolean forceStoredKey)
  {
    AESPlnk aesKeyToUse = null;
    /*
    if(db.get_offline_mode(usb_oi_pidx))
    {
      byte[] aesStored = db.readUSBKeyFromKS(ctx, usb_oi_pidx);
      if (aesStored != null && aesStored.length == 32) {
        if (IS_OFFLINE(null) || forceStoredKey) {
          aesKeyToUse = new AESPlnk(aesStored);
        } else {
          if (!Arrays.equals(aesStored, TELKEY_NO_IV().getRawAES())) {
            aesKeyToUse = new AESPlnk(aesStored);
          } else {
            aesKeyToUse = new AESPlnk(TELKEY_NO_IV().getRawAES());
          }
        }
      }
    }
    if(aesKeyToUse==null) {
      if(TELKEY_NO_IV()!=null)
      {
        aesKeyToUse = new AESPlnk(TELKEY_NO_IV().getRawAES());
      }
    }

     */
    return aesKeyToUse;
  }

}
