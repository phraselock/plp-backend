package com.ipoxo.plcore.lib.db;

import com.ipoxo.plcore.ctap2ecc.CTAP2EccJava;
import com.ipoxo.plcore.lib.*;

import java.io.ByteArrayOutputStream;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ksAnd
{
  protected Cipher cipherEnc = null;
  protected Cipher cipherDec = null;

  public byte[] mAESRawData = null;
  public byte[] mIVRawData = null;

  public ksAnd(byte[] aesKey, byte[] iv)
  {
    initWithKey(aesKey, iv);
  }

  public void initWithKey(byte[] aesKey, byte[] iv)
  {
    try
    {
      mAESRawData = aesKey;
      mIVRawData = iv;

      SecretKeySpec skeySpec = new SecretKeySpec(aesKey, "AES");
      // CBC-Mode
      if (iv != null && iv.length == 16)
      {
        cipherEnc = Cipher.getInstance(CTAP2EccJava.CBC_PADDING);
        cipherEnc.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(iv));

        cipherDec = Cipher.getInstance(CTAP2EccJava.CBC_PADDING);
        cipherDec.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(iv));

        // ECB-Mode
      } else
      {
        cipherEnc = Cipher.getInstance(CTAP2EccJava.ECB_PADDING);
        cipherEnc.init(Cipher.ENCRYPT_MODE, skeySpec);

        cipherDec = Cipher.getInstance(CTAP2EccJava.ECB_PADDING);
        cipherDec.init(Cipher.DECRYPT_MODE, skeySpec);
      }

    } catch (Exception e)
    {
      if (Configuration.DBGEN)
        Log.d(Configuration.DBGLEVEL, "EXCEPTION:  ksAnd::initWithKey: " + e.getMessage() + " / " + e.toString());
    }
  }

  public String encryptStringToB64(String plainData)
  {
    if (cipherEnc == null)
    {
      return null;
    }
    int plenOrigPlus003 = plainData.getBytes().length + 1;
    int paddinLen = 15 - ((plenOrigPlus003 + 15) % 16);

    StringBuilder sb = new StringBuilder(plainData);
    sb.append("\003");
    sb.append("\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000".substring(0, paddinLen));

    ByteArrayOutputStream encrypted = new ByteArrayOutputStream();
    int resLen = encryptByteArray(sb.toString().getBytes(), sb.toString().getBytes().length, encrypted);
    if (resLen > 0)
    {
      return ksAnd.b64encode2StringB(encrypted.toByteArray());
    }
    return null;
  }

  public String encryptByteArrayToB64(byte[] data)
  {
    if (data != null && data.length > 0)
    {
      int lenIn = data.length;
      ByteArrayOutputStream encData = new ByteArrayOutputStream();
      int lenC = encryptByteArray(data, lenIn, encData);
      if (lenC > 0)
      {
        return ksAnd.b64encode2StringB(encData.toByteArray());
      }
    }
    return null;
  }

  public int encryptByteArray(byte[] input, int inputLen, ByteArrayOutputStream encData)
  {
    int resLen = -1;
    try
    {
      if (cipherEnc != null)
      {
        byte[] tmp = cipherEnc.doFinal(input, 0, inputLen);
        resLen = tmp.length;
        if (resLen > 0)
        {
          encData.write(tmp, 0, resLen);
        }
      }
    } catch (Exception e)
    {
      if (Configuration.DBGEN)
        Log.d(Configuration.DBGLEVEL, "EXCEPTION:  ksAnd::_encrypt: resLen = " + resLen + " " + e.getMessage() + " / " + e.toString());
    }
    return resLen;
  }

  public String decryptStringFromB64(String b64Value)
  {
    try
    {
      if (cipherDec == null || b64Value==null || b64Value.length()<16)
      {
        return null;
      }
      byte[] cipherArray = ksAnd.b64decode2ByteArray(b64Value);
      assert cipherArray != null;
      int lenca = cipherArray.length;

      ByteArrayOutputStream decData = new ByteArrayOutputStream();
      int resLen = decryptByteArray(cipherArray, lenca, decData);
      String plainText = new String(decData.toByteArray(), 0, resLen/*lenca*/);

      int eotIdx = plainText.indexOf('\003');
      if (eotIdx < 0)
      {
        return plainText;
      }
      return plainText.substring(0, eotIdx);

    } catch (Exception e)
    {
      if (Configuration.DBGEN)
        Log.d(Configuration.DBGLEVEL, "EXCEPTION:  ksAnd::decrypt: " + e.getMessage() + " / " + e.toString());
    }
    return null;
  }

  public int decryptByteArray(byte[] input, int inputLen, ByteArrayOutputStream decData)
  {
    int resLen = -1;
    if (
      input != null &&
        input.length > 0 &&
        input.length % 16 == 0
    )
    {
      try
      {
        if (cipherDec != null)
        {

          byte[] tmp = cipherDec.doFinal(input, 0, inputLen);
          resLen = tmp.length;
          if (resLen > 0)
          {
            decData.write(tmp, 0, resLen);
          }
        }
      } catch (Exception e)
      {
        if (Configuration.DBGEN)
          Log.d(Configuration.DBGLEVEL, "EXCEPTION:  ksAnd::_decrypt: resLen = " + resLen + " " + e.getMessage() + " / " + e.toString());
      }
    }
    return resLen;
  }

  public static byte[] b64decode2ByteArray(String input)
  {
    try
    {
      if (input != null /*&& input.length() > 0*/)
      {
        if (!ksAnd.isUrlSafe(input))
        {
          input = ksAnd.makeB64DataURLSafe(input);
        }
        return Base64.getUrlDecoder().decode(input);
      }
    } catch (Exception ignore) {}
    return null;
  }

  public static String b64decode2String(String input)
  {
    try
    {
      if (input != null/* && input.length() > 0*/)
      {
        if (!ksAnd.isUrlSafe(input))
        {
          input = ksAnd.makeB64DataURLSafe(input);
        }
        byte[] bx = Base64.getUrlDecoder().decode(input);
        if (bx != null && bx.length > 0)
        {
          return new String(bx);
        }
      }
    } catch (Exception ignore) {}
    return null;
  }

  public static String b64decode2StringNotNull(String input)
  {
    try
    {
      if (input != null /*&& input.length() > 0*/)
      {
        if (!ksAnd.isUrlSafe(input))
        {
          input = ksAnd.makeB64DataURLSafe(input);
        }
        byte[] bx = Base64.getUrlDecoder().decode(input);
        if (bx != null && bx.length > 0)
        {
          return new String(bx);
        }
      }
    } catch (Exception ignore) {}
    return "";
  }

  public static String b64encode2String(String input)
  {
    try
    {
      if (input != null /*&& input.length() > 0*/)
      {
        return Base64.getUrlEncoder().encodeToString(input.getBytes());
      }
    } catch (Exception ignore) {}
    return null;
  }

  public static String b64encode2StringB(byte[] input)
  {
    try
    {
      if (input != null)
      {
        return Base64.getUrlEncoder().encodeToString(input);
      }
    } catch (Exception ignore) {}
    return null;
  }

  private static boolean isUrlSafe(String b64Data)
  {
    if (b64Data.contains("/")) return false;
    if (b64Data.contains("+")) return false;
    return true;
  }

  public static String makeB64DataURLSafe(String b64Data)
  {
    if (b64Data != null)
    {
      b64Data = b64Data.replace('/', '_');
      b64Data = b64Data.replace('+', '-');
    }
    return b64Data;
  }

  public static String makeB64DataPKCSSafe(String b64Data)
  {
    if (b64Data != null)
    {
      b64Data = b64Data.replace('_', '/');
      b64Data = b64Data.replace('-', '+');
    }
    return b64Data;
  }

}
