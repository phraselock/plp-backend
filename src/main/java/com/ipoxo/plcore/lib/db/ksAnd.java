package com.ipoxo.plcore.lib.db;

import com.ipoxo.plcore.ctap2ecc.CTAP2EccJava;
import com.ipoxo.plcore.lib.*;
import com.ipoxo.plcore.lib.ns.NSData;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.Context;

import static com.ipoxo.plcore.ctap2ecc.CTAP2EccJava.DEFAULT_KEY_STORE;

public class ksAnd
{
  public static String PLP_KS_KEY_BASE              = "com.ipoxo.phraselock.port";            // So beginnen alle Keys

  public static String PLP_KS_IV                    = "com.ipoxo.phraselock.port.IV";         // Generierter IV zum abgeleiteten Key aus der HW-UUID
  public static String PLP_KS_OTP                   = "com.ipoxo.phraselock.port.OTP";        // OTP-Block
  public static String PLP_KS_KST                   = "com.ipoxo.phraselock.port.KST";        // Keystore
  public static String PLP_KS_LNGV                  = "com.ipoxo.phraselock.port.LNGV";       // Verarbeitete Übersetzungen

  public static String PLP_KS_LIC                   = "com.ipoxo.phraselock.port.LIC";        // Lizenz-Restrictionen
  public static String PLP_KS_ORF                   = "com.ipoxo.phraselock.port.ORF";        // Lizenz- oder Order Ref. ID
  public static String PLP_KS_TID                   = "com.ipoxo.phraselock.port.TID";        // Device -ID
  public static String PLP_KS_SNO                   = "com.ipoxo.phraselock.port.SNO";        // Seriennummer der Lizenz
  public static String PLP_KS_QRC                   = "com.ipoxo.phraselock.port.QRC";        // QR-Code der Lizenz
  public static String PLP_KS_LTC                   = "com.ipoxo.phraselock.port.LTC";        // Serive UUID
  public static String PLP_KS_TKN                   = "com.ipoxo.phraselock.port.TKN";        // Telefon-Token

  // User defined MQTT Params
  public static String PLP_KS_MQTT_USR              = "com.ipoxo.phraselock.port.USR";        // User
  public static String PLP_KS_MQTT_PWD              = "com.ipoxo.phraselock.port.PWD";        // Passwort
  public static String PLP_KS_MQTT_TLS              = "com.ipoxo.phraselock.port.TLS";        // TLS Adresse
  public static String PLP_KS_MQTT_PRT              = "com.ipoxo.phraselock.port.PRT";        // TLS Port

  // PhraseLock MQTT Default Parameter
  public static String PLP_KS_MQTT_DFLT_VER         = "com.ipoxo.phraselock.port.DFLT_VER";   // Version der Default Parameter
  public static String PLP_KS_MQTT_DFLT_USR         = "com.ipoxo.phraselock.port.DFLT_USR";   // User
  public static String PLP_KS_MQTT_DFLT_PWD         = "com.ipoxo.phraselock.port.DFLT_PWD";   // Passwort
  public static String PLP_KS_MQTT_DFLT_TLS         = "com.ipoxo.phraselock.port.DFLT_TLS";   // TLS Adresse
  public static String PLP_KS_MQTT_DFLT_PRT         = "com.ipoxo.phraselock.port.DFLT_PRT";   // TLS P

  // Client und Subscription Params
  public static String FXCLN                        = "TKNCLN-";                              // MQTT CLient + LTC
  public static String FXTKN                        = "TKN-";                                 // Subscription
  public static String FXDEV                        = "DEV-";                                 // Smartphone

  public static String PLP_KS_MDX_MODE              = "com.ipoxo.phraselock.port.MDX";        // Mode -> Mqtt oder BLE - Gibt es nur auf Mac
  public static String PLP_KS_DFLT_MODE             = "com.ipoxo.phraselock.port.DFLT";       // Default MQTT Params

  protected Cipher cipherEnc = null;
  protected Cipher cipherDec = null;

  public byte[] mAESRawData = null;
  public byte[] mIVRawData = null;

  public ksAnd(byte[] aesKey)
  {
    initWithKey(aesKey, null);
  }

  public ksAnd(byte[] aesKey, byte[] iv)
  {
    initWithKey(aesKey, iv);
  }

  public ksAnd(SecretKey secretKey, byte[] iv)
  {
    initWithSecretKeyDec(secretKey, iv);
  }

  public ksAnd(SecretKey secretKey)
  {
    initWithSecretKeyEnc(secretKey);
  }

  public ksAnd(DDXMLElement skey)
  {
    String key = SKeyX.getKey(skey);
    String ivs = SKeyX.getIV(skey);
    byte[] aesKey = FCOEM.hexStringToByteArray(key.toString());
    byte[] iv = FCOEM.hexStringToByteArray(ivs.toString());
    initWithKey(aesKey, iv);
  }

  public static void ksInitKeyChain(Context ctx)
  {
    /*
    KeyStore keyStore = null;
    KeyGenerator keyGenerator = null;

    try {
      keyStore = KeyStore.getInstance(DEFAULT_KEY_STORE);
      keyStore.load(null);

      final KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(CTAP2EccJava.PL_KS_KEY, null);
      if (secretKeyEntry != null) {
        return;
      }
    }catch (Exception e){
      if (Configuration.DBGEN) Log.d(Configuration.DBGLEVEL, "EXCEPTION:ksInitKeyChain 0: " + e.getMessage());
    }

    try {
      keyStore = KeyStore.getInstance(DEFAULT_KEY_STORE);
      keyStore.load(null);

      keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, DEFAULT_KEY_STORE);
      KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(CTAP2EccJava.PL_KS_KEY,
        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
        .setUserAuthenticationRequired(false)
        .build();

      keyGenerator.init(keyGenParameterSpec);
      final SecretKey secretKey = keyGenerator.generateKey();

    } catch (Exception e) {
      if (Configuration.DBGEN) Log.d(Configuration.DBGLEVEL, "EXCEPTION:ksInitKeyChain 2: " + e.getMessage());
    }
    */
  }

  @SuppressWarnings("all")
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

  private void initWithSecretKeyEnc(SecretKey secretKey)
  {
    try
    {
      cipherEnc = Cipher.getInstance(CTAP2EccJava.CBC_PADDING);
      cipherEnc.init(Cipher.ENCRYPT_MODE, secretKey);
    } catch (Exception e)
    {
      if (Configuration.DBGEN)
        Log.d(Configuration.DBGLEVEL, "EXCEPTION:  ksAnd::initWithSecretKeyEnc: " + e.getMessage() + " / " + e.toString());
    }
  }

  private void initWithSecretKeyDec(SecretKey secretKey, byte[] iv)
  {
    try
    {
      mAESRawData = null;
      mIVRawData = iv;

      // CBC-Mode
      if (iv != null && iv.length == 16)
      {
        cipherDec = Cipher.getInstance(CTAP2EccJava.CBC_PADDING);
        cipherDec.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        // ECB-Mode
      } else
      {
        cipherDec = Cipher.getInstance(CTAP2EccJava.ECB_PADDING);
        cipherDec.init(Cipher.DECRYPT_MODE, secretKey);
      }

    } catch (Exception e)
    {
      if (Configuration.DBGEN)
        Log.d(Configuration.DBGLEVEL, "EXCEPTION:  ksAnd::initWithSecretKeyDec: " + e.getMessage() + " / " + e.toString());
    }
  }

  public byte[] getRawAES()
  {
    return mAESRawData;
  }

  public byte[] getRawIV()
  {
    return mIVRawData;
  }

  public byte[] getSecretKeyEncIV()
  {
    try
    {
      return cipherEnc.getIV();
    } catch (Exception e)
    {
      if (Configuration.DBGEN)
        Log.d(Configuration.DBGLEVEL, "EXCEPTION:  ksAnd::getSecretKeyEncIV: " + e.getMessage() + " / " + e.toString());
    }
    return null;
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
        String se = ksAnd.b64encode2StringB(encData.toByteArray());
        return se;
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

  public byte[] decryptByteArrayFromB64_Obsolet(String b64Value)
  {
    if (cipherDec == null || b64Value==null || b64Value.length()<16)
    {
      return null;
    }
    byte[] cipherArray = ksAnd.b64decode2ByteArray(b64Value);
    int lenca = cipherArray.length;
    ByteArrayOutputStream decData = new ByteArrayOutputStream();
    int resLen = decryptByteArray(cipherArray, lenca, decData);
    if (resLen > 0)
    {
      return decData.toByteArray();
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
    } catch (Exception e)
    {
    }
    return null;
  }

  public static byte[] b64decode2ByteArrayB(byte[] input)
  {
    try
    {
      if (input != null /*&& input.length > 0*/)
      {
        if (!ksAnd.isUrlSafeB(input))
        {
          input = ksAnd.makeB64DataURLSafeB(input);
        }
        return Base64.getUrlDecoder().decode(input);
      }
    } catch (Exception e)
    {
    }
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
    } catch (Exception e)
    {
    }
    return null;
  }

  public static String b64decode2StringB(byte[] input)
  {
    try
    {
      if (input != null /*&& input.length > 0*/)
      {
        if (!ksAnd.isUrlSafeB(input))
        {
          input = ksAnd.makeB64DataURLSafeB(input);
        }
        byte[] bx = Base64.getUrlDecoder().decode(input);
        if (bx != null && bx.length > 0)
        {
          return new String(bx);
        }
      }
    } catch (Exception e)
    {
    }
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
    } catch (Exception e)
    {
    }
    return "";
  }

  public static String b64decode2StringNotNullB(byte[] input)
  {
    try
    {
      if (input != null /*&& input.length > 0*/)
      {
        if (!ksAnd.isUrlSafeB(input))
        {
          input = ksAnd.makeB64DataURLSafeB(input);
        }
        byte[] bx = Base64.getUrlDecoder().decode(input);
        if (bx != null && bx.length > 0)
        {
          return new String(bx);
        }
      }
    } catch (Exception e)
    {
    }
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
    } catch (Exception e)
    {
    }
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
    } catch (Exception e)
    {
    }
    return null;
  }

  public static byte[] b64encode2ByteArray(String input)
  {
    try
    {
      if (input != null /*&& input.length() > 0*/)
      {
        return Base64.getUrlEncoder().encode(input.getBytes());
      }
    } catch (Exception e)
    {
    }
    return null;
  }

  public static byte[] b64encode2ByteArrayB(byte[] input)
  {
    try
    {
      if (input != null /*&& input.length > 0*/)
      {
        return Base64.getUrlEncoder().encode(input);
      }
    } catch (Exception e)
    {
    }
    return null;
  }

  private static boolean isUrlSafe(String b64Data)
  {
    if (b64Data.indexOf("/") > -1)
      return false;
    if (b64Data.indexOf("+") > -1)
      return false;
    return true;
  }

  private static boolean isUrlSafeB(byte[] b64Data)
  {
    for (byte b : b64Data)
    {
      if (b == '/' || b == '+')
        return false;
    }
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

  private static byte[] makeB64DataURLSafeB(byte[] b64Data)
  {
    for (int i = 0; i < b64Data.length; i++)
    {
      if (b64Data[i] == '/')
      {
        b64Data[i] = '_';
        continue;
      }
      if (b64Data[i] == '+')
      {
        b64Data[i] = '-';
        //continue;
      }
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

  public boolean isEqualKey(ksAnd aesKey)
  {
    if(!Arrays.equals(mAESRawData,aesKey.getRawAES()))
    {
      return false;
    }
    if(mIVRawData!=null && mIVRawData.length == 16)
    {
      if(!Arrays.equals(mIVRawData,aesKey.getRawIV())) {
        return false;
      }
    }
    return true;
  }

  public static String appendRandom(String alphabet, int amount)
  {
    SecureRandom random = new SecureRandom();
    StringBuilder pass = new StringBuilder(amount);
    for (int i = 0; i < amount; i++)
    {
      pass.append(alphabet.charAt(random.nextInt(alphabet.length())));
    }
    return pass.toString();
  }

  public static String makeRandomPwd(int AZ, int az, int nx, int xx)
  {
    int length = AZ + az + nx + xx;

    String pwd = "";
    pwd += ksAnd.appendRandom(CTAP2EccJava.lettersAlphabet, az);
    pwd += ksAnd.appendRandom(CTAP2EccJava.capitalsAlphabet, AZ);
    pwd += ksAnd.appendRandom(CTAP2EccJava.digitsAlphabet, nx);
    pwd += ksAnd.appendRandom(CTAP2EccJava.symbolsAlphabet, xx);

    char[] cPassword = new char[length];
    pwd.getChars(0, pwd.length(), cPassword, 0);

    SecureRandom random = new SecureRandom();
    for (int i = 0; i < length; i++)
    {
      int r = random.nextInt(length);
      char temp = cPassword[i];
      cPassword[i] = cPassword[r];
      cPassword[r] = temp;
    }

    String npwd = new String(cPassword);
    return npwd;

  }

  public static String makeMD5(String s)
  {
    NSData dataIn = new NSData(s.getBytes());
    MessageDigest digest = null;
    try {
      digest = MessageDigest.getInstance("MD5");
      digest.reset();
    } catch (Exception e) {
    }
    String md5 = FCOEM.byteArrayToHexString(new NSData(digest.digest(dataIn.bytes())).bytes());
    return md5;
  }

  public static String GetDeviceGUID(Context ctx)
  {

    //String devGUUID = null;
    String devGUUID = "ich-bin-eine-device-id";
    /*
    devGUUID = ksAnd.readPLDevID(ctx);
    if(devGUUID!=null){
      return devGUUID;
    }
    String base = null;
    try {
      base = Settings.Secure.getString(ctx.getContentResolver(), Settings.Secure.ANDROID_ID);
    }catch (Exception e){
      base = UUID.randomUUID().toString().toUpperCase();
    }

    if(base==null){
      base = UUID.randomUUID().toString().toUpperCase();
    }

    String md = makeMD5(base).toUpperCase();

    StringBuilder sb = new StringBuilder();
    sb.append(md.substring(0,8));sb.append("-");
    sb.append(md.substring(8,12));sb.append("-");
    sb.append(md.substring(12,16));sb.append("-");
    sb.append(md.substring(16,20));sb.append("-");
    sb.append(md.substring(20,32));

    devGUUID = sb.toString();

    ksAnd.writePLDevID(ctx, devGUUID);
    */
    return devGUUID;
  }

  public static ksAnd getKeyStoreAESPlnkEnc(Context ctx)
  {
    try {
      KeyStore keyStore = KeyStore.getInstance(DEFAULT_KEY_STORE);
      keyStore.load(null);
      final KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(CTAP2EccJava.PL_KS_KEY, null);
      if (secretKeyEntry != null) {
        final SecretKey secretKey = secretKeyEntry.getSecretKey();
        if (secretKey != null)
        {
          ksAnd aesKeyEnc = new ksAnd(secretKey);
          return aesKeyEnc;
        }
      }
    } catch (Exception e) {
      if (Configuration.DBGEN) Log.d(Configuration.DBGLEVEL, "EXCEPTION:getKeyStoreAESPlnkEnc: " + e.getMessage());
    }
    return null;
  }

  public static String ksEncData(Context ctx, String plainData)
  {
    ksAnd aesKey = getKeyStoreAESPlnkEnc(ctx);
    if(aesKey!=null)
    {
      String encDataB64 = aesKey.encryptStringToB64(plainData);
      byte[] iv  = aesKey.getSecretKeyEncIV();
      String siv = FCOEM.byteArrayToHexString(iv);
      String secret = String.format("{\"iv\":\"%s\",\"ec\":\"%s\"}", siv, encDataB64);
      try {
        return ksAnd.b64encode2String(secret);
      } catch (Exception e) {
        if (Configuration.DBGEN) Log.d(Configuration.DBGLEVEL, "EXCEPTION:ksEncData: " + e.getMessage());
      }
    }
    return null;
  }

  public static String ksDecData(Context ctx, String encDataB64)
  {
    /*
    try {
      String psiv = null;
      String encp = null;
      if (encDataB64 != null)
      {
        try {
          JSONObject jsondata = new JSONObject(ksAnd.b64decode2String(encDataB64));
          psiv = jsondata.getString("iv");
          encp = jsondata.getString("ec");
        } catch (Exception e) {
          if (Configuration.DBGEN) Log.d(Configuration.DBGLEVEL, "EXCEPTION:ksDecData: JSON: " + e.getMessage());
          return null;
        }
      }
      if(psiv!=null && encp!=null)
      {
        ksAnd aesKey = getKeyStoreAESPlnkDec(ctx,FCOEM.hexStringToByteArray(psiv));
        if(aesKey!=null)
        {
          String decData = aesKey.decryptStringFromB64(encp);
          return decData;
        }
      }
    } catch (Exception e) {
      if (Configuration.DBGEN) Log.d(Configuration.DBGLEVEL, "EXCEPTION:ksDecData: " + e.getMessage());
    }
     */
    return null;
  }

  public static int ksWriteData(Context ctx, String key, String plainData)
  {
    /*
    ksAnd aesKey = getKeyStoreAESPlnkEnc(ctx);
    if(aesKey!=null)
    {
      String encData = aesKey.encryptStringToB64(plainData);
      byte[] iv  = aesKey.getSecretKeyEncIV();
      String siv = FCOEM.byteArrayToHexString(iv);
      String secret = String.format("{\"iv\":\"%s\",\"ec\":\"%s\"}", siv, encData);
      try {
        SharedPreferences pref = androidx.preference.PreferenceManager.getDefaultSharedPreferences(ctx);
        pref.edit().putString(key, ksAnd.b64encode2String(secret)).commit();
        return 0;
      } catch (Exception e) {
        if (Configuration.DBGEN) Log.d(Configuration.DBGLEVEL, "EXCEPTION:ksWriteData: " + e.getMessage());
      }
    }

     */
    return -1;
  }

  public static String ksReadData(Context ctx, String key)
  {
    /*
    try {
      SharedPreferences pref = androidx.preference.PreferenceManager.getDefaultSharedPreferences(ctx);
      String b64Data =  pref.getString(key, null);
      String psiv = null;
      String encp = null;
      if (b64Data != null)
      {
        try {
          JSONObject jsondata = new JSONObject(ksAnd.b64decode2String(b64Data));
          psiv = jsondata.getString("iv");
          encp = jsondata.getString("ec");
        } catch (Exception e) {
          if (Configuration.DBGEN) Log.d(Configuration.DBGLEVEL, "EXCEPTION:readPLMainKeyPINCode: JSON: " + e.getMessage());
          return null;
        }
      }
      if(psiv!=null && encp!=null)
      {
        ksAnd aesKey = getKeyStoreAESPlnkDec(ctx,FCOEM.hexStringToByteArray(psiv));
        if(aesKey!=null)
        {
          String decData = aesKey.decryptStringFromB64(encp);
          return decData;
        }
      }
    } catch (Exception e) {
      if (Configuration.DBGEN) Log.d(Configuration.DBGLEVEL, "EXCEPTION:ksReadData: " + e.getMessage());
    }
     */
    return null;
  }

  public static int ksDeleteData(Context ctx,String key)
  {

    KeyStore keyStore = null;
    try {
      keyStore = KeyStore.getInstance(DEFAULT_KEY_STORE);
      if(keyStore!=null) {
        keyStore.load(null);
        keyStore.deleteEntry(key);
      }
    } catch (Exception e) {
      if (Configuration.DBGEN) Log.d(Configuration.DBGLEVEL, "EXCEPTION:ksReadData: " + e.getMessage());
    }
    return 0;
    /*
    try {
      SharedPreferences pref = androidx.preference.PreferenceManager.getDefaultSharedPreferences(ctx);
      long tc = 0;
      pref.edit().remove(key).commit();
      return 0;
    } catch (Exception e) {
      if (Configuration.DBGEN) Log.d(Configuration.DBGLEVEL, "EXCEPTION:ksDeleteData: " + e.getMessage());
    }
    return 0;
     */
  }

  public static ksAnd getKeyStoreAESPlnkDec(Context ctx, byte[] iv)
  {
    try {
      KeyStore keyStore = KeyStore.getInstance(DEFAULT_KEY_STORE);
      keyStore.load(null);
      final KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(CTAP2EccJava.PL_KS_KEY, null);
      if (secretKeyEntry != null) {
        final SecretKey secretKey = secretKeyEntry.getSecretKey();
        if (secretKey != null)
        {
          ksAnd aesKeyDec = new ksAnd(secretKey,iv);
          return aesKeyDec;
        }
      }
    } catch (Exception e) {
      if (Configuration.DBGEN) Log.d(Configuration.DBGLEVEL, "EXCEPTION:getKeyStoreAESPlnkDec: " + e.getMessage());
    }
    return null;
  }

  public static int ksWriteUSBTokenKey(Context ctx, String ltc, String aes, String iv)
  {

    String idx = (CTAP2EccJava.USBKEY_PREFIX + "_" + ltc).toUpperCase();
    DDXMLElement skey = SKeyX.makeSKeyFromAESIV(aes,iv);
    String export = SKeyX.exportJSONFormat(skey);
    return ksAnd.ksWriteData(ctx,idx,export);
  }

  public static ksAnd ksReadUSBTokenKey(Context ctx, String ltc)
  {

    String idx = (CTAP2EccJava.USBKEY_PREFIX + "_" + ltc).toUpperCase();
    String decJSON = ksAnd.ksReadData(ctx,idx);
    if(decJSON!=null && decJSON.length()>0)
    {
      DDXMLElement skey = SKeyX.makeSKeyFromPlainJSON(decJSON);
      if(skey!=null)
      {
        ksAnd aesKey = new ksAnd(skey);
        return aesKey;
      }
    }
    return null;
  }

  public static void ksDeleteUSBTokenKey(Context ctx, String ltc)
  {
    String idx = (CTAP2EccJava.USBKEY_PREFIX + "_" + ltc).toUpperCase();
    ksAnd.ksDeleteData(ctx, idx);
  }

  public static void ksSetUserVerification(Context ctx, boolean verify)
  {
    if(verify)
    {
      ksAnd.ksWriteData(ctx, CTAP2EccJava.USERAUTHENTICATION, "1");
    }else{
      ksAnd.ksWriteData(ctx, CTAP2EccJava.USERAUTHENTICATION, "0");
    }
  }

  public static boolean ksGetUserVerification(Context ctx)
  {
    String uver = ksAnd.ksReadData(ctx, CTAP2EccJava.USERAUTHENTICATION);
    if(uver!=null && uver.equalsIgnoreCase("1"))
    {
      return true;
    }
    return false;
  }

  // Device-ID read/write from preferences
  public static boolean writePLDevID(Context ctx, String devid)
  {
    /*
    try {
      SharedPreferences pref = androidx.preference.PreferenceManager.getDefaultSharedPreferences(ctx);
      long tc = 0;
      pref.edit().putString(CTAP2EccJava.PL_DEV_UNIQUE_ID, devid).commit();
      return true;
    } catch (Exception e) {
    }

     */
    return false;
  }

  public static String readPLDevID(Context ctx)
  {
    /*
    try {
      SharedPreferences pref = androidx.preference.PreferenceManager.getDefaultSharedPreferences(ctx);
      return pref.getString(CTAP2EccJava.PL_DEV_UNIQUE_ID, null);
    } catch (Exception e) {
    }
     */
    return null;
  }

}
