package com.ipoxo.plcore.lib;


import com.ipoxo.plcore.ctap2ecc.CTAP2EccJava;
import com.ipoxo.plcore.lib.db.ksAnd;
import com.ipoxo.plcore.lib.ns.NSData;

import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import org.json.JSONObject;

public class SKeyX
{
  final private static String SKEY_XML_V1_EMPTY_CONTAINER = "<skey version='1' date='2016-01-01 00:00:00' upload='0'> " + "<key></key> " + "<iv></iv> " + "<pin></pin> " + "</skey>";
  final private static String SKEY_KEY  = "key";
  final private static String SKEY_IV  = "iv";
  final private static String SKEY_DATE  = "date";
  final private static String SKEY_UPLOAD  = "upload";
  final private static String SKEY_PIN  = "pin";

  final private static String JSON_TX  = "tx";
  final private static String JSON_KS  = "ks";
  final private static String JSON_IV  = "iv";

  public static DDXMLElement makeSKeyFromAESIV(String aesHex, String ivHex)
  {
    DDXMLElement skey = SKeyX.makeNewSKeyWithoutPIN();
    SKeyX.setKeyElement(skey,aesHex);
    SKeyX.setIVElement(skey,ivHex);
    return skey;
  }

  public static byte[] makeRawAESKeyFromPINCode(String pincode)
  {
    MessageDigest digest = null;
    try
    {
      digest = MessageDigest.getInstance("SHA-256");
      digest.reset();
      return digest.digest(pincode.toString().getBytes());
    } catch (Exception ignore)
    {
    }
    return null;
  }

  public static DDXMLElement makeNewSKeyWithoutPIN()
  {
    DDXMLElement skey = null;
    try {
      skey = DDXMLElement.initWithXMLString(SKEY_XML_V1_EMPTY_CONTAINER);
      // Key erzeugen
      String keyNew = makeNewKey();
      String ivNew = makeNewIV();

      setKeyElement(skey, keyNew);
      setIVElement(skey, ivNew);
      setPINElement(skey, "");
      setCurrentDate(skey);

    } catch (Exception ignore) {
    }
    return skey;
  }

  public static DDXMLElement makeNewSKeyFromPIN(String pinCode)
  {
    DDXMLElement skey = null;
    try
    {
      skey = DDXMLElement.initWithXMLString(SKEY_XML_V1_EMPTY_CONTAINER);
      // Key erzeugen
      String keyNew = makeNewKey();
      String ivNew = makeNewIV();

      setKeyElement(skey, keyNew);
      setIVElement(skey, ivNew);
      setPINElement(skey, pinCode);
      setCurrentDate(skey);

    } catch (Exception ignore)
    {
    }
    return skey;
  }

  public static DDXMLElement makeSKeyFromB64JSONImport(String skB64, String pin)
  {
    if (skB64 != null && pin != null)
    {
      byte[] importKey = makeRawAESKeyFromPINCode(pin);
      if (importKey != null)
      {
        skB64 = ksAnd.makeB64DataURLSafe(skB64);
        ksAnd aesKey = new ksAnd(importKey);
        String dec = decryptStringData(aesKey, skB64);
        if (dec != null)
        {
          try {
            JSONObject jsondata = new JSONObject(dec);
            if (jsondata != null)
            {
              String tx = jsondata.getString(JSON_TX);
              String ks = jsondata.getString(JSON_KS);
              String iv = jsondata.getString(JSON_IV);
              if (
                tx != null && tx.length() >= 0 &&
                  ks != null && ks.length() > 0 &&
                  iv != null && iv.length() >= 0
              )
              {
                DDXMLElement skey = DDXMLElement.initWithXMLString(SKEY_XML_V1_EMPTY_CONTAINER);
                if (skey != null)
                {
                  setDate(skey, tx);
                  setKeyElement(skey, ks);
                  setIVElement(skey, iv);
                  setPINElement(skey, pin);
                  return skey;
                }
              }
            }
          } catch(Exception ignore) {}
        }
      }
    }
    return null;
  }

  public static DDXMLElement makeSKeyFromPlainJSON(String jsonSkey)
  {
    if (jsonSkey != null) {
      try {
        JSONObject jsondata = new JSONObject(jsonSkey);
        if(jsondata!=null)
        {
          String tx = jsondata.getString(JSON_TX);
          String ks = jsondata.getString(JSON_KS);
          String iv = jsondata.getString(JSON_IV);
          if (
            tx != null && tx.length() >= 0 &&
              ks != null && ks.length() > 0 &&
              iv != null && iv.length() >= 0
          )
          {
            DDXMLElement skey = DDXMLElement.initWithXMLString(SKEY_XML_V1_EMPTY_CONTAINER);
            if (skey != null)
            {
              setDate(skey, tx);
              setKeyElement(skey, ks);
              setIVElement(skey, iv);
              setPINElement(skey, "");
              return skey;
            }
          }
        }
      } catch (Exception e) {
        Log.d(Configuration.DBGLEVEL,"makeSKeyFromPlainJSON exception: "+e.getMessage());
      }
    }
    return null;
  }

  public static void setDate(DDXMLElement skey, String date)
  {
    skey.setAttribute(SKEY_DATE, date);
  }

  public static void setKeyElement(DDXMLElement skey, String key)
  {
    skey.setChildNode(SKEY_KEY, key);
  }

  public static void setIVElement(DDXMLElement skey, String iv)
  {
    skey.setChildNode(SKEY_IV, iv);
  }

  public static void setPINElement(DDXMLElement skey, String pin)
  {
    skey.setChildNode(SKEY_PIN, ksAnd.b64encode2StringB(pin.getBytes()));
  }

  public static String getKey(DDXMLElement skey)
  {
    return skey.firstElementStringValue(SKEY_KEY,"");
  }

  public static String getIV(DDXMLElement skey)
  {
    return skey.firstElementStringValue(SKEY_IV,"");
  }

  public static String getPIN(DDXMLElement skey)
  {
    String encPIN = skey.firstElementStringValue(SKEY_PIN,null);
    if(encPIN!=null){
      return ksAnd.b64decode2String(encPIN);
    }
    return null;
  }

  public static String getSKeyDate(DDXMLElement skey)
  {
    return skey.getAttribute(SKEY_DATE);
  }

  public static boolean isUpload(DDXMLElement skey)
  {
    return skey.attributeForNameAsBool(SKEY_UPLOAD);
  }

  public static void setUpload(DDXMLElement skey, boolean bVal)
  {
    if (bVal)
    {
      skey.setAttribute(SKEY_UPLOAD, "1");

    } else
    {
      skey.setAttribute(SKEY_UPLOAD, "0");
    }
  }

  public static String encryptStringData(ksAnd aeskey, String data)
  {
    if (aeskey != null && data != null)
    {
      return aeskey.encryptStringToB64(data);
    } else
    {
      return data;
    }
  }

  public static String decryptStringData(final ksAnd aeskey, String data)
  {
    if (aeskey != null && data != null)
    {
      return aeskey.decryptStringFromB64(data);
    } else
    {
      return data;
    }
  }

  public static void setCurrentDate(DDXMLElement skey)
  {
    String dateString = new SimpleDateFormat("yyyy-MM-dd-HH:mm:ss", Locale.GERMAN).format(new Date());
    setDate(skey, dateString);
  }

  private static String makeNewKey()
  {
    String res = null;

    String rand = "";
    rand += ksAnd.appendRandom(CTAP2EccJava.lettersAlphabet, 10);
    rand += ksAnd.appendRandom(CTAP2EccJava.capitalsAlphabet, 10);
    rand += ksAnd.appendRandom(CTAP2EccJava.digitsAlphabet, 10);
    rand += ksAnd.appendRandom(CTAP2EccJava.symbolsAlphabet, 10);

    NSData newPINAESkey = null;
    NSData dataIn = new NSData(rand.toString().getBytes());
    MessageDigest digest = null;
    try
    {
      digest = MessageDigest.getInstance("SHA-256");
      digest.reset();
    } catch (Exception ignore)
    {
    }
    newPINAESkey = new NSData(digest.digest(dataIn.bytes()));

    try
    {
      res = FCOEM.byteArrayToHexString(newPINAESkey.bytes());
    } catch (Exception ignore)
    {
    }
    return res;
  }

  public static String makeNewIV()
  {
    String res = null;
    String rand = "";
    rand += ksAnd.appendRandom(CTAP2EccJava.lettersAlphabet, 10);
    rand += ksAnd.appendRandom(CTAP2EccJava.capitalsAlphabet, 10);
    rand += ksAnd.appendRandom(CTAP2EccJava.digitsAlphabet, 10);
    rand += ksAnd.appendRandom(CTAP2EccJava.symbolsAlphabet, 10);

    NSData newPINAESkey = null;
    NSData dataIn = new NSData(rand.toString().getBytes());
    MessageDigest digest = null;
    try
    {
      digest = MessageDigest.getInstance("SHA-256");
      digest.reset();
    } catch (Exception ignore)
    {
    }
    newPINAESkey = new NSData(digest.digest(dataIn.bytes()));

    try
    {
      res = FCOEM.byteArrayToHexString(newPINAESkey.bytes()).substring(0, 32);
    } catch (Exception ignore)
    {
    }
    return res;
  }

  public static String exportJSONFormat(DDXMLElement skey)
  {
    if (skey != null)
    {
      String tx = getSKeyDate(skey);
      String key = getKey(skey);
      String iv = getIV(skey);
      return String.format("{\"tx\":\"%s\",\"ks\":\"%s\",\"iv\":\"%s\"}", tx, key, iv);
    }
    return null;
  }

  public static String exportJSONFormat4Input(DDXMLElement skey)
  {
    if (skey != null)
    {
      String key = getKey(skey);
      String iv = getIV(skey);
      return String.format("{\"ks\":\"%s\",\"iv\":\"%s\"}", key.toLowerCase(), iv.toLowerCase());
    }
    return null;
  }

  public static String export4Display(DDXMLElement skey)
  {
    try
    {
      if (skey != null)
      {
        String tx = getSKeyDate(skey);
        String key = getKey(skey);
        String iv = getIV(skey);
        String pin = getPIN(skey);

        if (tx != null && key != null && iv != null && pin != null)
        {
          return String.format("Date:%s\nPIN :%s\nKey :%s - %s\n", tx, pin, iv, key);
        }
      }
    } catch (Exception ignore)
    {
    }
    return null;
  }

  public static String export4Upload(DDXMLElement skey)
  {
    try
    {
      if (skey != null)
      {
        String jf = exportJSONFormat(skey);
        if (jf != null)
        {
          String pin = getPIN(skey);
          byte[] exportKey = makeRawAESKeyFromPINCode(pin);
          if (exportKey != null)
          {
            ksAnd aesKey = new ksAnd(exportKey);
            String enc = encryptStringData(aesKey, jf);
            enc = ksAnd.makeB64DataPKCSSafe(enc);
            return enc;
          }
        }
      }
    } catch (Exception ignore)
    {
    }
    return null;
  }

  public static boolean isValid(DDXMLElement skey)
  {
    try{
      if(skey == null) return false;
      String aesKey = SKeyX.getKey(skey);
      if(aesKey == null || aesKey.length()!=64) return false;
      byte[] keyData = FCOEM.hexStringToByteArray(aesKey);
      if(keyData == null || keyData.length!=32) return false;
      return true;
    }catch(Exception ignore){}
    return false;
  }




  /* Obsolet ???
  public static DDXMLElement getSKey_by_usb_sno(AESPlnk aesKey, String usb_sno)
  {
    try
    {
      if (usb_sno != null)
      {
        DB db = PhraseLockApplication.getDB();
        String encSkey = db.read_usb_skey_4_usb_sno(usb_sno);
        if (encSkey != null)
        {
          String decSkey = decryptStringData(aesKey, encSkey);
          if (decSkey != null)
          {
            DDXMLElement skey = DDXMLElement.initWithXMLString(decSkey);
            return skey;
          }
        }
      }
    } catch (Exception ignore)
    {
    }
    return null;
  }
  */
  /*
  public static DDXMLElement getSKey_by_usb_oi_pidx(AESPlnk aesKey, String usb_oi_pidx)
  {
    try
    {
      if (usb_oi_pidx != null)
      {
        DB db = PhraseLockApplication.getDB();
        String encSkey = db.read_usb_skey_4_usb_oi_pidx(usb_oi_pidx);
        if (encSkey != null)
        {
          String decSkey = decryptStringData(aesKey, encSkey);
          if (decSkey != null)
          {
            DDXMLElement skey = DDXMLElement.initWithXMLString(decSkey);
            return skey;
          }
        }
      }
    } catch (Exception ignore)
    {
    }
    return null;
  }

  public static void saveSKey_by_usb_sno(AESPlnk aesKey, DDXMLElement skey, String usb_sno)
  {
    try
    {
      if (skey != null && usb_sno != null)
      {
        DB db = PhraseLockApplication.getDB();
        String skeyXMLString = skey.XMLString();
        if (skeyXMLString != null)
        {
          String encSKey = encryptStringData(aesKey, skeyXMLString);
          db.update_usb_skey_4_usb_sno(usb_sno, encSKey);
        }
      }
    } catch (Exception ignore)
    {
    }
  }

  public static void saveSKey_by_usb_oi_pidx(AESPlnk aesKey, DDXMLElement skey, String usb_oi_pidx)
  {
    try
    {
      if (skey != null && usb_oi_pidx != null)
      {
        DB db = PhraseLockApplication.getDB();
        String skeyXMLString = skey.XMLString();
        if (skeyXMLString != null)
        {
          String encSKey = encryptStringData(aesKey, skeyXMLString);
          db.update_usb_skey_4_usb_oi_pidx(usb_oi_pidx, encSKey);
        }
      }
    } catch (Exception ignore)
    {
    }
  }

  public static void revokeSKeyByUsbSno(String usb_sno)
  {
    try
    {
      DB db = PhraseLockApplication.getDB();
      db.update_usb_skey_4_usb_sno(usb_sno, "---REVOKED----");

    } catch (Exception ignore)
    {
    }
  }

  public static void revokeSKeyByUsbOiPidx(String usb_oi_pidx)
  {
    try
    {
      DB db = PhraseLockApplication.getDB();
      db.update_usb_skey_4_usb_oi_pidx(usb_oi_pidx, "---REVOKED---");

    } catch (Exception ignore)
    {
    }
  }
  */

}
