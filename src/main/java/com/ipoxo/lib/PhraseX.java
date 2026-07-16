package com.ipoxo.lib;

import com.ipoxo.plcore.lib.DDXMLElement;
import com.ipoxo.plcore.lib.db.ksAnd;

import java.io.ByteArrayOutputStream;
import org.json.JSONObject;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class PhraseX
{
  final public static String PHRASE_XML_V8_EMPTY_CONTAINER =
    "<p4 vers='7'> " +
      "<items cat='TAB' finalenter='1' bes='' opdx='0' edt='1' wbck='1' sync='0' ts='0' ft='0' privEnc='0' opmode='2'></items> " +
      "<useruuid></useruuid> " +
      "<links></links> " +
      "<text></text> " +
      "<otp type='totp' len='6' intv='30'></otp> " +
      "<fidotoken fidoactive='0'></fidotoken> " +
      "<fidopin></fidopin> " +
      "</p4>";

  final public static String SYNC_CONTAINER = "{\"nx\":\"%s\",\"p1\":\"%s\",\"p2\":\"%s\",\"p3\":\"%s\",\"ln\":\"%s\",\"tx\":\"%s\",\"op\":\"%s\",\"ft\":\"%s\",\"fp\":\"%s\"}";

  final public static String PHRASE_P1 = "p1";
  final public static String PHRASE_P2 = "p2";
  final public static String PHRASE_P3 = "p3";
  final public static String PHRASE_ORDER = "order";
  final public static String PHRASE_AUROSEND = "autosend";
  final public static String PHRASE_ITEMS = "items";
  final public static String PHRASE_ITEM = "item";
  final public static String PHRASE_LINKS = "links";
  final public static String PHRASE_LINK = "link";
  final public static String PHRASE_OTP = "otp";
  final public static String PHRASE_FINALENTER = "finalenter";
  final public static String PHRASE_CATS = "cats";
  final public static String PHRASE_FIDOACTIVE = "fidoactive";
  final public static String PHRASE_ACTIVE = "active";
  final public static String PHRASE_FIDOTOKEN = "fidotoken";
  final public static String PHRASE_FIDOPIN = "fidopin";
  final public static String PHRASE_TEXT = "text";
  final public static String PHRASE_TYPE = "type";
  final public static String PHRASE_TOTP = "totp";
  final public static String PHRASE_SYNC = "sync";
  final public static String PHRASE_EDT = "edt";
  final public static String PHRASE_PRIVENC = "privEnc";
  final public static String PHRASE_WBCK = "wbck";
  final public static String PHRASE_OPDX = "opdx";
  final public static String PHRASE_FT = "ft";
  final public static String PHRASE_TS = "ts";
  final public static String PHRASE_BES = "bes";
  final public static String PHRASE_CAT = "cat";
  final public static String PHRASE_TAB = "TAB";
  final public static String PHRASE_LN = "ln";
  final public static String PHRASE_TX = "tx";
  final public static String PHRASE_OP = "op";
  final public static String PHRASE_FP = "fp";

  final public static String PHRASE_PHRASE = "PHRASE";
  final public static String PHRASE_PHRASELIST = "phraselist";
  final public static String PHRASE_LABEL = "label";
  final public static String PHRASE_RNDX = "rndx";


  final public static String PHRASE_CREDUUID = "credUUID";
  final public static String PHRASE_USERUUID = "useruuid";
  final public static String PHRASE_CREDDOMAIN = "credDomain";
  final public static String PHRASE_CREDNAME = "credName";
  final public static String PHRASE_USERID = "userid";
  final public static String PHRASE_UNAME = "uname";
  final public static String PHRASE_DNAME = "dname";
  final public static String PHRASE_RPIDHASH = "rpidhash";
  final public static String PHRASE_CRIDHASH = "cridhash";
  final public static String PHRASE_RESIDENTKEY = "residentkey";
  final public static String PHRASE_PRIVKEY = "privkey";


  private static String decryptStringData(AESPlnk aesKey, String data)
  {
    try
    {
      if (aesKey != null && data != null)
      {
        return aesKey.decryptStringFromB64(data);
      } else
      {
        return data;
      }
    } catch (Exception ignore)
    {
    }
    return null;
  }

  private static String encryptStringData(AESPlnk aesKey, String data)
  {
    try
    {
      if (aesKey != null && data != null)
      {
        return aesKey.encryptStringToB64(data);
      } else
      {
        return data;
      }
    } catch (Exception ignore)
    {
    }
    return null;
  }

  public static DDXMLElement findFidoTokenElement(DDXMLElement p4)
  {
    DDXMLElement fidotoken = p4.firstElement(PHRASE_FIDOTOKEN);
    if (fidotoken != null)
    {
      return fidotoken;
    }
    DDXMLElement dx = p4.setChildNode(PHRASE_FIDOTOKEN, "");
    return dx;
  }

  public static DDXMLElement findUserUUIDElement(DDXMLElement p4)
  {
    DDXMLElement fidotoken = p4.firstElement(PHRASE_USERUUID);
    if (fidotoken != null)
    {
      return fidotoken;
    }
    DDXMLElement dx = p4.setChildNode(PHRASE_USERUUID, "");
    return dx;
  }

  private static DDXMLElement findFidoPinElement(DDXMLElement p4)
  {
    DDXMLElement fidotoken = p4.firstElement(PHRASE_FIDOPIN);
    if (fidotoken != null)
    {
      return fidotoken;
    }
    DDXMLElement dx = p4.setChildNode(PHRASE_FIDOPIN, "");
    return dx;
  }

  public static String getFidoToken(AESPlnk aesKey, DDXMLElement p4)
  {
    DDXMLElement dx = findFidoTokenElement(p4);
    if (dx != null)
    {
      String data = dx.getTextContent();
      if (data != null && data.length() >= 16)
      {
        String fidoToken = decryptStringData(aesKey, data);
        if (fidoToken != null && fidoToken.length() == 0)
          fidoToken = null;
        return fidoToken;
      }
    }
    return null;
  }

  public static String getFidoToken(DDXMLElement p4)
  {
    DDXMLElement dx = findFidoTokenElement(p4);
    if (dx != null)
    {
      String data = dx.getTextContent();
      return data;
    }
    return null;
  }

  public static void setFidoToken(AESPlnk aesKey, DDXMLElement p4, String tokenID)
  {
    if (tokenID != null)
    {
      DDXMLElement fidoToken = findFidoTokenElement(p4);
      if (tokenID.length() > 0)
      {
        String encData = encryptStringData(aesKey, tokenID);
        fidoToken.setTextContent(encData);
      }
    }
  }

  public static void setFidoTokenAsB64(DDXMLElement p4, String tokenID)
  {
    if (tokenID != null)
    {
      DDXMLElement fidoToken = findFidoTokenElement(p4);
      if (tokenID.length() > 0)
      {
        String encData = AESPlnk.b64encode2String(tokenID);
        fidoToken.setTextContent(encData);
      }
    }
  }

  public static void deleteFidoToken(DDXMLElement p4)
  {
    DDXMLElement fidoToken = findFidoTokenElement(p4);
    fidoToken.setTextContent("");
  }

  public static String getFidoPin(AESPlnk aesKey, DDXMLElement p4)
  {
    DDXMLElement dx = findFidoPinElement(p4);
    if (dx != null)
    {
      String data = dx.getTextContent();
      if (data != null && data.length() >= 16)
      {
        String fidoPin = decryptStringData(aesKey, data);
        if (fidoPin != null && fidoPin.length() == 0)
          fidoPin = null;
        return fidoPin;
      }
    }
    return null;
  }

  public static String getFidoPin(DDXMLElement p4)
  {
    DDXMLElement dx = findFidoPinElement(p4);
    if (dx != null)
    {
      String data = dx.getTextContent();
      return data;
    }
    return null;
  }

  public static void setFidoPin(AESPlnk aesKey, DDXMLElement p4, String pin)
  {
    if (pin != null)
    {
      DDXMLElement fidoPin = findFidoPinElement(p4);
      if (pin.length() >= 0)
      {
        String encData = encryptStringData(aesKey, pin);
        fidoPin.setTextContent(encData);
      }
    }
  }

  public static void setFidoPinAsB64(DDXMLElement p4, String pin)
  {
    if (pin != null)
    {
      DDXMLElement fidoPin = findFidoPinElement(p4);
      if (pin.length() >= 0)
      {
        String encData = AESPlnk.b64encode2String(pin);
        fidoPin.setTextContent(encData);
      }
    }
  }

  public static boolean isFidoActive(DDXMLElement p4)
  {
    DDXMLElement dx = findFidoTokenElement(p4);
    if (dx != null)
    {
      return dx.attributeForNameAsBool(PHRASE_FIDOACTIVE);
    }
    return false;
  }

  public static void setFidoActivation(DDXMLElement p4, boolean active)
  {
    DDXMLElement dx = findFidoTokenElement(p4);
    if (active)
    {
      dx.setAttribute(PHRASE_FIDOACTIVE, "1");
    } else
    {
      dx.setAttribute(PHRASE_FIDOACTIVE, "0");
    }
  }

  private static DDXMLElement findOTPElement(DDXMLElement p4)
  {
    return p4.firstElement(PHRASE_OTP);
  }

  public static void setWithFinalEnter(DDXMLElement p4, boolean bEnter)
  {
    DDXMLElement dx = findItemsBlock(p4);
    if (dx != null)
    {
      if (bEnter)
      {
        dx.setAttribute(PHRASE_FINALENTER, "1");
      } else
      {
        dx.setAttribute(PHRASE_FINALENTER, "0");
      }
    }
  }

  public static void setAutosend(DDXMLElement p4, String vx, int order)
  {
    DDXMLElement dx = findPhraseElement(p4, order);
    if (dx != null)
    {
      dx.setAttribute(PHRASE_AUROSEND, vx);
    }
  }

  public static DDXMLElement makeNewP4(AESPlnk aesKey, String p1, String p2, String p3, String lnk1, String txt)
  {
    DDXMLElement p4 = DDXMLElement.initWithXMLString(PHRASE_XML_V8_EMPTY_CONTAINER);
    setPhraseElement(aesKey, p4, p1, 1);
    setPhraseElement(aesKey, p4, p2, 2);
    setPhraseElement(aesKey, p4, p3, 3);
    setLinkElement(aesKey, p4, lnk1);
    setTextElement(aesKey, p4, txt);
    return p4;
  }

  public static void setTextElement(AESPlnk aesKey, DDXMLElement p4, String vx)
  {
    DDXMLElement p = findTextElement(p4);
    if (p != null && vx != null && vx.length() >= 0)
    {
      String encData = encryptStringData(aesKey, vx);
      p.setTextContent(encData);
    }
  }

  public static void setTextElementAsB64(DDXMLElement p4, String vx)
  {
    DDXMLElement p = findTextElement(p4);
    if (p != null && vx != null && vx.length() >= 0)
    {
      String encData = AESPlnk.b64encode2String(vx);
      p.setTextContent(encData);
    }
  }

  public static void setUserUUID(DDXMLElement p4, String vx)
  {
    if (vx!=null) {
      DDXMLElement uuid = findUserUUIDElement(p4);
      if(uuid!=null){
        uuid.setStringValue(vx);
      }
    }
  }

  private static DDXMLElement findTextElement(DDXMLElement p4)
  {
    return p4.firstElement(PHRASE_TEXT);
  }

  public static void setLinkElement(AESPlnk aesKey, DDXMLElement p4, String vx)
  {
    DDXMLElement p = findLinkElement(p4);
    if (p != null && vx != null && vx.length() >= 0)
    {
      String encData = encryptStringData(aesKey, vx);
      p.setTextContent(encData);
    }
  }

  private static DDXMLElement findLinkElement(DDXMLElement p4)
  {
    DDXMLElement links = p4.firstElement(PHRASE_LINKS);
    if (links != null)
    {
      DDXMLElement link = links.firstElement(PHRASE_LINK);
      if (link != null)
      {
        return link;
      } else
      {
        links.setChildNode(PHRASE_LINK, "");
        return links.firstElement(PHRASE_LINK);
      }
    }
    return null;
  }

  public static String getLinkElement(AESPlnk aesKey, DDXMLElement p4)
  {
    DDXMLElement dx = findLinkElement(p4);
    if (dx != null)
    {
      String encData = dx.getTextContent();
      if (encData != null && encData.length() > 1)
        return decryptStringData(aesKey, encData);
    }
    return null;
  }

  public static DDXMLElement decryptP4ForBackup(AESPlnk aesKey, DDXMLElement p4)
  {
    DDXMLElement items = p4.firstElement(PHRASE_ITEMS);
    DDXMLElement links = p4.firstElement(PHRASE_LINKS);

    if(items!=null) {
      NodeList ar = items.elementsForName(PHRASE_ITEM);
      if (ar != null && ar.getLength() > 0)
      {
        for (int i = 0; i < ar.getLength(); i++)
        {
          Node nx = ar.item(i);
          DDXMLElement dx = new DDXMLElement(nx);
          String vx = dx.getStringValue();
          if (vx != null && vx.length()>0)
          {
            vx = aesKey.decryptStringFromB64(vx);
            vx = AESPlnk.b64encode2String(vx);
            dx.setStringValue(vx);
          }
        }
      }
    }

    if(links!=null) {
      NodeList ar = links.elementsForName(PHRASE_LINK);
      if (ar != null && ar.getLength() > 0)
      {
        for (int i = 0; i < ar.getLength(); i++)
        {
          Node nx = ar.item(i);
          DDXMLElement dx = new DDXMLElement(nx);
          String vx = dx.getStringValue();
          if (vx != null && vx.length()>0)
          {
            vx = aesKey.decryptStringFromB64(vx);
            vx = AESPlnk.b64encode2String(vx);
            dx.setStringValue(vx);
          }
        }
      }
    }
    return p4;
  }

  public static DDXMLElement decryptP4ForExport(AESPlnk aesKey, DDXMLElement p4)
  {
    DDXMLElement items = p4.firstElement(PHRASE_ITEMS);
    DDXMLElement links = p4.firstElement(PHRASE_LINKS);

    if(items!=null) {
      NodeList ar = items.elementsForName(PHRASE_ITEM);
      if (ar != null && ar.getLength() > 0)
      {
        for (int i = 0; i < ar.getLength(); i++)
        {
          Node nx = ar.item(i);
          DDXMLElement dx = new DDXMLElement(nx);
          String vx = dx.getStringValue();
          if (vx != null && vx.length()>0)
          {
            vx = aesKey.decryptStringFromB64(vx);
            vx = AESPlnk.b64encode2String(vx);
            dx.setStringValue(vx);
          }
        }
      }
    }

    if(links!=null) {
      NodeList ar = links.elementsForName(PHRASE_LINK);
      if (ar != null && ar.getLength() > 0)
      {
        for (int i = 0; i < ar.getLength(); i++)
        {
          Node nx = ar.item(i);
          DDXMLElement dx = new DDXMLElement(nx);
          String vx = dx.getStringValue();
          if (vx != null && vx.length()>0)
          {
            vx = aesKey.decryptStringFromB64(vx);
            vx = AESPlnk.b64encode2String(vx);
            dx.setStringValue(vx);
          }
        }
      }
    }

    try{
      String otp  = getOTPSecretCode(aesKey,p4);
      String tx = getTextElement(aesKey,p4);
      String fp = getFidoPin(aesKey,p4);
      String ft = getFidoToken(aesKey,p4);

      if(otp!=null) setOTPSecretCode(p4,otp);
      if(tx!=null) setTextElementAsB64(p4,tx);
      if(fp!=null) setFidoPinAsB64(p4,fp);
      if(ft!=null) setFidoTokenAsB64(p4,ft);

    } catch (Exception e) {}

    return p4;
  }

  public static String getTextElement(AESPlnk aesKey, DDXMLElement p4)
  {
    DDXMLElement dx = findTextElement(p4);
    if (dx != null)
    {
      String encData = dx.getTextContent();
      if (encData != null && encData.length() > 1)
        return decryptStringData(aesKey, encData);
    }
    return null;
  }

  public static String getTextElement(DDXMLElement p4)
  {
    DDXMLElement dx = findTextElement(p4);
    if (dx != null)
    {
      String data = dx.getTextContent();
      return data;
    }
    return null;
  }

  public static String getUserUUID(DDXMLElement p4)
  {
    DDXMLElement uuid = findUserUUIDElement(p4);
    if (uuid != null)
    {
      return uuid.getTextContent();
    }
    return null;
  }

  public static String getPhraseElement(AESPlnk aesKey, DDXMLElement p4, int order)
  {
    DDXMLElement dx = findPhraseElement(p4, order);
    if (dx != null)
    {
      String encData = dx.getTextContent();
      if (encData != null && encData.length() > 1)
        return decryptStringData(aesKey, encData);
    }
    return null;
  }

  public static void setPhraseElement(AESPlnk aesKey, DDXMLElement p4, String vx, int order)
  {
    DDXMLElement dx = findPhraseElement(p4, order);
    if (dx != null)
    {
      if (vx != null && vx.length() >= 0)
      {
        String encData = encryptStringData(aesKey, vx);
        if (encData != null && encData.length() > 1)
        {
          dx.setTextContent(encData);
        }
      }
    }
  }

  private static DDXMLElement findPhraseElement(DDXMLElement p4, int order)
  {
    DDXMLElement itemBlock = findItemsBlock(p4);
    if (itemBlock != null)
    {
      NodeList items = itemBlock.getElementsByTagName(PHRASE_ITEM);
      int cx = items.getLength();
      for (int idx = 0; idx < cx; idx++)
      {
        Element item = (Element) items.item(idx);
        if (item != null)
        {
          DDXMLElement dx = new DDXMLElement(item);
          int ox = dx.attributeForNameAsInt(PHRASE_ORDER);
          if (ox == order)
          {
            return dx;
          }
        }
      }
      Element ex = p4.createElement(PHRASE_ITEM);
      ex.setAttribute(PHRASE_ORDER, String.valueOf(order));
      ex.setAttribute(PHRASE_AUROSEND, "1");
      itemBlock.appendChild((Node) ex);
      return new DDXMLElement(ex);
    }
    return null;
  }

  //private

  public static DDXMLElement findItemsBlock(DDXMLElement p4)
  {
    return p4.firstElement(PHRASE_ITEMS);
  }

  public static String getOTPSecretCode(AESPlnk aesKey, DDXMLElement p4)
  {
    Element dx = findOTPElement(p4);
    if (dx != null)
    {
      String data = dx.getTextContent();
      if (data != null && data.length() >= 4)
      {
        String otpSecret = decryptStringData(aesKey, data);
        if (otpSecret != null && otpSecret.length() == 0)
          otpSecret = null;
        return otpSecret;
      }
    }
    return null;
  }

  public static String getOTPSecretCode(DDXMLElement p4)
  {
    Element dx = findOTPElement(p4);
    if (dx != null)
    {
      String data = dx.getTextContent();
      if (data != null && data.length() >= 4)
      {
        return data;
      }
    }
    return null;
  }

  public static boolean isOTPActive(DDXMLElement p4)
  {
    DDXMLElement dx = findOTPElement(p4);
    if (dx != null)
    {
      return dx.attributeForNameAsBool(PHRASE_ACTIVE);
    }
    return false;
  }

  public static void setOTPSecretCode(AESPlnk aesKey, DDXMLElement p4, String vx)
  {
    DDXMLElement dx = findOTPElement(p4);
    if (dx != null && vx != null)
    {
      String encData = encryptStringData(aesKey, vx);
      dx.setTextContent(encData);
    }
  }

  public static void setOTPSecretCode(DDXMLElement p4, String vx)
  {
    DDXMLElement dx = findOTPElement(p4);
    if (dx != null && vx != null)
    {
      String encData = AESPlnk.b64encode2String(vx);
      dx.setTextContent(encData);
    }
  }

  public static void setOTPActive(DDXMLElement p4, boolean active)
  {
    DDXMLElement dx = findOTPElement(p4);
    if (dx != null)
    {
      if (active)
      {
        dx.setAttribute(PHRASE_ACTIVE, "1");
      } else
      {
        dx.setAttribute(PHRASE_ACTIVE, "0");
      }
    }
  }

  public static void setOTPTimerType(DDXMLElement p4)
  {
    DDXMLElement dx = findOTPElement(p4);
    if (dx != null)
    {
      dx.setAttribute(PHRASE_TYPE, PHRASE_TOTP);
    }
  }

  public static boolean isSyncActive(DDXMLElement p4)
  {
    DDXMLElement dx = findItemsBlock(p4);
    if (dx != null)
    {
      return dx.attributeForNameAsBool(PHRASE_SYNC);
    }
    return false;
  }

  public static void setSyncActive(DDXMLElement p4, boolean active)
  {
    if(p4 == null) return;
    DDXMLElement dx = findItemsBlock(p4);
    if (dx != null)
    {
      if (active)
      {
        dx.setAttribute(PHRASE_SYNC, "1");
      } else
      {
        dx.setAttribute(PHRASE_SYNC, "0");
      }
    }
  }

  public static void setOpMode(DDXMLElement p4, int mode)
  {
    if(p4 == null) return;
    DDXMLElement dx = findItemsBlock(p4);
    if (dx != null)
    {
      dx.setAttribute("opmode", String.format("%d",mode));
    }
  }

  // MODE.values()[PhraseX.getOpMode(mP4)];
  public static int getOpMode(DDXMLElement p4)
  {
    DDXMLElement dx = findItemsBlock(p4);
    if (dx != null)
    {
      return dx.attributeForNameAsInt("opmode");
    }
    return 0;
  }

  public static void setPrivateEncrytion(DDXMLElement p4, boolean active)
  {
    if(p4 == null) return;
    DDXMLElement dx = findItemsBlock(p4);
    if (dx != null)
    {
      if (active)
      {
        dx.setAttribute(PHRASE_PRIVENC, "1");
      } else
      {
        dx.setAttribute(PHRASE_PRIVENC, "0");
      }
    }
  }

  public static boolean isPrivateEncrytion(DDXMLElement p4)
  {
    DDXMLElement dx = findItemsBlock(p4);
    if (dx != null)
    {
      return dx.attributeForNameAsBool(PHRASE_PRIVENC);
    }
    return false;
  }

  public static void setEditableActive(DDXMLElement p4, boolean active)
  {
    if(p4 == null) return;
    DDXMLElement dx = findItemsBlock(p4);
    if (dx != null)
    {
      if (active)
      {
        dx.setAttribute(PHRASE_EDT, "1");
      } else
      {
        dx.setAttribute(PHRASE_EDT, "0");
      }
    }
  }

  public static boolean isEditableActive(DDXMLElement p4)
  {
    DDXMLElement dx = findItemsBlock(p4);
    if (dx != null)
    {
      return dx.attributeForNameAsBool(PHRASE_EDT);
    }
    return false;
  }

  public static void setWriteBackActive(DDXMLElement p4, boolean active)
  {
    if(p4 == null) return;
    DDXMLElement dx = findItemsBlock(p4);
    if (dx != null)
    {
      if (active)
      {
        dx.setAttribute(PHRASE_WBCK, "1");
      } else
      {
        dx.setAttribute(PHRASE_WBCK, "0");
      }
    }
  }

  public static boolean isWriteBackActive(DDXMLElement p4)
  {
    DDXMLElement dx = findItemsBlock(p4);
    if (dx != null)
    {
      return dx.attributeForNameAsBool(PHRASE_WBCK);
    }
    return false;
  }

  public static void setOrigOiPidx(DDXMLElement p4, String opdx)
  {
    if(p4 == null) return;
    DDXMLElement dx = findItemsBlock(p4);
    if (dx != null)
    {
      dx.setAttribute(PHRASE_OPDX, opdx);
    }
  }

  public static String getOrigOiPidx(DDXMLElement p4)
  {
    DDXMLElement dx = findItemsBlock(p4);
    if (dx != null)
    {
      return dx.getAttributeNode(PHRASE_OPDX).getTextContent();
    }
    return null;
  }

  public static boolean isExternManaged(DDXMLElement p4)
  {
    String val = PhraseX.getOrigOiPidx(p4);
    if (val != null)
    {
      return Integer.parseInt(val) != 0;
    }
    return true;
  }


  public static void setBESUUID(DDXMLElement p4, String bes)
  {
    DDXMLElement dx = findItemsBlock(p4);
    if (dx != null)
    {
      if(bes==null) {
        dx.setAttribute(PHRASE_BES, "");
      }else{
        dx.setAttribute(PHRASE_BES, bes);
      }
    }
  }

  public static String getBESUUID(DDXMLElement p4)
  {
    DDXMLElement dx = findItemsBlock(p4);
    if (dx != null)
    {
      Attr attr = dx.getAttributeNode(PHRASE_BES);
      if(attr!=null)
      {
        return attr.getTextContent();
      }
    }
    return null;
  }


  public static void setChangeDateFt(DDXMLElement p4, String ft)
  {
    if(p4 == null) return;
    DDXMLElement dx = findItemsBlock(p4);
    if (dx != null)
    {
      dx.setAttribute(PHRASE_FT, ft);
    }
  }

  public static String getChangeDateFt(DDXMLElement p4)
  {
    DDXMLElement dx = findItemsBlock(p4);
    if (dx != null)
    {
      return dx.getAttributeNode(PHRASE_FT).getTextContent();
    }
    return null;
  }

  public static void setChangeDateTs(DDXMLElement p4, String ts)
  {
    if(p4 == null) return;
    DDXMLElement dx = findItemsBlock(p4);
    if (dx != null)
    {
      dx.setAttribute(PHRASE_TS, ts);
    }
  }

  public static String getChangeDateTs(DDXMLElement p4)
  {
    DDXMLElement dx = findItemsBlock(p4);
    if (dx != null)
    {
      return dx.getAttributeNode(PHRASE_TS).getTextContent();
    }
    return null;
  }

  public static DDXMLElement makeP4FromB64String(String b64String)
  {
    String xmlData = AESPlnk.b64decode2String(b64String);
    return DDXMLElement.initWithXMLString(xmlData);
  }

  public static boolean isAutosend(DDXMLElement p4, int order)
  {
    DDXMLElement dx = findPhraseElement(p4, order);
    if (dx != null)
    {
      return dx.attributeForNameAsBool(PHRASE_AUROSEND);
    }
    return false;
  }

  public static boolean isWithFinalEnter(DDXMLElement p4)
  {
    DDXMLElement dx = findItemsBlock(p4);
    if (dx != null)
    {
      return dx.attributeForNameAsBool(PHRASE_FINALENTER);
    }
    return false;
  }

  public static boolean isTabCatenate(DDXMLElement p4)
  {
    DDXMLElement dx = findItemsBlock(p4);
    if (dx != null)
    {
      String val = dx.getAttributeNode(PHRASE_CAT).getTextContent();
      return val.compareTo(PHRASE_TAB) == 0;
    }
    return false;
  }

  public static boolean isValidForSendDlg(AESPlnk aesKey, DDXMLElement p4)
  {
    if(PhraseX.isFidoActive(p4))
    {
      return true;
    }
    String cmd = PhraseX.prepareFullLoginDataToSend(aesKey,p4);
    if (cmd != null && cmd.length() > 0)
    {
      return true;
    }
    return false;
  }

  public static String prepareFullLoginDataToSend(AESPlnk aesKey, DDXMLElement p4)
  {
    StringBuilder cmd = new StringBuilder();
    if (p4 != null)
    {
      DDXMLElement items = findItemsBlock(p4);
      if (items != null)
      {
        boolean bFinalEnter = isWithFinalEnter(p4);
        boolean bTabCat = isTabCatenate(p4);

        String p1 = getPhraseElement(aesKey, p4, 1);
        String p2 = getPhraseElement(aesKey, p4, 2);
        String p3 = getPhraseElement(aesKey, p4, 3);
        // 1
        boolean isJustEmptyAtAll = true;
        if (p1 != null && p1.length() > 0 && PhraseX.isAutosend(p4, 1))
        {
          isJustEmptyAtAll = false;
          cmd.append(p1);
        }
        // 2
        if (p2 != null && p2.length() > 0 && PhraseX.isAutosend(p4, 2))
        {
          if (bTabCat && !isJustEmptyAtAll)
          {
            cmd.append("\011");
          }
          isJustEmptyAtAll = false;
          cmd.append(p2);
        }
        // 3
        if (p3 != null && p3.length() > 0 && PhraseX.isAutosend(p4, 3))
        {
          if (bTabCat && !isJustEmptyAtAll)
          {
            cmd.append("\011");
          }
          isJustEmptyAtAll = false;
          cmd.append(p3);
        }
        // Enter
        if (bFinalEnter && (!isJustEmptyAtAll))
        {
          cmd.append("\015");
        }
      }
    }
    return cmd.toString();
  }

  public static boolean isImportEqual(AESPlnk aesKey, DDXMLElement p4, DDXMLElement p4Imp)
  {
    String p1c = PhraseX.getPhraseElement(aesKey, p4, 1);
    String p2c = PhraseX.getPhraseElement(aesKey, p4, 2);
    String p3c = PhraseX.getPhraseElement(aesKey, p4, 3);
    String lnc = PhraseX.getLinkElement(aesKey, p4);
    String txc = PhraseX.getTextElement(aesKey, p4);
    String ftkn = PhraseX.getFidoToken(aesKey,p4);
    String fpin = PhraseX.getFidoPin(aesKey,p4);
    String otpb = PhraseX.getOTPSecretCode(aesKey,p4);
    Boolean privEncC = PhraseX.isPrivateEncrytion(p4);

    if (p1c == null)
      p1c = "";
    if (p2c == null)
      p2c = "";
    if (p3c == null)
      p3c = "";
    if (lnc == null)
      lnc = "";
    if (txc == null)
      txc = "";
    if (ftkn == null)
      ftkn = "";
    if (fpin == null)
      fpin = "";
    if (otpb == null)
      otpb = "";

    String p1Imp = PhraseX.getPhraseElement(aesKey, p4Imp, 1);
    String p2Imp = PhraseX.getPhraseElement(aesKey, p4Imp, 2);
    String p3Imp = PhraseX.getPhraseElement(aesKey, p4Imp, 3);
    String lnImp = PhraseX.getLinkElement(aesKey, p4Imp);
    String txImp = PhraseX.getTextElement(aesKey, p4Imp);
    String ftknImp = PhraseX.getFidoToken(aesKey, p4Imp);
    String fpinImp = PhraseX.getFidoPin(aesKey, p4Imp);
    String otpbImp = PhraseX.getOTPSecretCode(aesKey, p4Imp);
    Boolean privEncImp = PhraseX.isPrivateEncrytion(p4Imp);
    if (p1Imp == null)
      p1Imp = "";
    if (p2Imp == null)
      p2Imp = "";
    if (p3Imp == null)
      p3Imp = "";
    if (lnImp == null)
      lnImp = "";
    if (txImp == null)
      txImp = "";
    if (ftknImp == null)
      ftknImp = "";
    if (fpinImp == null)
      fpinImp = "";
    if (otpbImp == null)
      otpbImp = "";

    if(
      !(p1Imp.equals(p1c)) ||
        !(p2Imp.equals(p2c)) ||
        !(p3Imp.equals(p3c)) ||
        !(lnImp.equals(lnc)) ||
        !(txImp.equals(txc))||
        !(ftknImp.equals(ftkn))||
        !(fpinImp.equals(fpin))||
        !(otpbImp.equals(otpb)) ||
        (privEncImp !=privEncC)
    )
    {
      return false;
    }
    return true;
  }

  public static DDXMLElement mergeImport(AESPlnk aesKey, DDXMLElement p4, DDXMLElement p4Imp)
  {
    String p1Imp  = PhraseX.getPhraseElement(aesKey, p4Imp, 1);
    String p2Imp  = PhraseX.getPhraseElement(aesKey, p4Imp, 2);
    String p3Imp  = PhraseX.getPhraseElement(aesKey, p4Imp, 3);
    String lnImp  = PhraseX.getLinkElement(aesKey, p4Imp);
    String txImp  = PhraseX.getTextElement(aesKey, p4Imp);
    String otp    = PhraseX.getOTPSecretCode(aesKey,p4Imp);
    String fdo    = PhraseX.getFidoToken(aesKey,p4Imp);
    String fdPin  = PhraseX.getFidoPin(aesKey,p4Imp);

    if (p1Imp == null)
      p1Imp = "";
    if (p2Imp == null)
      p2Imp = "";
    if (p3Imp == null)
      p3Imp = "";
    if (lnImp == null)
      lnImp = "";
    if (txImp == null)
      txImp = "";

    PhraseX.setPhraseElement(aesKey, p4, p1Imp, 1);
    PhraseX.setPhraseElement(aesKey, p4, p2Imp, 2);
    PhraseX.setPhraseElement(aesKey, p4, p3Imp, 3);
    PhraseX.setLinkElement(aesKey, p4, lnImp);
    PhraseX.setTextElement(aesKey, p4, txImp);

    if(otp!=null) PhraseX.setOTPSecretCode(aesKey, p4, otp);
    if(fdo!=null) PhraseX.setFidoToken(aesKey, p4, fdo);
    if(fdPin!=null) PhraseX.setFidoPin(aesKey, p4, fdPin);

    PhraseX.setSyncActive(p4, PhraseX.isSyncActive(p4Imp));
    PhraseX.setEditableActive(p4, PhraseX.isEditableActive(p4Imp));
    PhraseX.setWriteBackActive(p4, PhraseX.isWriteBackActive(p4Imp));
    PhraseX.setFidoActivation(p4, PhraseX.isFidoActive(p4Imp));

    PhraseX.setOrigOiPidx(p4, String.valueOf(PhraseX.getOrigOiPidx(p4Imp)));

    PhraseX.setChangeDateFt(p4, PhraseX.getChangeDateFt(p4Imp));
    PhraseX.setChangeDateTs(p4, String.valueOf(PhraseX.getChangeDateTs(p4Imp)));

    return p4;
  }

  /**
   *
   * @param aesTelKey : Key für die Verschlüsselung in der PhraseLock-App
   * @param p4        : Der Datensatz im XML Format
   * @param label     : Bezeichnung des Datensatzes
   * @param skey      : Der Transportschlüssel mit IV
   * @return          : Der Datensatz verschlüsselt mit SKey als Base64-String
   */
  public static String exportForSync(AESPlnk aesTelKey, DDXMLElement p4, String label, DDXMLElement skey)
  {
    if (skey != null && p4 != null && aesTelKey != null)
    {
      if (label != null)
      {
        if (PhraseX.isSyncActive(p4))
        {
          String p1 = PhraseX.getPhraseElement(aesTelKey, p4, 1);
          String p2 = PhraseX.getPhraseElement(aesTelKey, p4, 2);
          String p3 = PhraseX.getPhraseElement(aesTelKey, p4, 3);
          String ln = PhraseX.getLinkElement(aesTelKey, p4);
          String tx = PhraseX.getTextElement(aesTelKey, p4);
          String op = PhraseX.getOTPSecretCode(aesTelKey, p4);
          String ft = PhraseX.getFidoToken(aesTelKey, p4);
          String fp = PhraseX.getFidoPin(aesTelKey, p4);

          if (p1 == null)
            p1 = "";
          if (p2 == null)
            p2 = "";
          if (p3 == null)
            p3 = "";
          if (ln == null)
            ln = "";
          if (tx == null)
            tx = "";
          if (op == null)
            op = "";
          if (ft == null)
            ft = "";
          if (fp == null)
            fp = "";

          String srecPlain = String.format(PhraseX.SYNC_CONTAINER, AESPlnk.b64encode2StringB(label.getBytes()), AESPlnk.b64encode2StringB(p1.getBytes()), AESPlnk.b64encode2StringB(p2.getBytes()), AESPlnk.b64encode2StringB(p3.getBytes()), AESPlnk.b64encode2StringB(ln.getBytes()), AESPlnk.b64encode2StringB(tx.getBytes()), AESPlnk.b64encode2StringB(op.getBytes()), AESPlnk.b64encode2StringB(ft.getBytes()), AESPlnk.b64encode2StringB(fp.getBytes()));

          ksAnd aesSKeyEnc = new ksAnd(skey);
          String srecCrypt = aesSKeyEnc.encryptByteArrayToB64(srecPlain.getBytes());
          srecCrypt = AESPlnk.makeB64DataPKCSSafe(srecCrypt);
          return srecCrypt;
        }
      }
    }
    return null;
  }

  public static DDXMLElement makeFromJSONImport(AESPlnk aesKey, String cypherJSON, DDXMLElement skey)
  {
    if (cypherJSON != null)
    {
      cypherJSON = AESPlnk.makeB64DataURLSafe(cypherJSON);
      if (skey != null && aesKey != null) {
        byte[] cipherArray = AESPlnk.b64decode2ByteArray(cypherJSON);
        int lenC = cipherArray.length;
        ksAnd aesSKeyDec = new ksAnd(skey);
        ByteArrayOutputStream decrypted = new ByteArrayOutputStream();
        int lenDec = aesSKeyDec.decryptByteArray(cipherArray, lenC, decrypted);
        if (lenDec >=0)
        {
          String plainText2 = new String(decrypted.toByteArray(), 0, lenDec);
          try {
            String p1 = "";
            String p2 = "";
            String p3 = "";
            String ln = "";
            String tx = "";
            String op = "";
            String ft = "";
            String fp = "";

            JSONObject jsonDict = new JSONObject(plainText2);

            try {
              p1 = jsonDict.getString(PHRASE_P1);
            } catch (Exception e) {
              p1 = "";
            }
            try {
              p2 = jsonDict.getString(PHRASE_P2);
            } catch (Exception e) {
              p2 = "";
            }
            try {
              p3 = jsonDict.getString(PHRASE_P3);
            } catch (Exception e) {
              p3 = "";
            }
            try {
              ln = jsonDict.getString(PHRASE_LN);
            } catch (Exception e) {
              ln = "";
            }
            try {
              tx = jsonDict.getString(PHRASE_TX);
            } catch (Exception e) {
              tx = "";
            }
            try {
              op = jsonDict.getString(PHRASE_OP);
            } catch (Exception e) {
              op = "";
            }
            try {
              ft = jsonDict.getString(PHRASE_FT);
            } catch (Exception e) {
              ft = "";
            }
            try {
              fp = jsonDict.getString(PHRASE_FP);
            } catch (Exception e) {
              fp = "";
            }

            p1 = AESPlnk.b64decode2StringNotNull(p1);
            p2 = AESPlnk.b64decode2StringNotNull(p2);
            p3 = AESPlnk.b64decode2StringNotNull(p3);
            ln = AESPlnk.b64decode2StringNotNull(ln);
            tx = AESPlnk.b64decode2StringNotNull(tx);
            op = AESPlnk.b64decode2StringNotNull(op);
            ft = AESPlnk.b64decode2StringNotNull(ft);
            fp = AESPlnk.b64decode2StringNotNull(fp);

            DDXMLElement p4 = PhraseX.makeNewP4(aesKey, p1, p2, p3, ln, tx);

            if (op != null && op.length() > 0) {
              PhraseX.setOTPTimerType(p4);
              PhraseX.setOTPSecretCode(aesKey, p4, op);
              PhraseX.setOTPActive(p4, true);
            } else {
              PhraseX.setOTPActive(p4, false);
            }

            if (ft != null && ft.length() > 0 && fp != null && fp.length() > 0) {
              PhraseX.setFidoToken(aesKey, p4, ft);
              PhraseX.setFidoPin(aesKey, p4, fp);
              PhraseX.setFidoActivation(p4, true);
            } else {
              PhraseX.setFidoActivation(p4, false);
            }

            return p4;
          } catch (Exception ignored) {
          }
        }
      }
    }
    return null;
  }

  public static DDXMLElement homogeniziseInputWithCurrent(DDXMLElement p4Currend, DDXMLElement p4Import)
  {
    PhraseX.setSyncActive(p4Import, PhraseX.isSyncActive(p4Currend));
    PhraseX.setOrigOiPidx(p4Import, PhraseX.getOrigOiPidx(p4Currend));

    PhraseX.setEditableActive(p4Import, PhraseX.isEditableActive(p4Currend));
    PhraseX.setWriteBackActive(p4Import, PhraseX.isWriteBackActive(p4Currend));

    PhraseX.setFidoActivation(p4Import, PhraseX.isFidoActive(p4Currend));

    if (PhraseX.getChangeDateFt(p4Currend) != null)
    {
      PhraseX.setChangeDateFt(p4Import, PhraseX.getChangeDateFt(p4Currend));
    }
    if (PhraseX.getChangeDateTs(p4Currend) != null)
    {
      PhraseX.setChangeDateTs(p4Import, PhraseX.getChangeDateTs(p4Currend));
    }

    PhraseX.setPrivateEncrytion(p4Import, PhraseX.isPrivateEncrytion(p4Currend));
    return p4Import;
  }

  public static void saveP4ByLidx(DDXMLElement p4, int lidx)
  {
    /*
    try
    {
      if (p4 != null)
      {
        String p4XMLString = p4.XMLString();
        p4XMLString = AESPlnk.b64encode2String(p4XMLString);
        db.update_px(String.valueOf(lidx), PHRASE_P4, p4XMLString);
      }
    } catch (Exception ignore)
    {
    }

     */
  }

  public static void saveP4ByLidx(DDXMLElement p4, String lidx)
  {
    if(p4 == null) return;
    saveP4ByLidx(p4, Integer.parseInt(lidx));
  }

  public static void saveP4ByUuid(DDXMLElement p4, String uuid, String usb_oi_pidx)
  {
    /*
    try
    {
      if (p4 != null)
      {
        String p4XMLString = p4.XMLString();
        p4XMLString = AESPlnk.b64encode2String(p4XMLString);
        String lidx = db.getPhraseLidxByUUID(uuid, usb_oi_pidx);
        db.update_px(lidx, PHRASE_P4, p4XMLString);
      }
    } catch (Exception ignore)
    {
    }

     */
  }

  public static DDXMLElement makeEncryptedP4FromBackupP4(AESPlnk aesKey, DDXMLElement p4)
  {
    if(p4 == null) return null;
    DDXMLElement items = p4.firstElement(PHRASE_ITEMS);
    DDXMLElement links = p4.firstElement(PHRASE_LINKS);

    if (items != null)
    {
      NodeList ar = items.getElementsByTagName(PHRASE_ITEM);
      int iCount = ar.getLength();
      for (int i = 0; i < iCount; i++)
      {
        Node nx = ar.item(i);
        if (nx != null)
        {
          String vx = nx.getTextContent();
          if (vx != null && vx.length() > 0)
          {
            vx = AESPlnk.b64decode2String(vx);
            if (vx != null)
            {
              vx = aesKey.encryptStringToB64(vx);
              nx.setTextContent(vx);
            }
          }
        }
      }
    }

    if (links != null)
    {
      NodeList ar = links.getElementsByTagName(PHRASE_LINK);
      int iCount = ar.getLength();
      for (int i = 0; i < iCount; i++)
      {
        Node nx = ar.item(i);
        if (nx != null)
        {
          String vx = nx.getTextContent();
          if (vx != null && vx.length() > 0)
          {
            vx = AESPlnk.b64decode2String(vx);
            if (vx != null)
            {
              vx = aesKey.encryptStringToB64(vx);
              nx.setTextContent(vx);
            }
          }
        }
      }
    }
    return p4;
  }


  public static DDXMLElement makeEncryptedP4FromExportP4(AESPlnk aesKey, DDXMLElement p4)
  {
    if(p4 == null) return null;
    DDXMLElement items = p4.firstElement(PHRASE_ITEMS);
    DDXMLElement links = p4.firstElement(PHRASE_LINKS);

    if (items != null)
    {
      NodeList ar = items.getElementsByTagName(PHRASE_ITEM);
      int iCount = ar.getLength();
      for (int i = 0; i < iCount; i++)
      {
        Node nx = ar.item(i);
        if (nx != null)
        {
          String vx = nx.getTextContent();
          if (vx != null && vx.length() > 0)
          {
            vx = AESPlnk.b64decode2String(vx);
            if (vx != null)
            {
              vx = aesKey.encryptStringToB64(vx);
              nx.setTextContent(vx);
            }
          }
        }
      }
    }

    if (links != null)
    {
      NodeList ar = links.getElementsByTagName(PHRASE_LINK);
      int iCount = ar.getLength();
      for (int i = 0; i < iCount; i++)
      {
        Node nx = ar.item(i);
        if (nx != null)
        {
          String vx = nx.getTextContent();
          if (vx != null && vx.length() > 0)
          {
            vx = AESPlnk.b64decode2String(vx);
            if (vx != null)
            {
              vx = aesKey.encryptStringToB64(vx);
              nx.setTextContent(vx);
            }
          }
        }
      }
    }
    try{
      String otp = getOTPSecretCode(p4);
      //String tx = getTextElement(aesKey,p4);
      //String fp = getFidoPin(aesKey,p4);
      //String ft = getFidoToken(aesKey,p4);

      if(otp!=null) setOTPSecretCode(aesKey,p4,AESPlnk.b64decode2String(otp));
      //if(tx!=null) setTextElementAsB64(p4,tx);
      //if(fp!=null) setFidoPinAsB64(p4,fp);
      //if(ft!=null) setFidoTokenAsB64(p4,ft);

    } catch (Exception e) {}

    return p4;
  }

}
