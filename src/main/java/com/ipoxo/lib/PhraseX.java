package com.ipoxo.lib;

import com.ipoxo.plcore.lib.DDXMLElement;
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

  final public static String PHRASE_ORDER = "order";
  final public static String PHRASE_AUROSEND = "autosend";
  final public static String PHRASE_ITEMS = "items";
  final public static String PHRASE_ITEM = "item";
  final public static String PHRASE_LINKS = "links";
  final public static String PHRASE_LINK = "link";
  final public static String PHRASE_OTP = "otp";
  final public static String PHRASE_ACTIVE = "active";
  final public static String PHRASE_FIDOTOKEN = "fidotoken";
  final public static String PHRASE_FIDOPIN = "fidopin";
  final public static String PHRASE_TEXT = "text";
  final public static String PHRASE_TYPE = "type";
  final public static String PHRASE_TOTP = "totp";
  final public static String PHRASE_SYNC = "sync";
  final public static String PHRASE_BES = "bes";


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
    } catch (Exception ignore) {}
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
    } catch (Exception ignore) {}
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

  private static DDXMLElement findOTPElement(DDXMLElement p4)
  {
    return p4.firstElement(PHRASE_OTP);
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
        if (otpSecret != null && otpSecret.isEmpty())
          otpSecret = null;
        return otpSecret;
      }
    }
    return null;
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

}
