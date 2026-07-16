package com.ipoxo.plcore.lib;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Attr;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.TypeInfo;
import org.w3c.dom.UserDataHandler;

public class DDXMLElement implements Element
{
  private Element mElement;
  
  public DDXMLElement()
  {
    mElement = null;
  }
  
  public Document getDoc()
  {
    return mElement.getOwnerDocument();
  }
  
  public Node getNode()
  {
    return mElement;
  }
  
  public NamedNodeMap getAttr()
  {
    return mElement.getAttributes();
  }
  
  public NodeList getNodes()
  {
    return mElement.getChildNodes();
  }
  
  public static Document asDocument(Node n) {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    DocumentBuilder db;
    Document newDoc = null;
    try {
      db = dbf.newDocumentBuilder();
      newDoc = db.newDocument();
      newDoc.appendChild(newDoc.importNode(n, true));
    } catch (Exception e) {
      e.printStackTrace();
    }
    return newDoc;
  }
  
  public Element createElement(String name)
  {
    return mElement.getOwnerDocument().createElement(name);
  }
  
  public Attr createAttribute(String name)
  {
    return mElement.getOwnerDocument().createAttribute(name);
  }
  
  public DDXMLElement(Element element)
  {
    mElement = element;
  }
  
  public DDXMLElement(Node node)
  {
    
    mElement = (Element)node;
  }
  
  public static DDXMLElement initWithXMLString(String xmlData)
  {
    try
    {
      DDXMLElement dx = new DDXMLElement();
      InputStream istream = new ByteArrayInputStream(xmlData.getBytes(StandardCharsets.UTF_8));
      DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
      DocumentBuilder docBuilder = null;
      docBuilder = builderFactory.newDocumentBuilder();
      dx.mElement = (Element) docBuilder.parse(istream).getFirstChild();
      return dx;
    } catch (Exception e)
    {
    }
    return null;
  }
  
  public String XMLString()
  {
    try
    {
      StringWriter writer = new StringWriter();
      Transformer transformer = TransformerFactory.newInstance().newTransformer();
      transformer.transform(new DOMSource(mElement), new StreamResult(writer));
      String output = writer.toString();
      output = output.substring(output.indexOf("?>") + 2);//remove <?xml version="1.0" encoding="UTF-8"?>
      return output;
    } catch (Exception e)
    {
      e.printStackTrace();
    }
    return null;
  }
  
  public static String XMLString(Element element)
  {
    try
    {
      StringWriter writer = new StringWriter();
      Transformer transformer = TransformerFactory.newInstance().newTransformer();
      transformer.transform(new DOMSource(element), new StreamResult(writer));
      String output = writer.toString();
      output = output.substring(output.indexOf("?>") + 2);//remove <?xml version="1.0" encoding="UTF-8"?>
      return output;
    } catch (Exception e)
    {
      e.printStackTrace();
    }
    return null;
  }
  
  public DDXMLElement firstElement(String name)
  {
    try
    {
      NodeList nodes = mElement.getElementsByTagName(name);
      int maxN = nodes.getLength();
      if(maxN>0)
      {
        Element ex = (Element) nodes.item(0);
        return new DDXMLElement(ex);
      }
    } catch (Exception e)
    {
      e.printStackTrace();
    }
    return null;
  }
  
  public String firstElementStringValue(String name)
  {
    try
    {
      NodeList nodes = mElement.getElementsByTagName(name);
      int maxN = nodes.getLength();
      if(maxN>0)
      {
        Element ex = (Element) nodes.item(0);
        return ex.getTextContent();
      }
    } catch (Exception e)
    {
      e.printStackTrace();
    }
    return null;
  }
  
  public String firstElementStringValue(String name, String defRes)
  {
    try
    {
      NodeList nodes = mElement.getElementsByTagName(name);
      int maxN = nodes.getLength();
      if(maxN>0)
      {
        Element ex = (Element) nodes.item(0);
        return ex.getTextContent();
      }
    } catch (Exception e)
    {
      e.printStackTrace();
    }
    return defRes;
  }
  
  public NodeList elementsForName(String name)
  {
    try
    {
      NodeList nList = mElement.getElementsByTagName(name);
      return nList;
    } catch (Exception e)
    {
      e.printStackTrace();
    }
    return null;
  }
  
  public void setStringValue(String value)
  {
    if (mElement != null)
    {
      mElement.setTextContent(value);
    }
  }
  
  public String attributeForName(String name)
  {
    return getAttribute(name);
  }
  
  public void removeAttributeForName(String name)
  {
    removeAttribute(name);
  }
  
  public int attributeForNameAsInt(String name)
  {
    String sx = attributeForName(name);
    if (sx != null)
    {
      return Integer.valueOf(sx);
    }
    return 0;
  }
  
  public boolean attributeForNameAsBool(String name)
  {
    int ix = attributeForNameAsInt(name);
    if (ix != 0)
    {
      return true;
    }
    return false;
  }
  
  public String getStringValue()
  {
    if (mElement != null)
    {
      return mElement.getTextContent();
    }
    return null;
  }
  
  public void setAttribute(String key, String value)
  {
    Attr at = (Attr) createAttribute(key);
    at.setNodeValue(value);
    setAttributeNode(at);
  }
  
  public DDXMLElement setChildNode(String key, String value)
  {
    if (mElement != null)
    {
      DDXMLElement dx = firstElement(key);
      if (dx != null)
      {
        if(value!=null)
        {
          dx.setTextContent(value);
        }
        return dx;
      } else
      {
        Element ex = createElement(key);
        if(value!=null)
        {
          ex.setTextContent(value);
        }
        appendChild(ex);
        return firstElement(key);
      }
    }
    return null;
  }
  
  @Override
  public String getNodeName()
  {
    return mElement.getNodeName();
  }
  
  @Override
  public String getNodeValue() throws DOMException
  {
    return mElement.getNodeValue();
  }
  
  @Override
  public void setNodeValue(String nodeValue) throws DOMException
  {
    mElement.setNodeValue(nodeValue);
  }
  
  @Override
  public short getNodeType()
  {
    return mElement.getNodeType();
  }
  
  @Override
  public Node getParentNode()
  {
    return mElement.getParentNode();
  }
  
  @Override
  public NodeList getChildNodes()
  {
    return mElement.getChildNodes();
  }
  
  @Override
  public Node getFirstChild()
  {
    return mElement.getFirstChild();
  }
  
  @Override
  public Node getLastChild()
  {
    return mElement.getLastChild();
  }
  
  @Override
  public Node getPreviousSibling()
  {
    return mElement.getPreviousSibling();
  }
  
  @Override
  public Node getNextSibling()
  {
    return mElement.getNextSibling();
  }
  
  @Override
  public NamedNodeMap getAttributes()
  {
    return mElement.getAttributes();
  }
  
  @Override
  public Document getOwnerDocument()
  {
    return mElement.getOwnerDocument();
  }
  
  @Override
  public Node insertBefore(Node newChild, Node refChild) throws DOMException
  {
    return mElement.insertBefore(newChild, refChild);
  }
  
  @Override
  public Node replaceChild(Node newChild, Node oldChild) throws DOMException
  {
    return mElement.replaceChild(newChild, oldChild);
  }
  
  @Override
  public Node removeChild(Node oldChild) throws DOMException
  {
    return mElement.removeChild(oldChild);
  }
  
  @Override
  public Node appendChild(Node newChild) throws DOMException
  {
    return mElement.appendChild(newChild);
  }
  
  @Override
  public boolean hasChildNodes()
  {
    return mElement.hasChildNodes();
  }
  
  @Override
  public Node cloneNode(boolean deep)
  {
    return mElement.cloneNode(deep);
  }
  
  @Override
  public void normalize()
  {
    mElement.normalize();
  }
  
  @Override
  public boolean isSupported(String feature, String version)
  {
    return mElement.isSupported(feature, version);
  }
  
  @Override
  public String getNamespaceURI()
  {
    return mElement.getNamespaceURI();
  }
  
  @Override
  public String getPrefix()
  {
    return mElement.getPrefix();
  }
  
  @Override
  public void setPrefix(String prefix) throws DOMException
  {
    mElement.setPrefix(prefix);
  }
  
  @Override
  public String getLocalName()
  {
    return mElement.getLocalName();
  }
  
  @Override
  public boolean hasAttributes()
  {
    return mElement.hasAttributes();
  }
  
  @Override
  public String getBaseURI()
  {
    return mElement.getBaseURI();
  }
  
  @Override
  public short compareDocumentPosition(Node other) throws DOMException
  {
    return mElement.compareDocumentPosition(other);
  }
  
  @Override
  public String getTextContent() throws DOMException
  {
    return mElement.getTextContent();
  }
  
  @Override
  public void setTextContent(String textContent) throws DOMException
  {
    mElement.setTextContent(textContent);
  }
  
  @Override
  public boolean isSameNode(Node other)
  {
    return mElement.isSameNode(other);
  }
  
  @Override
  public String lookupPrefix(String namespaceURI)
  {
    return mElement.lookupPrefix(namespaceURI);
  }
  
  @Override
  public boolean isDefaultNamespace(String namespaceURI)
  {
    return mElement.isDefaultNamespace(namespaceURI);
  }
  
  @Override
  public String lookupNamespaceURI(String prefix)
  {
    return mElement.lookupNamespaceURI(prefix);
  }
  
  @Override
  public boolean isEqualNode(Node arg)
  {
    return mElement.isEqualNode(arg);
  }
  
  @Override
  public Object getFeature(String feature, String version)
  {
    return mElement.getFeature(feature, version);
  }
  
  @Override
  public Object setUserData(String key, Object data, UserDataHandler handler)
  {
    return mElement.setUserData(key, data, handler);
  }
  
  @Override
  public Object getUserData(String key)
  {
    return mElement.getUserData(key);
  }
  
  @Override
  public String getTagName()
  {
    return mElement.getTagName();
  }
  
  @Override
  public String getAttribute(String name)
  {
    NamedNodeMap nm = ((Node)mElement).getAttributes();
    if(nm!=null)
    {
      Node n = nm.getNamedItem(name);
      if(n!=null)
      {
        return n.getTextContent();
      }
    }
    return null;
  }
  
  @Override
  public void removeAttribute(String name) throws DOMException
  {
    mElement.removeAttribute(name);
  }
  
  @Override
  public Attr getAttributeNode(String name)
  {
    return mElement.getAttributeNode(name);
  }
  
  @Override
  public Attr setAttributeNode(Attr newAttr) throws DOMException
  {
    return mElement.setAttributeNode(newAttr);
  }
  
  @Override
  public Attr removeAttributeNode(Attr oldAttr) throws DOMException
  {
    return mElement.removeAttributeNode(oldAttr);
  }
  
  @Override
  public NodeList getElementsByTagName(String name)
  {
    return mElement.getElementsByTagName(name);
  }
  
  @Override
  public String getAttributeNS(String namespaceURI, String localName) throws DOMException
  {
    return mElement.getAttributeNS(namespaceURI,localName);
  }
  
  @Override
  public void setAttributeNS(String namespaceURI, String qualifiedName, String value) throws DOMException
  {
    mElement.setAttributeNS(namespaceURI,qualifiedName,value);
  }
  
  @Override
  public void removeAttributeNS(String namespaceURI, String localName) throws DOMException
  {
    mElement.removeAttributeNS(namespaceURI,localName);
  }
  
  @Override
  public Attr getAttributeNodeNS(String namespaceURI, String localName) throws DOMException
  {
    return mElement.getAttributeNodeNS(namespaceURI,localName);
  }
  
  @Override
  public Attr setAttributeNodeNS(Attr newAttr) throws DOMException
  {
    return mElement.setAttributeNodeNS(newAttr);
  }
  
  @Override
  public NodeList getElementsByTagNameNS(String namespaceURI, String localName) throws DOMException
  {
    return mElement.getElementsByTagNameNS(namespaceURI, localName);
  }
  
  @Override
  public boolean hasAttribute(String name)
  {
    return mElement.hasAttribute(name);
  }
  
  @Override
  public boolean hasAttributeNS(String namespaceURI, String localName) throws DOMException
  {
    return mElement.hasAttributeNS(namespaceURI, localName);
  }
  
  @Override
  public TypeInfo getSchemaTypeInfo()
  {
    return mElement.getSchemaTypeInfo();
  }
  
  @Override
  public void setIdAttribute(String name, boolean isId) throws DOMException
  {
    mElement.setIdAttribute(name, isId);
  }
  
  @Override
  public void setIdAttributeNS(String namespaceURI, String localName, boolean isId) throws DOMException
  {
    mElement.setIdAttributeNS(namespaceURI, localName, isId);
  }
  
  @Override
  public void setIdAttributeNode(Attr idAttr, boolean isId) throws DOMException
  {
    mElement.setIdAttributeNode(idAttr,isId);
  }
  
}
