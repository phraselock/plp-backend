package com.ipoxo.plcore.lib;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringReader;
import java.io.StringWriter;

public class Log
{
  private static final ObjectMapper MAPPER = new ObjectMapper();

  private static String ts()
  {
    return java.time.LocalDateTime.now()
      .format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS"));
  }

  /** Pretty-prints a JSON string or object; falls back to String.valueOf on error. */
  public static String json(Object value)
  {
    try
    {
      Object target = (value instanceof String s) ? MAPPER.readValue(s, Object.class) : value;
      return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(target);
    }
    catch (Exception e)
    {
      return String.valueOf(value);
    }
  }

  /** Pretty-prints an XML string or Document; falls back to String.valueOf on error. */
  public static String xml(Object value)
  {
    try
    {
      DOMSource source;
      if (value instanceof String s)
      {
        Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder()
          .parse(new InputSource(new StringReader(s)));
        source = new DOMSource(doc);
      }
      else if (value instanceof Document doc)
      {
        source = new DOMSource(doc);
      }
      else
      {
        return String.valueOf(value);
      }

      var transformer = TransformerFactory.newInstance().newTransformer();
      transformer.setOutputProperty(OutputKeys.INDENT,   "yes");
      transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
      transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");

      StringWriter writer = new StringWriter();
      transformer.transform(source, new StreamResult(writer));
      return writer.toString();
    }
    catch (Exception e)
    {
      return String.valueOf(value);
    }
  }

  static public void e(String filter, String msg)
  {
    System.err.println(ts() + " E " + filter + ": " + msg);
  }
  static public void e(String msg)
  {
    System.err.println(ts() + " E " + msg);
  }

  static public void i(String filter, String msg)
  {
    System.out.println(ts() + " I " + filter + ": " + msg);
  }
  static public void i(String msg)
  {
    System.out.println(ts() + " I " + msg);
  }

  static public void d(String filter, String msg)
  {
    System.out.println(ts() + " D " + filter + ": " + msg);
  }
  static public void d(String msg)
  {
    System.out.println(ts() + " D " + msg);
  }

}
