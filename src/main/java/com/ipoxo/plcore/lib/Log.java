package com.ipoxo.plcore.lib;

import com.fasterxml.jackson.databind.ObjectMapper;

public class Log
{
  private static final ObjectMapper MAPPER = new ObjectMapper();

  private static String ts()
  {
    return java.time.LocalDateTime.now()
      .format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS"));
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
