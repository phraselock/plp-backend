package com.ipoxo.plcore.lib;

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;

public class Configuration {
  
  // Vormals DB.java
  public static String DBGLEVEL     = "PLNK_DEBUG";
  
  // Steuert das Logging
  public static boolean DBLIFECYCLE = false;
  public static boolean DEBUG_DEBUG = true;
  public static boolean DBFULLBLE   = DEBUG_DEBUG;
  public static boolean DBGEN       = DEBUG_DEBUG;
  public static boolean DBAFC       = DEBUG_DEBUG;
  
  
  public static long FORCE_DEBUG			    = 0x00000001;		  /* Forcing some output in debug-mode only */
	
	public static long LOG_PL	              = 0x00000002;		  /* Logging PhraseLock.m */
	public static long LOG_FDO_RW           = 0x00000004;   	/* Logging of CTAP1/CTAP2 Messages */
	public static long LOG_KEYS             = 0x00000008;   	/* Logging of keys exchanged! Do not set in release-versions!!! */
	
	public static long LOG_CTAP             = 0x00000010;   	/* Deep logging of CTAP1/CTAP2 communication */
	public static long LOG_CBOR             = 0x00000020;   	/* Deep logging of CBOR */
	public static long LOG_DMP              = 0x00000040;   	/* Deep logging of dumps */
	
	public static long LOG_INIT             = 0x00000080;		  /* Logging of BLE init-prozess */
	public static long LOG_BLE_RW           = 0x00000100;   	/* Extended logging of BLE communication */
	public static long LOG_DGB_BLE          = 0x00000200;   	/* Logging of full BLE communication */
	public static long LOG_DGB_BLE_FINE     = 0x00000400;	  	/* Deep logging of BLE communication */


}