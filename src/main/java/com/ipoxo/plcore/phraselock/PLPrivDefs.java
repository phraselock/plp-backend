package com.ipoxo.plcore.phraselock;

public interface PLPrivDefs
{
  public static final char BASE_32_BYTE_SIZE = 32;
  
  /* Client Characteristic Configuration Descriptor */
  public final static String CCCD                     = "00002902-0000-1000-8000-00805f9b34fb";
  /* Characteristic User Description - Unused so far! */
  public final static String CCUD                     = "00002901-0000-1000-8000-00805f9b34fb";
  
  /* -------- PL-Protocol Characteristics -------- */
  /* Notification (Receive) Characteristic */
  public static final String UUID_PLP_INDICATION      = "AC6E2E38-CAF1-4916-B7EB-012DBD22AE4E";
  /* Read Characteristic Plain */
  public static final String UUID_PLP_READ            = "BD73F901-C8A5-4C6B-BB95-7CA2E02EB4FA";
  /* Read Characteristic Encrypted */
  public static final String UUID_PLP_READ_ENC        = "CF0D078F-398A-4344-9EBD-5C599618ADB3";
  
  /* -------- SUOTA Protocol Characteristics -------- */
  public static final String UUID_SUOTA_STATUS        = "5F78DF94-798C-46F5-990A-B3EB6A065C88";
  
  /* -------- CC2540 Protocol Characteristics -------- */
  public static final String BLE_DEVICE_NOTIFY_UUID   = "00007AA1-0000-1000-8000-00805F9B34FB";
  public static final String BLE_DEVICE_WRITE_UUID    = "00007AA9-0000-1000-8000-00805F9B34FB";
  
   /* -------- Phrase-Lock commands -------- */
  public final static byte OPCODE_HID_DATA_AUTO = (byte) 0x8A;    // Automatic mode
  public static final byte HID_PROTOCOL_SIZE = 8;  // Fixed for keyboard, mouse & co.
  
  /* -------- Timeout for BLE connection -------- */
  public static final long CONNECT_TIMEOUT_BLE = (6 *1000); //10000;
  
  /* -------- Timeout for MQTT connection -------- */
  public static final long CONNECT_TIMEOUT_MQTT = (2 *1000); //35000;

  /* -------- You may use different receiver to filter messages coming from the USB-Key. -------- */
  public static final byte RECV_HID = (byte) 0x02;
}
