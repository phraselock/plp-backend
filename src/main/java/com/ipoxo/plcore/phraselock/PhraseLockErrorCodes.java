package com.ipoxo.plcore.phraselock;

public interface PhraseLockErrorCodes
{
  
  /*
   * Error-Codes
   */
  public static final char ERROR_NO = 0x00;
  
  public static final char ERROR_ECDH_9A = 0x1A;
  public static final char ERROR_AES_PROTOCOLL_SEL = 0x1B;
  
  public static final char ERROR_ECDH_MASK = 0x0F;
  
  public static final char ERROR_RANDOM = 0xA0;
  public static final char ERROR_KEYGEN = 0xA1;
  public static final char ERROR_IVGEN = 0xA2;
  public static final char ERROR_PEER_SIGNATUR = 0xA3;
  public static final char ERROR_SIGNATUR_CALC = 0xA4;
  public static final char ERROR_INVALID_API_KEY = 0xA5;
  public static final char ERROR_INVALID_RW_LEN = 0xA6;
  public static final char ERROR_INVALID_RW_CRC = 0xA7;
  
  public static final char ERROR_NVM_NO_VALID_PARTITION = 0xC1;
  public static final char ERROR_NVM_RW_OVERFLOW = 0xC2;
  public static final char ERROR_NVM_OPEN_PART = 0xC3;
  public static final char ERROR_NVM_RW_FAILED = 0xC4;
  public static final char ERROR_NVM_RW_VERFIY = 0xC5;
  
  public static final char ERROR_U_IMG_UNKNOWN = 0xE0;
  public static final char ERROR_U_IMG_ERASE = 0xE1;
  public static final char ERROR_U_IMG_INVALIDE = 0xE2;
  public static final char ERROR_U_IMG_OPEN_PART = 0xE3;
  public static final char ERROR_U_IMG_EQUAL = 0xE4;
  public static final char ERROR_U_IMG_MALLOC_RW = 0xE5;
  public static final char ERROR_U_IMG_COPYING_R = 0xE6;
  public static final char ERROR_U_IMG_COPYING_W = 0xE7;
  public static final char ERROR_U_IMG_WRONG_CMD = 0xE8;
  public static final char ERROR_U_IMG_CPY_DENIED = 0xE9;
  
  public static final char ERROR_OTP_KEY_WRITE = 0xD0;
  public static final char ERROR_OTP_KEY_READ = 0xD0;
  public static final char ERROR_OTP_KEY_CRC = 0xD1;
  public static final char ERROR_OTP_KEY_EXISTS = 0xD2;
  
  public static final char ERROR_UNINST_PART = 0xEE;
  public static final char ERROR_UNINST_ERASE = 0xEF;
  
  public static final char ERROR_DATA_RW = 0xF1;
  
  public static final char ERROR_MTU_TOO_SMALL = 0xFD;
  public static final char ERROR_UNSUPPORTED = 0xFE;
  public static final char ERROR_UNKNOWN = 0xFF;
  
}
