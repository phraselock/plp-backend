package com.ipoxo.plcore.ctap2ecc;
/*
import android.annotation.SuppressLint;
import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.util.Base64;
import android.util.Log;
*/
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.ipoxo.plcore.lib.FCOEM;
import com.ipoxo.plcore.lib.Log;

import com.ipoxo.plcore.phraselock.PLPrivDefs;

import javax.crypto.KeyAgreement;
import javax.naming.Context;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;


public class CTAP2EccJava
{
  public static final String DEFAULT_KEY_STORE = "AndroidKeyStore";
  public static final String PL_KS_KEY = "com.phraselock.app.kskey";
  public static final String PL_DEV_UNIQUE_ID = "com.phraselock.app.device.id";
  public static final String USBKEY_PREFIX = "USBLTC";
  public static final String USERAUTHENTICATION = "USERAUTHENTICATION";
  public static final String DEVICE_ID_ECCKEY = "DEVICE_ID_ECCKEY";
  //public static final String lettersAlphabet = "abcdefghijklmnopqrstuvwxyz";
  public static final String lettersAlphabet   = "abcdefghijkmnopqrstuvwxyz";
  //public static final String capitalsAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  public static final String capitalsAlphabet   = "ABCDEFGHJKLMNPQRSTUVWXYZ";
  public static final String digitsAlphabet = "0123456789";
  public static final String symbolsAlphabet = "!@[#$)%*];?(";
  //public static final String CBC_PADDING = "AES/CBC/PKCS7Padding"; // Funktioniert nur auf Android
  public static final String CBC_PADDING = "AES/CBC/PKCS5Padding";
  public static final String ECB_PADDING = "AES/ECB/NoPadding";
  
  /**
   * Wir auf Android nicht gebraucht. Client-Certs werden nur über die EKU in der KeyChain organisiert.
   * Leider funktioniert das nicht so wie ich wollte. Aber um die Code-Logik beizubehalten, ist es
   * implementiert wie für iOS und Mac.
   */
  /*
  public static final String PLP_CLIENT_CERT_KEY_A  = "com.phraselock.ck.a";  // Client Private-Key phraselock.net
  public static final String PLP_CLIENT_CERT_KEY_B  = "com.phraselock.ck.b";  // Client Private-Key phraselock.org
  public static final String PLP_CLIENT_CERT_KEY_C  = "com.phraselock.ck.c";  // Client Private-Key Primärer MQTT Server auf .org:8883
  public static final String PLP_CLIENT_CERT_KEY_D  = "com.phraselock.ck.d";  // Client Private-Key Custom
  
  public static final String PLP_CLIENT_CERT_PEM_A   = "com.phraselock.cc.a";  // Client-Cert phraselaock.net
  public static final String PLP_CLIENT_CERT_PEM_B   = "com.phraselock.cc.b";  // Client-Cert phraselaock.org
  public static final String PLP_CLIENT_CERT_PEM_C   = "com.phraselock.cc.c";  // Client-Cert Primärer MQTT Server auf .org:8883
  public static final String PLP_CLIENT_CERT_PEM_D   = "com.phraselock.cc.d";  // Client-Cert Primärer Custom
  */
  
  public static final String PLP_EKU_OID_A = "1.3.6.1.4.1.59269.100.10";   // EKU-OID phraselock.net
  public static final String PLP_EKU_OID_B = "1.3.6.1.4.1.59269.100.11";   // EKU-OID phraselock.org
  public static final String PLP_EKU_OID_C = "1.3.6.1.4.1.59269.100.12";   // EKU-OID Primärer MQTT Server auf .org:8883
  public static final String PLP_EKU_OID_D = "1.3.6.1.4.1.59269.100.13";   // EKU-OID Custom
  
  public static final String PLP_CLIENT_CERT_EXT   = ".CLIENTCERT";  // Client-Cert Primärer Custom
  public static final String PLP_CLIENT_CERT_PEM   = ".PEM";  // Client-Cert Primärer Custom
  
  X509Certificate derCert;
  byte[] p12PrivCert;
  byte[] derPublCert;
  String certPWD;
  
  ECPrivateKey privateKey;
  ECPublicKey publicKey;
  ECPoint ecp;
  
  String eccpD;
  String eccpX;
  String eccpY;
  
  public static class EccPoint
  {
    public EccPoint()
    {
    }
    
    public EccPoint(byte[] x, byte[] y)
    {
      this.x = x;
      this.y = y;
    }
    
    public byte[] x = new byte[PLPrivDefs.BASE_32_BYTE_SIZE];
    public byte[] y = new byte[PLPrivDefs.BASE_32_BYTE_SIZE];
    
    int sizeof()
    {
      return x.length + y.length;
    }
    
    public byte[] serialize()
    {
      ByteBuffer bb = ByteBuffer.wrap(new byte[sizeof()]);
      bb.put(x);
      bb.put(y);
      return bb.array();
    }
    
    public byte[] serializeRev()
    {
      ByteBuffer bb = ByteBuffer.wrap(new byte[sizeof()]);
      bb.put(FCOEM.revertByteArray(x));
      bb.put(FCOEM.revertByteArray(y));
      return bb.array();
    }
  }
  
  public static boolean isIVValid(byte[] iv)
  {
    if (iv == null)
    {
      return false;
    }
    for (byte b : iv)
    {
      if (b > 0)
      {
        return true;
      }
    }
    return false;
  }
  
  public static int encryptAES256(byte[] aeskey, byte[] iv, byte[] data, int len)
  {
    Cipher cipherEnc = null;
    Cipher cipherDec = null;
    try
    {
      // CBC-Mode
      if (isIVValid(iv))
      {
        SecretKeySpec skeySpec = new SecretKeySpec(aeskey, "AES");
        cipherEnc = Cipher.getInstance("AES/CBC/PKCS7Padding");
        cipherEnc.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(iv));
        cipherDec = Cipher.getInstance("AES/CBC/PKCS7Padding");
        cipherDec.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(iv));
        // ECB-Mode
      }
      else
      {
        SecretKeySpec skeySpec = new SecretKeySpec(aeskey, "AES");
        cipherEnc = Cipher.getInstance("AES/ECB/NoPadding");
        cipherEnc.init(Cipher.ENCRYPT_MODE, skeySpec);
        cipherDec = Cipher.getInstance("AES/ECB/NoPadding");
        cipherDec.init(Cipher.DECRYPT_MODE, skeySpec);
      }
    } catch (Exception e)
    {
      return 0;
    }
    
    int resLen = 0;
    try
    {
      resLen = cipherEnc.doFinal(data, 0, len, data);
      return resLen;
    } catch (Exception e)
    {
      return resLen;
    }
  }
  

  public static int decryptAES256(byte[] aeskey, byte[] iv, byte[] data, int len)
  {
    Cipher cipherEnc = null;
    Cipher cipherDec = null;
    try
    {
      // CBC-Mode
      if (isIVValid(iv))
      {
        SecretKeySpec skeySpec = new SecretKeySpec(aeskey, "AES");
        cipherEnc = Cipher.getInstance("AES/CBC/PKCS7Padding");
        cipherEnc.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(iv));
        cipherDec = Cipher.getInstance("AES/CBC/PKCS7Padding");
        cipherDec.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(iv));
        // ECB-Mode
      }
      else
      {
        SecretKeySpec skeySpec = new SecretKeySpec(aeskey, "AES");
        cipherEnc = Cipher.getInstance("AES/ECB/NoPadding");
        cipherEnc.init(Cipher.ENCRYPT_MODE, skeySpec);
        cipherDec = Cipher.getInstance("AES/ECB/NoPadding");
        cipherDec.init(Cipher.DECRYPT_MODE, skeySpec);
      }
    } catch (Exception ignored)
    {
      return 0;
    }
    
    int resLen = 0;
    try
    {
      resLen = cipherDec.doFinal(data, 0, len, data);
      return resLen;
    } catch (Exception e)
    {
      return resLen;
    }
  }
  
  public void initWithCerts(byte[] p12PrivCert, byte[] derPublCert, String certPWD)
  {
    this.p12PrivCert = p12PrivCert;
    this.derPublCert = derPublCert;
    this.certPWD = certPWD;
    
    KeyStore keyStore = null;
    try
    {
      keyStore = KeyStore.getInstance("PKCS12");
      keyStore.load(new ByteArrayInputStream(p12PrivCert), certPWD.toCharArray());
      
      String certificateAlias = keyStore.aliases().nextElement();
      derCert = (X509Certificate) keyStore.getCertificate(certificateAlias);
      
      // Retrieving the private key.
      KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(
        certificateAlias,
        new KeyStore.PasswordProtection(certPWD.toCharArray())
      );
      
      privateKey = (ECPrivateKey) privateKeyEntry.getPrivateKey();
      publicKey = (ECPublicKey) derCert.getPublicKey();
      ecp = publicKey.getW();
      
      eccpD = privateKey.getS().toString(16);
      eccpX = ecp.getAffineX().toString(16);
      eccpY = ecp.getAffineY().toString(16);
      
    } catch (Exception ignored)
    {
    }
  }
  
  public void resetCert()
  {
    //resetSHABuffer();
    privateKey = null;
    publicKey = null;
  }
  
  public boolean isInitialized()
  {
    return privateKey != null;
  }
  
  public boolean initKey(byte[] d)
  {
    try
    {
      privateKey = rawToEncodedECPrivateKey("EC", d);
      return true;
    } catch (Exception ignored)
    {
    }
    return false;
  }
  
  public boolean initKey(byte[] x, byte[] y)
  {
    try
    {
      publicKey = rawToEncodedECPublicKey("EC", x, y);
      return true;
    } catch (Exception ignored)
    {
    }
    return false;
  }
  
  public boolean initKey(byte[] x, byte[] y, byte[] d)
  {
    try
    {
      privateKey = rawToEncodedECPrivateKey("EC", d);
      publicKey = rawToEncodedECPublicKey("EC", x, y);
      return true;
    } catch (Exception ignored)
    {
    }
    return false;
  }
  
  public byte[] exportPublCertDer()
  {
    try
    {
      return derCert.getEncoded();
    } catch (Exception ignored)
    {
    }
    return null;
  }
  
  public static byte[] getSHA256(byte[] data, int len)
  {
    MessageDigest SHA256 = null;
    try
    {
      SHA256 = MessageDigest.getInstance("SHA-256");
    } catch (Exception ignored)
    {
    }
    SHA256.reset();
    return SHA256.digest(data);
  }
  
  public static byte[] generateRandom(int amount)
  {
    byte[] random = new byte[amount];
    SecureRandom srandom = new SecureRandom();
    byte[] seed = srandom.generateSeed(PLPrivDefs.BASE_32_BYTE_SIZE);
    srandom.setSeed(seed);
    for (int i = 0; i < amount; i++)
    {
      random[i] = (byte) srandom.nextInt();
    }
        /* Nur für Testzwecke
        for(int i=0;i<amount;i++){
            random[i] = (byte) (0xFF & i+1);
        }
        */
    return random;
  }
  
  public static ECParameterSpec ecParameterSpecForCurve(String algol, String curveName) throws NoSuchAlgorithmException, InvalidParameterSpecException
  {
    AlgorithmParameters params = AlgorithmParameters.getInstance(algol);
    params.init(new ECGenParameterSpec(curveName));
    return params.getParameterSpec(ECParameterSpec.class);
  }
  
  public static ECPrivateKey rawToEncodedECPrivateKey(String algol, byte[] p)
  {
    try
    {
      KeyFactory kf = KeyFactory.getInstance(algol);
      ECParameterSpec ecParam = ecParameterSpecForCurve(algol, "secp256r1");
      ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(new BigInteger(1, p), ecParam);
      return (ECPrivateKey) kf.generatePrivate(ecPrivateKeySpec);
    } catch (Exception ignored)
    {
    }
    return null;
  }
  
  public static ECPublicKey rawToEncodedECPublicKey(String algol, byte[] x, byte[] y)
  {
    try
    {
      KeyFactory kf = KeyFactory.getInstance(algol);
      ECPoint w = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
      ECParameterSpec ecParam = ecParameterSpecForCurve(algol, "secp256r1");
      ECPublicKeySpec keySpec = new ECPublicKeySpec(w, ecParam);
      return (ECPublicKey) kf.generatePublic(keySpec);
    } catch (Exception ignored)
    {
    }
    return null;
  }
  
  public static byte[][] derECPublicKey2Raw(ECPublicKey derPublicKey)
  {
    try
    {
      byte[] baX = FCOEM.revertByteArray(derPublicKey.getW().getAffineX().toByteArray());
      byte[] baY = FCOEM.revertByteArray(derPublicKey.getW().getAffineY().toByteArray());
      byte[][] bx = {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
      System.arraycopy(baX, 0, bx[0], 0, baX.length <= PLPrivDefs.BASE_32_BYTE_SIZE ? baX.length : PLPrivDefs.BASE_32_BYTE_SIZE);
      System.arraycopy(baY, 0, bx[1], 0, baY.length <= PLPrivDefs.BASE_32_BYTE_SIZE ? baY.length : PLPrivDefs.BASE_32_BYTE_SIZE);
      bx[0] = FCOEM.revertByteArray(bx[0]);
      bx[1] = FCOEM.revertByteArray(bx[1]);
      /* Nur zu Testzwecken */
      ECPublicKey publicKey = CTAP2EccJava.rawToEncodedECPublicKey("EC", bx[0], bx[1]);
      if (publicKey == null)
      {
        return null;
      }
      return bx;
    } catch (Exception ignored)
    {
    }
    return null;
  }
  
  public static byte[] derECPrivateKey2Raw(ECPrivateKey derPriateKey)
  {
    try
    {
      byte[] bb = FCOEM.revertByteArray(derPriateKey.getS().toByteArray());
      byte[] bp = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
      System.arraycopy(bb, 0, bp, 0, bb.length <= PLPrivDefs.BASE_32_BYTE_SIZE ? bb.length : PLPrivDefs.BASE_32_BYTE_SIZE);
      bp = FCOEM.revertByteArray(bp);
      /* Nur zu Testzwecken */
      ECPrivateKey priateKey = CTAP2EccJava.rawToEncodedECPrivateKey("EC", bp);
      if (priateKey == null)
      {
        return null;
      }
      return bp;
    } catch (Exception ignored)
    {
    }
    return null;
  }
  
  public static byte[] revertByteArray(byte[] data)
  {
    byte[] tmp = new byte[data.length];
    for (int i = 0; i < data.length; i++)
    {
      tmp[i] = data[data.length - 1 - i];
    }
    return tmp;
  }
  
  public static boolean ecc_valid_public_key(ECPublicKey publicUSBKey)
  {
    if (publicUSBKey != null)
    {
      return true;
    }
    return false;
  }
  
  public static byte[] ecdsa_sign(byte[] privKey, byte[] rand, byte[] phash)
  {
    try
    {
      Signature ecdsaSign = Signature.getInstance("NONEwithECDSA");
      PrivateKey privateKeyTmp = rawToEncodedECPrivateKey("EC", revertByteArray(privKey));
      ecdsaSign.initSign(privateKeyTmp, new SecureRandom(rand));
      ecdsaSign.update(phash);
      byte[] signature = ecdsaSign.sign();
      if (signature != null)
      {
        //if (Configuration.DBGEN) Log.d(Configuration.DBGLEVEL, "CTAP2EccJava Signature: " + FCOEM.byteArrayToHexString(signature));
        return signature;
      }
    } catch (Exception ignored)
    {
    }
    return null;
  }
  
  public byte[] sign(byte[] rand, byte[] sha256)
  {
    try
    {
      Signature ecdsaSign = Signature.getInstance("NONEwithECDSA");
      ecdsaSign.initSign(privateKey, new SecureRandom(rand));
      ecdsaSign.update(sha256);
      byte[] signature = ecdsaSign.sign();
      if (signature != null)
      {
        return signature;
      }
    } catch (Exception ignored)
    {
    }
    return null;
  }
  
  public boolean verify(byte[] signature, byte[] sha256)
  {
    boolean bres = false;
    try
    {
      Signature ecdsaVerify = Signature.getInstance("NONEwithECDSA");
      ecdsaVerify.initVerify(publicKey);
      ecdsaVerify.update(sha256);
      bres = ecdsaVerify.verify(signature);
    } catch (Exception e)
    {
      Log.e("PLNK_DEBUG","Exception: verify: "+e.getMessage());
    }
    return bres;
  }
  
  public static boolean verifyWithPublKey(byte[] Ux, byte[] Uy, byte[] signature, byte[] sha256)
  {
    boolean bres = false;
    try
    {
      CTAP2EccJava.EccPoint pubKey = new CTAP2EccJava.EccPoint(Ux, Uy);
      Signature ecdsaVerify = Signature.getInstance("NONEwithECDSA");
      
      PublicKey publicKey = CTAP2EccJava.rawToEncodedECPublicKey("EC",
        pubKey.x,
        pubKey.y);
      
      ecdsaVerify.initVerify(publicKey);
      ecdsaVerify.update(sha256);
      bres = ecdsaVerify.verify(signature);
    } catch (Exception ignored)
    {
    }
    return bres;
  }
  
  public static KeyPair ecc_make_key()
  {
    try
    {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
      kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
      KeyPair keyPair = kpg.generateKeyPair();
      return keyPair;
    } catch (Exception ignored)
    {
    }
    return null;
  }
  
  public byte[] dhExchangeWithRawPeer(boolean revertSecret, byte[] peerX, byte[] peerY)
  {
    ECPublicKey publKey = CTAP2EccJava.rawToEncodedECPublicKey("EC", peerX, peerY);
    byte[] nsSharedSecret = CTAP2EccJava.ecdh_shared_secret(privateKey, publKey);
    return nsSharedSecret;
  }
  
  public byte[] dhExchangeWithRawPeer(boolean revertSecret, byte[] privD, byte[] peerX, byte[] peerY)
  {
    ECPrivateKey privKey = CTAP2EccJava.rawToEncodedECPrivateKey("EC", privD);
    ECPublicKey publKey = CTAP2EccJava.rawToEncodedECPublicKey("EC", peerX, peerY);
    byte[] nsSharedSecret = CTAP2EccJava.ecdh_shared_secret(privKey, publKey);
    return nsSharedSecret;
  }
  
  public static byte[][] createECCKeyASN()
  {
    KeyPair keyPair = CTAP2EccJava.ecc_make_key();
    ECPrivateKey privKey = (ECPrivateKey) keyPair.getPrivate();
    ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
    byte[] ans1PrivKey = CTAP2EccJava.derECPrivateKey2Raw((ECPrivateKey) keyPair.getPrivate());
    byte[][] ans1PublKey = CTAP2EccJava.derECPublicKey2Raw((ECPublicKey) keyPair.getPublic());
    byte[][] r = {ans1PrivKey, ans1PublKey[0], ans1PublKey[1]};
    return r;
  }
  
  public static byte[] ecdh_shared_secret(ECPrivateKey privateKey, ECPublicKey publicKey)
  {
    try {
      KeyAgreement kaD = KeyAgreement.getInstance("ECDH");
      kaD.init(privateKey);
      kaD.doPhase(publicKey, true);
      byte[] sharedSecret = kaD.generateSecret();
      return sharedSecret;
    } catch (Exception ignored)
    {
    }
    return null;
  }



  public static byte[] raw32ToPkcs8(byte[] raw32)
  {
    try
    {
      BigInteger spec = new BigInteger(1, raw32);
      // EC Parameter für secp256r1
      AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
      params.init(new ECGenParameterSpec("secp256r1"));
      ECParameterSpec ecSpec = params.getParameterSpec(ECParameterSpec.class);
      // PrivateKeySpec bauen
      ECPrivateKeySpec privSpec = new ECPrivateKeySpec(spec, ecSpec);
      // KeyFactory erzeugt PKCS#8
      KeyFactory kf = KeyFactory.getInstance("EC");
      PrivateKey pk = kf.generatePrivate(privSpec);
      return pk.getEncoded(); // PKCS#8 DER
    }catch (Exception e) {
      Log.e("PLNK_DEBUG","Exception: raw32ToPkcs8: "+e.getMessage());
    }
    return null;
  }

} // public class CTAP2EccJava

