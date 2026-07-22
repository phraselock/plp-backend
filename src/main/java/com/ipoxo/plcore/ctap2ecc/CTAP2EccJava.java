package com.ipoxo.plcore.ctap2ecc;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidParameterSpecException;

import com.ipoxo.plcore.lib.FCOEM;
import com.ipoxo.plcore.lib.Log;
import com.ipoxo.plcore.phraselock.PLPrivDefs;

import javax.crypto.KeyAgreement;


public class CTAP2EccJava
{
  public static final String CBC_PADDING = "AES/CBC/PKCS5Padding";
  public static final String ECB_PADDING = "AES/ECB/NoPadding";

  ECPrivateKey privateKey;
  ECPublicKey publicKey;

  public static class EccPoint
  {
    public byte[] x;
    public byte[] y;

    public EccPoint(byte[] x, byte[] y)
    {
      this.x = x;
      this.y = y;
    }
  }

  public void initKey(byte[] d)
  {
    try
    {
      privateKey = rawToEncodedECPrivateKey("EC", d);
    } catch (Exception ignored) {}
  }

  public void initKey(byte[] x, byte[] y)
  {
    try
    {
      publicKey = rawToEncodedECPublicKey("EC", x, y);
    } catch (Exception ignored) {}
  }
  
  public void initKey(byte[] x, byte[] y, byte[] d)
  {
    try
    {
      privateKey = rawToEncodedECPrivateKey("EC", d);
      publicKey = rawToEncodedECPublicKey("EC", x, y);
    } catch (Exception ignored) {}
  }

  public static byte[] getSHA256(byte[] data, int len)
  {
    MessageDigest SHA256 = null;
    try
    {
      SHA256 = MessageDigest.getInstance("SHA-256");
    } catch (Exception ignored) {}
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
    } catch (Exception ignored) {}
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
    } catch (Exception ignored) {}
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
    } catch (Exception ignored) {}
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
    } catch (Exception ignored) {}
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

  public static KeyPair ecc_make_key()
  {
    try
    {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
      kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
      return kpg.generateKeyPair();
    } catch (Exception ignored) {}
    return null;
  }
  
  public byte[] dhExchangeWithRawPeer(boolean revertSecret, byte[] privD, byte[] peerX, byte[] peerY)
  {
    ECPrivateKey privKey = CTAP2EccJava.rawToEncodedECPrivateKey("EC", privD);
    ECPublicKey publKey = CTAP2EccJava.rawToEncodedECPublicKey("EC", peerX, peerY);
    return CTAP2EccJava.ecdh_shared_secret(privKey, publKey);
  }
  
  public static byte[][] createECCKeyASN()
  {
    KeyPair keyPair = CTAP2EccJava.ecc_make_key();
    byte[] ans1PrivKey = CTAP2EccJava.derECPrivateKey2Raw((ECPrivateKey) keyPair.getPrivate());
    byte[][] ans1PublKey = CTAP2EccJava.derECPublicKey2Raw((ECPublicKey) keyPair.getPublic());
    return new byte[][]{ans1PrivKey, ans1PublKey[0], ans1PublKey[1]};
  }
  
  public static byte[] ecdh_shared_secret(ECPrivateKey privateKey, ECPublicKey publicKey)
  {
    try {
      KeyAgreement kaD = KeyAgreement.getInstance("ECDH");
      kaD.init(privateKey);
      kaD.doPhase(publicKey, true);
      return kaD.generateSecret();
    } catch (Exception ignored) {}
    return null;
  }

}

