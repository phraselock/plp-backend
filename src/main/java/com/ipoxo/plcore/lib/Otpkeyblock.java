package com.ipoxo.plcore.lib;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;

import com.ipoxo.plcore.ctap2ecc.CTAP2EccJava.EccPoint;
import com.ipoxo.plcore.phraselock.PLPrivDefs;

public class Otpkeyblock extends Object
{
  
  public class Keyblock
  {
    public byte[] serviceUUID = new byte[16];
    public byte[] priv = new byte[PLPrivDefs.BASE_32_BYTE_SIZE];
    public byte[] publ = new byte[2 * PLPrivDefs.BASE_32_BYTE_SIZE];
    
    public void createFromByteArray(byte[] keydata)
    {
      if (keydata != null && keydata.length == this.sizeof()) {
        ByteBuffer bb = ByteBuffer.wrap(keydata);
        
        bb.get(serviceUUID);
        bb.get(priv);
        bb.get(publ);
      }
    }
    
    public EccPoint getPublicKeyAsEccPoint()
    {
      ByteBuffer bb = ByteBuffer.wrap(publ);
      byte[] x = new byte[PLPrivDefs.BASE_32_BYTE_SIZE];
      byte[] y = new byte[PLPrivDefs.BASE_32_BYTE_SIZE];
      bb.get(x);
      bb.get(y);
      return new EccPoint(x, y);
    }
    
    public byte[] serialize()
    {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      try {
        baos.write(serviceUUID);
        baos.write(priv);
        baos.write(publ);
      } catch (Exception e) {
        return null;
      }
      return baos.toByteArray();
    }
    
    public int sizeof()
    {
      return serviceUUID.length + priv.length + publ.length;
    }
  }
  
  public Integer crc;
  public Integer reservedFF;
  public Keyblock keyblock = new Keyblock();
  
  public byte[] serialize()
  {
    int bbs = sizeof();
    ByteBuffer bb = ByteBuffer.allocate(bbs);
    
    bb.putInt(crc);
    bb.putInt(reservedFF);
    bb.put(keyblock.serialize());
    
    return bb.array();
  }
  
  public int sizeof()
  {
    return crc.BYTES + reservedFF.BYTES + keyblock.sizeof();
  }
  
}
