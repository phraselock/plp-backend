package com.ipoxo.lib;

import com.ipoxo.plcore.ctap2ecc.CTAP2EccJava;
import com.ipoxo.plcore.lib.FCOEM;
import com.ipoxo.plcore.lib.Log;

import org.json.JSONObject;
import plp.handler.MqttService;
import java.util.*;

public class PeerCom
{
  final public static  String pfxPEER = "PEER-";
  final public static  String pfxBES  = "BES-";

  /* KDBX */
  final public static String MQTT_PEER_DATA_REQUEST_KDBX       = "peer_data_request_kdbx";
  final public static String MQTT_PEER_DATA_RESPONSE_KDBX      = "peer_data_response_kdbx";

  final public static String MQTT_SKEY_NEGO_REQUEST_KDBX       = "skey_nego_request_kdbx";
  final public static String MQTT_SKEY_NEGO_RESPONSE_KDBX      = "skey_nego_response_kdbx";

  final public static String MQTT_FULL_SYNC_REQUEST_KDBX       = "full_sync_request_kdbx";

  final public static String MQTT_ENC_PAYLOAD_KDBX             = "enc_payload_kdbx";
  final public static String MQTT_ENC_PAYLOAD_NEXT_KDBX        = "enc_payload_next_kdbx";
  final public static String MQTT_ACK_PAYLOAD_KDBX             = "ack_payload_kdbx";

  /* Psono */
  final public static String MQTT_PEER_DATA_REQUEST_PSONO       = "peer_data_request_psono";
  final public static String MQTT_PEER_DATA_RESPONSE_PSONO      = "peer_data_response_psono";

  final public static String MQTT_SKEY_NEGO_REQUEST_PSONO       = "skey_nego_request_psono";
  final public static String MQTT_SKEY_NEGO_RESPONSE_PSONO      = "skey_nego_response_psono";

  final public static String MQTT_FULL_SYNC_REQUEST_PSONO       = "full_sync_request_psono";

  final public static String MQTT_ENC_PAYLOAD_PSONO             = "enc_payload_psono";
  final public static String MQTT_ENC_PAYLOAD_NEXT_PSONO        = "enc_payload_next_psono";
  final public static String MQTT_ACK_PAYLOAD_PSONO             = "ack_payload_psono";

  public List<String> credList;
  public byte[] sessionKey;
  public boolean handshakeComplete;
  public int phraseLidx;

  // ---- Singleton Session Store ----
  private static final Map<String, PeerCom> sessionStore = new HashMap<>();

  public static synchronized PeerCom sessionForPeer(String peerId)
  {
    PeerCom peer = sessionStore.get(peerId);
    if (peer == null)
    {
      peer = new PeerCom();
      peer.credList = null;
      peer.sessionKey = null;
      peer.handshakeComplete = false;
      peer.phraseLidx = 0;
      sessionStore.put(peerId, peer);
    }
    return peer;
  }

  public static synchronized void removeSession(String peerId)
  {
    try {
      sessionStore.remove(peerId);
    } catch (Exception ignore)
    {}
  }

  public static byte[] buildPeerDataResponse(String peerAdrGUID, String request, JSONObject response)
  {
    try
    {
      String sd = MqttService.getInstance().getConfig().getProperty("bes.id.dpriv");
      String sx = MqttService.getInstance().getConfig().getProperty("bes.id.xpubl");
      String sy = MqttService.getInstance().getConfig().getProperty("bes.id.ypubl");

      byte[] d = FCOEM.hexStringToByteArray(sd);
      byte[] x = FCOEM.hexStringToByteArray(sx);
      byte[] y = FCOEM.hexStringToByteArray(sy);

      PeerCom.sessionForPeer(peerAdrGUID).sessionKey = null;

      CTAP2EccJava sign_cecc = new CTAP2EccJava();
      sign_cecc.initKey(x, y, d);

      String contentB64 = AESPlnk.b64encode2String(response.toString());

      byte[] hash = CTAP2EccJava.getSHA256(contentB64.getBytes(), contentB64.getBytes().length);
      byte[] sign = sign_cecc.sign(CTAP2EccJava.generateRandom(32), hash);

      boolean isOk = sign_cecc.verify(sign, hash);
      if(isOk)
      {
        JSONObject jsonPackage = new JSONObject();
        jsonPackage.put("peer", peerAdrGUID);
        jsonPackage.put("request", request);
        jsonPackage.put("version", "1");
        jsonPackage.put("hash", FCOEM.byteArrayToHexString(hash));
        jsonPackage.put("signature", FCOEM.byteArrayToHexString(sign));
        jsonPackage.put("content", contentB64);

        return jsonPackage.toString().getBytes();
      }
    } catch (Exception ignore) {}
    return null;
  }

  public static byte[] buildPeerDataRequest(String peerAdrGUID, String serviceUuid, String request)
  {
    try
    {
      String sd = MqttService.getInstance().getConfig().getProperty("bes.id.dpriv");
      String sx = MqttService.getInstance().getConfig().getProperty("bes.id.xpubl");
      String sy = MqttService.getInstance().getConfig().getProperty("bes.id.ypubl");

      byte[] d = FCOEM.hexStringToByteArray(sd);
      byte[] x = FCOEM.hexStringToByteArray(sx);
      byte[] y = FCOEM.hexStringToByteArray(sy);

      PeerCom.sessionForPeer(peerAdrGUID).sessionKey = null;

      CTAP2EccJava sign_cecc = new CTAP2EccJava();
      sign_cecc.initKey(x, y, d);

      JSONObject jsonContent = new JSONObject();
      jsonContent.put("publ_x", sx);
      jsonContent.put("publ_y", sy);
      String contentB64 = AESPlnk.b64encode2String(jsonContent.toString());

      byte[] hash = CTAP2EccJava.getSHA256(contentB64.getBytes(), contentB64.getBytes().length);
      byte[] sign = sign_cecc.sign(CTAP2EccJava.generateRandom(32), hash);

      boolean isOk = sign_cecc.verify(sign, hash);
      if(isOk)
      {
        JSONObject jsonPackage = new JSONObject();
        jsonPackage.put("peer", serviceUuid);
        jsonPackage.put("request", request);
        jsonPackage.put("version", "1");
        jsonPackage.put("hash", FCOEM.byteArrayToHexString(hash));
        jsonPackage.put("signature", FCOEM.byteArrayToHexString(sign));
        jsonPackage.put("content", contentB64);

        return jsonPackage.toString().getBytes();
      }
    } catch (Exception ignore) {}
    return null;
  }

  public static byte[] buildSKeyNegotiationResponse(JSONObject peerDict, JSONObject jsonObject, String serviceUuid, String request)
  {
    if(peerDict!=null && jsonObject !=null)
    {
      try
      {
        String peer = jsonObject.getString("peer");
        String signature = jsonObject.getString("signature");
        String contentb64 = jsonObject.getString("content");

        PeerCom.sessionForPeer(peer).sessionKey = null;

        // Signatur überprüfen
        String peer_publ_x = peerDict.getString("publ_x");
        String peer_publ_y = peerDict.getString("publ_y");
        CTAP2EccJava verify_cecc   = new CTAP2EccJava();
        verify_cecc.initKey(FCOEM.hexStringToByteArray(peer_publ_x),FCOEM.hexStringToByteArray(peer_publ_y));
        byte[] bHash = CTAP2EccJava.getSHA256(contentb64.getBytes(),contentb64.getBytes().length);
        byte[] bSign = FCOEM.hexStringToByteArray(signature);
        boolean bOk = verify_cecc.verify(bSign,bHash);

        if(bOk)
        {
          String contentJSON = AESPlnk.b64decode2String(contentb64);
          JSONObject jsonContent = new JSONObject(contentJSON);
          if(jsonContent!=null)
          {
            byte[][] eccKey = CTAP2EccJava.createECCKeyASN();
            String bX = FCOEM.byteArrayToHexString(eccKey[1]);
            String bY = FCOEM.byteArrayToHexString(eccKey[2]);

            String publ_x_a = jsonContent.getString("publ_x");
            String publ_y_a = jsonContent.getString("publ_y");

            byte[] aX = FCOEM.hexStringToByteArray(publ_x_a);
            byte[] aY = FCOEM.hexStringToByteArray(publ_y_a);

            PeerCom.sessionForPeer(peer).sessionKey = new CTAP2EccJava().dhExchangeWithRawPeer(false, eccKey[0], aX, aY);
            PeerCom.sessionForPeer(peer).handshakeComplete = true;
            Log.i("PLNK_DEBUG", "(1)Peer SKEY:  " + FCOEM.byteArrayToHexString(PeerCom.sessionForPeer(peer).sessionKey));

            JSONObject payloadDict = new JSONObject();
            payloadDict.put("publ_x", bX);
            payloadDict.put("publ_y", bY);
            String responseb64 = AESPlnk.b64encode2String(payloadDict.toString());

            byte[] nsHash = CTAP2EccJava.getSHA256(responseb64.getBytes(), responseb64.getBytes().length);

            String sd = MqttService.getInstance().getConfig().getProperty("bes.id.dpriv");
            String sx = MqttService.getInstance().getConfig().getProperty("bes.id.xpubl");
            String sy = MqttService.getInstance().getConfig().getProperty("bes.id.ypubl");

            byte[] dPrivateKey = FCOEM.hexStringToByteArray(sd);
            byte[] dPublicKeyX = FCOEM.hexStringToByteArray(sx);
            byte[] dPublicKeyY = FCOEM.hexStringToByteArray(sy);

            if(dPrivateKey!=null && dPublicKeyX!=null && dPublicKeyY!=null)
            {
              CTAP2EccJava sign_cecc = new CTAP2EccJava();
              sign_cecc.initKey(dPublicKeyX, dPublicKeyY, dPrivateKey);

              byte[] signaturePayload = sign_cecc.sign(CTAP2EccJava.generateRandom(32),nsHash);

              JSONObject packageDict = new JSONObject();
              packageDict.put("peer", serviceUuid);
              packageDict.put("request", request);
              packageDict.put("version", "1");
              packageDict.put("hash", FCOEM.byteArrayToHexString(nsHash));
              packageDict.put("signature", FCOEM.byteArrayToHexString(signaturePayload));
              packageDict.put("content", responseb64);

              return packageDict.toString().getBytes();
            }
          }
        }
      } catch (Exception e) {
        Log.e("Exception in buildSKeyNegotiationResponse: " + e.getMessage());
      }
    }
    return null;
  }

  public static byte[] buildPayloadTransfer(String peerAdrGUID, String request, String payLoad, String serviceUuid)
  {
    try
    {
      String sd = MqttService.getInstance().getConfig().getProperty("bes.id.dpriv");

      byte[] dPrivateKey = FCOEM.hexStringToByteArray(sd);

      CTAP2EccJava sign_cecc = new CTAP2EccJava();
      sign_cecc.initKey(dPrivateKey);

      byte[] iv = CTAP2EccJava.generateRandom(16);
      AESPlnk aes = new AESPlnk(PeerCom.sessionForPeer(peerAdrGUID).sessionKey,iv);
      String contentB64 = aes.encryptByteArrayToB64(payLoad.getBytes());

      byte[] hash = CTAP2EccJava.getSHA256(contentB64.getBytes(), contentB64.getBytes().length);
      byte[] sign = sign_cecc.sign(CTAP2EccJava.generateRandom(32), hash);

      JSONObject jsonPackage = new JSONObject();
      jsonPackage.put("peer", serviceUuid);
      jsonPackage.put("request", request);
      jsonPackage.put("version", "1");
      jsonPackage.put("iv", FCOEM.byteArrayToHexString(iv));
      jsonPackage.put("hash", FCOEM.byteArrayToHexString(hash));
      jsonPackage.put("signature", FCOEM.byteArrayToHexString(sign));
      jsonPackage.put("content", contentB64);

      return jsonPackage.toString().getBytes();

    } catch (Exception ignore) {}
    return null;
  }

  public static String getNSStringPayLoad(JSONObject peerDict, JSONObject jsonObject)
  {
    if(peerDict!=null && jsonObject !=null)
    {
      try
      {
        String peer = jsonObject.getString("peer");
        String iv = jsonObject.getString("iv");
        String signature = jsonObject.getString("signature");
        String contentb64 = jsonObject.getString("content");

        // Signatur verification
        String peer_publ_x = peerDict.getString("publ_x");
        String peer_publ_y = peerDict.getString("publ_y");
        CTAP2EccJava verify_cecc   = new CTAP2EccJava();
        verify_cecc.initKey(FCOEM.hexStringToByteArray(peer_publ_x),FCOEM.hexStringToByteArray(peer_publ_y));
        byte[] bHash = CTAP2EccJava.getSHA256(contentb64.getBytes(),contentb64.getBytes().length);
        byte[] bSign = FCOEM.hexStringToByteArray(signature);
        boolean bOk = verify_cecc.verify(bSign,bHash);
        if(bOk)
        {
          // Payload entschlüsseln
          byte[] nsIV = FCOEM.hexStringToByteArray(iv);
          byte[] nsAES = PeerCom.sessionForPeer(peer).sessionKey;
          AESPlnk aes = new AESPlnk(nsAES, nsIV);
          String payload = aes.decryptStringFromB64(contentb64);
          return payload;
        }
      } catch (Exception ignore) {}
    }
    return null;
  }

}

