package plp.ui;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ipoxo.plcore.lib.Log;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;

import io.javalin.http.Context;
import org.eclipse.jetty.util.IO;
import plp.lib.PLTool;
import plp.lib.CredentialDao;

import java.security.SecureRandom;
import java.util.*;


public class WebAuthn
{
  public static void registerStart(Context ctx)
  {
    Map<String, Object> json = ctx.bodyAsClass(Map.class);

    String displayname = (String) json.get("displayname");
    String user = (String) json.get("user");
    String rpid = (String) json.get("rpid");
    String device = (String) json.get("device");

    // 1. Challenge erzeugen
    byte[] challengeBytes = new byte[32];
    new SecureRandom().nextBytes(challengeBytes);
    String challengeB64 = PLTool.b64encode2String(challengeBytes);

    // 2. Challenge speichern (Session oder Map)
    ctx.sessionAttribute("challenge", challengeB64);

    byte[] userId = PLTool.generateRandom(32);
    // 3. Beispiel-User (später dynamisch)
    String userIdB64 = PLTool.b64encode2String(userId);

    Map<String, Object> response = Map.of(
      "challenge",  challengeB64,
      "rp", Map.of(
        "name", "PhraseLock",
        "id", rpid
      ),
      "attestation", "none",
      "timeout", 60000,
      "user", Map.of(
        "id", userIdB64,
        "name", user,
        "displayName", displayname
      ),
      "pubKeyCredParams", List.of(
        Map.of("type", "public-key", "alg", -7),  // ES256
        Map.of("type", "public-key", "alg", -257) // RS256
      ),
      "authenticatorSelection", Map.of(
        "authenticatorAttachment", "cross-platform",
        "residentKey", "required",
        "userVerification", "preferred"
      )
    );

    ctx.sessionAttribute("userid", PLTool.byteArrayToHexString(userId));
    CredentialDao.setUser(PLTool.byteArrayToHexString(userId),user,displayname,rpid);
    ctx.json(response);
  }

  public static void registerFinish(Context ctx)
  {
    String rpidHost   = ctx.host().split(":")[0];
    String schema = null;
    String port = null;
    schema = ctx.header("X-Forwarded-Proto");
    port = ctx.header("X-Forwarded-Port");
    if(schema==null) schema     = ctx.scheme();
    if(port==null) port     = String.valueOf(ctx.port());

    // 1. Challenge aus Session holen
    String challengeB64 = ctx.sessionAttribute("challenge");
    if (challengeB64 == null) {
      ctx.status(400).json((Map.of("success", false,"reason","No Challenge found")));
      return;
    }
    byte[] challengeBytes = Base64.getUrlDecoder().decode(challengeB64);
    Challenge challenge = new DefaultChallenge(challengeBytes);

    // 2. JSON vom Browser (PublicKeyCredential)
    String json = ctx.body();

    // 3. WebAuthnManager
    WebAuthnManager manager = WebAuthnManager.createNonStrictWebAuthnManager();

    // 4. RegistrationData aus JSON parsen
    RegistrationData registrationData = manager.parseRegistrationResponseJSON(json);

    // 5. OriginPredicate definieren
    Origin origin = new Origin(schema + "://" + rpidHost + ":" + port);

    // 6. ServerProperty
    ServerProperty serverProperty = new ServerProperty(
      origin,
      rpidHost,
      challenge,
      null
    );

    // 7. RegistrationParameters
    RegistrationParameters registrationParameters =
      new RegistrationParameters(serverProperty, null, false);

    // 8. Validierung
    RegistrationData verified = manager.validate(registrationData, registrationParameters);

    // 9. Credential extrahieren
    AttestationObject attObj = verified.getAttestationObject();
    AuthenticatorData<?> authData = attObj.getAuthenticatorData();

    byte[] credentialId = authData.getAttestedCredentialData().getCredentialId();

    COSEKey coseKey = authData.getAttestedCredentialData().getCOSEKey();

    byte[] publicKey = null;
    try {
      ObjectMapper cbor = new ObjectMapper();
      publicKey = cbor.writeValueAsBytes(coseKey);
    }catch (Exception e){
      ctx.status(400).json((Map.of("success", false,"reason","CBOR Mapping failed")));
    }

    try {
      manager.verify(registrationData, registrationParameters);
    } catch (Exception e) {
      ctx.status(400).json((Map.of("success", false,"reason","Verify registration data failed")));
      return;
    }

    CredentialRecord credentialRecord =
      new CredentialRecordImpl(
        registrationData.getAttestationObject(),
        registrationData.getCollectedClientData(),
        registrationData.getClientExtensions(),
        registrationData.getTransports()
      );

    ObjectConverter objectConverter = new ObjectConverter();
    AttestedCredentialDataConverter attestedCredentialDataConverter = new AttestedCredentialDataConverter(objectConverter);

    // serialize
    byte[] serializedCR = attestedCredentialDataConverter.convert(credentialRecord.getAttestedCredentialData());


    String userid = ctx.sessionAttribute("userid");
    CredentialDao.setCredentialRecord(userid,PLTool.byteArrayToHexString(serializedCR));
    CredentialDao.setCredentialId(userid,PLTool.byteArrayToHexString(credentialId));
    CredentialDao.setPublicKey(userid,PLTool.byteArrayToHexString(publicKey));
    CredentialDao.setSignCounter(userid,authData.getSignCount());

    ctx.result("Registrierung erfolgreich!");
  }

  public static String generateChallenge()
  {
    SecureRandom random = new SecureRandom();
    byte[] bytes = new byte[32];
    random.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  public static void loginOptions(Context ctx)
  {
    String rpidHost   = ctx.host().split(":")[0];
    Log.i("rpidHost: " + rpidHost);

    // Challenge erzeugen
    String challenge = generateChallenge();

    // Challenge in Session speichern
    ctx.sessionAttribute("webauthn_challenge", challenge);

    // JSON-Objekt als Map bauen
    Map<String, Object> resp = new HashMap<>();
    resp.put("challenge", challenge);
    resp.put("rpId", rpidHost);   // deine Domain
    resp.put("timeout", 60000);
    resp.put("userVerification", "preferred");

    ctx.json(resp);
  }

  public class AssertionResponse {
    public String id;
    public String rawId;
    public String type;

    public Response response;

    public static class Response {
      public String authenticatorData;
      public String clientDataJSON;
      public String signature;
      public String userHandle;
    }
  }

  public static void loginVerify(Context ctx)
  {
    String rpidHost   = ctx.host().split(":")[0];
    String schema = null;
    String port = null;
    schema = ctx.header("X-Forwarded-Proto");
    port = ctx.header("X-Forwarded-Port");
    if(schema==null) schema     = ctx.scheme();
    if(port==null) port     = String.valueOf(ctx.port());

    // 1. Rohes JSON vom Browser
    String json = ctx.body();

    // 2. Challenge aus Session
    String expectedChallenge = ctx.sessionAttribute("webauthn_challenge");
    if (expectedChallenge == null) {
      ctx.status(400).json((Map.of("success", false,"reason","No challenge")));
      return;
    }

    // 3. WebAuthnManager
    WebAuthnManager manager = WebAuthnManager.createNonStrictWebAuthnManager();

    // 4. JSON → AuthenticationData
    AuthenticationData authData;
    try {
      authData = manager.parseAuthenticationResponseJSON(json);
    } catch (Exception e) {
      ctx.status(400).json((Map.of("success", false,"reason","Parse failed")));
      return;
    }

    // 5. Credential anhand credentialId (rawId) finden
    //String credentialId = authData.getCredentialId().getBase64Url();
    String credentialId = PLTool.byteArrayToHexString(authData.getCredentialId());
    Log.i("   credentialId " + credentialId);


    CredentialDao.StoredCredential credStored = CredentialDao.findByCredentialId(credentialId);
    if (credStored == null) {
      ctx.status(400).json((Map.of("success", false,"reason","Unknown credential")));
      return;
    }

    // 6. ServerProperty bauen
    Origin origin = new Origin(schema + "://" + rpidHost + ":" + port);
    ServerProperty serverProperty = new ServerProperty(
      origin,
      rpidHost,
      new DefaultChallenge(expectedChallenge),
      null
    );

    ObjectConverter objectConverter = new ObjectConverter();
    AttestedCredentialDataConverter attestedCredentialDataConverter = new AttestedCredentialDataConverter(objectConverter);
    String stmp = credStored.credentialRecord();
    byte[] sArr = PLTool.hexStringToByteArray(stmp);
    AttestedCredentialData attestedCredentialData = attestedCredentialDataConverter.convert(sArr);

    CredentialRecord credentialRecord =
      new CredentialRecordImpl(null,
        null,
        null,
        null,
        credStored.signCount(),
        attestedCredentialData,
        null,
        null,
        null,
        null );

    List<byte[]> allowCredentials = null;
    boolean userVerificationRequired = true;
    boolean userPresenceRequired = true;

    AuthenticationParameters authenticationParameters =
      new AuthenticationParameters(
        serverProperty,
        credentialRecord,
        allowCredentials,
        userVerificationRequired,
        userPresenceRequired
      );

    // 8. Validierung
    try {
      manager.verify(authData, authenticationParameters);
    } catch (Exception e) {
      ctx.status(400).result("Validation failed");
      return;
    }

    // 9. userHandle prüfen (discoverable credential)
    if (authData.getUserHandle() != null) {
      //String userHandle = new String(authData.getUserHandle().getBytes());
      String userHandle =  PLTool.byteArrayToHexString(authData.getUserHandle());
      if (!userHandle.equals(credStored.userId())) {
        ctx.status(400).result("UserHandle mismatch");
        return;
      }
    }

    // 10. SignCount aktualisieren
    long updateSignCount = authData.getAuthenticatorData().getSignCount();
    if (updateSignCount > credStored.signCount())
    {
      CredentialDao.updateSignatureCounter(credentialId,updateSignCount);
    }

    // 11. Session setzen
    ctx.sessionAttribute("userId", credStored.userId());
    ctx.json((Map.of("success", true,"reason","none")));
  }

}