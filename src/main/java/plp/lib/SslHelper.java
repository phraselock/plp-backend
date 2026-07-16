package plp.lib;

import javax.net.ssl.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;


public class SslHelper {

  /**
   * Builds an SSLSocketFactory for mTLS.
   * The server is validated against the default Java TrustStore (public CA).
   * clientCertPath – client certificate (X.509 PEM)
   * clientKeyPath  – client private key (PKCS8 PEM, "BEGIN PRIVATE KEY", EC)
   */
  public static SSLSocketFactory buildSocketFactory(
      String clientCertPath, String clientKeyPath) throws Exception {

    CertificateFactory cf = CertificateFactory.getInstance("X.509");

    // Load client certificate and private key into KeyStore
    X509Certificate clientCert;
    try (InputStream in = new FileInputStream(clientCertPath)) {
      clientCert = (X509Certificate) cf.generateCertificate(in);
    }
    PrivateKey privateKey = loadPkcs8Key(clientKeyPath);

    char[] pw = new char[0];
    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, null);
    keyStore.setKeyEntry("client", privateKey, pw, new java.security.cert.Certificate[]{clientCert});

    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    kmf.init(keyStore, pw);

    // null → use default Java TrustStore (public CAs)
    SSLContext ctx = SSLContext.getInstance("TLS");
    ctx.init(kmf.getKeyManagers(), null, null);
    return ctx.getSocketFactory();
  }

  /**
   * Wie buildSocketFactory(), aber der Server-Cert wird nicht geprüft —
   * akzeptiert also auch selbstsignierte Zertifikate. Client-Cert und Key
   * bleiben aktiv (mTLS bleibt erhalten). Nur für Tests verwenden!
   */
  public static SSLSocketFactory buildSocketFactoryTrustAll(
      String clientCertPath, String clientKeyPath) throws Exception {

    CertificateFactory cf = CertificateFactory.getInstance("X.509");

    X509Certificate clientCert;
    try (InputStream in = new FileInputStream(clientCertPath)) {
      clientCert = (X509Certificate) cf.generateCertificate(in);
    }
    PrivateKey privateKey = loadPkcs8Key(clientKeyPath);

    char[] pw = new char[0];
    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, null);
    keyStore.setKeyEntry("client", privateKey, pw, new java.security.cert.Certificate[]{clientCert});

    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    kmf.init(keyStore, pw);

    TrustManager[] trustAll = new TrustManager[]
    {
      new X509TrustManager()
      {
        public void checkClientTrusted(X509Certificate[] c, String a) {}
        public void checkServerTrusted(X509Certificate[] c, String a) {}
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
      }
    };

    SSLContext ctx = SSLContext.getInstance("TLS");
    ctx.init(kmf.getKeyManagers(), trustAll, null);
    return ctx.getSocketFactory();
  }

  private static PrivateKey loadPkcs8Key(String keyPath) throws Exception {
    String pem = Files.readString(Path.of(keyPath));
    String base64 = pem
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .replaceAll("\\s+", "");
    byte[] der = Base64.getDecoder().decode(base64);
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
    return KeyFactory.getInstance("EC").generatePrivate(spec);
  }
}
