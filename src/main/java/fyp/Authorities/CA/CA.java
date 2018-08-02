package fyp.Authorities.CA;

import fyp.SharedServices.Configuration;
import fyp.SharedServices.KeyStoreHandler;
import fyp.SharedServices.LogFile;
import java.io.IOException;
import java.security.KeyManagementException;
import javax.net.ssl.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.operator.OperatorCreationException;

public class CA {

    private static final Logger CALogger = Logger.getLogger(CA.class.getName());
    private X509Certificate caCert;
    private PrivateKey caKey;
    private SSLServerSocket sslServerSocket;
    String caKeyStorePath = Configuration.get("caKeystorePath");
    String caKeyStorePassword = Configuration.get("caKeystorePass");
    String caCertificateAlias = Configuration.get("caCertAlias");
    String caKeyAlias = Configuration.get("caKeyAlias");

    static {
        LogFile.logFile(CALogger);
    }

    public CA(SSLServerSocket sslServerSocket) {

        this.sslServerSocket = sslServerSocket;

        try {
            this.caKey = KeyStoreHandler.getPrivateKey(caKeyAlias, caKeyStorePath, caKeyStorePassword);
            this.caCert = KeyStoreHandler.getCertificate(caCertificateAlias, caKeyStorePath, caKeyStorePassword);
        } catch (Exception e) {
            CALogger.log(Level.SEVERE, "Not able to get CA cert!", e);
        }
    }

    public void run() {

        while (true) {
            try {
                SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();
                CALogger.log(Level.INFO, "New Request from: {0}", sslSocket.getInetAddress().getHostAddress());
                new CARequestHandler(sslSocket, caCert, caKey).start();
                //CALogger.log(Level.INFO, "CA Server running");
            } catch (Exception e) {
                CALogger.log(Level.SEVERE, "Not able to run CA runnable!", e);
            }
        }
    }

    //public static void main(String[] args) {
    public static void main(String[] args) {
        String keyStorePath = Configuration.get("caKeystorePath");
        String keyStorePassword = Configuration.get("caKeystorePass");
        String keyPassword = Configuration.get("caTruststorePass");
        int portNo = Integer.parseInt(Configuration.get("caPort"));
        String trustStorePath = Configuration.get("caTruststorePath");
        System.setProperty("javax.net.ssl.trustStore", trustStorePath);

        try {

            KeyStore keyStore = KeyStoreHandler.getKeyStore(keyStorePath, keyStorePassword);
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(keyStore, keyPassword.toCharArray());
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
            SSLServerSocket sslServerSocket = (SSLServerSocket) sslContext.getServerSocketFactory().createServerSocket(portNo);
            CALogger.log(Level.INFO, "Starting CA Server...");
            new CA(sslServerSocket).run();

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | NoSuchProviderException | OperatorCreationException | UnrecoverableKeyException | KeyManagementException ex) {
            CALogger.log(Level.SEVERE, "Unable to start CA server!", ex);
        }
    }
}
