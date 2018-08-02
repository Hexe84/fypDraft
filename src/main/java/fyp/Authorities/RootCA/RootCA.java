package fyp.Authorities.RootCA;

import fyp.Authorities.CA.*;
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

public class RootCA {

    private static final Logger rootLogger = Logger.getLogger(CA.class.getName());
    private X509Certificate rootCert;
    private PrivateKey rootKey;
    private SSLServerSocket sslServerSocket;
    private static String rootKeyStorePath = Configuration.get("rootKeystorePath");
    private static String rootKeyStorePassword = Configuration.get("rootKeystorePass");
    private static String rootCertificateAlias = Configuration.get("rootCertAlias");
    private static String rootKeyAlias = Configuration.get("rootKeyAlias");

    static {
        LogFile.logFile(rootLogger);
    }

    public RootCA(SSLServerSocket sslServerSocket) {

        this.sslServerSocket = sslServerSocket;

        try {
            this.rootKey = KeyStoreHandler.getPrivateKey(rootKeyAlias, rootKeyStorePath, rootKeyStorePassword);
            this.rootCert = KeyStoreHandler.getCertificate(rootCertificateAlias, rootKeyStorePath, rootKeyStorePassword);
        } catch (Exception e) {
            rootLogger.log(Level.SEVERE, "Not able to get Root CA cert!", e);
        }
    }

    public void run() {

        while (true) {
            try {
                SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();
                rootLogger.log(Level.INFO, "New Request from: {0}", sslSocket.getInetAddress().getHostAddress());
                new RootCARequestHandler(sslSocket, rootCert, rootKey).start();
                //rootLogger.log(Level.INFO, "Root CA Server running");
            } catch (Exception e) {
                rootLogger.log(Level.SEVERE, "Not able to run root CA runnable!", e);
            }
        }
    }

    public static void main(String[] args) {

        String trustStorePassword = Configuration.get("rootTruststorePass");
        int portNo = Integer.parseInt(Configuration.get("rootPort"));
        String trustStorePath = Configuration.get("rootTruststorePath");
        System.setProperty("javax.net.ssl.trustStore", trustStorePath);

        try {

            KeyStore keyStore = KeyStoreHandler.getKeyStore(rootKeyStorePath, rootKeyStorePassword);
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(keyStore, trustStorePassword.toCharArray());
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
            SSLServerSocket sslServerSocket = (SSLServerSocket) sslContext.getServerSocketFactory().createServerSocket(portNo);
            rootLogger.log(Level.INFO, "Starting Root CA Server...");
            new RootCA(sslServerSocket).run();

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | NoSuchProviderException | OperatorCreationException | UnrecoverableKeyException | KeyManagementException ex) {
            rootLogger.log(Level.SEVERE, "Unable to start CA server!", ex);
        }
    }
}
