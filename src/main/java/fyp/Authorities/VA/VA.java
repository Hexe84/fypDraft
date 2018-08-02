package fyp.Authorities.VA;

import fyp.SharedServices.Configuration;
import fyp.SharedServices.KeyStoreHandler;
import fyp.SharedServices.LogFile;
import java.io.IOException;
import java.security.KeyManagementException;
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
import javax.net.ssl.*;
import org.bouncycastle.operator.OperatorCreationException;

public class VA {

    private static final Logger VALogger = Logger.getLogger(VA.class.getName());
    private SSLServerSocket sslServerSocket;
    private X509Certificate vaCert;
    private PrivateKey vaKey;
    String vaKSPath = Configuration.get("vaKeystorePath");
    String vaKSPassword = Configuration.get("vaKeystorePass");
    String vaCertAlias = Configuration.get("vaCertAlias");
    String vaKeyAlias = Configuration.get("vaKeyAlias");

    static {
        LogFile.logFile(VALogger);
    }

    public VA(SSLServerSocket sslServerSocket) {

        this.sslServerSocket = sslServerSocket;

        try {
            this.vaKey = KeyStoreHandler.getPrivateKey(vaKeyAlias, vaKSPath, vaKSPassword);
            this.vaCert = KeyStoreHandler.getCertificate(vaCertAlias, vaKSPath, vaKSPassword);
        } catch (Exception e) {
            VALogger.log(Level.SEVERE, "Not able to get VA cert!", e);
        }
    }

    public void run() {
        
        while (true) {
            try {
                SSLSocket sslSocket = (SSLSocket) this.sslServerSocket.accept();
                VALogger.log(Level.INFO, ("New OCSP Request from: " + sslSocket.getInetAddress().getHostAddress()));
                new VARequestHandler(sslSocket, this.vaCert, this.vaKey).start();
            } catch (Exception e) {
                VALogger.log(Level.SEVERE, "Not able to run VA runnable!", e);
            }
        }
    }

    public static void main(String[] args) {

        String keyPassword = Configuration.get("vaKeystorePass");
        int port = Integer.parseInt(Configuration.get("vaPort"));
        String ksPath = Configuration.get("vaKeystorePath");
        String ksPassword = Configuration.get("vaKeystorePass");
        String tsPath = Configuration.get("vaTruststorePath");
        System.setProperty("javax.net.ssl.trustStore", tsPath);

        try {

            KeyStore keyStore = KeyStoreHandler.getKeyStore(ksPath , ksPassword);
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(keyStore, keyPassword.toCharArray());
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
            SSLServerSocket sslServerSocket = (SSLServerSocket) sslContext.getServerSocketFactory().createServerSocket(port);
            VALogger.log(Level.INFO, "Starting VA Server...");
            new VA(sslServerSocket).run();
            
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | NoSuchProviderException | OperatorCreationException | UnrecoverableKeyException | KeyManagementException ex) {
            VALogger.log(Level.SEVERE, "Not able to start VA Server!", ex);
        }
    }
}
