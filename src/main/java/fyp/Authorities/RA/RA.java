package fyp.Authorities.RA;

import fyp.SharedServices.Configuration;
import fyp.SharedServices.KeyStoreHandler;
import fyp.SharedServices.LogFile;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.*;
import org.bouncycastle.operator.OperatorCreationException;

/**
 *
 * @author Marta
 */
public class RA implements Runnable {

    private static final Logger RALogger = Logger.getLogger(RA.class.getName());
    private final SSLServerSocket sslServerSocket;

    static {
        LogFile.logFile(RALogger);

    }

    public RA(SSLServerSocket sslSS) {
        this.sslServerSocket = sslSS;
    }

    public void run() {
        while (true) {
            try {
                SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();
                RALogger.log(Level.INFO, "New request received from : {0}", sslSocket.getInetAddress().getHostAddress());
                new RARequestHandler(sslSocket).start();
            } catch (IOException ex) {
                RALogger.log(Level.SEVERE, "Not able to run RA runnable!", ex);
            }
        }
    }

    public static void main(String[] args) {

        String keyStorePath = Configuration.get("raKeystorePath");
        String keyStorePassword = Configuration.get("raKeystorePass");
        String trustStorePath = Configuration.get("raTruststorePath");
        String trustStorePass = Configuration.get("raTruststorePass");
        int portNo = Integer.parseInt(Configuration.get("raPort"));
        System.setProperty("javax.net.ssl.trustStore", trustStorePath);
        //System.setProperty("javax.net.ssl.trustStorePassword", trustStorePass);

        try {

            KeyStore keyStore = KeyStoreHandler.getKeyStore(keyStorePath, keyStorePassword);
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(keyStore, keyStorePassword.toCharArray());
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
            SSLServerSocketFactory sslA = sslContext.getServerSocketFactory();
            SSLServerSocket sslServerSocket = (SSLServerSocket) sslA.createServerSocket(portNo);

            RALogger.log(Level.INFO, "Starting RA Server...");
            new RA(sslServerSocket).run();
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | NoSuchProviderException | OperatorCreationException | UnrecoverableKeyException | KeyManagementException | NumberFormatException e) {
            RALogger.log(Level.SEVERE, "Unable to start RA Server!", e);
        }
    }
}
