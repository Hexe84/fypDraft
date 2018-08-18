package fyp.Authorities.CA;

import fyp.SharedServices.CertificateHandler;
import fyp.SharedServices.Configuration;
import fyp.SharedServices.KeyStoreHandler;
import fyp.SharedServices.OCSPHandler;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.operator.OperatorCreationException;

/**
 *
 * @author Marta
 */
public class CARequestHandler extends Thread implements Runnable {

    private static final Logger CARequestLogger = Logger.getLogger(CARequestHandler.class.getName());
    DataInputStream clientDataInputStream;
    DataOutputStream clientDataOutputStream;
    SSLSocket clientSslSocket;

    private X509Certificate caCert;
    private PrivateKey caKey;
    private String certStorePath = Configuration.get("certstorePath");
    private String certStorePassword = Configuration.get("certstorePass");
    private static final String vaIP = Configuration.get("vaIP");
    private static final int vaPORT = Integer.parseInt(Configuration.get("vaPort"));
    private String deviceCertAlias = Configuration.get("devicesCertAlias");

    public CARequestHandler(SSLSocket sslSocket, X509Certificate caCert, PrivateKey caKey) throws IOException {
        try {
            this.caCert = caCert;
            this.caKey = caKey;
            this.clientSslSocket = sslSocket;
            this.clientDataInputStream = new DataInputStream(clientSslSocket.getInputStream());
            this.clientDataOutputStream = new DataOutputStream(clientSslSocket.getOutputStream());
        } catch (Exception ex) {
            CARequestLogger.log(Level.SEVERE, "Unable to create data input/output stream!", ex);
        }
    }

    @Override
    public void run() {
        try {
            byte[] request = CertificateHandler.readDataFromInputStream(clientDataInputStream);
            byte[] response = null;
            try {
                PKCS10CertificationRequest csr = new PKCS10CertificationRequest(request);

                CARequestLogger.log(Level.INFO, "{0}: CSR for {1} received!", new Object[]{clientSslSocket.getInetAddress().getHostAddress(), csr.getSubject()});
                // get address of  OCSP Responder
                String OCSP_URL = "http://" + Configuration.get("vaIP") + ":" + Configuration.get("vaPort");

                try {
                    // Create Certificate
                    X509Certificate certificate = CertificateHandler.createDeviceCertificate(caKey, caCert, csr.getSubject(), csr.getSubjectPublicKeyInfo());
                    System.out.println("Certificate created Successfully: " + certificate.getSubjectDN() + " : serialNumber=" + certificate.getSerialNumber());
                    response = certificate.getEncoded();
                    //Write Certificate to the CertStore
                    try {
                        KeyStoreHandler.storeCertificateEntry(deviceCertAlias + " " + certificate.getSubjectDN().toString().split(" ")[1], certificate, certStorePath, certStorePassword);
                    } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException | NoSuchProviderException | OperatorCreationException e) {
                        CARequestLogger.log(Level.SEVERE, "Unable to save cert to the CertStore", e);
                    }

                } catch (CertificateEncodingException | IOException e) {

                    String certSN = new String(request);
                    String m = "Unable to create Certificate: " + certSN;
                    CARequestLogger.log(Level.SEVERE, m, e);
                    response = m.getBytes();
                }

            } catch (IOException | NumberFormatException | OperatorCreationException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException e) {

                CARequestLogger.log(Level.SEVERE, null, e);
                response = "Unable to create certificate. Problem with CSR".getBytes();

            }

            clientDataOutputStream.write(response);
            CARequestLogger.log(Level.INFO, "Response sent to : {0}", clientSslSocket.getInetAddress().getHostAddress());
            System.out.println("--------------- CA Request successful! ------------------");
        } catch (IOException ex) {
            CARequestLogger.log(Level.SEVERE, null, ex);
        } finally {
            try {
                this.clientSslSocket.close();
            } catch (IOException ex) {
                CARequestLogger.log(Level.SEVERE, null, ex);
            }
        }
    }

}
