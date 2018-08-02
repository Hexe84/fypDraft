package fyp.Authorities.CA;

import fyp.SharedServices.CertificateHandler;
import fyp.SharedServices.Configuration;
import fyp.SharedServices.KeyStoreHandler;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.DataInputStream;
import java.io.DataOutputStream;
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
    private static final String CA_IP = Configuration.get("caIP");
    private static final int CA_PORT = Integer.parseInt(Configuration.get("caPort"));
    private String deviceCertAlias = Configuration.get("devicesCertAlias");
    //private static final int CA_HTTP_PORT = Integer.parseInt(Configuration.get("caHttpPort"));

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
                //String CRL_URL = "http://" + rootCA_IP + ":" + Integer.parseInt(Configuration.get("rootCaHttpPort")) + Configuration.get("rootCaHttpPort");
                String OCSP_URL = "http://" + Configuration.get("vaIP") + ":" + Configuration.get("vaPort");

                try {
                    // Create Certificate
                    X509Certificate certificate = CertificateHandler.createDeviceCertificate(caKey, caCert, csr.getSubject(), csr.getSubjectPublicKeyInfo(), OCSP_URL);
                    System.out.println("Certificate created Successfully: " + certificate.getSubjectDN() + " : serialNumber=" + certificate.getSerialNumber());
                    response = certificate.getEncoded();
                    KeyStoreHandler.storeCertificateEntry(deviceCertAlias, certificate, certStorePath, certStorePassword);

                    /*
                    System.setProperty("javax.net.ssl.keyStore", Configuration.get("caKeystorePath"));
                    System.setProperty("javax.net.ssl.keyStorePassword", Configuration.get("caKeystorePass"));


                    CARequestLogger.log(Level.INFO, ("Certificate " + certificate.getSerialNumber() + " Publication Request sent to : " + CA_IP + ":" + CA_PORT));
                    SSLSocketFactory f = (SSLSocketFactory) SSLSocketFactory.getDefault();
                    try (SSLSocket connectionRepository = (SSLSocket) f.createSocket(CA_IP, CA_PORT)) {
                        connectionRepository.startHandshake();
                        DataOutputStream w = new DataOutputStream(connectionRepository.getOutputStream());
                        DataInputStream r = new DataInputStream(connectionRepository.getInputStream());
                        w.write(certificate.getEncoded());
                        CertificateHandler.readDataFromInputStream(r);
                    }
                     */
                } catch (CertificateEncodingException | IOException e) {
                    CARequestLogger.log(Level.SEVERE, "Unable to create Certificate", e);
                    response = "Unable to create certificate".getBytes();
                }

            } catch (IOException | NumberFormatException | OperatorCreationException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException e) {

                CARequestLogger.log(Level.SEVERE, null, e);
                response = "Unable to create certificate. Problem with CSR".getBytes();

            }

            if (request != null) {
                clientDataOutputStream.write(response);
                CARequestLogger.log(Level.INFO, "Response sent to : {0}", clientSslSocket.getInetAddress().getHostAddress());
                System.out.println("--------------- CA Request successful! ------------------");
            }
        } catch (IOException | KeyStoreException ex) {
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
