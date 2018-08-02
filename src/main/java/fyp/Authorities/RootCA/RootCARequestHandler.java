package fyp.Authorities.RootCA;

import fyp.Authorities.RootCA.*;
import fyp.SharedServices.CSRHandler;
import fyp.SharedServices.CertificateHandler;
import fyp.SharedServices.Configuration;
import fyp.Authorities.RA.RARequestHandler;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
//import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
//import org.bouncycastle.operator.OperatorCreationException;

/**
 *
 * @author Marta
 */
public class RootCARequestHandler extends Thread implements Runnable {

    private static final Logger RootRequestLogger = Logger.getLogger(RootCARequestHandler.class.getName());
    DataInputStream clientDataInputStream;
    DataOutputStream clientDataOutputStream;
    SSLSocket clientSslSocket;

    private X509Certificate rootCert;
    private PrivateKey rootKey;

    private static final String ROOT_CA_IP = Configuration.get("rootIP");
    private static final int ROOT_CA_PORT = Integer.parseInt(Configuration.get("rootPort"));
    //private static final int ROOT_CA_HTTP_PORT = Integer.parseInt(Configuration.get("rootHttpPort"));

    public RootCARequestHandler(SSLSocket sslSocket, X509Certificate rootCert, PrivateKey rootKey) throws IOException {
        try {
            this.rootCert = rootCert;
            this.rootKey = rootKey;
            this.clientSslSocket = sslSocket;
            this.clientDataInputStream = new DataInputStream(clientSslSocket.getInputStream());
            this.clientDataOutputStream = new DataOutputStream(clientSslSocket.getOutputStream());
        } catch (Exception ex) {
            RootRequestLogger.log(Level.SEVERE, "Unable to create data input/output stream!", ex);

        }
    }

    @Override
    public void run() {
        /*
        try {
            
            byte[] requestData = CertificateHandler.readDataFromInputStream(clientDataInputStream);
            try {
                PKCS10CertificationRequest csr = new PKCS10CertificationRequest(requestData);

                System.out.println(clientSslSocket.getInetAddress().getHostAddress() + ": CSR received from: " + csr.getSubject());
                System.out.println("_____________________________________________________________________");
                System.out.println(clientSslSocket.toString());
                // get addresses of CRL and OCSP Responder
                //String CRL_URL = "http://" + ROOT_CA_IP + ":" + Integer.parseInt(Configuration.get("caHttpPort")) + Configuration.get("caHttpPort");
                String OCSP_URL = "http://" + Configuration.get("vaIP") + ":" + Configuration.get("vaPort");
                // Create Certificate intermediate (that's all it does)
                X509Certificate certificate = null;
                //X509Certificate certificate = CertificateHandler.createSignedCertificateIntermediate(csr.getSubject(), KeyPair keyPair, rootCert, rootKey, false, OCSP_URL);
                if (csr.getSubject().toString().toLowerCase().contains("validation")) {
                    certificate = CertificateHandler.createSignedCertificateIntermediate(csr.getSubject().toString(), rootCert, rootKey, true, OCSP_URL);
                } else {
                    certificate = CertificateHandler.createSignedCertificateIntermediate(csr.getSubject().toString(), rootCert, rootKey, false, OCSP_URL);
                }
                //X509Certificate certificate = CertificateHandler.createDeviceCertificate(caKey, caCert, csr.getSubject(), csr.getSubjectPublicKeyInfo(), OCSP_URL);
                System.out.println("Certificate Created Successfully: " + certificate.getSubjectDN() + " : serialNumber=" + certificate.getSerialNumber());
                //certificate.getEncoded();

                try {
                    System.setProperty("javax.net.ssl.keyStore", Configuration.get("rootKeystorePath"));
                    System.setProperty("javax.net.ssl.keyStorePassword", Configuration.get("rootKeystorePass"));
                    //RootRequestLogger.log(Level.INFO, ("Certificate " + certificate.getSerialNumber() + " Publication Request sent to : " + ROOT_CA_IP + ":" + ROOT_CA_PORT));
                    SSLSocketFactory f = (SSLSocketFactory) SSLSocketFactory.getDefault();
                    try (SSLSocket connectionRepository = (SSLSocket) f.createSocket(ROOT_CA_IP, ROOT_CA_PORT)) {
                        connectionRepository.startHandshake();
                        DataOutputStream w = new DataOutputStream(connectionRepository.getOutputStream());
                        DataInputStream r = new DataInputStream(connectionRepository.getInputStream());
                        w.write(certificate.getEncoded());
                        CertificateHandler.readDataFromInputStream(r);
                    }
                } catch (CertificateEncodingException | IOException e) {
                    RootRequestLogger.log(Level.SEVERE, "Could Not Create Certificate", e);
                }

            } catch (IOException | NumberFormatException e) {

                RootRequestLogger.log(Level.SEVERE, null, e);
                throw e;

            }

        } catch (Exception ex) {
            RootRequestLogger.log(Level.SEVERE, null, ex);
        } finally {
            try {
                this.clientSslSocket.close();
            } catch (IOException e) {
                RootRequestLogger.log(Level.SEVERE, null, e);
            }
        }
        */
    }
}
