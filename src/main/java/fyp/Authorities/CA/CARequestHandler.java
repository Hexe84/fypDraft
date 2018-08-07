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
                    //TODO: make sure alias contains some cert specific info -like devices MAC or cert SN
                    try {
                        KeyStoreHandler.storeCertificateEntry(deviceCertAlias + " " + certificate.getSubjectDN().toString().split(" ")[1], certificate, certStorePath, certStorePassword);
                    } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException | NoSuchProviderException | OperatorCreationException e) {
                        CARequestLogger.log(Level.SEVERE, "Unable to save cert to the CertStore", e);
                    }
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
                    //TODO: go through that as sth is not right
                    String certSN = new String(request);
                    System.out.println("-----------------------------------CERT SN--------------  " + certSN);
                    //String m = "Unable to create Certificate. Sending Revocation Request for cert: " + certSN;
                    String m = "Unable to create Certificate: " + certSN;
                    CARequestLogger.log(Level.SEVERE, m, e);
                    response = m.getBytes();
                    //Revoke then ???----------------------------------------
                    //TODO: all that should run from rootCAHandler
                    //on this level it should only send revocation request to root just like RA sends request to CA
                    /*try {
                        String crlFileName = Configuration.get("CRL_FILE_PATH");
                        X509CRLHolder crlHolder =  new X509CRLHolder(new FileInputStream(crlFileName));
                        X509CRLHolder newCrlHolder = OCSPHandler.revokeCertificate(crlHolder, certSN, caCert, caKey);

                        //save to the file system
                        FileUtils.writeByteArrayToFile(new File(crlFileName), newCrlHolder.getEncoded());

                        System.out.println("CRL (version " + crlHolder.getExtension(Extension.cRLNumber).getParsedValue().toString()
                                + ") - new entry added: SN= " + certSN + ". Update sent to : " + vaIP + ":" + vaPORT);

                        String res = "Certificate no: " + certSN + " revoked successfully";
                        response = res.getBytes();
                        //byte[] vaResponse ;
                        //-----------------
                        try{
                        System.setProperty("javax.net.ssl.keyStore", "keystore/ca.keystore");
                        System.setProperty("javax.net.ssl.keyStorePassword", "password");
                        SSLSocketFactory f = (SSLSocketFactory) SSLSocketFactory.getDefault();
                            try (SSLSocket connectionVA = (SSLSocket) f.createSocket(vaIP, vaPORT)) {
                                connectionVA.startHandshake();
                                DataOutputStream dos = new DataOutputStream(connectionVA.getOutputStream());
                                //DataInputStream dis = new DataInputStream(connectionVA.getInputStream());
                                dos.write(newCrlHolder.getEncoded());
                                //vaResponse = CertificateHandler.readDataFromInputStream(dis);
                                //-----------------
                            }
                        }
                        catch(Exception ex){
                            
                        }
                    } catch (Exception ex) {
                        response = "Unable to save the Revocation Status.".getBytes();

                    }*/
                    //Revoke then finished__________________________________

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
