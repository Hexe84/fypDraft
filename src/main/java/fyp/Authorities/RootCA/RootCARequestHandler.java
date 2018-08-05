package fyp.Authorities.RootCA;

import fyp.Authorities.RootCA.*;
import fyp.SharedServices.CSRHandler;
import fyp.SharedServices.CertificateHandler;
import fyp.SharedServices.Configuration;
import fyp.Authorities.RA.RARequestHandler;
import fyp.SharedServices.DatabaseHandler;
import fyp.SharedServices.OCSPHandler;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
//import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.util.Calendar;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
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

    private static final String rootIP = Configuration.get("rootIP");
    private static final int rootPORT = Integer.parseInt(Configuration.get("rootPort"));
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

        try {

            byte[] requestData = CertificateHandler.readDataFromInputStream(clientDataInputStream);
            byte[] responseData;
            String certSerialNumber = new String(requestData);
            System.out.println(clientSslSocket.getInetAddress().getHostAddress()
                    + ": Certificate Revocation Request for certificate no: " + certSerialNumber);
            try {
                String crlFileName = Configuration.get("RevokedPath");
                X509CRLHolder crlHolder = new X509CRLHolder(new FileInputStream(crlFileName));
                X509CRLHolder updatedCrlHolder = OCSPHandler.revokeCertificate(crlHolder, certSerialNumber, rootCert, rootKey);

                //save to the updated crl file and CRL database
                FileUtils.writeByteArrayToFile(new File(crlFileName), updatedCrlHolder.getEncoded());
                //updatedCrlHolder.getRevokedCertificate(new BigInteger(certSerialNumber)).getExtension(Extension.reasonCode);
                System.out.println("CRL (version " + crlHolder.getExtension(Extension.cRLNumber).getParsedValue().toString()
                        + ") Successfully Updated with new entry '" + certSerialNumber + "'");

                String res = "Certificate no: " + certSerialNumber + " revoked Successfully";
                responseData = res.getBytes();

            } catch (Exception ex) {
                responseData = "Unable to get Revocation Status!".getBytes();
            }

            if (requestData != null) {
                clientDataOutputStream.write(responseData);
                RootRequestLogger.log(Level.INFO, "Response sent to : {0}", clientSslSocket.getInetAddress().getHostAddress());
                System.out.println("--------------- ROOT CA Request successful! ------------------");
            }
            //Revoke then ???----------------------------------------
            //TODO: all that should run from rootCAHandler
            //on this level it should only send revocation request to root just like RA sends request to CA
            /*try {
                        String crlFileName = Configuration.get("RevokedPath");
                        X509CRLHolder crlHolder = OCSPHandler.readCRLFromFile(crlFileName);
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

        } catch (Exception ex) {
            RootRequestLogger.log(Level.SEVERE, null, ex);
        } finally {
            try {
                this.clientSslSocket.close();
            } catch (IOException e) {
                RootRequestLogger.log(Level.SEVERE, null, e);
            }
        }

    }
}
