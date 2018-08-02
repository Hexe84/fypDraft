package fyp.Authorities.RA;

import fyp.SharedServices.CertificateHandler;
import fyp.SharedServices.Configuration;
import fyp.UI.UserInput;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import javax.net.ssl.*;
import java.io.IOException;
import java.net.URL;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

public class RARequestHandler extends Thread implements Runnable {

    private static final Logger RARequestLogger = Logger.getLogger(RARequestHandler.class.getName());
    DataInputStream clientDataInputStream;
    DataOutputStream clientDataOutputStream;
    SSLSocket clientSslSocket;

    private static final String caIP = Configuration.get("caIP");
    private static final int caPORT = Integer.parseInt(Configuration.get("caPort"));

    public RARequestHandler(SSLSocket sslsocket) {
        this.clientSslSocket = sslsocket;
    }

    @Override
    public void run() {

        byte[] requestBytes;
        try {
            clientDataInputStream = new DataInputStream(clientSslSocket.getInputStream());
            clientDataOutputStream = new DataOutputStream(clientSslSocket.getOutputStream());

            byte[] deviceSpecs = CertificateHandler.readDataFromInputStream(clientDataInputStream);
            //put some device specific subject like mac address
            String macFromSpecs = new String(deviceSpecs).split(";")[0];
            String subject = UserInput.normalizeMAC(macFromSpecs);
            clientDataOutputStream.write("Request CSR".getBytes());
            // get request from socket and parse the request data to csr
            requestBytes = CertificateHandler.readDataFromInputStream(clientDataInputStream);

            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(requestBytes);
            String csrSubjectName = csr.getSubject().toString();

            try {
                //case when certificate already exists
                /*if (getX509CertificateFromCertStore(subject) != null) {

                    deviceCertificate = getX509CertificateFromCertStore(subject);
                    String response = "CSR Rejected - certificate already exists for: " + deviceCertificate.getSubjectDN().getName();
                    clientDataOutputStream.write(response.getBytes());
                    clientDataInputStream.close();
                    System.out.println("CSR rejected for device:" + deviceCertificate.getSubjectDN().getName() + ". Response sent to : " + clientSslSocket.getInetAddress().getHostAddress());
                    return;
                    
                } else {*/
                if (!csrSubjectName.equals("CN=Device " + subject)) {
                    String response = "Subject Name on CSR: " + csrSubjectName
                            + " doesn't match the device's MAC: " + subject;
                    clientDataOutputStream.write(response.getBytes());
                    clientDataInputStream.close();
                    RARequestLogger.log(Level.WARNING, "CSR for device {0} rejected."
                            + " CSR data invalid! Response sent to : {1}",
                            new Object[]{subject, clientSslSocket.getInetAddress().getHostAddress()});
                    return;
                }
                try {

                    String keyStorePath = Configuration.get("raKeystorePath");
                    String keyStorePassword = Configuration.get("raKeystorePass");
                    System.setProperty("javax.net.ssl.keyStore", keyStorePath);
                    System.setProperty("javax.net.ssl.keyStorePassword", keyStorePassword);

                    SSLSocketFactory f = (SSLSocketFactory) SSLSocketFactory.getDefault();
                    SSLSocket c = (SSLSocket) f.createSocket(caIP, caPORT);
                    c.startHandshake();
                    DataOutputStream write = new DataOutputStream(c.getOutputStream());
                    DataInputStream read = new DataInputStream(c.getInputStream());
                    write.write(requestBytes);
                    byte[] caResponse = CertificateHandler.readDataFromInputStream(read);
                    c.close();

                    RARequestLogger.log(Level.INFO, "CSR accepted for device {0}. "
                            + "CSR sent to Signing Certificate Authority : {1}:{2}",
                            new Object[]{subject, caIP, caPORT});
                    try {
                        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(caResponse));
                        System.out.println("Certificate for " + cert.getSubjectDN() + " : serialNumber=" + cert.getSerialNumber()+ " created successfully!");

                    } catch (Exception es) {
                        RARequestLogger.log(Level.SEVERE, "Unable to retrieve cert from byte array", es);
                    }

                    clientDataOutputStream.write(caResponse);
                    RARequestLogger.log(Level.INFO, "Response sent to : {0}", clientSslSocket.getInetAddress().getHostAddress());
                    System.out.println("--------------- RA Request successful! ------------------");

                } catch (IOException ex1) {
                    RARequestLogger.log(Level.SEVERE, "Error in RA request", ex1);
                }
                //}//-----end of if cert already exists
            } catch (Exception e) {
                RARequestLogger.log(Level.SEVERE, "Some exception e in RARequestHandler", e);
                /*
                if (deviceCertificate != null) {

                    // if device cert exists but something is wrong then revoke it
                    String certSerialNumber = deviceCertificate.getSerialNumber().toString();
                    requestBytes = certSerialNumber.getBytes();
                    String logMsg = clientSslSocket.getInetAddress().getHostAddress() + ": Certificate Revocation Request for Device: "
                            + subject + " , cert serial number : " + certSerialNumber + ". Sending request to: " + caIP + ":" + caPORT;
                    RARequestLogger.log(Level.INFO, logMsg, e);

                } else {
                    String response = "Unknown error! There is no record on certificate for : " + subject;
                    clientDataOutputStream.write(response.getBytes());
                    clientDataInputStream.close();
                    RARequestLogger.log(Level.SEVERE, clientSslSocket.getInetAddress().getHostAddress() + ": Uknown Error! Revocation Request rejected for device " + subject + ". Certificate doesn't exist!", e);
                    return;

                }
                 */
            }

        } catch (Exception ex) {
            RARequestLogger.log(Level.SEVERE, "Error in RA request handler", ex);

        } finally {
            try {
                this.clientSslSocket.close();
            } catch (IOException ex) {
                RARequestLogger.log(Level.SEVERE, "Unable to close the socket.", ex);
            }
        }
    }
//TODO: not gonna work

    /*  
    private X509Certificate getX509CertificateFromRepository(String s) throws IOException {

        String httpRepositoryURL = "http://" + Configuration.get("IP_REPOSITORY") + ":" + Configuration.get("PORT_REPOSITORY_HTTP") + "/get?CN=";
        URL oracle = new URL(httpRepositoryURL + s);
        byte[] bytes = IOUtils.toByteArray(oracle.openStream());
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(bytes));
        } catch (Exception e) {
            RARequestLogger.log(Level.SEVERE, "Unable to get cert from byte[] object", e);
            return null;
        }

    }
     */
    //JUST TESTING method atm
    //TODO: not fully right change the filePath to corresponding one
    private X509Certificate getX509CertificateFromCertStore(String s) throws IOException {
        String filePath = "CertStore/" + s + ".cer";

        if (new File(filePath).isFile()) {
            FileInputStream fis = new FileInputStream(filePath);
            BufferedInputStream bis = new BufferedInputStream(fis);
            RARequestLogger.log(Level.INFO, "Certificate exists for: {0}", s);

            try {
                return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(bis);
            } catch (Exception e) {
                RARequestLogger.log(Level.SEVERE, "Unable to get cert from bis object", e);
                return null;
            }
        } else {
            RARequestLogger.log(Level.SEVERE, "Cert doesn't exist");
            return null;
        }
    }
}
