package fyp.SharedServices;

import fyp.SharedServices.CertificateHandler;
import fyp.SharedServices.LogFile;
import java.io.ByteArrayInputStream;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

public class HandshakeHandler {

    private static final Logger handshakeLogger = Logger.getLogger(HandshakeHandler.class.getName());
    DataInputStream dataInputStream;
    DataOutputStream dataOutputStream;
    SSLSocket sslSocket;

    public HandshakeHandler(String ip, int port) throws IOException {
        LogFile.logFile(handshakeLogger);
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        this.sslSocket = (SSLSocket) sf.createSocket(ip, port);
        this.sslSocket.startHandshake();
        this.dataInputStream = new DataInputStream(sslSocket.getInputStream());
        this.dataOutputStream = new DataOutputStream(sslSocket.getOutputStream());
    }

    public X509Certificate requestCertificate(PKCS10CertificationRequest csr, String deviceSpecs) throws IOException {
        byte[] response;
        //Output device specification
        
        dataOutputStream.write(deviceSpecs.getBytes());
        response = CertificateHandler.readDataFromInputStream(dataInputStream);
        //write the CSR to the RA
        dataOutputStream.write(csr.getEncoded());
        response = CertificateHandler.readDataFromInputStream(dataInputStream);
        X509Certificate cert = null;
        String hostInfo = sslSocket.getInetAddress().getCanonicalHostName() + ":" + sslSocket.getPort();
        try {
            System.out.println("CSR request sent to " + hostInfo);
            // retrieve the certificate from the byte[] object
            cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(response));
            handshakeLogger.log(Level.INFO, String.format("Certificate %d successfully created for %s", cert.getSerialNumber(), hostInfo));

        } catch (Exception e) {
            handshakeLogger.log(Level.SEVERE, String.format("%s : %s", hostInfo, new String(response)), e);
        }
        return cert;

    }

    public String revokeCertificate(String deviceMAC) throws IOException {
        dataOutputStream.write(deviceMAC.getBytes());
        // device status
        byte[] response = CertificateHandler.readDataFromInputStream(dataInputStream);
        System.out.println("Data Input Stream response: " + new String(response));
        // revocation request
        dataOutputStream.write("Revocation Request".getBytes());
        // read response and display
        //String responseMessage = new String(CertificateHandler.readDataFromInputStream(dataInputStream));
        String hostInfo = sslSocket.getInetAddress().getCanonicalHostName() + ":" + sslSocket.getPort();
        System.out.println("Certificate Revocation Request sent to " + hostInfo );
        //TODO: check if it gives the same as above
        //get response on revocation request
        //responseMessage = new String(CertificateHandler.readDataFromInputStream(dataInputStream));
        //System.out.println(hostInfo + " : " + responseMessage);
        
        return new String("------------------------ "+response+ "------------------------ ");
    }

}
