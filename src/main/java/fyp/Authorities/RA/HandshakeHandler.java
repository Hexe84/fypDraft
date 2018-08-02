package fyp.Authorities.RA;

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
import java.util.Arrays;
import java.util.logging.Level;
//import java.util.Scanner;
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
        System.out.println("SSLSocket getEnabledCipherSuites: " + Arrays.toString(this.sslSocket.getEnabledCipherSuites()));
        this.sslSocket.startHandshake();
        this.dataInputStream = new DataInputStream(sslSocket.getInputStream());
        this.dataOutputStream = new DataOutputStream(sslSocket.getOutputStream());
    }

    public X509Certificate requestCertificate(PKCS10CertificationRequest csr, String deviceSpecs) throws IOException {
        byte[] response;
        //Output device specification
        dataOutputStream.write(deviceSpecs.getBytes());
        System.out.println("Read DataInputStream device Specs: " + dataInputStream);
        response = CertificateHandler.readDataFromInputStream(dataInputStream);
        System.out.println("Data Input Stream response: " + new String(response));
        byte[] bytesCSR = csr.getEncoded();

        System.out.println("CSR in bytes: " + bytesCSR);
        System.out.println("CSR in bytes STRING: " + Arrays.toString(bytesCSR));
        //write the CSR to the RA
        dataOutputStream.write(csr.getEncoded());
        System.out.println("Read DataInputStream STRING: " + dataInputStream);
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

}
