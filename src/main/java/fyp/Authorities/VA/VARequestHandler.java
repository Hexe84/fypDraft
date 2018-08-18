package fyp.Authorities.VA;

import fyp.SharedServices.CertificateHandler;
import fyp.SharedServices.LogFile;
import fyp.SharedServices.OCSPHandler;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import javax.net.ssl.SSLSocket;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.URL;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.io.IOUtils;

public class VARequestHandler extends Thread implements Runnable {

    private SSLSocket clientSslSocket;
    private DataInputStream clientDataInputStream;
    private DataOutputStream clientDataOutputStream;
    private X509Certificate vaCert;
    private PrivateKey vaKey;
    private Logger vaLogger = Logger.getLogger(VARequestHandler.class.getName());

    public VARequestHandler(SSLSocket clientSslSocket, X509Certificate vaCert, PrivateKey vaKey) {
        LogFile.logFile(vaLogger);
        try {
            this.clientSslSocket = clientSslSocket;
            this.clientDataInputStream = new DataInputStream(clientSslSocket.getInputStream());
            this.clientDataOutputStream = new DataOutputStream(clientSslSocket.getOutputStream());
            this.vaCert = vaCert;
            this.vaKey = vaKey;
        } catch (IOException e) {
            vaLogger.log(Level.SEVERE, "Unable to create data streaming", e);
        }
    }

    @Override
    public void run() {
        try {
            System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
            System.out.println(clientDataInputStream.toString());
            byte[] request = CertificateHandler.readDataFromInputStream(clientDataInputStream);
            // OCSPReq from the requestData
            OCSPReq ocspRequest = new OCSPReq(request);
            vaLogger.log(Level.INFO, "OCSP Request created for Serial Number : {0}", ocspRequest.getRequestList()[0].getCertID().getSerialNumber());
            OCSPResp ocspResponse = OCSPHandler.generateOCSPResponse(ocspRequest, this.vaCert, this.vaKey); //Generate the response
            clientDataOutputStream.write(ocspResponse.getEncoded());
            vaLogger.log(Level.INFO, "Response sent to : {0} ", clientSslSocket.getInetAddress().getHostAddress());

        } catch (Exception e) {
            vaLogger.log(Level.SEVERE, "Socket error", e);
        }
        try {
            this.clientSslSocket.close();
        } catch (IOException e) {
            vaLogger.log(Level.SEVERE, "Unable to close socket", e);
        }
    }
}
