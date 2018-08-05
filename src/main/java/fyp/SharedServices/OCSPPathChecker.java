package fyp.SharedServices;

import fyp.SharedServices.CertificateHandler;
import fyp.SharedServices.OCSPHandler;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.math.BigInteger;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

public class OCSPPathChecker extends PKIXCertPathChecker {

    private static final Logger OCSPPathLogger = Logger.getLogger(OCSPHandler.class.getName());
    private X509Certificate ocspResponderCert;
    private String ocspIP;
    private int ocspPort;

    public OCSPPathChecker(X509Certificate issuerCert, X509Certificate ocspResponderCert) {
        this.ocspResponderCert = ocspResponderCert;
        String ocspResponderURL = CertificateHandler.ocspURLFromCert(issuerCert);
        this.ocspIP = ocspResponderURL.split(":")[0];
        this.ocspPort = new Integer(ocspResponderURL.split(":")[1]);

    }

    @Override
    public void check(Certificate cert, Collection<String> extensions) throws CertPathValidatorException {

        X509Certificate x509Cert = (X509Certificate) cert; // This is the certificate we want to check
        BigInteger serial = x509Cert.getSerialNumber(); // Get the serial
        String message = "";
        try {
            OCSPReq ocspreq = OCSPHandler.generateOCSPRequest(ocspResponderCert, serial); // Create an OCSP Request

            byte[] resp = null;

            try {
                SSLSocketFactory f = (SSLSocketFactory) SSLSocketFactory.getDefault();
                SSLSocket c = (SSLSocket) f.createSocket(ocspIP, ocspPort);
                c.startHandshake();
                DataOutputStream w = new DataOutputStream(c.getOutputStream());
                DataInputStream r = new DataInputStream(c.getInputStream());
                w.write(ocspreq.getEncoded());
                resp = CertificateHandler.readDataFromInputStream(r);
                w.close();
                r.close();
            } catch (Exception e) {
                throw new Exception(e);
            }

            try {
                OCSPResp response = new OCSPResp(resp); // Parse it to OCSPResp
                //message = OCSPHandler.analyseResponse(response, ocspreq, ocspResponderCert); // Analyse the response


                BasicOCSPResp basicResponse = (BasicOCSPResp) response.getResponseObject(); // retrieve the Basic Resp of the Response


                if (basicResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(ocspResponderCert.getPublicKey()))) {
                    
                    SingleResp[] responses = basicResponse.getResponses();

                    byte[] reqNonce = ocspreq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce).getExtnId().getEncoded();
                    byte[] respNonce = basicResponse.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce).getExtnId().getEncoded();

                    // validate the nonce if exists
                    if (reqNonce == null || Arrays.equals(reqNonce, respNonce)) { //If both nonces match

                        for (int i = 0; i != responses.length;) {
                            message += "Certificate number " + responses[i].getCertID().getSerialNumber();
                            if (responses[i].getCertStatus() == CertificateStatus.GOOD) {
                                message = message + "; Status: Good";
                            } else {
                                message = message + "; Status: Revoked";
                            }
                        }
                        OCSPPathLogger.log(Level.INFO, message);
                    } else {
                        OCSPPathLogger.log(Level.INFO, "Unable to get nonce from response.");
                    }
                } else {
                    OCSPPathLogger.log(Level.INFO, "Unable to read OCSP signature or signature invalid.");
                }

            } catch (Exception e) {
                throw new CertPathValidatorException(new String(resp));
            }

        } catch (Exception e) {
            throw new CertPathValidatorException("Could not connect with OCSP Responder", e);
        }

        if (message.endsWith("Good")) {
            System.out.println("OCSP Response: Certificate: " + serial + " is valid!");
        } else {
            throw new CertPathValidatorException(message);
        }
    }
   
    @Override
     public void init(boolean forwardChecking) throws CertPathValidatorException {
         
    }

    @Override
    public boolean isForwardCheckingSupported() {
        return true;
    }

    @Override
    public Set<String> getSupportedExtensions() {
        return null;
    }
}
