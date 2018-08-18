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
import java.security.SecureRandom;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

public class OCSPPathChecker extends PKIXCertPathChecker {

    private static final Logger OCSPPathLogger = Logger.getLogger(OCSPHandler.class.getName());
    private X509Certificate ocspResponderCert;
    private String ocspIP;
    private int ocspPort;

    public OCSPPathChecker(X509Certificate issuerCert, X509Certificate ocspResponderCert) {
        this.ocspResponderCert = ocspResponderCert;
        String ocspURL = null; // Get the address of the OCSP Responder of the cert
        try {
            ocspURL = AuthorityInformationAccess.getInstance(X509ExtensionUtil.fromExtensionValue(issuerCert.getExtensionValue(Extension.authorityInfoAccess.getId()))).getAccessDescriptions()[0].getAccessLocation().getName().toASN1Primitive().toString().split("://")[1];
        } catch (Exception e) {
            OCSPPathLogger.log(Level.SEVERE, "Unable to get OCSP url from cert", e);
        }
        this.ocspIP = ocspURL.split(":")[0];
        this.ocspPort = new Integer(ocspURL.split(":")[1]);

    }

    @Override
    public void check(Certificate cert, Collection<String> extensions) throws CertPathValidatorException {

        X509Certificate c = (X509Certificate) cert;
        BigInteger serialNo = c.getSerialNumber();
        String message = "";
        try {
            OCSPReq ocspreq = null;
            try {
                //ocspreq = OCSPHandler.generateOCSPRequest(ocspResponderCert, serialNo); // Create an OCSP Request
                CertificateID id = new CertificateID(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build().get(CertificateID.HASH_SHA1), new X509CertificateHolder(ocspResponderCert.getEncoded()), serialNo);
                OCSPReqBuilder ocspGen = new OCSPReqBuilder();
                ocspGen.addRequest(id);
                BigInteger ocspNonce = new BigInteger(150, new SecureRandom());
                Extension ext = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, true, new DEROctetString(ocspNonce.toByteArray()));
                ocspGen.addRequest(id).setRequestExtensions(new Extensions(new Extension[]{ext}));
                ocspGen.build();
            } catch (Exception e) {

                System.out.println("_________________________------------------------------------------__________________________________" + e.getMessage());
                OCSPPathLogger.log(Level.SEVERE, "Unable to create OCSPRequest object! =-=========");
            }
            byte[] resp = null;

            try {
                SSLSocketFactory f = (SSLSocketFactory) SSLSocketFactory.getDefault();
                SSLSocket s = (SSLSocket) f.createSocket(ocspIP, ocspPort);
                s.startHandshake();
                DataInputStream read = new DataInputStream(s.getInputStream());
                try (DataOutputStream write = new DataOutputStream(s.getOutputStream())) {
                    write.write(ocspreq.getEncoded());
                    resp = CertificateHandler.readDataFromInputStream(read);

                } catch (Exception ex) {
                    throw new Exception(ex);
                }

                read.close();
            } catch (Exception e) {
                System.out.println("___________________llllllllllllllllllllllllllllllllllllllllllllll__________________________");
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
            System.out.println("OCSP Response: Certificate: " + serialNo + " is valid!");
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
