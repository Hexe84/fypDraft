/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package fyp.SharedServices;

import java.math.BigInteger;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;

import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 *
 * @author Marta
 */
public class OCSPValidator {

    private static final Logger OCSPValidatorLogger = Logger.getLogger(OCSPValidator.class.getName());

    public enum CertificateStatus {
        Good,
        Revoked,
        Unknown
    }

    public static void validate(X509Certificate deviceCert, X509Certificate issuerCert, String ocspIP, int ocspPort) throws Exception {

        OCSPValidatorLogger.log(Level.INFO, "OCSP certificate validation request called for deviceCert: {0}, issuerCert: {1}, certID: {2}", new Object[]{deviceCert.getSubjectDN().getName(), issuerCert.getSubjectDN().getName(), deviceCert.getSerialNumber()});

        try {
            //Security.addProvider(new BouncyCastleProvider());
            AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withECDSA");
            AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
            CertificateID certID = new CertificateID(
                    //new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                    new JcaDigestCalculatorProviderBuilder().setProvider("BC").build().get(digAlgId),
                    new JcaX509CertificateHolder(issuerCert), deviceCert.getSerialNumber());

            OCSPReqBuilder builder = new OCSPReqBuilder();
            builder.addRequest(certID);
            //create a nonce to avoid replay attack
            BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());

            Extension ext = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, true, new DEROctetString(nonce.toByteArray()));
            builder.setRequestExtensions(new Extensions(new Extension[]{ext}));
            //OCSPResp resp = sendOCSPReq(builder.build(), ocspIP, ocspPort);
            OCSPResp response = new HandshakeHandler(ocspIP, ocspPort).validateCertificate(builder.build());
            System.out.println("resp byte[] object ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::/n " + new String(response.getEncoded()));
            //OCSPResp response = new OCSPResp(resp);
            //OCSPResp response = this.sendOCSPReq(builder.build(), ocspIP, ocspPort);
            //BasicOCSPResp resp = basicBuilder.build(
            //    new JcaContentSignerBuilder("SHA256withRSA").build(issuer.getPrivateKey()),
            //    null, new Date());
            BasicOCSPResp basicOCSPResponse = (BasicOCSPResp) response.getResponseObject();
            Optional<SingleResp> singleResponse = Arrays.stream(basicOCSPResponse.getResponses())
                    .filter(singleResp -> singleResp.getCertID().equals(certID)).findFirst();
            if (!singleResponse.isPresent()) {
                throw new RuntimeException("No OCSP response is present");
            }
            org.bouncycastle.cert.ocsp.CertificateStatus status = singleResponse.get().getCertStatus();
            if (status == org.bouncycastle.cert.ocsp.CertificateStatus.GOOD) {
                OCSPValidatorLogger.log(Level.INFO, "OCSP certificate validation : status = 'GOOD' ");
            } else //create case for unknown and revoked status
            {
                OCSPValidatorLogger.log(Level.INFO, "OCSP certificate validation : status = ", status);
                throw new IllegalStateException(String.format("Unknown OCSP certificate status <%s> received", status));
            }
        } catch (RuntimeException e) {
            throw e;
        }
    }

    /*
     * RESTRICTED METHODS
     */
 /*
    private static OCSPResp sendOCSPReq(OCSPReq request, String ocspIP, int ocspPort) throws IOException {
        byte[] bytes = request.getEncoded();
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setRequestProperty("Content-Type", "application/ocsp-request");
        connection.setRequestProperty("Accept", "application/ocsp-response");
        connection.setDoOutput(true);
        OCSPValidatorLogger.log(Level.INFO, "Sending OCSP request to ", url);
        try (DataOutputStream outputStream = new DataOutputStream(new BufferedOutputStream(connection.getOutputStream()))) {
            outputStream.write(bytes);
            outputStream.flush();
        }
        //if (connection.getResponseCode() != 200) {
            OCSPValidatorLogger.log(Level.INFO, "OCSP request response code (HTTP {0} - {1}", new Object[]{connection.getResponseCode(), connection.getResponseMessage()});
        //}
        try (InputStream in = (InputStream) connection.getContent()) {
            return new OCSPResp(in);
        }
    }
     */
 /*
    private static byte[] sendOCSPReq(OCSPReq ocspReq, String ocspIP, int ocspPort) throws IOException {
        byte[] resp = null;
        try {
            SSLSocketFactory f = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket c = (SSLSocket) f.createSocket(ocspIP, ocspPort);
            c.startHandshake();
            DataOutputStream w = new DataOutputStream(c.getOutputStream());
            DataInputStream r = new DataInputStream(c.getInputStream());
            //- handshakehandler
            System.out.println("OCSP RESPONSE ------------------------------------" + Arrays.toString(ocspReq.getEncoded()));

            w.write(ocspReq.getEncoded());
            try {
                resp = CertificateHandler.readDataFromInputStream(r);
                System.out.println("OCSPResp read data from input resp: " + new String(resp));
            } catch (Exception e) {
                OCSPValidatorLogger.log(Level.SEVERE, "OCSPResp read data from input exception", e);
            }
            //handshakeHandler.validateCertificate(ocspReq)
            w.close();
            r.close();
        } catch (Exception e) {
                OCSPValidatorLogger.log(Level.SEVERE, "OCSPResp read data from input exception", e);
        }

        return resp;

    }
     */
 /* private static CertificateID generateCertificateIdForRequest(BigInteger deviceCertSerialNumber, X509Certificate issuerCert)
            throws OperatorCreationException, CertificateEncodingException, OCSPException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        return new CertificateID(
                new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                new JcaX509CertificateHolder(issuerCert), deviceCertSerialNumber);
    }
     */
}
