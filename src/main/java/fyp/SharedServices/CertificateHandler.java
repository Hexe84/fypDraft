package fyp.SharedServices;

import fyp.UI.UserInput;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

/**
 *
 * @author Marta
 */
public class CertificateHandler {

    private static final Logger CertHandlerLogger = Logger.getLogger(CertificateHandler.class.getName());
    static String crlUrl = "http://" + Configuration.get("RevokedPath");
    //String crlUrl = "http://" + Configuration.get("rootIP") + ":" + Configuration.get("rootPort"); + "/Revoked.crl";
    public String ocspUrl = "http://" + Configuration.get("vaIP") + ":" + Configuration.get("vaPort");

    static {
        Security.addProvider(new BouncyCastleProvider());
        LogFile.logFile(CertHandlerLogger);
    }

    /**
     * Method returns PKC10 CSR with subject name and key pair passed as
     * parameters and connects to CA/RA server to get signed cert with the CSR
     *
     */
    public static X509Certificate requestCertificate(String caIP, int caPort, String deviceSpecs, KeyPair keyPair) {
        X509Certificate cert = null;
        try {

            String subjectName = UserInput.normalizeMAC(deviceSpecs.split(";")[0]);
            PKCS10CertificationRequest csr = CSRHandler.generateCSR(subjectName, keyPair);
            System.out.println("CSR generated with Subject Name: " + csr.getSubject());
            try {
                cert = new HandshakeHandler(caIP, caPort).requestCertificate(csr, subjectName);
                
            } catch (Exception e) {
                System.out.println("CSR failed");
            }
        } catch (NoSuchAlgorithmException | OperatorCreationException e) {
            CertHandlerLogger.log(Level.SEVERE, "Certificate Request Failed! ", e);
        }
        return cert;
    }

    public static void saveCertToFile(X509Certificate cert, String fileName) throws CertificateEncodingException, IOException {
        try {
            FileUtils.writeByteArrayToFile(new File("./Certificates/" + fileName + ".cer"), cert.getEncoded());
        } catch (CertificateEncodingException e) {
            CertHandlerLogger.log(Level.SEVERE, "Unable to encode the cert!", e);
        } catch (IOException e) {
            CertHandlerLogger.log(Level.SEVERE, "Unable to create .cert file", e);
        }

    }

    /**
     * Method returns data passed via socket
     *
     * @param dis
     * @return byte[]
     * @throws java.io.IOException
     */
    public static byte[] readDataFromInputStream(DataInputStream dis) throws IOException {

        try {
            byte[] buffer = new byte[4096];
            int bytesRead = dis.read(buffer);
            //throws exception if nothing read
            if (bytesRead == -1) {
                throw new IOException();
            }
            //Create array of specific size and copy array over 
            byte[] data_fitted = new byte[bytesRead];
            System.arraycopy(buffer, 0, data_fitted, 0, bytesRead);
            return data_fitted;
        } catch (IOException e) {
            CertHandlerLogger.log(Level.SEVERE, "Unable to read from DataInputStream", e);
            throw new IOException(e);
        }

    }

    public static X509Certificate certificateFromByteArray(byte[] bytes) {
        /*
         * Method gets a X509 Certificate from byte[]
         */
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(bytes));
        } catch (Exception e) {
            CertHandlerLogger.log(Level.SEVERE, "Unable to get cert from byte[]", e);
            return null;
        }
    }

    /**
     * Return the crl url from the certificate crlDistributionPoints extension
     *
     * @param cert
     * @return
     */
    public static String crlURLFromCert(X509Certificate cert) {

        try {
            return CRLDistPoint.getInstance(X509ExtensionUtil.fromExtensionValue(cert.getExtensionValue(Extension.cRLDistributionPoints.getId()))).getDistributionPoints()[0].getDistributionPoint().getName().toASN1Primitive().toString().split("://")[1];
        } catch (IOException e) {
            CertHandlerLogger.log(Level.SEVERE, "Unable to get crlDistributionPoints from cert", e);
            return null;
        }
    }

    /*
    public static String crlURLFromCert(X509Certificate cert) {
        String url;
        try {
            byte[] crldpExtension = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
            ASN1Primitive value = X509ExtensionUtil.fromExtensionValue(crldpExtension);
            CRLDistPoint crldp = CRLDistPoint.getInstance(value);
            DistributionPoint[] distributionPoints = crldp.getDistributionPoints();
            url = distributionPoints[0].getDistributionPoint().getName().toASN1Primitive().toString();
            return url.substring(4, url.length() - 1);
        } catch (IOException e) {
            CertHandlerLogger.log(Level.SEVERE, "Unable to get CRLDistPoint from cert", e);
            return null;

        }
    }
     */
    /**
     * Return the OCSP Responder url from the certificate extension
     * authorityInfoAccess
     *
     * @param cert
     * @return
     */
    public static String ocspURLFromCert(X509Certificate cert) {

        try {
            return AuthorityInformationAccess.getInstance(X509ExtensionUtil.fromExtensionValue(cert.getExtensionValue(Extension.authorityInfoAccess.getId()))).getAccessDescriptions()[0].getAccessLocation().getName().toASN1Primitive().toString().split("://")[1];
        } catch (Exception e) {
            CertHandlerLogger.log(Level.SEVERE, "Unable to get OCSP url from cert", e);
            return null;
        }
    }

    /*
    public static Certificate[] createNewChain(Certificate[] chain, X509Certificate cert) {
        
        // Add the given certificate to the chain Certificate[]
        
        Certificate[] newchain = new Certificate[chain.length + 1];
        System.arraycopy(chain, 0, newchain, 0, chain.length);
        newchain[chain.length] = cert;
        return newchain;
    }
     */
 /*
    public static String getSubjectName(X509Certificate cert) {
        X500Name x500name = null;
        try {
            x500name = new JcaX509CertificateHolder(cert).getSubject();
        } catch (CertificateEncodingException e) {

            CertHandlerLogger.log(Level.SEVERE, "Unable to get Subject from cert", e);
        }
        RDN cn = x500name.getRDNs(BCStyle.CN)[0];
        return IETFUtils.valueToString(cn.getFirst().getValue());
    }
     */
    public static X509Certificate createSelfSignedCertificate(String subjectName, KeyPair keyPair, String ocspUrl) throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {

        BigInteger serialNumber = BigInteger.TEN;

        Calendar cal = Calendar.getInstance();
        Date notBefore = cal.getTime();
        cal.add(Calendar.YEAR, 30);
        Date notAfter = cal.getTime();

        X500Name subjectx500Name = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, subjectName).build();
        X500Name issuerx500Name = subjectx500Name;

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerx500Name, serialNumber, notBefore, notAfter, subjectx500Name, keyPair.getPublic());

        //Signed by its own private key (for root CA)
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(keyPair.getPrivate());

        //------------------------- Extensions ------------------------
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        SubjectKeyIdentifier subjKeyId = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic());
        builder.addExtension(Extension.subjectKeyIdentifier, false, subjKeyId);

        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign)); //KeyUsage must be critic
        ASN1EncodableVector purposes = new ASN1EncodableVector();
        //purposes.add(KeyPurposeId.id_kp_OCSPSigning);
        purposes.add(KeyPurposeId.anyExtendedKeyUsage);
        builder.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes));
        GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(crlUrl));
        DistributionPointName distributionPointName = new DistributionPointName(new GeneralNames(generalName));
        DistributionPoint distributionPoint = new DistributionPoint(distributionPointName, null, null);
        DERSequence derSequence = new DERSequence(distributionPoint);
        builder.addExtension(Extension.cRLDistributionPoints, false, derSequence);
        GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(ocspUrl));
        AuthorityInformationAccess aia = new AuthorityInformationAccess(Extension.authorityInfoAccess, gn);
        builder.addExtension(Extension.authorityInfoAccess, false, aia);

        //-------------------
        X509CertificateHolder holder = builder.build(contentSigner);

        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
    }

    //public static X509Certificate createSignedCertificateIntermediate(String commonName, KeyPair keyPair, X509Certificate signerCertificate, PrivateKey issuerPrivateKey, Boolean isVA, String ocspUrl) throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {
    public static X509Certificate createSignedCertificateIntermediate(KeyPair keyPair, String commonName, X509Certificate signerCertificate, PrivateKey signerPrivateKey, Boolean isVA, String ocspUrl) throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {
        /* EXTENSION:CRITICAL
         * basicConstraint(true)
		 * authorityKeyIdentifier keyid:always, issuer:always false
		 * subjectKeyIdentifier:hash false
		 * KeyUsage: KeyCertSign
		 *
		 * ExtendedKeyUsage:
		 * authorityInfoAccess: http://ocsp.localhost.org
         */
        //KeyPair keyPair = CertificateHandler.generateKeyPair();
        // X500Name signerName = new X500Name(signerCertificate.getSubjectDN().getName());
        //X500Name subjectName = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, subject).build();
        //X500Name subjectName = new X500Name("CN=Device " + subject);

        String currentTimeInMills = String.valueOf(1000 * System.currentTimeMillis());
        BigInteger certificateSerialNumber = new BigInteger(currentTimeInMills);

        Calendar calendar = Calendar.getInstance();
        Date notBefore = calendar.getTime();
        if (isVA == true) {
            calendar.add(Calendar.MONTH, 1); // valid for short time if it's VA
        } else {
            calendar.add(Calendar.YEAR, 30); // valid for 30 years
        }
        Date notAfter = calendar.getTime();

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(signerCertificate, certificateSerialNumber, notBefore, notAfter, new X500Principal("CN=" + commonName), keyPair.getPublic());

        ContentSigner cSigner = new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(signerPrivateKey);
        //eXTENSIONS
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        builder.addExtension(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic()));
        builder.addExtension(Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(signerCertificate));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        if (ocspUrl != null) {
            GeneralName ou = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(ocspUrl));
            builder.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(Extension.authorityInfoAccess, ou));
        }
//for VA neededExtension
        if (isVA == true) {
            ASN1EncodableVector purposes = new ASN1EncodableVector();
            purposes.add(KeyPurposeId.id_kp_OCSPSigning);
            //new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.5")
            //ASN1EncodableVector purposes1 = new ASN1EncodableVector();
            //purposes1.add(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck);
            //purposes1.add(null);
            //purposes.add(KeyPurposeId.anyExtendedKeyUsage);
            //purposes.add(KeyPurposeId.id_kp_macAddress);
            //builder.addExtension(new Extension(purposes1), false, new DERSequence(purposes));
            //non-critical ocsp_nocheck extension 
            //builder.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck, false, new DERSequence(purposes1));
            //TODO: figure out how to add extension ocsp_nocheck and ocsp_nonce - do I need nonce 

            builder.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes));
            /*
            AccessDescription ocsp = new AccessDescription(AccessDescription.id_ad_ocsp,
                    new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String("http://ocsp.localhost.org")));

            ASN1EncodableVector aia_ASN = new ASN1EncodableVector();
            aia_ASN.add(caIssuers);
            aia_ASN.add(ocsp);

            certGen.addExtension(Extension.authorityInfoAccess, false, new DERSequence(aia_ASN));
            kUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment |);
             */
        }

        X509CertificateHolder holder = builder.build(cSigner);

        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
    }

    /*
         * Sign the given OKCS10CertificationRequest with the given private key
     */
    public static X509Certificate createDeviceCertificate(PrivateKey signerPrivateKey, X509Certificate signerCertificate, X500Name commonName, SubjectPublicKeyInfo subjectPublicKeyInfo, String ocspUrl) throws IOException, OperatorCreationException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException {

        /* EXTENSION:	CRITICAL
         * basicConstraints(false)true
		 * authorityKeyIdentifier keyid:always
		 * subjectKeyIdentifier:hash
		 * keyUsage: digitalSignature, nonRepudiation
		 * nsComment "Device Certificate"
		 * authorityInfoAccess: http://ocsp.localhost.or
         */
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withECDSA");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        AsymmetricKeyParameter parameterCa = PrivateKeyFactory.createKey(signerPrivateKey.getEncoded());

        X500Name issuerName = new X500Name(signerCertificate.getSubjectDN().getName());
        //Serial number should be unique - like combination of device MAC and timestamp
        // String SN_String = commonName.toString() + String.valueOf(System.currentTimeMillis());
        String SN_String = String.valueOf(System.currentTimeMillis());
        BigInteger certificateSerialNumber = new BigInteger(SN_String);

        Calendar calendar = Calendar.getInstance();
        Date notBefore = calendar.getTime();
        calendar.add(Calendar.YEAR, 30); // cert valid long enough to last the lifetime of the device 
        Date notAfter = calendar.getTime();

        X509v3CertificateBuilder certificateGenerator = new X509v3CertificateBuilder(issuerName, certificateSerialNumber, notBefore, notAfter, commonName, subjectPublicKeyInfo);

        ContentSigner sigGen = new BcECContentSignerBuilder(sigAlgId, digAlgId).build(parameterCa);

        //------------------------- Extensions ------------------------
        certificateGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        certificateGenerator.addExtension(Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(signerCertificate));

        SubjectKeyIdentifier subjectKeyId = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(subjectPublicKeyInfo);
        certificateGenerator.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyId);
        certificateGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.dataEncipherment | KeyUsage.nonRepudiation | KeyUsage.keyEncipherment));

        GeneralName gName = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(ocspUrl));
        AuthorityInformationAccess aic = new AuthorityInformationAccess(Extension.authorityInfoAccess, gName);
        certificateGenerator.addExtension(Extension.authorityInfoAccess, false, aic);

        /*List<GeneralName> altNames = new ArrayList<>();
        String manufacturer = "Toshiba";
        String type = "Fridge";
        altNames.add(new GeneralName(GeneralName.otherName, new DERIA5String(manufacturer)));
        altNames.add(new GeneralName(GeneralName.otherName, new DERIA5String(type)));

        GeneralNames subjectAltNames = GeneralNames.getInstance(new DERSequence((GeneralName[]) altNames.toArray(new GeneralName[]{})));
        certificateGenerator.addExtension(Extension.targetInformation, false, subjectAltNames);
         */
        // GeneralName gN = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(manufacturer));
        //SubjectAlternativeName aic1 = new SubjectAlternativeName(Extension.subjectAlternativeName, gN);
        // certificateGenerator.addExtension(Extension.subjectAlternativeName, false, aic1);
        /*// OSNA OID 1.3.6.1.4.1.44409
        
                ASN1ObjectIdentifier asn1iod = new ASN1ObjectIdentifier("1.3.6.1.4.1.44409");
        ASN1Encodable asn1E = sigAlgId.getParameters();
        builder.addExtension(asn1iod, false,asn1E);
        
        
        //-------------other solution
        Asn1EncodableVector otherName = new Asn1EncodableVector();
        otherName.Add(new DerObjectIdentifier("1.3.6.1.4.1.44409"));
        otherName.Add(new DerTaggedObject(true, GeneralName.OtherName, new DerUtf8String(siteName)));
        Asn1Object upn = new DerTaggedObject(false, 0, new DerSequence(otherName));
        Asn1EncodableVector generalNames = new Asn1EncodableVector();
        generalNames.Add(upn);

        // Adding extension to X509V3CertificateGenerator
        certificateGenerator.addExtension(X509Extensions.SubjectAlternativeName, false, new DerSequence(generalNames));
        // ---------------end of other solution
         */

 /*
        GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(crlUrl));
        GeneralNames generalNames = new GeneralNames(generalName);
        DistributionPointName distributionPointName = new DistributionPointName(generalNames);
        DistributionPoint distributionPoint = new DistributionPoint(distributionPointName, null, null);
        DERSequence derSequence = new DERSequence(distributionPoint);
        certificateGenerator.addExtension(Extension.cRLDistributionPoints, false, derSequence);
         */
        //ASN1EncodableVector purposes = new ASN1EncodableVector();
        //purposes.add(KeyPurposeId.id_kp_serverAuth);
        //purposes.add(KeyPurposeId.id_kp_clientAuth);
        //purposes.add(KeyPurposeId.anyExtendedKeyUsage);
        //purposes.add(KeyPurposeId.id_kp_macAddress);
        //builder.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes));
        X509CertificateHolder holder = certificateGenerator.build(sigGen);
        return (X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
    }

    public static KeyPair generateKeyPair() {
        KeyPairGenerator kpGen = null;
        try {
            kpGen = KeyPairGenerator.getInstance("ECDSA", "BC");
            kpGen.initialize(new ECGenParameterSpec("prime256v1"), new SecureRandom());
            //kpGen = KeyPairGenerator.getInstance("RSA", "BC");
            //kpGen.initialize(1024);

        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            CertHandlerLogger.log(Level.SEVERE, "Unable to generate KeyPair", e);
        }
        return kpGen.generateKeyPair();
    }

    public static void validateCertificate(X509Certificate userCert, X509Certificate issuerCert, X509Certificate ocspResponderCert) {
        try {

            OCSPHandler.checkPathDeviceCertificate(userCert, false, new OCSPPathChecker(issuerCert, ocspResponderCert), new X509Certificate[]{}, issuerCert);
        } catch (Exception e) {
            CertHandlerLogger.log(Level.SEVERE, "Cannot retrieve certificate from KeyStore ", e);

        }
    }
}
