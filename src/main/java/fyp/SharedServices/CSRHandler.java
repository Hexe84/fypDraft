package fyp.SharedServices;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Marta
 */
public class CSRHandler {

    private static final Logger CSRLogger = Logger.getLogger(CSRHandler.class.getName());
    static {
        LogFile.logFile(CSRLogger);
    
    }

    public static PKCS10CertificationRequest generateCSR(String name, KeyPair keyPair) throws NoSuchAlgorithmException, OperatorCreationException {
        try {
            SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
            PKCS10CertificationRequestBuilder csrBuilder = new PKCS10CertificationRequestBuilder(new X500Name("CN=Device " + name), keyInfo);
            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(keyPair.getPrivate());
            return csrBuilder.build(contentSigner);
        } catch (OperatorCreationException e) {
            CSRLogger.log(Level.SEVERE, "Unable to generate csr", e);
            throw e;
        }
    }
}