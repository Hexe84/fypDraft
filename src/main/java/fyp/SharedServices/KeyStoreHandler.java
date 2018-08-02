package fyp.SharedServices;

import com.google.common.io.Files;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Marta
 */
public class KeyStoreHandler {

    private static final Logger KeyStoreLogger = Logger.getLogger(KeyStoreHandler.class.getName());

    static {
        Security.addProvider(new BouncyCastleProvider());
        LogFile.logFile(KeyStoreLogger);
    }

    public static KeyStore getKeyStore(String path, String password) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, NoSuchProviderException, OperatorCreationException {

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        File keyStoreFile = new File(path);

        if (!keyStoreFile.exists()) {
            Files.createParentDirs(keyStoreFile);
            keyStore.load(null);
            keyStore.store(new FileOutputStream(path), password.toCharArray());
        } else {
            keyStore.load(new FileInputStream(path), password.toCharArray());
        }
        return keyStore;
    }

    public static void storeCertificateEntry(String certificateAlias, X509Certificate certificate, String path, String password) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, NoSuchProviderException, OperatorCreationException {
        try{
        KeyStore keyStore = getKeyStore(path, password);
        keyStore.setCertificateEntry(certificateAlias, certificate);
        keyStore.store(new FileOutputStream(path), password.toCharArray());
        }
        catch(KeyStoreException | CertificateException | NoSuchAlgorithmException e){
            KeyStoreLogger.log(Level.SEVERE, "Unable to read device cert from device Keystore", e);
        }
    }

    public static void storePrivateKeyEntry(String kAlias, PrivateKey kPrivate, X509Certificate cert, String path, String password) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, NoSuchProviderException, OperatorCreationException {
        KeyStore keyStore = getKeyStore(path, password);
        keyStore.setKeyEntry(kAlias, kPrivate, password.toCharArray(), new Certificate[]{cert});
        keyStore.store(new FileOutputStream(path), password.toCharArray());
    }

    public static X509Certificate getCertificate(String certAlias, String path, String password) throws Exception {
        try {
            return (X509Certificate) getKeyStore(path, password).getCertificate(certAlias);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | NoSuchProviderException | OperatorCreationException e) {
            throw new Exception("Unable to retrieve certificate from the keyStore", e);
        }
    }

    public static PrivateKey getPrivateKey(String keyAlias, String path, String password) throws Exception {
        try {
            return (PrivateKey) getKeyStore(path, password).getKey(keyAlias, password.toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | NoSuchProviderException | OperatorCreationException | UnrecoverableKeyException e) {
            throw new Exception("Unable to retrieve private key from the keyStore", e);
        }
    }
}
