package fyp.UI;

import fyp.SharedServices.KeyStoreHandler;
import fyp.SharedServices.OCSPHandler;
import fyp.SharedServices.LogFile;
import fyp.SharedServices.CertificateHandler;
import fyp.SharedServices.Configuration;
import fyp.SharedServices.DatabaseHandler;
import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.operator.OperatorCreationException;

/**
 *
 * @author Marta
 */
public class PKISetup {

    private static Logger MainTestLogger = Logger.getLogger(PKISetup.class.getName());
//Trust setting up method 

    public static void main(String... args) throws CertificateParsingException, InvalidKeyException, SecurityException, SignatureException {

        LogFile.logFile(MainTestLogger);
        try {

            String OCSP_URL = "http://" + Configuration.get("vaIP") + ":" + Configuration.get("vaPort");

            // ---------------------- Root CA SETUP
            String rootName = Configuration.get("rootAlias");
            String rootKeyStorePath = Configuration.get("rootKeystorePath");
            String rootKeyStorePassword = Configuration.get("rootKeystorePass");
            String rootTrustStorePath = Configuration.get("rootTruststorePath");
            String rootTrustStorePassword = Configuration.get("rootTruststorePass");
            String rootCertificateAlias = Configuration.get("rootCertAlias");
            String rootKeyAlias = Configuration.get("rootKeyAlias");
            String certStorePath = Configuration.get("certstorePath");
            String certStorePassword = Configuration.get("certstorePass");
            KeyPair rootKeyPair = CertificateHandler.generateKeyPair();
            // Generate self signed certificate for the Root CA
            X509Certificate rootCert = CertificateHandler.createSelfSignedCertificate(rootName, rootKeyPair);

            // Store private Key and cert in the CA keystore
            KeyStoreHandler.storeCertificateEntry(rootCertificateAlias, rootCert, rootKeyStorePath, rootKeyStorePassword);
            KeyStoreHandler.storePrivateKeyEntry(rootKeyAlias, rootKeyPair.getPrivate(), rootCert, rootKeyStorePath, rootKeyStorePassword);
            CertificateHandler.saveCertToFile(rootCert, "Root_CA");

            /*
            //TODO: test for serializable for writing to the db
            byte[] serializedObj = SerializationUtils.serialize(rootCert);
            //String certString = new String(serializedObj,"UTF-8");
            String certString = new String(Base64.encodeBase64(serializedObj));
 
            //certString goes to DB
            System.out.println("Cert String: " + certString.length());
            System.out.println("____________________________________");
            System.out.println("Cert String: " + certString);
            byte[] byteCert = Base64.decodeBase64(certString);
            Object deserializedObj = SerializationUtils.deserialize(byteCert);
            X509Certificate newCert = (X509Certificate) deserializedObj;
            CertificateHandler.saveCertToFile(newCert, "new_rootCA");
            //end of testing
             */
            // ---------------------- CA SETUP
            String caName = Configuration.get("caAlias");
            String caKeyStorePath = Configuration.get("caKeystorePath");
            String caKeyStorePassword = Configuration.get("caKeystorePass");
            String caTrustStorePath = Configuration.get("caTruststorePath");
            String caTrustStorePassword = Configuration.get("caTruststorePass");
            String caCertificateAlias = Configuration.get("caCertAlias");
            String caKeyAlias = Configuration.get("caKeyAlias");

            KeyPair caKeyPair = CertificateHandler.generateKeyPair();
            // Generate rootCA-signed certificate for the Signing CA
            X509Certificate caCert = CertificateHandler.createSignedCertificateIntermediate(caKeyPair, caName, rootCert, rootKeyPair.getPrivate(), false);
            // Store private Key and cert in the CA keystore and Certificates directory
            KeyStoreHandler.storeCertificateEntry(caCertificateAlias, caCert, caKeyStorePath, caKeyStorePassword);
            KeyStoreHandler.storePrivateKeyEntry(caKeyAlias, caKeyPair.getPrivate(), caCert, caKeyStorePath, caKeyStorePassword);
            CertificateHandler.saveCertToFile(caCert, "CA");

            // ---------------------- RA SETUP
            String raName = Configuration.get("raAlias");
            String raKeyStorePath = Configuration.get("raKeystorePath");
            String raKeyStorePassword = Configuration.get("raKeystorePass");
            String raTrustStorePath = Configuration.get("raTruststorePath");
            String raTrustStorePassword = Configuration.get("raTruststorePass");
            String raCertificateAlias = Configuration.get("raCertAlias");
            String raKeyAlias = Configuration.get("raKeyAlias");

            KeyPair raKeyPair = CertificateHandler.generateKeyPair();
            // Generate rootCA-signed certificate for the RA 
            X509Certificate raCert = CertificateHandler.createSignedCertificateIntermediate(raKeyPair, raName, rootCert, rootKeyPair.getPrivate(), false);
            // Store private Key and cert in the RA keystore and Certificates directory
            KeyStoreHandler.storeCertificateEntry(raCertificateAlias, raCert, raKeyStorePath, raKeyStorePassword);
            KeyStoreHandler.storePrivateKeyEntry(raKeyAlias, raKeyPair.getPrivate(), raCert, raKeyStorePath, raKeyStorePassword);
            CertificateHandler.saveCertToFile(raCert, "RA");

            // ---------------------- VA SETUP
            String vaName = Configuration.get("vaAlias");
            String vaKeyStorePath = Configuration.get("vaKeystorePath");
            String vaKeyStorePassword = Configuration.get("vaKeystorePass");
            String vaCertificateAlias = Configuration.get("vaCertAlias");
            String vaKeyAlias = Configuration.get("vaKeyAlias");
            String vaTrustStorePath = Configuration.get("vaTruststorePath");
            String vaTrustStorePassword = Configuration.get("vaTruststorePass");

            KeyPair vaKeyPair = CertificateHandler.generateKeyPair();
            // Generate rootCA-signed certificate for the VA
            X509Certificate vaCert = CertificateHandler.createSignedCertificateIntermediate(raKeyPair, vaName, rootCert, rootKeyPair.getPrivate(), true);
            // Store private Key and cert in the VA keystore and Certificates directory
            KeyStoreHandler.storeCertificateEntry(vaCertificateAlias, vaCert, vaKeyStorePath, vaKeyStorePassword);
            KeyStoreHandler.storePrivateKeyEntry(vaKeyAlias, vaKeyPair.getPrivate(), vaCert, vaKeyStorePath, vaKeyStorePassword);
            CertificateHandler.saveCertToFile(vaCert, "VA");

            // CRL SETUP
            X509CRLHolder crlRoot = OCSPHandler.createCRL(rootCert, rootKeyPair.getPrivate());
            FileUtils.writeByteArrayToFile(new File(Configuration.get("RevokedPath")), crlRoot.getEncoded());

            try {
                new DatabaseHandler().createCRLTable();
            } catch (SQLException | ClassNotFoundException ex) {
                MainTestLogger.log(Level.SEVERE, "Unable to create CRL database", ex);
            }

            // TRUST STORES
            KeyStoreHandler.storeCertificateEntry(caCertificateAlias, caCert, rootTrustStorePath, rootTrustStorePassword);
            KeyStoreHandler.storeCertificateEntry(raCertificateAlias, raCert, caTrustStorePath, caTrustStorePassword);
            KeyStoreHandler.storeCertificateEntry(caCertificateAlias, caCert, raTrustStorePath, raTrustStorePassword);
            KeyStoreHandler.storeCertificateEntry(rootCertificateAlias, rootCert, raTrustStorePath, raTrustStorePassword);
            KeyStoreHandler.storeCertificateEntry(rootCertificateAlias, rootCert, caTrustStorePath, caTrustStorePassword);
            KeyStoreHandler.storeCertificateEntry(rootCertificateAlias, rootCert, vaTrustStorePath, vaTrustStorePassword);
            KeyStoreHandler.storeCertificateEntry(vaCertificateAlias, vaCert, rootTrustStorePath, rootTrustStorePassword);
            KeyStoreHandler.storeCertificateEntry(raCertificateAlias, raCert, rootTrustStorePath, rootTrustStorePassword);
            // ADD rootCA,CA,RA,VA certs to cert store
            KeyStoreHandler.storeCertificateEntry(rootCertificateAlias, rootCert, certStorePath, certStorePassword);
            KeyStoreHandler.storeCertificateEntry(caCertificateAlias, caCert, certStorePath, certStorePassword);
            KeyStoreHandler.storeCertificateEntry(raCertificateAlias, raCert, certStorePath, certStorePassword);
            KeyStoreHandler.storeCertificateEntry(vaCertificateAlias, vaCert, certStorePath, certStorePassword);

            String deviceKsPath = Configuration.get("devicesKeystorePath");
            String deviceKsPass = Configuration.get("devicesKeystorePass");
            KeyStoreHandler.getKeyStore(deviceKsPath, deviceKsPass);

            try {
                new DatabaseHandler().createCertificatesTable();
            } catch (SQLException | ClassNotFoundException ex) {
                MainTestLogger.log(Level.SEVERE, "Unable to create Certificates database", ex);
            }
            MainTestLogger.log(Level.INFO, "Authority Certificates created successfully! ");

        } catch (IOException | NoSuchAlgorithmException | OperatorCreationException | CertificateException | KeyStoreException | NoSuchProviderException e) {

            MainTestLogger.log(Level.SEVERE, "Ooops something went wrong in MainTest! ", e);
        }
    }
}
