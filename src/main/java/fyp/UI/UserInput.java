package fyp.UI;

import fyp.SharedServices.HandshakeHandler;
import fyp.SharedServices.LogFile;
import fyp.SharedServices.CertificateHandler;
import fyp.SharedServices.Configuration;
import fyp.SharedServices.DatabaseHandler;
import fyp.SharedServices.KeyStoreHandler;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.cert.X509Certificate;
import java.util.Scanner;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import java.awt.Desktop;
import java.io.File;
import java.math.BigInteger;

/**
 *
 * @author Marta
 */
public class UserInput {

    private static final Logger UserInputLogger = Logger.getLogger(UserInput.class.getName());

    private static X509Certificate devCert;
    private static String raIP;
    private static int raPORT;
    private static String caIP;
    private static int caPORT;
    private static String tsPath;
    private static String tsPass;
    private static String deviceKsPath;
    private static String deviceKsPass;
    private static String deviceCert;
    private static String deviceKey;
    private static String caCertAlias;
    private static String raCertAlias;
    private static String vaCertAlias;
    private static String rootCertAlias;

    public static void main(String... args) throws KeyManagementException {

        LogFile.logFile(UserInputLogger);
        Security.addProvider(new BouncyCastleProvider());

        tsPath = Configuration.get("devicesTruststorePath");
        tsPass = Configuration.get("devicesTruststorePass");
        deviceCert = Configuration.get("devicesCertAlias");
        deviceKey = Configuration.get("devicesKeyAlias");
        deviceKsPath = Configuration.get("devicesKeystorePath");
        deviceKsPass = Configuration.get("devicesKeystorePass");
        raIP = Configuration.get("raIP");
        raPORT = Integer.parseInt(Configuration.get("raPort"));
        caIP = Configuration.get("caIP");
        caPORT = Integer.parseInt(Configuration.get("caPort"));
        caCertAlias = Configuration.get("caCertAlias");
        raCertAlias = Configuration.get("raCertAlias");
        vaCertAlias = Configuration.get("vaCertAlias");
        rootCertAlias = Configuration.get("rootCertAlias");
        System.setProperty("javax.net.ssl.trustStore", tsPath);
        System.setProperty("javax.net.ssl.trustStorePassword", tsPass);
        System.setProperty("javax.net.ssl.keyStore", deviceKsPath);
        System.setProperty("javax.net.ssl.keyStorePassword", deviceKsPass);
//----------------delete if needed-------------
        /*      TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("SunX509");

        trustMgrFact.init(new KeyStore(tsPath));

        SSLContext clientContext = null;

        try {
            clientContext = SSLContext.getInstance("TLS");
            clientContext.init(null, trustMgrFact.getTrustManagers(), SecureRandom.getInstance("DEFAULT", "BC"));
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(UserInput.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(UserInput.class.getName()).log(Level.SEVERE, null, ex);
        }

        try {
            SSLSocketFactory fact = clientContext.getSocketFactory();
            SSLSocket cSock = (SSLSocket) fact.createSocket(raIP, raPORT);
            OutputStream out = cSock.getOutputStream();
            InputStream in = cSock.getInputStream();
        } catch (IOException ex) {
            Logger.getLogger(UserInput.class.getName()).log(Level.SEVERE, null, ex);
        }
         */
//-------------------end of delete if needed---------------------
        /*      try {
            newCert = KeyStoreHandler.getCertificate(deviceCert, deviceKsPath, deviceKsPass);
        } catch (Exception e) {
            UserInputLogger.log(Level.SEVERE, "Unable to read get cert - device specification", e);
        }
         */
        try {
            // Establish the trust by putting authority certs into devices Truststore 
            String rootCertPath = ".\\Certificates\\Root_CA.cer";
            getCertificateFromPath(rootCertPath, rootCertAlias);
            UserInputLogger.log(Level.INFO, " Root CA Cert Successfully Imported!");

            String caCertPath = ".\\Certificates\\CA.cer";
            getCertificateFromPath(caCertPath, caCertAlias);
            UserInputLogger.log(Level.INFO, " Signing CA Cert Successfully Imported!");

            String raCertPath = ".\\Certificates\\RA.cer";
            getCertificateFromPath(raCertPath, raCertAlias);
            UserInputLogger.log(Level.INFO, " RA Cert Successfully Imported!");

            String vaCertPath = ".\\Certificates\\VA.cer";
            getCertificateFromPath(vaCertPath, vaCertAlias);
            UserInputLogger.log(Level.INFO, "VA Cert Successfully Imported!");

        } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | OperatorCreationException e) {
            UserInputLogger.log(Level.SEVERE, "Unable to import trusted authority certificates!", e);
        }

        try {
            MenuHandler menuHandler = new MenuHandler();
            menuHandler.startMenu();
        } catch (Exception e) {
            UserInputLogger.log(Level.SEVERE, "Unable to load start screen", e);
        }
    }

    /**
     * Method checks if MAC address is valid commonly it's a 6x2 number in
     * hexadecimal system e.g. 1A:2B:3C:4D:5E:6F sometimes 4x3 number e.g.
     * 1A2B.3C4D.5E6F dividers are :.-
     *
     * @return true or false
     *
     */
    public static boolean validateMac(String mac) {
        Pattern p1 = Pattern.compile("^([0-9A-Fa-f]{2}[.:-]){5}([0-9A-Fa-f]{2})$");
        Pattern p2 = Pattern.compile("^([0-9A-Fa-f]{3}[:.-]){3}[0-9A-Fa-f]{3}$");
        return (p1.matcher(mac).find() || p2.matcher(mac).find());
    }

    public static String normalizeMAC(String mac) {

        return mac.replaceAll("(\\.|\\,|\\:|\\-)", "").toUpperCase();
    }

    /*
    private static void getCertificateFromStorage(String url, String alias) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException {

        byte[] bytes = IOUtils.toByteArray(new URL(url).openStream());
        X509Certificate cert = CertificateHandler.certificateFromByteArray(bytes);
        KeyStoreHandler.storeCertificateEntry(alias, cert, tsPath, tsPass);
    }
     */
    private static void getCertificateFromPath(String path, String alias) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException {

        CertificateFactory certFactory;
        FileInputStream inStream;

        certFactory = CertificateFactory.getInstance("X.509");
        inStream = new FileInputStream(path);
        X509Certificate cer = (X509Certificate) certFactory.generateCertificate(inStream);
        KeyStoreHandler.storeCertificateEntry(alias, cer, tsPath, tsPass);
        inStream.close();
    }

    /**
     * Method reads user input as integer (if not integer then returns null)
     *
     * @return int (or null)
     */
    public static Integer readUserInt() {
        Scanner sc = new Scanner(System.in);
        try {
            String s = sc.nextLine();
            return new Integer(s);
        } catch (Exception e) {
            //UserInputLogger.log(Level.SEVERE, "Unable to read user's chosen option", e);
            System.out.println("Choose Numeric Option Again: ");
            return readUserInt();
        }
    }

    /**
     * Method reads user input of device specification and saves it as String
     * format "MAC;DeviceType;Manufacturer"
     *
     * @param mac
     * @return String (or throw exception)
     */
    public static String readDeviceSpecs(String mac) {
        try {
            Scanner sc = new Scanner(System.in);
            System.out.println("Enter Device Type: ");
            String dType = sc.nextLine();
            System.out.println("Enter Device's Manufacturer: ");
            String dManufacturer = sc.nextLine();
            return String.format("%s;%s;%s", mac, dType, dManufacturer);

        } catch (Exception e) {
            UserInputLogger.log(Level.SEVERE, "Unable to read user input - device specification", e);
            throw e;
        }
    }

    private static class MenuHandler {

        public void startMenu() throws Exception {
            String macAddr;
            Scanner sc = new Scanner(System.in);
            System.out.println("Enter device's MAC Address: ");
            try {
                macAddr = sc.nextLine();
                if (macAddr != null || !" ".equals(macAddr)) {
                    try {
                        yesNoOption(macAddr);
                    } catch (Exception e) {
                        UserInputLogger.log(Level.SEVERE, "Problem in device's MAC user confirmation");
                        startMenu();
                    }
                } else {
                    UserInputLogger.log(Level.SEVERE, "User Input Null or empty string");
                }
            } catch (Exception e) {
                UserInputLogger.log(Level.SEVERE, "Error in User input - device MAC");
                throw e;
            }
        }

        public void mainMenu(String MAC) throws Exception {
            int userOption = manageDeviceMenu();
            String normMAC = normalizeMAC(MAC);
            switch (userOption) {

                //Request new Cert
                case 1:
                    String deviceSpec = readDeviceSpecs(MAC);
                    /*      try {
                        X509Certificate DevC = KeyStoreHandler.getCertificate(deviceCert + normMAC, deviceKsPath, deviceKsPass);
                        UserInputLogger.log(Level.INFO, "Certificate for {0} already exists", DevC.getSubjectDN());
                        int uOption = manageCertMenu();
                        manageCertHandler(uOption, normMAC);
                    } catch (Exception e) {
                     */
                    KeyPair keyPair = CertificateHandler.generateKeyPair();
                    try {
                        devCert = CertificateHandler.requestCertificate(raIP, raPORT, deviceSpec, keyPair);
                    } catch (Exception e) {
                        UserInputLogger.log(Level.INFO, "#######################################################################");//TODO: delete this
                        break;
                    }

                    if (devCert != null) {
                        UserInputLogger.log(Level.INFO, "Certificate for {0} successfully created", devCert.getSubjectDN());
                        //write to the local storage / external db
                        KeyStoreHandler.storeCertificateEntry(deviceCert + normMAC, devCert, deviceKsPath, deviceKsPass);
                        KeyStoreHandler.storePrivateKeyEntry(deviceKey + normMAC, keyPair.getPrivate(), devCert, deviceKsPath, deviceKsPass);
                        CertificateHandler.saveCertToFile(devCert, "Device " + normMAC);
                        //new DatabaseHandler().saveCertToDB(devCert);
                        new DatabaseHandler().saveCertToCertDB(devCert);
                        UserInputLogger.log(Level.INFO, "Certificate for {0} saved to file and Keystore", devCert.getSubjectDN());
                    }
                    int uOption = manageCertMenu();
                    manageCertHandler(uOption, normMAC);
                    //}
                    //return ;
                    break;

                // Manage existing cert
                case 2:

                    try {
                        KeyStoreHandler.getCertificate(deviceCert + normMAC, deviceKsPath, deviceKsPass);
                        int uOp = manageCertMenu();
                        manageCertHandler(uOp, normMAC);
                    } catch (Exception e) {
                        UserInputLogger.log(Level.INFO, "Certificate for device {0} doesn't exist. Request it first!", MAC);
                        mainMenu(MAC);
                    }
                    break;

                default:
                    System.out.println("Only 1 or 2 are possible options!");
                    System.out.println("Choose again:");
                    mainMenu(MAC);
                    break;
            }

        }

        public void yesNoOption(String mAddr) throws Exception {
            Scanner sc = new Scanner(System.in);
            if (mAddr != null) {
                try {
                    System.out.println("You entered: " + mAddr + "\nAre you sure the MAC Address is correct ?[Y/N]");
                    char yesNo = sc.next().charAt(0);

                    switch (Character.toUpperCase(yesNo)) {
                        case 'Y':
                            if (validateMac(mAddr)) {
                                mainMenu(mAddr);
                            } else {
                                UserInputLogger.log(Level.SEVERE, "MAC address not valid.");
                                System.out.println("MAC address invalid. Lets try again!");
                                startMenu();

                            }
                            break;
                        case 'N':
                            startMenu();
                            break;
                        default:
                            System.out.println("Only Y/N are possible options");
                            System.out.println("Let's try again:");
                            yesNoOption(mAddr);
                            break;
                    }

                } catch (Exception e) {
                    UserInputLogger.log(Level.SEVERE, "Exception in YES/NO user input.", e);
                }
            }
        }

        private static int manageCertMenu() {
            System.out.println("========================================");
            System.out.println("|         Manage Certificate           |");
            System.out.println("========================================");
            System.out.println("| Options:                             |");
            System.out.println("|    1 - View Certificate              |");
            System.out.println("|    2 - Validate Certificate          |");
            System.out.println("|    3 - Revoke Certificate            |");
            System.out.println("|    4 - <----Go Back to Main Menu     |");
            System.out.println("========================================");
            System.out.print(" Choose Option: ");
            return readUserInt();
        }

        private static int manageDeviceMenu() {
            System.out.println("========================================");
            System.out.println("|           PKI Main Menu              |");
            System.out.println("========================================");
            System.out.println("| Options:                             |");
            System.out.println("|   1 - Request New Certificate        |");
            System.out.println("|   2 - Manage Existing Certificate    |");
            System.out.println("========================================");
            System.out.println("Choose Option: ");
            return readUserInt();
        }

        private static void manageCertHandler(int userOption, String normalizedMAC) throws Exception {
            switch (userOption) {

                case 1:
                    //1-View Certificate
                    devCert = KeyStoreHandler.getCertificate(deviceCert + normalizedMAC, deviceKsPath, deviceKsPass);
                    System.out.println(devCert);
                    Desktop.getDesktop().open(new File("./Certificates/"));
                    /*System.out.println("Press any key to cotinue...");
                    Scanner sc = new Scanner(System.in);
                    if (sc.next() != null) {*/
                    int uOption = manageCertMenu();
                    manageCertHandler(uOption, normalizedMAC);
                    //}

                    // return;
                    break;
                case 2:
                    //2-Validate Cert
                    devCert = KeyStoreHandler.getCertificate(deviceCert + normalizedMAC, deviceKsPath, deviceKsPass);
                    if (devCert == null) {
                        System.out.println("Error! You don't have a certificate, Please request a new one");
                        return;
                    }
                    //X509Certificate rootCert = KeyStoreHandler.getCertificate(rootCertAlias, tsPath, tsPass);
                    X509Certificate rootCert = KeyStoreHandler.getCertificate(rootCertAlias, tsPath, tsPass);
                    X509Certificate vaCert = KeyStoreHandler.getCertificate(vaCertAlias, tsPath, tsPass);
                    CertificateHandler.validateCertificate(devCert, rootCert, vaCert);
                    int uOpt = manageCertMenu();
                    manageCertHandler(uOpt, normalizedMAC);
                    break;
                case 3:
                    //3-Revoke cert
                    devCert = KeyStoreHandler.getCertificate(deviceCert + normalizedMAC, deviceKsPath, deviceKsPass);
                    BigInteger serialNo = devCert.getSerialNumber();

                    String rootIP = Configuration.get("rootIP");
                    int rootPort = Integer.parseInt(Configuration.get("rootPort"));

                    try {
                        new HandshakeHandler(rootIP, rootPort).revokeCertificate(serialNo);
                    } catch (Exception e) {
                        UserInputLogger.log(Level.SEVERE, "Certification Revocation Failed !", e);
                    }
                    int usrOpt = manageCertMenu();
                    manageCertHandler(usrOpt, normalizedMAC);
                    break;
                case 4:
                    //4-Go Back  
                    new MenuHandler().startMenu();
                    break;
                default:
                    System.out.println("Only options 1 - 4 are available.");
                    System.out.println("Choose again:");
                    manageCertHandler(userOption, normalizedMAC);
                    break;
            }
            System.out.println("");
        }

    }
}
