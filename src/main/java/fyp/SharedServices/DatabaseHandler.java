package fyp.SharedServices;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.sql.*;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Marta
 *
 * just a draft code to check if I can connect to the db
 */
public class DatabaseHandler {

    private static final Logger dbLogger = Logger.getLogger(DatabaseHandler.class.getName());

    //  Database credentials
    static final String DB_URL = Configuration.get("dbURL");
    static final String USER = Configuration.get("dbOwner");
    static final String PASS = Configuration.get("dbPass");
    static Connection conn;
    static Statement stmt;

    public DatabaseHandler() throws SQLException, ClassNotFoundException {
        LogFile.logFile(dbLogger);

        Class.forName("com.mysql.jdbc.Driver");
        System.out.println("Connecting to database...");
        conn = DriverManager.getConnection(DB_URL, USER, PASS);
        stmt = conn.createStatement();
        dbLogger.log(Level.INFO, "DB Connection started");

    }

    public void createCRLTable() {

        try {
            //String sql = "DROP TABLE IF EXISTS CRL"; // Delete table (if needed)
            String sql = "CREATE TABLE IF NOT EXISTS CRL "
                    + "(SerialNumber BIGINT, "
                    + " RevocationDate DATE, "
                    + " Reason VARCHAR(255), "
                    + " PRIMARY KEY ( SerialNumber ))";
            stmt.executeUpdate(sql);
            dbLogger.log(Level.INFO, "CRL database created successfully");
        } catch (SQLException se) {

            dbLogger.log(Level.SEVERE, "SQL Exception: ", se);
        } catch (Exception e) {
            dbLogger.log(Level.SEVERE, "Unable to process CREATE TABLE query", e);
        } finally {
            //close resources
            closeDatabase(conn, stmt);
        }
    }

    public void createCertificatesTable() {

        try {
            //String sql = "DROP TABLE IF EXISTS CRL"; // Delete table (if needed)
            String sql = "CREATE TABLE IF NOT EXISTS CERTIFICATES "
                    + " (SerialNumber BIGINT, "
                    + " SubjectName VARCHAR(255), "
                    + " Cert LONGBLOB, "
                    + " PRIMARY KEY ( SerialNumber ))";
            stmt.executeUpdate(sql);
            dbLogger.log(Level.INFO, "Certificates database created successfully");
        } catch (SQLException se) {

            dbLogger.log(Level.SEVERE, "SQL Exception: ", se);
        } catch (Exception e) {
            dbLogger.log(Level.SEVERE, "Unable to process query", e);
        } finally {
            //close resources
            closeDatabase(conn, stmt);
        }
    }

    /* public void saveCertToDB(X509Certificate cert) {

        //(Version, SerialNumber, SignatureAlgorithm, SignatureHashAlgorithm, Issuer, NotBefore, NotAfter, SubjectName, PublicKey, BasicConstraints, KeyUsage, AuthorityKeyIdentifier, SubjectKeyIdentifier, AuthorityInformationAccess )
        try {
            System.out.println("__________________DATABASE PARAMS_______________________1)" + cert.getVersion() + ", 2)'"
                    + cert.getSerialNumber() + ", 3)'" + cert.getSigAlgName() + ",4) "
                    + cert.getIssuerDN() + ", 5)'" + cert.getNotBefore() + "', 6)'"
                    + cert.getNotAfter() + ", 7)" + cert.getSubjectDN() + ", 8)"
                    + cert.getPublicKey().toString() + ", 9)" + cert.getBasicConstraints() + ", 10)" + Arrays.toString(cert.getKeyUsage()));

            String sql = "INSERT INTO CERTIFICATES VALUES ('" + cert.getVersion() + "', "
                    + cert.getSerialNumber() + ", '" + cert.getSigAlgName() + "', '"
                    //+ cert.getIssuerDN() + ", '" + new java.sql.Date(new SimpleDateFormat("yyyy-MM-dd").format(cert.getNotBefore())) + "', '"
                    + cert.getIssuerDN() + "', '" + new java.sql.Date(cert.getNotBefore().getTime()) + "', '"
                    + new java.sql.Date(cert.getNotAfter().getTime()) + "', '" + cert.getSubjectDN() + "', "
                    + cert.getPublicKey().toString() + ", '" + cert.getBasicConstraints() + "', '" + Arrays.toString(cert.getKeyUsage()) + "')";

            stmt.executeUpdate(sql);
        } catch (SQLException se) {
            dbLogger.log(Level.SEVERE, "SQL Exception: ", se);
        } catch (Exception e) {
            dbLogger.log(Level.SEVERE, "Unable to process query", e);
        } finally {
            //close resources
            closeDatabase(conn, stmt);
        }
    }
     */
    public static void updateCRLtoDB(BigInteger serialNo, Date revDate, String reason) {

        try {
            String sql = "INSERT INTO CRL VALUES (" + serialNo + ", '" + revDate + "', '" + reason + "')";
            stmt.executeUpdate(sql);
            dbLogger.log(Level.INFO, "CRL database updated successfully");
        } catch (SQLException se) {
            dbLogger.log(Level.SEVERE, "SQL Exception: ", se);
        } catch (Exception e) {
            dbLogger.log(Level.SEVERE, "Unable to process query", e);
        } finally {
            //close resources
            closeDatabase(conn, stmt);
        }

    }

    public static boolean isCertInCRL(BigInteger serialNo) {
        Boolean check = null;
        try {
            String sql = "SELECT * FROM CRL WHERE SerialNumber = " + serialNo;
            ResultSet rs = stmt.executeQuery(sql);
            if (!rs.isBeforeFirst()) {
                dbLogger.log(Level.INFO, "Serial Number not in CRL Database.");
                check = false;
            } else {
                dbLogger.log(Level.INFO, "Serial Number in CRL Database. Certificate revoked!");
                check = true;
            }
        } catch (SQLException se) {
            dbLogger.log(Level.SEVERE, "SQL Exception: ", se);
        } catch (Exception e) {
            dbLogger.log(Level.SEVERE, "Unable to process query", e);
        } finally {
            //close resources
            closeDatabase(conn, stmt);
        }
        return check;
    }

    public static boolean isCertInCertDB(String subjectName) {
        Boolean check = null;
        try {
            String sql = "SELECT * FROM CERTIFICATES "
                    + "WHERE SubjectName = '" + subjectName + "'";
            ResultSet rs = stmt.executeQuery(sql);
            if (!rs.isBeforeFirst()) {
                dbLogger.log(Level.INFO, "Certificate not in Database.");
                check = false;
            } else {
                dbLogger.log(Level.INFO, "Certificate in Database.");
                check = true;
            }
        } catch (SQLException se) {
            dbLogger.log(Level.SEVERE, "SQL Exception: ", se);
        } catch (Exception e) {
            dbLogger.log(Level.SEVERE, "Unable to process query", e);
        } finally {
            //close resources
            closeDatabase(conn, stmt);
        }
        return check;
    }

    private static void closeDatabase(Connection c, Statement s) {

        try {
            if (s != null) {
                s.close();
            }
        } catch (SQLException e) {
            dbLogger.log(Level.SEVERE, "Unable to close DB statement: ", e);
        }
        try {
            if (c != null) {
                c.close();
            }
            dbLogger.log(Level.INFO, "Closing DB connection");
        } catch (SQLException se) {
            dbLogger.log(Level.SEVERE, "Unable to close DB connection: ", se);
        }

    }

    //TODO: for testing only
    public void createCertsTable() {

        try {
            //String sql = "DROP TABLE IF EXISTS CERTIFICATES"; // Delete table (in needed)
            String sql = "CREATE TABLE IF NOT EXISTS CERTS "
                    + " SerialNumber BIGINT, "
                    + " Cert LONGBLOB, "
                    + " PRIMARY KEY ( SerialNumber ))";
            stmt.executeUpdate(sql);

        } catch (SQLException se) {
            dbLogger.log(Level.SEVERE, "SQL Exception: ", se);
        } catch (Exception e) {
            dbLogger.log(Level.SEVERE, "Unable to process query", e);
        } finally {
            //finally block used to close resources
            closeDatabase(conn, stmt);
        }

    }

    public void saveCertToCertDB(X509Certificate cert) {

        //(Version, SerialNumber, SignatureAlgorithm, SignatureHashAlgorithm, Issuer, NotBefore, NotAfter, SubjectName, PublicKey, BasicConstraints, KeyUsage, AuthorityKeyIdentifier, SubjectKeyIdentifier, AuthorityInformationAccess )
        //cert file needs to be in byte[] form so cert.getEncoded()
        try {
            String sql = "INSERT INTO CERTIFICATES VALUES (" + cert.getSerialNumber() + ", '" + cert.getSubjectDN() + "', '" + Arrays.toString(cert.getEncoded()) + "')";

            stmt.executeUpdate(sql);
        } catch (SQLException se) {
            dbLogger.log(Level.SEVERE, "SQL Exception: ", se);
        } catch (Exception e) {
            dbLogger.log(Level.SEVERE, "Unable to process query", e);
        } finally {
            //close resources
            closeDatabase(conn, stmt);
        }
    }
}
