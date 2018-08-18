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
            dbLogger.log(Level.SEVERE, "SQL Exception in creating CRL db: ", se);
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
            dbLogger.log(Level.SEVERE, "SQL Exception in creating Certificates db: ", se);
        } catch (Exception e) {
            dbLogger.log(Level.SEVERE, "Unable to process query", e);
        } finally {
            //close resources
            closeDatabase(conn, stmt);
        }
    }

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
    
    public void saveCertToCertDB(X509Certificate cert) {
        
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
}
