package fyp.SharedServices;

import java.math.BigInteger;
import java.sql.*;
import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

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
        dbLogger.log(Level.INFO, "DB Connection strted");

    }

    public void createCertificatesTable() {

        try {
            //String sql = "DROP TABLE IF EXISTS CERTIFICATES"; // Delete table (in needed)
            String sql = "CREATE TABLE CERTIFICATES "
                    + "(Version VARCHAR(255), "
                    //+ " SerialNumber BIGINT, " 
                    + " SerialNumber VARBINARY(8), "
                    + " SignatureAlgorithm VARCHAR(255), "
                    + " SignatureHashAlgorithm VARCHAR(255), "
                    + " Issuer VARCHAR(255), "
                    + " NotBefore TIMESTAMP, "
                    + " NotAfter TIMESTAMP, "
                    + " SubjectName VARCHAR(255), "
                    + " PublicKey VARBINARY(8), "
                    //Extensions
                    + " Extensions TEXT, "
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

    public void createCRLTable() {

        try {
            //String sql = "DROP TABLE IF EXISTS CRL"; // Delete table (in needed)
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
            dbLogger.log(Level.SEVERE, "Unable to process query", e);
        } finally {
            //close resources
            closeDatabase(conn, stmt);
        }
    }

    public void saveCertToDB() {

        try {
            String sql = "INSERT INTO CERTIFICATES ";
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
            String sql = "SELECT * FROM CRL "
                    + "WHERE SerialNumber = " + serialNo;
            ResultSet rs = stmt.executeQuery(sql);

            if (rs != null) {
                System.out.println("Serial Number in CRL. Certificate revoked!");
                check = true;
            } else {
                check = false;
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
}
