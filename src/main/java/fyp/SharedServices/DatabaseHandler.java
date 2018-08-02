package fyp.SharedServices;

import java.sql.*;
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
    static Connection conn = null;
    static Statement stmt = null;

    public DatabaseHandler() throws SQLException, ClassNotFoundException {
        LogFile.logFile(dbLogger);

        Class.forName("com.mysql.jdbc.Driver");
        System.out.println("Connecting to database...");
        conn = DriverManager.getConnection(DB_URL, USER, PASS);

    }

    public void dbInit() {

        try {
            System.out.println("Creating statement...");
            stmt = conn.createStatement();
            System.out.println("Connection working");
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
            ResultSet rs = stmt.executeQuery(sql);

            rs.close();
            //stmt.close();
            //conn.close();
        } catch (SQLException se) {

            dbLogger.log(Level.SEVERE, "SQL Exception: ", se);
        } catch (Exception e) {
            dbLogger.log(Level.SEVERE, "Unable to process query", e);
        } finally {
            //finally block used to close resources
            try {
                if (stmt != null) {
                    stmt.close();
                }
            } catch (SQLException e) {
                dbLogger.log(Level.SEVERE, "Unable to close DB statement: ", e);
            }
            try {
                if (conn != null) {
                    conn.close();
                }
            } catch (SQLException se) {
                dbLogger.log(Level.SEVERE, "Unable to close DB connection: ", se);
            }
        }
        System.out.println("Closing DB connection");
    }
public void saveCert2DB() {

        try {
            System.out.println("Creating statement...");
            stmt = conn.createStatement();
            System.out.println("Connection working");
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
            ResultSet rs = stmt.executeQuery(sql);

            rs.close();
            //stmt.close();
            //conn.close();
        } catch (SQLException se) {

            dbLogger.log(Level.SEVERE, "SQL Exception: ", se);
        } catch (Exception e) {
            dbLogger.log(Level.SEVERE, "Unable to process query", e);
        } finally {
            //finally block used to close resources
            try {
                if (stmt != null) {
                    stmt.close();
                }
            } catch (SQLException e) {
                dbLogger.log(Level.SEVERE, "Unable to close DB statement: ", e);
            }
            try {
                if (conn != null) {
                    conn.close();
                }
            } catch (SQLException se) {
                dbLogger.log(Level.SEVERE, "Unable to close DB connection: ", se);
            }
        }
        System.out.println("Closing DB connection");
    }
}


/*

DROP TABLE IF EXISTS `drawings`;
CREATE TABLE IF NOT EXISTS `drawings` (
  `id` varchar(36) NOT NULL,
  `name` varchar(255) DEFAULT NULL,
  `creation_date` datetime NOT NULL,
  `data` text,
  `owner_id` varchar(36) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `owner_id` (`owner_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

*/
