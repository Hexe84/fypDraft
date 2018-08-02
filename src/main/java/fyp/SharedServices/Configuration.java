package fyp.SharedServices;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Configuration {

    private static final Logger ConfigLogger = Logger.getLogger(Configuration.class.getName());
    public static final String CONFIGURATION_FILE = ".\\target\\classes\\config";

    public static String get(String propertyName) {
        //LogFile.logFile(ConfigLogger);
        try {
            Properties property = new Properties();
            property.load(new FileInputStream(CONFIGURATION_FILE));
            String propertyValue = property.getProperty(propertyName);
            if (propertyValue != null) {
                return propertyValue;
            } 
            else {
                ConfigLogger.log(Level.SEVERE, "Property {0} not found in the config file", propertyName);
                System.exit(1);
            }
        } catch (IOException e) {
            ConfigLogger.log(Level.SEVERE, "Configuration file '" + CONFIGURATION_FILE + "' not found!", e);
            System.exit(1);
        }
        return null;
    }
}
