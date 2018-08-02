/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package fyp.SharedServices;

import java.io.IOException;
import java.util.logging.ConsoleHandler;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/**
 *
 * @author Marta
 */
public class LogFile {

    private static FileHandler fh;

    public static void logFile(Logger logger) {

        try {
            logger.getName();
            String i = new String(logger.getName());
            System.out.println(i);
            fh = new FileHandler(".\\LOGS\\LOG_FILE.log", true);
            //fh = new FileHandler(".\\"+i+".log", true);
            fh.setFormatter(new SimpleFormatter());
            fh.setLevel(Level.ALL);
            logger.setUseParentHandlers(false);
            logger.addHandler(fh);
            //logging to console
            ConsoleHandler ch = new ConsoleHandler();
            ch.setFormatter(new SimpleFormatter());
            ch.setLevel(Level.ALL);
            logger.setUseParentHandlers(false);
            logger.addHandler(ch);

        } catch (SecurityException | IOException ex) {

            Logger.getLogger(LogFile.class.getName()).log(Level.SEVERE, "Exception in creating Log File", ex);
        }
    }
}
