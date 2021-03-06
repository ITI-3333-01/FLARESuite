package edu.trevecca.flare.core.logging;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Date;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;

/**
 * Adds some useful info to logging output.
 *
 * @author Keenan Thompsan
 */
public class CustomFormatter extends Formatter {

    private final Date dat = new Date();

    public String format(LogRecord record) {
        this.dat.setTime(record.getMillis());
        String source;
        if (record.getSourceClassName() != null) {
            source = record.getSourceClassName();
            if (record.getSourceMethodName() != null) {
                source = source + " " + record.getSourceMethodName();
            }
        }
        else {
            source = record.getLoggerName();
        }

        String message = this.formatMessage(record);
        String throwable = "";
        if (record.getThrown() != null) {
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            pw.println();
            record.getThrown().printStackTrace(pw);
            pw.close();
            throwable = sw.toString();
        }

        return String.format("%1$tY-%1$tm-%1$td %1$tH:%1$tM:%1$tS.%1$tL [%4$s] [%3$s] %5$s %6$s%n", this.dat, source,
                             record.getLoggerName(), record.getLevel().getLocalizedName(), message, throwable
                            );
    }
}