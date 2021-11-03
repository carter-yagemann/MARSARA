package tracker;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import parsers.PTEventParser;
import parsers.PTEventSequence;
import parsers.ParseLinuxAudit;
import parsers.jgraph.ULogNode;

import java.util.Map;

public class PTMain {
    private static final Logger l = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) throws Exception {
        String traceFile = "logs/simple_server/server_trace.json";
        String auditFile = "logs/simple_server/audit.log";

        PTEventSequence ptSeq = PTEventParser.parsePTTrace(traceFile);
        Map<Long, ULogNode> ptMap = PTEventParser.parsePTMap(traceFile);

        // got the pt sequences, now grab the audit log graph
        Configuration config = new Configuration();
        config.parseCommandLineArgs(args);
        ParseLinuxAudit pLinux = new ParseLinuxAudit(config);
        pLinux.parseLogFile(auditFile);

//        String logName = Utils.getFileName(auditFile.toString());
//        logName = Utils.removeExtensionFirst(logName);
    }
}
