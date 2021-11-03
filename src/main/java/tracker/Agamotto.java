package tracker;

import dotgraph.DotGraph;
import org.apache.tinkerpop.gremlin.structure.Graph;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import parsers.ParseLinuxAudit;
import record.*;

import java.util.List;
import java.util.ListIterator;
import java.util.Map;

public class Agamotto {
    private static final Logger l = LoggerFactory.getLogger(PTAnalyzer.class);

    /**
     * The main pt analyzer to work on the traces
     */
    private final PTAnalyzer ptAnalyzer;
    private final String outputDir;
    private final String outputFile;
    private final Configuration config;

    public Agamotto(String binary, String traceFile, String auditFile, String wlogFile,
                    String outputDir, String outputFile, String[] args) {
        this.ptAnalyzer = new PTAnalyzer(binary, traceFile, auditFile, wlogFile, args);
        this.outputDir = outputDir;
        this.outputFile = outputFile;

        this.config = new Configuration();
        this.config.parseCommandLineArgs(args);
    }

    public void generateGraphs() throws Exception {
        l.info("Starting Agamotto analysis...");
        UnitManager unitManager = ptAnalyzer.analyzeTrace();
        for (Map.Entry<Integer, List<ExecutionUnit>> entry : unitManager.entrySet()) {
            int pid = entry.getKey();
            l.info("Generating plots for process with PID = {}", pid);
            int i = 0;
            for (ExecutionUnit unit : entry.getValue()) {
                if (unit.size() == 0)
                    continue;
                ListIterator<RecordEvent> recordIterator = unit.getIterator();
                // finish up the parsing using the stock linux parser
                ParseLinuxAudit parseLinuxAudit = new ParseLinuxAudit(this.config);
                while (recordIterator.hasNext()) {
                    RecordEvent event = recordIterator.next();
                    if (event.isAuditRecord()) {
                        AuditRecord auditRecord = (AuditRecord) event;
                        Map<String, String> auditEvent = (Map<String, String>) auditRecord.getEvent();
                        parseLinuxAudit.finishEvent(auditEvent);
                    } else if (event.isAppLogRecord()) {
                        AppLogRecord appLogRecord = (AppLogRecord) event;
                        Map<String, String> auditEvent = appLogRecord.getAuditEvent();
                        parseLinuxAudit.finishEvent(auditEvent);
                    }
                }
                // finished with parsing, dump the graph into the output file
                Graph graph = parseLinuxAudit.getProvGraph();
                Summarization sum = new Summarization();
                graph = sum.mustSummarizations(graph, null);
                DotGraph dg = new DotGraph();
                String graphPath = buildGraphPath(pid, i);
                String pdfPath = buildPdfPath(pid, i);
                dg.DotGraphFromTinkerGraph(graph, true, graphPath, pdfPath);
                i++;
            }
        }
    }

    private String buildGraphPath(int pid, int i) {
        StringBuilder sb = new StringBuilder();
        sb.append(outputDir);
        if (outputDir.charAt(outputDir.length() - 1) != '/') {
            sb.append("/");
        }
        sb.append(pid)
                .append("_")
                .append(outputFile)
                .append("_")
                .append(i)
                .append(".dot");
        return sb.toString();
    }

    private String buildPdfPath(int pid, int i) {
        StringBuilder sb = new StringBuilder();
        sb.append(outputDir);
        if (outputDir.charAt(outputDir.length() - 1) != '/') {
            sb.append("/");
        }
        sb.append(pid)
                .append("_")
                .append(outputFile)
                .append("_")
                .append(i)
                .append(".pdf");
        return sb.toString();
    }

    public static void runServer(String[] args) throws Exception {
        String traceFile = "logs/server/server_trace.json";
        String auditFile = "logs/server/audit.log";
        String wlogFile = "logs/server/server.json";
        String outputDir = "dots/server/";
        String outputFile = "server";

        Agamotto agamotto = new Agamotto("server", traceFile, auditFile, wlogFile, outputDir, outputFile, args);
        agamotto.generateGraphs();
    }

    public static void main(String[] args) throws Exception {
        try {
            runServer(args);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
