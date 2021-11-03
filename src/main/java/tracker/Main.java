package tracker;

import dotgraph.DotGraph;
import org.apache.tinkerpop.gremlin.structure.Graph;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import parsers.ParseLinuxAudit;
import utils.Utils;

public class Main {
    static Logger logger = LoggerFactory.getLogger(Main.class);

    public static void tracker(String file_path, Configuration config) throws Exception {
        System.out.println("Graph generation started");
        ParseLinuxAudit pg = new ParseLinuxAudit(config);
        String test_name = Utils.getFileName(file_path);
        test_name = Utils.removeExtensionFirst(test_name);
        Graph full_graph = pg.parseLogFile(file_path);
        System.out.println("Parsing Completed === ====== ==== ");
        Summarization sum = new Summarization();
        full_graph = sum.mustSummarizations(full_graph, null);
        DotGraph dg = new DotGraph();
        dg.DotGraphFromTinkerGraph(full_graph, true, "dots/temp.dot", "dots/temp.pdf");
        //String filename = test_name + ".json";
        //System.out.println("Writing graph database " + filename);
        //full_graph.io(IoCore.graphson()).writeGraph(config.outputDir + filename);
    }

    public static void main(String[] args) throws Exception {
        System.out.println("Linux Auditd graph generation started");
        Configuration config = new Configuration();
        config.parseCommandLineArgs(args);
        tracker("logs/server/server.log", config);
//        DarpaParser dp = new DarpaParser();
//        dp.ParseInputFile("/Users/wajih/Downloads/dataset/ta1-fivedirections-e3-official-3.bin","/Users/wajih/Downloads/schema/TCCDMDatum.avsc");
    }
}
