package parsers.partitioner;

/*
import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.impl.Arguments;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import net.sourceforge.argparse4j.inf.Namespace;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import spade.core.*;
import spade.edge.cdm.SimpleEdge;
import spade.reporter.audit.AuditEventReader;
import spade.reporter.audit.OPMConstants;
import spade.storage.wlog.jparser.JParser;
import spade.storage.wlog.jparser.RegexMatcher;

import java.util.*;

public class GraphWlog {

    private static final Logger l = LogManager.getLogger(JParser.class.getName());

    private Graph spadeGraph = null;
    private JParser jParser = null;
    private Map<String,String> pidVertexMap = null;

    private String processName = null;
    private String jparserStartString = null;

    public GraphWlog(String dotfilepath, String process, JParser jparser, String jparserStartString){
        importModifiedSpadeGraph(dotfilepath);
        this.processName = process;
        this.jParser = jparser;
        this.jparserStartString = jparserStartString;
    }

    public Graph getSpadeGraph(){
        return spadeGraph;
    }

    public void importModifiedSpadeGraph(String path){
        spadeGraph = Graph.importGraph(path);
    }

    public Graph getProcessLineage (String procname) {

        Graph unionGraph = new Graph();

        Set<AbstractVertex> abstractVertices = spadeGraph.vertexSet();

        for (AbstractVertex v : abstractVertices) {
            String type = v.getAnnotation(ConstantVals.ann_type);
            if(type == null || type.isEmpty())
                continue;
            if (!type.equalsIgnoreCase(ConstantVals.ann_type_proc)) continue;
            if ((v.getAnnotation(ConstantVals.ann_name)).equals(procname)) {
                Graph depGraph = getDepGraph(v);
                unionGraph = Graph.union(unionGraph, depGraph);
            }
        }

        return unionGraph;
    }

    public Graph generateLineageGraph(String procname){
        if(spadeGraph==null) {
            l.error("Spade Graph is not imported");
            return null;
        }

        Graph lineageGraph = getProcessLineage(procname);
        return lineageGraph;
    }

    public Graph generatePrunedGraph(String procname){
        if(spadeGraph==null) {
            l.error("Spade Graph is not imported");
            return null;
        }
        Graph lineageGraph = getProcessLineage(procname);
        Graph pruned = Graph.remove(spadeGraph,lineageGraph);
        return pruned;
    }

    public Graph getDepGraph(AbstractVertex root){
        String hash = root.bigHashCode();
        Graph lineageBackward = spadeGraph.getLineage(hash,AbstractStorage.DIRECTION_ANCESTORS,ConstantVals.maxdepth);
        Graph lineageForward = spadeGraph.getLineage(hash,AbstractStorage.DIRECTION_DESCENDANTS,ConstantVals.maxdepth);

        return Graph.union(lineageBackward, lineageForward);
    }

    public void graftApplicationNodes(){
        int app = 0;
        if(pidVertexMap == null){
            pidVertexMap = scanPidNodes(spadeGraph);
        }
        Set<AbstractVertex> abstractVertices = spadeGraph.vertexSet();
        for(AbstractVertex v : abstractVertices) {
            String type = v.getAnnotation(ConstantVals.ann_type);
            if(type == null || type.isEmpty())
                continue;
            if (!type.equalsIgnoreCase(ConstantVals.ann_type_app)) continue;

            app++;
            String relatedProcess = v.getAnnotation(ConstantVals.ann_pid);
            AbstractVertex procnode = spadeGraph.getVertex(pidVertexMap.get(relatedProcess));
            if(procnode!=null) {
                SimpleEdge edge = new SimpleEdge(v, procnode);
                edge.addAnnotation(OPMConstants.EDGE_EVENT_ID,v.getAnnotation(AuditEventReader.EVENT_ID));
                spadeGraph.putEdge(edge);
            }
        }
        l.info("Number of application nodes "+app);
    }

    public static Map<String,String> scanPidNodes(Graph g){
        if(g == null) {
            l.error("Graph is not imported.");
        }
        Map<String,String> pidmap = new HashMap<>();
        Set<AbstractVertex> abstractVertices = g.vertexSet();
        for(AbstractVertex v : abstractVertices){
            String type = v.getAnnotation(ConstantVals.ann_type);
            if(type == null || type.isEmpty())
                continue;
            if (!type.equalsIgnoreCase(ConstantVals.ann_type_proc)) continue;
            String pid = v.getAnnotation(ConstantVals.ann_pid);
            pidmap.put(pid,v.bigHashCode());
        }
        return pidmap;
    }

    public static void exportDotGraph(Graph g, String file, String logKeyword, boolean shortenLog){
        if(shortenLog)
            shortenLogMessages(g, logKeyword);
        g.exportGraph(ConstantVals.dirpath + file );
    }

    private static void shortenLogMessages(Graph g, String keyword) {
        Set<AbstractVertex> abstractVertices = g.vertexSet();
        for(AbstractVertex v : abstractVertices) {
            if (!v.getAnnotation(ConstantVals.ann_type).equalsIgnoreCase(ConstantVals.ann_type_app)) continue;

            //editing the log msg here
            String msg = v.getAnnotation(ConstantVals.ann_log);

            int startindex = msg.length()>ConstantVals.loglength? msg.length()-ConstantVals.loglength:0;
            g.addAnnotationToVertex(v, ConstantVals.ann_log, msg.substring(startindex));

        }
    }


    private static GraphWlog parseArguments(String[] args) {
        GraphWlog wlog = null;
        ArgumentParser parser = ArgumentParsers.newFor("JParser").build()
                .defaultHelp(true)
                .description("Parse a log file and match it to a give json graph");
        parser.addArgument("-i", "--input")
                .type(String.class)
                .required(true)
                .help("The input graph file in json format");
        parser.addArgument("-l", "--log")
                .type(String.class)
                .required(true)
                .help("The input log file to read from");
        parser.addArgument("-p","--process")
                .type(String.class)
                .required(true)
                .help("The process name");
        parser.addArgument("-d", "--dot")
                .type(String.class)
                .required(true)
                .help("Spade generated dot file for log");
        parser.addArgument("--watch", "-w")
                .action(Arguments.storeTrue())
                .help("Run in watch mode (experimental");
        parser.addArgument("--simulate", "-s")
                .action(Arguments.storeTrue())
                .help("Run in simulation mode starting from the head node");
        parser.addArgument("--lookahead", "-k")
                .type(Integer.class)
                .required(true)
                .help("The maximum lookahead depth to use when parsing log entries");

        Namespace res;
        try {
            res = parser.parseArgs(args);
            l.debug(res);
            // get a new matcher
            RegexMatcher matcher = new RegexMatcher();

            // parse the log and create state history
            JParser jparser = new JParser(res.getString("input"), res.getString("log"),
                    res.getBoolean("watch"), matcher, res.getInt("lookahead"));
            String start = res.getBoolean("simulate")? "start" : "first";

            wlog = new GraphWlog(res.getString("dot"), res.getString("process"), jparser, start);
        } catch (ArgumentParserException e) {
            parser.handleError(e);
        }
        return wlog;

    }

    private static void runPartitioning(GraphWlog wlog, boolean shortenLog) {
        wlog.graftApplicationNodes();
        NodeSplitter n = new NodeSplitter(wlog.getSpadeGraph());
        n.partitionExecution(wlog.processName,wlog.jParser, wlog.jparserStartString);
        Graph g1 = wlog.generateLineageGraph(wlog.processName);
        exportDotGraph(g1,wlog.processName+ConstantVals.lineageGraphString,n.getLogKeyWord(), shortenLog);
    }

    public static void main(String[] args) {
        GraphWlog wlog = parseArguments(args);
        runPartitioning(wlog,true);
    }
}
 */
