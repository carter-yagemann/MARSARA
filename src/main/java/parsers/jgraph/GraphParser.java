package parsers.jgraph;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import parsers.PTEventParser;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;

public class GraphParser {
    private static final Logger l = LoggerFactory.getLogger(PTEventParser.class);

    private final String fileName;

    public GraphParser(String _fileName) {
        fileName = _fileName;

    }

    // parse a json file and generate a graph from it
    public static ULogGraph ReadGraph(String jsonFile) {
        int err;
        ULogGraph graph = null;
        FileReader freader = null;
        try {
            File inFile = new File(jsonFile);
            freader = new FileReader(inFile);
        } catch (IOException e) {
            System.err.println("Cannot read input file " + jsonFile);
            System.exit(-1);
        }

        JsonElement jsonTree = JsonParser.parseReader(freader);
        if (jsonTree.isJsonObject()) {
            graph = new ULogGraph();
            JsonObject obj = jsonTree.getAsJsonObject();

            // get graph attributes
            // boolean directed = obj.get("directed").getAsBoolean();
            // boolean multigraph = obj.get("multigraph").getAsBoolean();

            // now get the list of nodes
            JsonElement nodeTree = obj.get("nodes");

            // should be an array
            if (nodeTree.isJsonArray()) {
                JsonArray nodeList = nodeTree.getAsJsonArray();

                for (JsonElement nodeEntry : nodeList) {
                    ULogNode node = BuildNode(nodeEntry.getAsJsonObject());

                    err = graph.AddNode(node);
                    if (err != 0) {
                        l.error("Adding duplicate node, check your json file");
                        return null;
                    }
                }
            }

            // okay now get the links
            JsonElement linkTree = obj.get("links");
            if (linkTree.isJsonArray()) {
                JsonArray linkList = linkTree.getAsJsonArray();

                for (JsonElement linkEntry : linkList) {
                    JsonObject edgeObj = linkEntry.getAsJsonObject();

                    int srcId = edgeObj.get("source").getAsInt();
                    int dstId = edgeObj.get("target").getAsInt();

                    err = graph.AddEdge(srcId, dstId);
                    if (err != 0) {
                        l.debug("Could not add edge from {} to {}: ({})", srcId, dstId, err);
                        return null;
                    }

                    l.debug("Added edge from {} to {}", srcId, dstId);
                }
            }
        }

        // null if not able to parse
        return graph;
    }

    public static ULogNode BuildNode(JsonObject nodeObj) {
        // get those parameters
        int id = nodeObj.get("id").getAsInt();
        String val = nodeObj.get("val").getAsString();

        // check if it is a loop
        Boolean isLoop = false;
        if (nodeObj.has("is_loop")) {
            isLoop = nodeObj.get("is_loop").getAsBoolean();
        }

        // check if is start node
        Boolean isStart = false;
        if (nodeObj.has("is_start")) {
            isStart = nodeObj.get("is_start").getAsBoolean();
        }

        // check for is end node
        Boolean isEnd = false;
        if (nodeObj.has("is_end")) {
            isEnd = nodeObj.get("is_end").getAsBoolean();
        }

        // check for is exec
        Boolean isExec = false;
        if (nodeObj.has("is_exec")) {
            isExec = nodeObj.get("is_exec").getAsBoolean();
        }

        // check for the phony flag
        Boolean isPhony = false;
        if (nodeObj.has("is_phony")) {
            isPhony = nodeObj.get("is_phony").getAsBoolean();
        }

        // check for function heads
        Boolean isFuncHead = false;
        if (nodeObj.has("is_func_head")) {
            isFuncHead = nodeObj.get("is_func_head").getAsBoolean();
        }

        // check for function returns
        Boolean isFuncOut = false;
        if (nodeObj.has("is_func_out")) {
            isFuncOut = nodeObj.get("is_func_out").getAsBoolean();
        }

        // check for regex flag
        Boolean isRegex = false;
        if (nodeObj.has("is_regex")) {
            isRegex = nodeObj.get("is_regex").getAsBoolean();
        }

        // get the rva of the node
        long rva = -1;
        if (nodeObj.has("rva")) {
            rva = nodeObj.get("rva").getAsLong();
        }

        // check of syscall flag
        boolean isSyscall = false;
        if (nodeObj.has("is_syscall")) {
            isSyscall = nodeObj.get("is_syscall").getAsBoolean();
        }

        // check for function
        String function;
        if (nodeObj.has("function")) {
            if (nodeObj.get("function").isJsonNull())
                function = "";
            else
                function = nodeObj.get("function").getAsString();
        } else {
            function = "";
        }

        // check for last instruction
        String last_instruction;
        if (nodeObj.has("last_instruction")) {
            if (nodeObj.get("last_instruction").isJsonNull())
                last_instruction = "";
            else
                last_instruction = nodeObj.get("last_instruction").getAsString();
        } else {
            last_instruction = "";
        }

        // check for syscall name
        String syscallName;
        if (nodeObj.has("syscall_name")) {
            if (nodeObj.get("syscall_name").isJsonNull()) {
                syscallName = val;
            } else {
                syscallName = nodeObj.get("syscall_name").getAsString();
            }
        } else {
            syscallName = val;
        }

        // create the node and assign the attributes
        ULogNode node = new ULogNode(id);
        node.setAttribute("is_loop", isLoop);
        node.setAttribute("is_start", isStart);
        node.setAttribute("is_end", isEnd);
        node.setAttribute("is_exec", isExec);
        node.setAttribute("is_phony", isPhony);
        node.setAttribute("is_func_head", isFuncHead);
        node.setAttribute("is_func_out", isFuncOut);
        node.setAttribute("val", val);
        node.setAttribute("rva", rva);
        node.setAttribute("is_regex", isRegex);
        node.setAttribute("is_syscall", isSyscall);
        node.setAttribute("function", function);
        node.setAttribute("last_instruction", last_instruction);
        node.setAttribute("syscall_name", syscallName);

//		l.debug("Added node " + node);

        return node;
    }

    public String getFileName() {
        return fileName;
    }


    public static void main(String[] args) {
        String fname = "src/01_test.json";

        GraphParser parser = new GraphParser(fname);

        ReadGraph(parser.getFileName());
    }

}
