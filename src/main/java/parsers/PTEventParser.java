package parsers;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import event.PTEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import parsers.jgraph.GraphParser;
import parsers.jgraph.ULogGraph;
import parsers.jgraph.ULogNode;
import utils.CommonFunctions;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.Map;

public class PTEventParser {
    private static final Logger l = LoggerFactory.getLogger(PTEventParser.class);

    /**
     * Parse a json file and get the PT trace events
     * \param jsonFile     The name of the json file containing the PT event
     */
    public static PTEventSequence parsePTTrace(String jsonFile) {
        PTEventSequence seq = null;

        FileReader m_freader_ = null;
        try {
            File in_file = new File(jsonFile);
            m_freader_ = new FileReader(in_file);
        } catch (IOException e) {
            System.err.println("Cannot read input file " + jsonFile);
            System.exit(-1);
        }
        JsonElement jsonTree = JsonParser.parseReader(m_freader_);
        if (jsonTree.isJsonObject()) {
            seq = new PTEventSequence();

            JsonObject obj = jsonTree.getAsJsonObject();
            JsonObject events = obj.get("events").getAsJsonObject();

            // go over the pids
            for (Map.Entry<String, JsonElement> entry : events.entrySet()) {
                int pid = CommonFunctions.parseInt(entry.getKey(), -1);
                seq.addPid(pid);

                JsonArray eventList = entry.getValue().getAsJsonArray();
                for (JsonElement el : eventList) {
                    parseEvent(seq, el.getAsJsonObject(), pid);
                }
            }
        } else {
            l.error(MessageFormat.format("Malformed json file {}", jsonFile));
            System.exit(-1);
        }

        return seq;
    }

    public static Map<Long, ULogNode> parsePTMap(String jsonFile) {
        return parsePTMap(jsonFile, null);
    }

    public static Map<Long, ULogNode> parsePTMap(String jsonFile, ULogGraph graph) {
        HashMap<Long, ULogNode> avaToNode = null;

        FileReader m_freader_ = null;
        try {
            File in_file = new File(jsonFile);
            m_freader_ = new FileReader(in_file);
        } catch (IOException e) {
            System.err.println("Cannot read input file " + jsonFile);
            System.exit(-1);
        }

        JsonElement jsonTree = JsonParser.parseReader(m_freader_);
        if (jsonTree.isJsonObject()) {
            avaToNode = new HashMap<>();
            JsonObject obj = jsonTree.getAsJsonObject();
            // now parse the ava2node map
            JsonObject avaMap = obj.get("ava2node").getAsJsonObject();
            for (Map.Entry<String, JsonElement> entry : avaMap.entrySet()) {
                JsonObject node_obj = entry.getValue().getAsJsonObject();
                long addr = Long.parseLong(entry.getKey());

                ULogNode node = null;
                if (graph == null) {
                    node = GraphParser.BuildNode(node_obj);
                } else {
                    ULogNode temp = GraphParser.BuildNode(node_obj);
                    int id = temp.getId();
                    node = graph.GetNode(id);
                }

                avaToNode.put(addr, node);
            }
        } else {
            l.error(MessageFormat.format("Malformed json file {0}", jsonFile));
            System.exit(-1);
        }

        return avaToNode;
    }

    /**
     * Parse an omega log graph and return it.
     * <p>
     * \param wlogFile  The input omegalog JSON file
     * \return  A parsed omega log graph.
     */
    public static ULogGraph parseOmegaLogGraph(String wlogFile) {
        return GraphParser.ReadGraph(wlogFile);
    }

    private static PTEvent parseEvent(PTEventSequence seq, JsonObject el, int pid) {
        int type = el.get("event").getAsInt();

        if (type == 0) {
            // app log
            int wnode_id = el.get("node_id").getAsInt();
            String name = el.get("name").getAsString();

            return seq.createAppLogEvent(name, wnode_id, pid);
        } else if (type == 1) {
            // syscall
            String name = el.get("name").getAsString();
            int snum = el.get("call_num").getAsInt();
            String curr_obj = el.get("curr_object").getAsString();
            String prev_obj;
            try {
                prev_obj = el.get("prev_object").getAsString();
            } catch (UnsupportedOperationException e) {
                prev_obj = "None";
            }

            return seq.createSyscallEvent(name, snum, pid, curr_obj, prev_obj);
        } else if (type == 2) {
            // thread event
            String name = el.get("name").getAsString();
            int tid = el.get("tid").getAsInt();

            return seq.createThreadEvent(name, tid, pid);
        }

        return null;
    }

    public static void main(String[] args) throws Exception {
        String fileName = "logs/simple_server/server_trace.json";
        PTEventSequence seq = PTEventParser.parsePTTrace(fileName);
        System.out.println(seq);

        Map<Long, ULogNode> map = PTEventParser.parsePTMap(fileName);
        System.out.println("Size of the map is " + map.size());
        for (Map.Entry<Long, ULogNode> entry : map.entrySet()) {
            System.out.println(MessageFormat.format(
                    "Parsed {0} for {1}", entry.getKey(), entry.getValue()));
        }
    }

}
