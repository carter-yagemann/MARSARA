package provgraph;

import org.apache.tinkerpop.gremlin.structure.Edge;
import org.apache.tinkerpop.gremlin.structure.Graph;
import org.apache.tinkerpop.gremlin.structure.Vertex;
import parsers.AuditEventReader;
import record.ObjectType;
import utils.Utils;

import java.util.HashMap;
import java.util.Map;

public class GraphStructure {
    Graph prov_graph;
    long EVENT_COUNTER = 1;
    public Map<String, Vertex> seen_vertices = new HashMap<>();
    public Map<String, Vertex> seen_proc_vertices = new HashMap<>();
    public Map<String, Edge> seen_edges = new HashMap<>();

    public GraphStructure(Graph inputGraph) {
        this.prov_graph = inputGraph;
    }

    Vertex checkIfAlreadyExist(String uid) {
        return seen_vertices.getOrDefault(uid, null);
    }


    public Vertex addProcessVertex(Map<String, String> annotations) {
        String uid = Utils.getIdentifierProcess(annotations);
        Vertex found = checkIfAlreadyExist(uid);
        if (found != null)
            return found;
        String ppid = annotations.get("ppid");
        String pid = annotations.get("pid");
        String key = pid;
        String path = annotations.get("exe") == null ? "" : annotations.get("exe");
        String name = annotations.get("name") == null ? (annotations.get("comm") == null ? "" : annotations.get("comm")) : "";
        String cmdline = annotations.get("commandline") == null ? "" : annotations.get("commandline");
        String time = annotations.get("time");
        Vertex vertex = prov_graph.addVertex(ObjectType.PROCESS.name());
        vertex.property(NodeProperty.OBJECT_TYPE.name(), ObjectType.PROCESS.name());
        vertex.property(NodeProperty.ID.name(), uid);
        vertex.property(NodeProperty.PATH.name(), path);
        vertex.property(NodeProperty.PPID.name(), ppid);
        vertex.property(NodeProperty.PID.name(), pid);
        vertex.property(NodeProperty.NAME.name(), name);
//        vertex.property(NodeProperty.CREATED_TIME.name(), time);
        vertex.property(NodeProperty.CMD_LINE.name(), cmdline);
        vertex.property(NodeProperty.TERMINATE.name(), "FALSE");
        vertex.property(NodeProperty.HOP_COUNT.name(), 0);
        seen_vertices.put(uid, vertex);
        seen_proc_vertices.put(key, vertex);
        return vertex;
    }

    public Vertex addFileVertex(Map<String, String> annotations) {
        String path = annotations.get(AuditEventReader.PATH_PREFIX);
        ObjectType objtype = ObjectType.FILE;
        String uid = Utils.getIdentifierFile(path, objtype.name());
        Vertex found = checkIfAlreadyExist(uid);
        if (found != null)
            return found;
        Vertex vertex = prov_graph.addVertex(objtype.name());
        vertex.property(NodeProperty.OBJECT_TYPE.name(), objtype);
        vertex.property(NodeProperty.ID.name(), uid);
        vertex.property(NodeProperty.PATH.name(), path);
        seen_vertices.put(uid, vertex);
        return vertex;
    }

    public Vertex addApplogVertex(Map<String, String> annotations) {
        String data = annotations.get(AuditEventReader.DATA);
        String eventid = annotations.get(AuditEventReader.EVENT_ID);
        data = Utils.decodeHex(data);
        ObjectType objtype = ObjectType.FILE;
        String uid = Utils.getIdentifierFile(data + eventid, objtype.name());
        Vertex vertex = prov_graph.addVertex(objtype.name());
        vertex.property(NodeProperty.OBJECT_TYPE.name(), objtype);
        vertex.property(NodeProperty.ID.name(), uid);
        vertex.property(NodeProperty.PATH.name(), data);
        return vertex;
    }

    public Vertex addNetworkVertex(String act, String src_ip, String src_port, String dst_ip, String dst_port, String direction, String protocol) {
        String uid = Utils.getIdentifierNetwork(src_ip, src_port, dst_ip, dst_port, protocol, direction, act);
        Vertex found = checkIfAlreadyExist(uid);
        if (found != null)
            return found;

        Vertex vertex = prov_graph.addVertex(ObjectType.NETWORK.name());
        vertex.property(NodeProperty.OBJECT_TYPE.name(), ObjectType.NETWORK.name());
        vertex.property(NodeProperty.ID.name(), uid);
        vertex.property(NodeProperty.SRC_IP.name(), src_ip);
        vertex.property(NodeProperty.SRC_PORT.name(), src_port);
        vertex.property(NodeProperty.DST_IP.name(), dst_ip);
        vertex.property(NodeProperty.DST_PORT.name(), dst_port);
        vertex.property(NodeProperty.DIRECTION.name(), direction);
        vertex.property(NodeProperty.PROTOCOL.name(), protocol);
        // I add path to make all nodes have a path field
        vertex.property(NodeProperty.PATH.name(), src_ip + ":" + dst_ip);
        seen_vertices.put(uid, vertex);

        return vertex;
    }


    public Vertex addModuleVertex(Map<String, String> annotations) {
        String path = annotations.get(AuditEventReader.PATH_PREFIX);
        ObjectType objtype = ObjectType.MODULE;
        String uid = Utils.getIdentifierFile(path, objtype.name());
        Vertex found = checkIfAlreadyExist(uid);
        if (found != null)
            return found;
        Vertex vertex = prov_graph.addVertex(objtype.name());
        vertex.property(NodeProperty.OBJECT_TYPE.name(), objtype);
        vertex.property(NodeProperty.ID.name(), uid);
        vertex.property(NodeProperty.PATH.name(), path);
        seen_vertices.put(uid, vertex);
        return vertex;

    }


    public void addEdge(Vertex actor, Vertex target, String begin_time,
                        String syscall, String eventype, String eventid) {

        String uid = Utils.getEdgeId(actor, target, syscall, eventype, eventid);
        Edge edge = actor.addEdge(syscall, target);
        seen_edges.put(uid, edge);
        edge.property(EdgeProperty.ID.name(), uid);
        edge.property(EdgeProperty.BEGIN_TIME.name(), begin_time);
        edge.property(EdgeProperty.EVENTTYPE.name(), eventype);
        edge.property(EdgeProperty.SYSCALL.name(), syscall);
        edge.property(EdgeProperty.EVENTID.name(), eventid);
        edge.property(EdgeProperty.COUNTER.name(), EVENT_COUNTER);
        EVENT_COUNTER = EVENT_COUNTER + 1;
        if (Utils.getType(target).contains("PROCESS") && Utils.getType(actor).contains("PROCESS")) {
            boolean hopcount = actor.property(NodeProperty.HOP_COUNT.name()).isPresent();
            if (hopcount) {
                Integer hp = Integer.parseInt(actor.property(NodeProperty.HOP_COUNT.name()).value().toString());
                Integer hp_target = hp + 1;
                target.property(NodeProperty.HOP_COUNT.name(), hp_target);
            } else {
                actor.property(NodeProperty.HOP_COUNT.name(), 0);
                target.property(NodeProperty.HOP_COUNT.name(), 1);
            }
        }
    }
}
