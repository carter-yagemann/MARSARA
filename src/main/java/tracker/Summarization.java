package tracker;

import com.google.common.collect.Lists;
import event.GraphEventType;
import org.apache.tinkerpop.gremlin.structure.Direction;
import org.apache.tinkerpop.gremlin.structure.Edge;
import org.apache.tinkerpop.gremlin.structure.Graph;
import org.apache.tinkerpop.gremlin.structure.Vertex;
import org.javatuples.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import provgraph.EdgeProperty;
import provgraph.NodeProperty;
import record.ObjectType;
import utils.Utils;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

public class Summarization {
    public List<Edge> edges_to_remove = new ArrayList<Edge>();
    public List<Vertex> edges_to_add = new ArrayList<Vertex>();
    public List<Vertex> vertices_to_remove = new ArrayList<Vertex>();

    static Logger logger = LoggerFactory.getLogger(Summarization.class);

    public Graph maySummarizations(Graph full_graph) {
        mergeSameDstNetworks(full_graph);
//        mergeModuleVertices(full_graph);
//        mergeFileVertices(full_graph);
//        mergeRegistryKeyVertices(full_graph);
        deleteEdgesBtwSameVertices(full_graph);
//        removeTemporaryFiles(full_graph);
        return full_graph;
    }

    public Graph mustSummarizations(Graph full_graph, String json_file) {
        deleteSystemEdges(full_graph);
        deleteProc(full_graph);
        addDummyRoot(full_graph);
        return full_graph;
    }

    public boolean directoryAndExtensionSame(Pair<Vertex, String> pair, Vertex v2) {
        Vertex v1 = pair.getValue0();
        String file_path1 = v1.property(NodeProperty.PATH.name()).value().toString();
        String file_path2 = v2.property(NodeProperty.PATH.name()).value().toString();
        String filename = Utils.getFileName(file_path1);
        String directory = Utils.getDirectoryName(file_path1);
        String extension = Utils.getExtension(filename);
        String filename2 = Utils.getFileName(file_path2);
        String directory2 = Utils.getDirectoryName(file_path2);
        String extension2 = Utils.getExtension(filename2);
//        if (extension.isEmpty()){
//            return false;
//        }
        if (directory.toLowerCase().contains("/appdata/local/") || directory.toLowerCase().contains("/appdata/roaming/")) {
            //System.out.println("IAM HERE");
            return extension.equalsIgnoreCase(extension2) && directory.equalsIgnoreCase(directory2);
        }
        return false;
    }

//    public void addDummyParentProcessVertex(Graph inputGraph){
//        Map<String, List<Vertex>> map = new HashMap<>();
//        for (Iterator<Vertex> vertices = inputGraph.vertices(); vertices.hasNext();) {
//            Vertex vertex = vertices.next();
//            if (!vertex.property(NodeProperty.OBJECT_TYPE.name()).value().toString().equals(ObjectType.PROCESS.name()))
//                continue;
//            if (getListFromIterator(vertex.edges(Direction.IN)).size() > 0){
//                continue;
//            }
//            String key = getPath(vertex)  + " : " + getPid(vertex);
//            if (map.containsKey(key)){
//                List<Vertex> items = map.get(key);
//                items.add(vertex);
//            }else{
//                List<Vertex> items = new ArrayList<>();
//                items.add(vertex);
//            }
//        }
//
//        for (Map.Entry<String, List<Vertex>> e = map.entrySet()){
//            if (e.getValue().size() > 1){
//                String uid = Utils.getIdentifierProcess(e.getKey(),"","","", "", "");
//                Vertex vertex = inputGraph.addVertex();
//                vertex.property(NodeProperty.OBJECT_TYPE.name(), ObjectType.PROCESS.name());
//                vertex.property(NodeProperty.ID.name(), uid);
//                vertex.property(NodeProperty.PATH.name(), e.getKey());
//                vertex.property(NodeProperty.PID.name(), "");
//                vertex.property(NodeProperty.TID.name(), "");
//                vertex.property(NodeProperty.HASH.name(), "");
//                vertex.property(NodeProperty.USER_NAME.name(), "");
//                vertex.property(NodeProperty.FILE_ID.name(), "");
//                vertex.property(NodeProperty.CREATED_TIME.name(), "");
//                vertex.property(NodeProperty.SID.name(), "");
//                vertex.property(NodeProperty.CMD_LINE.name(), "");
//                vertex.property(NodeProperty.SESSION_ID.name(), "");
//                vertex.property(NodeProperty.USER_DOMAIN.name(), "");
//                vertex.property(NodeProperty.NORMALIZED_PATH.name(), "");
//                for (Vertex v : e.getValue()){
//
//                }
//            }
//        }
//
//        for (Vertex v: edges_to_add){
//            Edge edge  = root.addEdge("root",v);
//            edge.property(EdgeProperty.EVENTTYPE.name(),EventType.DUMMY);
//        }
//        return;
//    }

    public void addDummyRoot(Graph inputGraph) {
        List<Vertex> to_remove = new ArrayList<>();
        List<Edge> to_remove_edges = new ArrayList<>();
        for (Iterator<Vertex> vertices = inputGraph.vertices(); vertices.hasNext(); ) {
            Vertex vertex = vertices.next();
            if (!vertex.property(NodeProperty.OBJECT_TYPE.name()).value().toString().equals(ObjectType.PROCESS.name()))
                continue;
            if (!vertex.property(NodeProperty.HOP_COUNT.name()).isPresent()) {
                // REMOVE vertices that have no incoming or outgoing process edge
                boolean flag = true;
                for (Edge e : getListFromIterator(vertex.edges(Direction.BOTH))) {
                    String type = e.property(EdgeProperty.EVENTTYPE.name()).value().toString();
                    if (type.contains("PROCESS"))
                        flag = false;
                }
                if (flag) {
                    to_remove.add(vertex);
                    for (Edge e : getListFromIterator(vertex.edges(Direction.BOTH))) {
                        to_remove_edges.add(e);
                    }
                }
                continue;
            }
            Integer hopcount = Integer.parseInt(vertex.property(NodeProperty.HOP_COUNT.name()).value().toString());
            if (hopcount == 0) {
                edges_to_add.add(vertex);
            }
        }
        Vertex root = inputGraph.addVertex("Root");
        root.property(NodeProperty.OBJECT_TYPE.name(), ObjectType.DUMMY);
        root.property(NodeProperty.ID.name(), "0");
        root.property(NodeProperty.HOP_COUNT.name(), -1);
        int counter = 0;
        for (Vertex v : edges_to_add) {
            Edge edge = root.addEdge("root", v);
            edge.property(EdgeProperty.EVENTTYPE.name(), GraphEventType.DUMMY);
            edge.property(EdgeProperty.RULE_NAME.name(), "Nan");
            edge.property(EdgeProperty.SYSCALL.name(), "Nan");
            edge.property(EdgeProperty.ID.name(), "Nan" + counter);
            counter++;
        }
        for (Vertex v : to_remove) {
            Utils.deleteVertex(inputGraph, v);
        }
        for (Edge e : to_remove_edges) {
            Utils.deleteEdge(inputGraph, e);
        }
        return;
    }

    public void deleteExceptPython(Graph inputGraph, HashSet<String> list_to_preserve) {
        List<Edge> to_delete = new ArrayList<>();
        for (Iterator<Edge> edges = inputGraph.edges(); edges.hasNext(); ) {
            Edge edge = edges.next();
            String uid = Utils.getId(edge);
            if (!list_to_preserve.contains(uid))
                to_delete.add(edge);
        }
        for (Edge e : to_delete) {
            Utils.deleteEdgeWithVertex(inputGraph, e);
        }
        return;
    }

    public void deleteExceptPythonVertex(Graph inputGraph, HashSet<Vertex> list_to_preserve) {
        List<Vertex> to_delete = new ArrayList<>();
        List<Edge> to_delete_edge = new ArrayList<>();
        for (Iterator<Vertex> vertices = inputGraph.vertices(); vertices.hasNext(); ) {
            Vertex vertex = vertices.next();
            if (!list_to_preserve.contains(vertex))
                to_delete.add(vertex);
        }
        for (Vertex v : to_delete) {
            Utils.deleteVertex(inputGraph, v);
            for (Edge e : getListFromIterator(v.edges(Direction.BOTH))) {
                to_delete_edge.add(e);
            }
        }
        for (Edge e : to_delete_edge) {
            Utils.deleteEdge(inputGraph, e);
        }
        return;
    }

    public boolean directoryAndExtensionSameModule(Pair<Vertex, String> pair, Vertex v2) {
        Vertex v1 = pair.getValue0();
        String edgeType1 = pair.getValue1();
        String file_path1 = v1.property(NodeProperty.PATH.name()).value().toString();
        String file_path2 = v2.property(NodeProperty.PATH.name()).value().toString();
        String filename = Utils.getFileName(file_path1);
        String directory = Utils.getDirectoryName(file_path1);
        String extension = Utils.getExtension(filename);
        String filename2 = Utils.getFileName(file_path2);
        String directory2 = Utils.getDirectoryName(file_path2);
        String extension2 = Utils.getExtension(filename2);
        return extension.equalsIgnoreCase(extension2) && directory.equalsIgnoreCase(directory2);
    }


    public void deleteEdgesBtwSameVertices(Graph inputGraph) {
        edges_to_remove.clear();
        for (Iterator<Vertex> vertices = inputGraph.vertices(); vertices.hasNext(); ) {
            Vertex vertex = vertices.next();
            List<Pair<Vertex, String>> seenList = new ArrayList<Pair<Vertex, String>>();
            for (Edge e : getListFromIterator(vertex.edges(Direction.OUT))) {
                String current_edgetype = e.property(EdgeProperty.EVENTTYPE.name()).value().toString();
                Vertex current = e.inVertex();
                boolean found = false;
                for (Pair<Vertex, String> seen_pair : seenList) {
                    String other_id = current.property(NodeProperty.ID.name()).value().toString();
                    String seen_vertex_id = seen_pair.getValue0().property(NodeProperty.ID.name()).value().toString();
                    if (other_id.equals(seen_vertex_id) && seen_pair.getValue1().equals(current_edgetype)) {
                        edges_to_remove.add(e);
                        found = true;
                    }
                }
                if (!found)
                    seenList.add(new Pair<>(current, current_edgetype));
            }
        }
        int total_removed = 0;
        for (Edge e : edges_to_remove) {
            Utils.deleteEdge(inputGraph, e);
            total_removed += 1;
        }
        logger.info("Total Similar Edges removed: " + total_removed);
        return;
    }

    public void mergeSameTypeEdges(Graph inputGraph) {
        for (Iterator<Edge> edges = inputGraph.edges(); edges.hasNext(); ) {
            Edge edge = edges.next();
            Vertex src = edge.outVertex();
            Vertex dst = edge.inVertex();
            String src_id = src.property(NodeProperty.ID.name()).value().toString();
            String dst_id = dst.property(NodeProperty.ID.name()).value().toString();
        }
    }

    public static String getTypeVertex(Vertex vertex) {
        return vertex.property(NodeProperty.OBJECT_TYPE.name()).value().toString();
    }

    public static String getTypeEdge(Edge edge) {
        return edge.property(EdgeProperty.EVENTTYPE.name()).value().toString();
    }

    public static String getPath(Vertex vertex) {
        return vertex.property(NodeProperty.PATH.name()).value().toString();
    }

    public static String getSrcip(Vertex vertex) {
        return vertex.property(NodeProperty.SRC_IP.name()).value().toString();
    }

    public static String getDstip(Vertex vertex) {
        return vertex.property(NodeProperty.DST_IP.name()).value().toString();
    }

    public static String getPid(Vertex vertex) {
        return vertex.property(NodeProperty.PID.name()).value().toString();
    }

    public void mergeFileVertices(Graph inputGraph) {
        for (Iterator<Vertex> vertices = inputGraph.vertices(); vertices.hasNext(); ) {
            Vertex vertex = vertices.next();
            if (!getType(vertex).equals(ObjectType.PROCESS.name())) {
                continue;
            }
            ArrayList<ArrayList<Vertex>> groups = groupFileVertices(vertex);
            for (ArrayList<Vertex> group : groups) {
                if (group.size() <= 1) {
                    continue;
                }
                Vertex first = group.get(0);
                String intial_path = first.property(NodeProperty.PATH.name()).value().toString();
                inputGraph.vertices(first).next().property(NodeProperty.PATH.name(), intial_path + "***");
                // Except first vertex in the group remove everything
                for (Vertex v : group) {
                    if (getVertexId(v).equals(getVertexId(first))) {
                        continue;
                    }
                    removeEdge(inputGraph, v);
                }
            }
        }
        int total_removed = 0;
        for (Vertex v : vertices_to_remove) {
            Utils.deleteVertex(inputGraph, v);
            total_removed += 1;
        }
        for (Edge e : edges_to_remove) {
            Utils.deleteEdge(inputGraph, e);
        }
        logger.info("Total Vertices File removed: " + total_removed);
        vertices_to_remove.clear();
        edges_to_remove.clear();
    }

    public void mergeModuleVertices(Graph inputGraph) {
        for (Iterator<Vertex> vertices = inputGraph.vertices(); vertices.hasNext(); ) {
            Vertex vertex = vertices.next();
            if (!getType(vertex).equals(ObjectType.PROCESS.name())) {
                continue;
            }
            ArrayList<ArrayList<Vertex>> groups = groupModuleVertices(vertex);
            for (ArrayList<Vertex> group : groups) {
                if (group.size() <= 1) {
                    continue;
                }
                Vertex first = group.get(0);
                String intial_path = first.property(NodeProperty.PATH.name()).value().toString();
                inputGraph.vertices(first).next().property(NodeProperty.PATH.name(), intial_path + "***");
                // Except first vertex in the group remove everything
                for (Vertex v : group) {
                    if (getVertexId(v).equals(getVertexId(first))) {
                        continue;
                    }
                    removeEdge(inputGraph, v);
                }
            }
        }
        int total_removed = 0;
        for (Vertex v : vertices_to_remove) {
            Utils.deleteVertex(inputGraph, v);
            total_removed += 1;
        }
        for (Edge e : edges_to_remove) {
            Utils.deleteEdge(inputGraph, e);
        }
        logger.info("Total Vertices Module removed: " + total_removed);
        vertices_to_remove.clear();
        edges_to_remove.clear();
    }

    public ArrayList<ArrayList<Vertex>> groupModuleVertices(Vertex vertex) {
        List<Pair<Vertex, String>> pairList = new ArrayList<Pair<Vertex, String>>();
        // TODO CHANGE HERE to only include Modules which do not have children
        for (Edge e : getListFromIterator(vertex.edges(Direction.IN))) {
            Vertex other = e.outVertex();
            if (getVertexId(other).equals(getVertexId(vertex))) {
                continue;
            }
            if (getType(other).equals(ObjectType.MODULE.name())) {
                pairList.add(new Pair<>(other, e.property(EdgeProperty.EVENTTYPE.name()).value().toString()));
            }
        }
        for (Edge e : getListFromIterator(vertex.edges(Direction.OUT))) {
            Vertex other = e.inVertex();
            if (getVertexId(other).equals(getVertexId(vertex))) {
                continue;
            }
            if (getType(other).equals(ObjectType.MODULE.name())) {
                pairList.add(new Pair<>(other, e.property(EdgeProperty.EVENTTYPE.name()).value().toString()));
            }
        }
        ArrayList<ArrayList<Vertex>> sameFile = new ArrayList<>();
        for (Pair<Vertex, String> pair : pairList) {
            boolean added = false;
            for (List<Vertex> l : sameFile) {
                Vertex head = l.get(0);
                if (directoryAndExtensionSameModule(pair, head)) {
                    added = true;
                    l.add(pair.getValue0());
                    break;
                }
            }
            if (!added) {
                ArrayList<Vertex> nl = new ArrayList<>();
                nl.add(pair.getValue0());
                sameFile.add(nl);
            }
        }
        return sameFile;
    }


    public ArrayList<ArrayList<Vertex>> groupFileVertices(Vertex vertex) {
        List<Pair<Vertex, String>> pairList = new ArrayList<Pair<Vertex, String>>();
        // TODO CHANGE HERE to only include files which do not have children
        for (Edge e : getListFromIterator(vertex.edges(Direction.IN))) {
            Vertex other = e.outVertex();
            if (getVertexId(other).equals(getVertexId(vertex))) {
                continue;
            }
            if (getType(other).equals(ObjectType.FILE.name())) {
                pairList.add(new Pair<>(other, e.property(EdgeProperty.EVENTTYPE.name()).value().toString()));
            }
        }

        for (Edge e : getListFromIterator(vertex.edges(Direction.OUT))) {
            Vertex other = e.inVertex();
            if (getVertexId(other).equals(getVertexId(vertex))) {
                continue;
            }
            if (getType(other).equals(ObjectType.FILE.name())) {
                pairList.add(new Pair<>(other, e.property(EdgeProperty.EVENTTYPE.name()).value().toString()));
            }
        }

        ArrayList<ArrayList<Vertex>> sameFile = new ArrayList<>();
        for (Pair<Vertex, String> pair : pairList) {
            boolean added = false;
            for (List<Vertex> l : sameFile) {
                Vertex head = l.get(0);
                if (directoryAndExtensionSame(pair, head)) {
                    added = true;
                    l.add(pair.getValue0());
                    break;
                }
            }
            if (!added) {
                ArrayList<Vertex> nl = new ArrayList<>();
                nl.add(pair.getValue0());
                sameFile.add(nl);
            }
        }
        return sameFile;
    }


    public static <T> List<T> getListFromIterator(Iterator<T> iterator) {
        return Lists.newArrayList(iterator);
    }


    public void mergeSameDstNetworks(Graph inputGraph) {
        for (Iterator<Vertex> vertices = inputGraph.vertices(); vertices.hasNext(); ) {
            Vertex vertex = vertices.next();

            if (!getType(vertex).equals(ObjectType.PROCESS.name())) {
                continue;
            }

            ArrayList<ArrayList<Vertex>> groups = groupNetworkVertices(vertex);
            for (ArrayList<Vertex> group : groups) {
                if (group.size() <= 1) {
                    continue;
                }
                Vertex first = group.get(0);
                // Except first vertex in the group remove everything
                for (Vertex v : group) {
                    if (getVertexId(v).equals(getVertexId(first))) {
                        continue;
                    }
                    removeEdge(inputGraph, v);
                }
            }
        }
        int total_removed = 0;
        for (Vertex v : vertices_to_remove) {
            Utils.deleteVertex(inputGraph, v);
            total_removed += 1;
        }
        for (Edge e : edges_to_remove) {
            Utils.deleteEdge(inputGraph, e);
        }
        logger.info("Total Vertices Network removed: " + total_removed);
        vertices_to_remove.clear();
        edges_to_remove.clear();

    }

    public String getVertexId(Vertex vertex) {
        return vertex.property(NodeProperty.ID.name()).toString();
    }

    public void removeEdge(Graph graph, Vertex vertex) {
        for (Edge e : getListFromIterator(vertex.edges(Direction.BOTH))) {
            this.edges_to_remove.add(e);
        }
        this.vertices_to_remove.add(vertex);
    }

    public ArrayList<ArrayList<Vertex>> groupNetworkVertices(Vertex vertex) {
        List<Pair<Vertex, String>> pairList = new ArrayList<Pair<Vertex, String>>();
        for (Edge e : getListFromIterator(vertex.edges(Direction.IN))) {
            Vertex other = e.outVertex();
            if (getVertexId(other).equals(getVertexId(vertex))) {
                continue;
            }
            if (getType(other).equals(ObjectType.NETWORK.name())) {
                pairList.add(new Pair<>(other, e.property(EdgeProperty.EVENTTYPE.name()).value().toString()));
            }
        }
        for (Edge e : getListFromIterator(vertex.edges(Direction.OUT))) {
            Vertex other = e.inVertex();
            if (getVertexId(other).equals(getVertexId(vertex))) {
                continue;
            }
            if (getType(other).equals(ObjectType.NETWORK.name())) {
                pairList.add(new Pair<>(other, e.property(EdgeProperty.EVENTTYPE.name()).value().toString()));
            }
        }
        ArrayList<ArrayList<Vertex>> sameNetwork = new ArrayList<>();
        for (Pair<Vertex, String> pair : pairList) {
            boolean added = false;
            for (List<Vertex> l : sameNetwork) {
                Vertex head = l.get(0);
                if (sameIPAndPort(pair, head)) {
                    added = true;
                    l.add(pair.getValue0());
                    break;
                }
            }
            if (!added) {
                ArrayList<Vertex> nl = new ArrayList<>();
                nl.add(pair.getValue0());
                sameNetwork.add(nl);
            }
        }
        if (vertex.property(NodeProperty.PID.name()).value().toString().equals("1520")) {
            System.out.println("Second woooooo " + sameNetwork.size());
        }
        return sameNetwork;
    }

    public String getType(Vertex vertex) {
        return vertex.property(NodeProperty.OBJECT_TYPE.name()).value().toString();
    }

    public boolean sameIPAndPort(Pair<Vertex, String> pair, Vertex head) {

        //System.out.println("TYPE " + pair.getValue1());
        if (pair.getValue1().equals(GraphEventType.NETWORK_ACCEPT.name())) {
            return sameDstIPAndPort(pair.getValue0(), head);
        }
        if (pair.getValue1().equals(GraphEventType.NETWORK_CONNECT.name())) {
            return sameSrcIPAndPort(pair.getValue0(), head);
        }
        return false;
    }

    public boolean sameSrcIPAndPort(Vertex v1, Vertex v2) {
        String addrV1 = v1.property(NodeProperty.SRC_IP.name()).value().toString();
        String addrV2 = v2.property(NodeProperty.SRC_IP.name()).value().toString();
        String portV1 = v1.property(NodeProperty.SRC_PORT.name()).value().toString();
        String portV2 = v2.property(NodeProperty.SRC_PORT.name()).value().toString();

        return addrV1.equals(addrV2) && portV1.equals(portV2);
    }

    public boolean sameDstIPAndPort(Vertex v1, Vertex v2) {
        String addrV1 = v1.property(NodeProperty.DST_IP.name()).value().toString();
        String addrV2 = v2.property(NodeProperty.DST_IP.name()).value().toString();
        String portV1 = v1.property(NodeProperty.DST_PORT.name()).value().toString();
        String portV2 = v2.property(NodeProperty.DST_PORT.name()).value().toString();

        return addrV1.equals(addrV2) && portV1.equals(portV2);
    }

    public void deleteProc(Graph inputGraph) {
        for (Iterator<Vertex> vertices = inputGraph.vertices(); vertices.hasNext(); ) {
            Vertex vertex = vertices.next();
            if (!getType(vertex).equals(ObjectType.FILE.name())) {
                continue;
            }
            String path = Utils.getPath(vertex);
            if (path.contains("/proc/")) {
                vertices_to_remove.add(vertex);
                for (Edge e : getListFromIterator(vertex.edges(Direction.BOTH))) {
                    edges_to_remove.add(e);
                }
            }
        }
        int total_removed = 0;
        for (Vertex v : vertices_to_remove) {
            Utils.deleteVertex(inputGraph, v);
            total_removed += 1;
        }
        for (Edge e : edges_to_remove) {
            Utils.deleteEdge(inputGraph, e);
        }
        vertices_to_remove.clear();
        edges_to_remove.clear();
        logger.info("Total Vertices Network removed: " + total_removed);
    }

    public void deleteSystemEdges(Graph inputGraph) {
        for (Iterator<Vertex> vertices = inputGraph.vertices(); vertices.hasNext(); ) {
            Vertex vertex = vertices.next();
            if (!getType(vertex).equals(ObjectType.PROCESS.name())) {
                continue;
            }
            String path = Utils.getPath(vertex);

            if (path.contains("/lib/systemd/")) {
                vertices_to_remove.add(vertex);
                //logger.info("Removed Symantec: " + path);
                for (Edge e : getListFromIterator(vertex.edges(Direction.BOTH))) {
                    edges_to_remove.add(e);
                }
            }
        }
        int total_removed = 0;
        for (Vertex v : vertices_to_remove) {
            Utils.deleteVertex(inputGraph, v);
            total_removed += 1;
        }
        for (Edge e : edges_to_remove) {
            Utils.deleteEdge(inputGraph, e);
        }
        vertices_to_remove.clear();
        edges_to_remove.clear();
        System.out.println("Total Vertices Symantec removed: " + total_removed);
    }

    public void removeTemporaryFiles(Graph inputGraph) {
        edges_to_remove.clear();
        vertices_to_remove.clear();
        for (Iterator<Vertex> vertices = inputGraph.vertices(); vertices.hasNext(); ) {
            Vertex vertex = vertices.next();
            if (!getType(vertex).contains("FILE"))
                continue;
            String path = vertex.property(NodeProperty.PATH.name()).value().toString();
            String filename = Utils.getFileName(path);
            String directory = Utils.getDirectoryName(path);
            String extension = Utils.getExtension(filename);

            if (directory.toLowerCase().contains("/appdata/local/") || directory.toLowerCase().contains("/appdata/roaming/") ||
                    directory.toLowerCase().contains("local settings/temp") || directory.toLowerCase().contains("/appdata/locallow/")) {
                removeEdge(inputGraph, vertex);
            }
            if (extension.toLowerCase().equals(".tmp") || directory.toLowerCase().contains("/appdata/roaming/")) {
                removeEdge(inputGraph, vertex);
            }

        }
        int total_removed = 0;
        for (Vertex v : vertices_to_remove) {
            Utils.deleteVertex(inputGraph, v);
            total_removed += 1;
        }
        for (Edge e : edges_to_remove) {
            Utils.deleteEdge(inputGraph, e);
        }
        vertices_to_remove.clear();
        edges_to_remove.clear();
        logger.info("Total Vertices Temprary removed" + total_removed);

    }
    // List of temporary file regexes
    // *AppData\Local\Temp*
    // *Local Settings\Temp
    // Extensions .tmp .TMP
}
