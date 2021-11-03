package utils;

import com.google.common.base.Charsets;
import com.google.common.collect.Lists;
import com.google.common.hash.Hashing;
import dotgraph.DotGraph;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.apache.tinkerpop.gremlin.structure.Edge;
import org.apache.tinkerpop.gremlin.structure.Graph;
import org.apache.tinkerpop.gremlin.structure.Vertex;
import provgraph.EdgeProperty;
import provgraph.NodeProperty;
import record.AddressPort;
import record.ObjectType;
import tracker.Algorithms;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.time.Instant;
import java.util.*;

public class Utils {
    private static final String IPV4_NETWORK_SOCKET_SADDR_PREFIX = "02";
    private static final String IPV6_NETWORK_SOCKET_SADDR_PREFIX = "0A";
    private static final String UNIX_SOCKET_SADDR_PREFIX = "01";
    private static final String NETLINK_SOCKET_SADDR_PREFIX = "10";
    private static final int EINPROGRESS = -115;
    private static final String PROTOCOL_NAME_UDP = "udp", PROTOCOL_NAME_TCP = "tcp";

    public static String getIdentifierFile(String path, String objtype) {
        StringBuilder sb = new StringBuilder();
        sb.append(path);
        sb.append(objtype);
        return Hashing.murmur3_128().hashString(sb.toString(), Charsets.UTF_16).toString();
    }

    public static String getIdentifierModule(String path, String normalized_path, String hash, String size) {
        StringBuilder sb = new StringBuilder();
        sb.append(path);
        sb.append(normalized_path);
        sb.append(hash);
        sb.append(size);
        return Hashing.murmur3_128().hashString(sb.toString(), Charsets.UTF_16).toString();
    }

    public static String decodeHex(String hexString) {
        if (hexString == null) {
            return null;
        } else {
            try {
                return new String(Hex.decodeHex(hexString.toCharArray()));
            } catch (Exception e) {
                // ignore
                return null;
            }
        }
    }


    static public boolean isUnixSaddr(String saddr) {
        return saddr != null && saddr.startsWith(UNIX_SOCKET_SADDR_PREFIX);
    }

    static public boolean isNetworkSaddr(String saddr) {
        return saddr != null && (isIPv4Saddr(saddr) || isIPv6Saddr(saddr));
    }

    static public boolean isIPv4Saddr(String saddr) {
        return saddr != null && saddr.startsWith(IPV4_NETWORK_SOCKET_SADDR_PREFIX);
    }

    static public boolean isIPv6Saddr(String saddr) {
        return saddr != null && saddr.startsWith(IPV6_NETWORK_SOCKET_SADDR_PREFIX);
    }

    static public boolean isNetlinkSaddr(String saddr) {
        return saddr != null && saddr.startsWith(NETLINK_SOCKET_SADDR_PREFIX);
    }

    public static AddressPort parseSaddr(String saddr) {
        try {
            String address = null, port = null;
            if (isIPv4Saddr(saddr) && saddr.length() >= 17) {
                port = Integer.toString(Integer.parseInt(saddr.substring(4, 8), 16));
                int oct1 = Integer.parseInt(saddr.substring(8, 10), 16);
                int oct2 = Integer.parseInt(saddr.substring(10, 12), 16);
                int oct3 = Integer.parseInt(saddr.substring(12, 14), 16);
                int oct4 = Integer.parseInt(saddr.substring(14, 16), 16);
                address = String.format("%d.%d.%d.%d", oct1, oct2, oct3, oct4);
            } else if (isIPv6Saddr(saddr) && saddr.length() >= 49) {
                port = Integer.toString(Integer.parseInt(saddr.substring(4, 8), 16));
                String hextet1 = saddr.substring(16, 20);
                String hextet2 = saddr.substring(20, 24);
                String hextet3 = saddr.substring(24, 28);
                String hextet4 = saddr.substring(28, 32);
                String hextet5 = saddr.substring(32, 36);
                String hextet6 = saddr.substring(36, 40);
                String hextet7 = saddr.substring(40, 44);
                String hextet8 = saddr.substring(44, 48);
                address = String.format("%s:%s:%s:%s:%s:%s:%s:%s", hextet1, hextet2, hextet3, hextet4,
                        hextet5, hextet6, hextet7, hextet8);
            }
            if (address != null && port != null) {
                return new AddressPort(address, port);
            }
        } catch (Exception e) {
            System.out.println("Not Saddr");
        }
        return null;
    }

    public static String constructAbsolutePath(String path, String parentPath, String pid) {
        path = concatenatePaths(path, parentPath);
        if (path != null) {
            path = removeSpecialPathSymbols(path);
            if (path != null) {
                path = resolvePathStatically(path, pid);
                return path;
            }
        }
        return null;
    }

    public static String getProtocolName(Integer protocolNumber) {
        if (protocolNumber != null) {
            if (protocolNumber == 17) {
                return PROTOCOL_NAME_UDP;
            } else if (protocolNumber == 6) {
                return PROTOCOL_NAME_TCP;
            }
        }
        return null;
    }

    public static String removeSpecialPathSymbols(String path) {
        if (path == null) {
            return null;
        }
        String finalPath = "";
        path = path.trim();
        if (path.isEmpty()) {
            return null;
        } else {
            String[] parts = path.split(File.separator);
            for (int a = parts.length - 1; a > -1; a--) {
                if (parts[a].equals("..")) {
                    a--;
                    continue;
                } else if (parts[a].equals(".")) {
                    continue;
                } else if (parts[a].trim().isEmpty()) {
                    /*
                     * Cases:
                     * 1) Start of path (/path/to/something)
                     * 2) End of path (path/to/something/)
                     * 3) Double path separator (/path//to////something)
                     */
                    // Continue
                } else {
                    finalPath = parts[a] + File.separator + finalPath;
                }
            }
            // Adding the slash in the end if the given path had a slash in the end
            if (!path.endsWith(File.separator) && finalPath.endsWith(File.separator)) {
                finalPath = finalPath.substring(0, finalPath.length() - 1);
            }
            // Adding the slash in the beginning if the given path had a slash in the beginning
            if (path.startsWith(File.separator) && !finalPath.startsWith(File.separator)) {
                finalPath = File.separator + finalPath;
            }
            return finalPath;
        }
    }

    public static String concatenatePaths(String path, String parentPath) {
        if (path != null) {
            path = path.trim();
            if (path.isEmpty()) {
                return null;
            } else {
                if (path.startsWith(File.separator)) { //is absolute
                    return path;
                } else {

                    if (parentPath != null) {
                        parentPath = parentPath.trim();
                        if (parentPath.isEmpty() || !parentPath.startsWith(File.separator)) {
                            return null;
                        } else {
                            return parentPath + File.separator + path;
                        }
                    }
                }
            }
        }
        return null;
    }

    public static String resolvePathStatically(String path, String pid) {
        if (path == null) {
            return null;
        }
        if (path.startsWith("/proc/self")) {
            if (pid == null) {
                return path;
            } else {
                StringBuilder string = new StringBuilder();
                string.append(path);
                string.delete(6, 10); // index of self in /proc/self is 6 and ends at 10
                string.insert(6, pid); // replacing with pid
                return string.toString();
            }
        } else { // No symbolic link to replace
            return path;
        }
    }

    public static String getIdentifierProcess(Map<String, String> eventData) {
        StringBuilder sb = new StringBuilder();
        String ppid = eventData.get("ppid");
        String pid = eventData.get("pid");
//        String path = eventData.get("exe") == null ? "" : eventData.get("exe");
//        String name = eventData.get("name") == null ? (eventData.get("comm") == null ? "" : eventData.get("comm")) : "";
//        String cmdline =  eventData.get("commandline") == null ? "" : eventData.get("commandline");
//        sb.append(path);
//        sb.append(name);
        sb.append(pid);
        sb.append(ppid);
//        sb.append(cmdline);
        return Hashing.murmur3_128().hashString(sb.toString(), Charsets.UTF_16).toString();
    }

    public static String getIdentifierRegistry(String path, String typeid, String name, String objtype) {
        StringBuilder sb = new StringBuilder();
        sb.append(path);
        sb.append(typeid);
        sb.append(name);
        sb.append(objtype);
        return Hashing.murmur3_128().hashString(sb.toString(), Charsets.UTF_16).toString();
    }

    public static String getIdentifierNetwork(String src_ip, String src_port, String dst_ip, String dst_port, String protocol, String direction, String syscall) {
        StringBuilder sb = new StringBuilder();
        sb.append(src_ip);
        sb.append(src_port);
        sb.append(dst_ip);
        sb.append(dst_port);
        sb.append(protocol);
        sb.append(direction);
        sb.append(syscall);
        return Hashing.murmur3_128().hashString(sb.toString(), Charsets.UTF_16).toString();
    }

    public static String getid(Vertex vertex) {
        return vertex.property(NodeProperty.ID.name()).value().toString();
    }

    public static String getEdgeId(Vertex actor, Vertex target, String act, String eventype, String eventid) {
        String uid = getid(actor) + getid(target) + eventype + act + eventid;
        return Hashing.murmur3_128().hashString(uid, Charsets.UTF_16).toString();
    }

    public static String extractShortName(String name) {
        if (name.contains("/")) {
            String ret_string = name.substring(name.lastIndexOf("/") + 1);
            return ret_string.substring(0, Math.min(35, ret_string.length()));
        } else if (name.contains("\\")) {
            String ret_string = name.substring(name.lastIndexOf("\\") + 1);
            return ret_string.substring(0, Math.min(35, ret_string.length()));
        } else {
            return name.substring(0, Math.min(35, name.length()));
        }
    }

    public static String escapeFilePath(String s) {

        String str = s.replace("\\", "/");
        return str.replace("\"", "\\\"");
    }

    public static String replaceTrailing(String s) {
        if (s.endsWith("\\")) {
            s = s.substring(0, s.length() - 1);
        }
        return s;
    }

    public static String getFileName(String path) {
        if (path.contains("/")) {
            String ret_string = path.substring(path.lastIndexOf("/") + 1);
            return ret_string;
        } else if (path.contains("\\")) {
            String ret_string = path.substring(path.lastIndexOf("\\") + 1);
            return ret_string;
        }
        return "";
    }

    public static String getExtension(String filename) {
        if (filename.contains(".")) {
            return filename.substring(filename.lastIndexOf(".") + 1);
        }
        return "";
    }

    public static String removeExtension(String filename) {
        if (filename.contains(".")) {
            return filename.substring(0, filename.lastIndexOf("."));
        }
        return "";
    }

    public static String removeExtensionFirst(String filename) {
        if (filename.contains(".")) {
            return filename.substring(0, filename.indexOf("."));
        }
        return "";
    }


    public static String getDirectoryName(String path) {
        if (path.contains("/")) {
            String ret_string = path.substring(0, path.lastIndexOf("/"));
            return Utils.escapeFilePath(ret_string);
        } else if (path.contains("\\")) {
            String ret_string = path.substring(0, path.lastIndexOf("\\"));
            return Utils.escapeFilePath(ret_string);
        }
        return "";
    }

    public static void deleteVertex(Graph g, Vertex vertex) {
        Iterator<Vertex> it = g.vertices(vertex);
        while (it.hasNext()) {
            it.next().remove();
        }
    }

    public static void deleteEdge(Graph g, Edge edge) {
        Iterator<Edge> it = g.edges(edge);
        while (it.hasNext()) {
            it.next().remove();
        }

    }

    public static void deleteEdgeWithVertex(Graph g, Edge edge) {
        Vertex in = edge.inVertex();
        Vertex out = edge.inVertex();
        Iterator<Vertex> it2 = g.vertices(in);
        while (it2.hasNext()) {
            it2.next().remove();
        }
        Iterator<Vertex> it3 = g.vertices(out);
        while (it3.hasNext()) {
            it3.next().remove();
        }
        Iterator<Edge> it = g.edges(edge);
        while (it.hasNext()) {
            it.next().remove();
        }
    }

    public static String getType(Vertex vertex) {
        return vertex.property(NodeProperty.OBJECT_TYPE.name()).value().toString();
    }

    public static String getType(Edge edge) {
        return edge.property(EdgeProperty.EVENTTYPE.name()).value().toString();
    }

    public static String getTime(Edge edge) {
        return edge.property(EdgeProperty.BEGIN_TIME.name()).value().toString();
    }

    public static String getRule(Edge edge) {
        if (edge.property(EdgeProperty.RULE_NAME.name()).isPresent())
            return edge.property(EdgeProperty.RULE_NAME.name()).value().toString();
        else
            return "Nan";
    }

    public static String getScore(Edge edge) {
        if (edge.property(EdgeProperty.RULE_SCORE.name()).isPresent())
            return edge.property(EdgeProperty.RULE_SCORE.name()).value().toString();
        else
            return "0";
    }

    public static String getScoreMitre(Edge edge) {
        if (edge.property(EdgeProperty.MITRE_SCORE.name()).isPresent())
            return edge.property(EdgeProperty.MITRE_SCORE.name()).value().toString();
        else
            return "0";
    }

    public static String getPath(Vertex vertex) {
        return vertex.property(NodeProperty.PATH.name()).value().toString();
    }

    public static String getId(Vertex vertex) {
        return vertex.property(NodeProperty.ID.name()).value().toString();
    }

    public static String getId(Edge edge) {
        return edge.property(EdgeProperty.ID.name()).value().toString();
    }

    public static String getcmdline(Vertex vertex) {
        return vertex.property(NodeProperty.CMD_LINE.name()).value().toString();
    }

    public static Vertex getStartVertex(Graph full_graph, String input_path, String input_cmd) {

        Vertex vertex = null;
        for (Iterator<Vertex> vertices = full_graph.vertices(); vertices.hasNext(); ) {
            vertex = vertices.next();
            if (getType(vertex).equals(ObjectType.PROCESS.name())) {
                String path = getPath(vertex);
                String cmd = getcmdline(vertex);
                if (path.contains(input_path) && cmd.contains(input_cmd)) {
                    return vertex;
                }
            }
        }
        return null;
    }

    public static Vertex getStartVertexById(Graph full_graph, String input_id) {
        Vertex vertex = null;
        for (Iterator<Vertex> vertices = full_graph.vertices(); vertices.hasNext(); ) {
            vertex = vertices.next();
            if (getType(vertex).equals(ObjectType.PROCESS.name())) {
                String id = getId(vertex);
                if (id.equals(input_id)) {
                    return vertex;
                }
            }
        }
        return null;
    }

    public static <T> List<T> getListFromIterator(Iterator<T> iterator) {
        return Lists.newArrayList(iterator);
    }


    public static String getIdentifierKernel(String name, String objtype) {
        StringBuilder sb = new StringBuilder();
        sb.append(name);
        sb.append(objtype);
        return Hashing.murmur3_128().hashString(sb.toString(), Charsets.UTF_16).toString();
    }

    /**
     * Execute a bash command. We can handle complex bash commands including
     * multiple executions (; | && ||), quotes, expansions ($), escapes (\), e.g.:
     * "cd /abc/def; mv ghi 'older ghi '$(whoami)"
     *
     * @param command
     * @return true if bash got started, but your command may have failed.
     */
    public static boolean executeBashCommand(String command) {
        boolean success = false;
        System.out.println("Executing BASH command:\n   " + command);
        Runtime r = Runtime.getRuntime();
        // Use bash -c so we can handle things like multi commands separated by ; and
        // things like quotes, $, |, and \. My tests show that command comes as
        // one argument to bash, so we do not need to quote it to make it one thing.
        // Also, exec may object if it does not have an executable file as the first thing,
        // so having bash here makes it happy provided bash is installed and in path.
        String[] commands = {"bash", "-c", command};
        try {
            Process p = r.exec(commands);

            p.waitFor();
            BufferedReader b = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line = "";

            while ((line = b.readLine()) != null) {
                System.out.println(line);
            }

            b.close();
            success = true;
        } catch (Exception e) {
            System.err.println("Failed to execute bash with command: " + command);
            e.printStackTrace();
        }
        return success;
    }

    public static String convertToLink(String link, String name) {
        String fin = "<a href=\"" + link + "\"><p>" + name + "</p></a>";
        return fin;
    }

    public static void countProcessVertices(Graph inputGraph) {
        int counter = 0;
        for (Iterator<Vertex> vertices = inputGraph.vertices(); vertices.hasNext(); ) {
            Vertex vertex = vertices.next();

            if (getType(vertex).equals(ObjectType.PROCESS.name())) {
                counter++;
            }
        }
        System.out.println("Total Process Vertices in Graph " + counter);
    }

    public static List<Edge> filterForwardEdges(List<Edge> outEdges, String begin_time) {
        List<Edge> filtered_edges = new ArrayList<>();
        Instant ref_time = Instant.parse(begin_time);
        for (Edge edge : outEdges) {
            Instant cur_time = Instant.parse(getTime(edge));
            int result = cur_time.compareTo(ref_time);
            if (result >= 0) {
                filtered_edges.add(edge);
            } else {
                //System.out.println("found Smaller edge");
            }
        }
        return filtered_edges;
    }

    public static List<Edge> filterBackwardEdges(List<Edge> inEdges, String begin_time) {
        List<Edge> filtered_edges = new ArrayList<>();
        Instant ref_time = Instant.parse(begin_time);
        for (Edge edge : inEdges) {
            Instant cur_time = Instant.parse(getTime(edge));
            int result = ref_time.compareTo(cur_time);
            if (result >= 0) {
                filtered_edges.add(edge);
            }
        }
        return filtered_edges;
    }

    public static String getMitreTID(Edge edge) {
        if (edge.property(EdgeProperty.MITRE_TID.name()).isPresent())
            return edge.property(EdgeProperty.MITRE_TID.name()).value().toString();
        else
            return "Nan";
    }

    public static String getMitrePhases(Edge edge) {
        return edge.property(EdgeProperty.MITRE_PHASES.name()).value().toString();

    }

    public static String getMitreTech(Edge edge) {
        return edge.property(EdgeProperty.MITRE_TECH.name()).value().toString();

    }

    public static void generateDFSGraph(Graph full_graph, String test_name, DotGraph dotgraph, String start_id) throws Exception {
        // DFS
        Vertex start_vertex = Utils.getStartVertexById(full_graph, start_id);
        List<Edge> flat = new ArrayList<>();

        if (start_vertex != null) {
            System.out.println("WAJIH: " + Utils.getPath(start_vertex));
            Algorithms new_algo = new Algorithms();
            ArrayList<ArrayList<Edge>> edges = new_algo.runForward(start_vertex);
            System.out.println("Done with forward");
            for (List<Edge> list : edges) {
                for (Edge edge : list) {
                    flat.add(edge);
                }
            }
            if (flat.isEmpty()) {
                System.out.println("WARNING FLAT IS EMPTY!!!!!!!!!!!!!!!!!!!!!! ~~~~~~~~~~~~~~");
                return;
            }
            String outputGraph_dfs = "tmp/graph_dfs_" + test_name + ".dot";
            String outputGraph_dfs_pdf = "tmp/graph_dfs_" + test_name + ".pdf";
            dotgraph.DotGraphFromEdges(flat, outputGraph_dfs);
            String dot_graph = "dot -Tpdf " + outputGraph_dfs + " -o " + outputGraph_dfs_pdf;
            Runtime.getRuntime().exec(new String[]{"bash", "-c", dot_graph});
            System.out.println("Writing pdf file " + outputGraph_dfs_pdf);
        } else {
            System.out.println("start id was NULL");
        }
    }

    public static Map<Integer, String> getPathsWithNametype(Map<String, String> eventData, String nametypeValue) {
        Map<Integer, String> indexToPathMap = new HashMap<Integer, String>();
        if (eventData != null && nametypeValue != null) {
            Long items = CommonFunctions.parseLong(eventData.get("items"), 0L);
            for (int itemcount = 0; itemcount < items; itemcount++) {
                if (nametypeValue.equals(eventData.get("nametype" + itemcount))) {
                    indexToPathMap.put(itemcount, eventData.get("path" + itemcount));
                }
            }
        }
        return indexToPathMap;
    }

    public static String constructPath(String path, String parentPath) {
        try {

            if (path != null) {

                if (path.startsWith(File.separator)) { //is absolute
                    return new File(path).getCanonicalPath();
                } else {

                    if (parentPath != null) {
                        if (parentPath.startsWith(File.separator)) { //is absolute
                            return new File(parentPath + File.separator + path).getCanonicalPath();
                        }
                    }
                }
            }

        } catch (Exception e) {
            //TODO
            System.out.println("WAJIH: ERROR OCCURRED .........");
        }
        return null;
    }

    public static Map<String, String> readConfigFileAsKeyValueMap(String filepath, String keyValueSeparator) throws Exception {
        Map<String, String> map = new HashMap<String, String>();
        List<String> lines = readLines(filepath);
        for (String line : lines) {
            line = line.trim();
            if (!line.isEmpty() && !line.startsWith("#")) {
                String[] tokens = line.split(keyValueSeparator);
                if (tokens.length == 2) {
                    String from = tokens[0].trim();
                    String to = tokens[1].trim();
                    map.put(from, to);
                }
            }
        }
        return map;
    }

    public static List<String> readLines(String path) throws Exception {
        if (isFileReadable(path)) {
            return FileUtils.readLines(getFile(path));
        } else {
            throw new Exception("Not a readable file");
        }
    }

    private static File getFile(String path) throws Exception {
        return new File(path);
    }

    public static boolean isFileReadable(String path) throws Exception {
        if (isFile(path)) {
            return getFile(path).canRead();
        } else {
            throw new Exception("Path is not a file");
        }

    }

    public static boolean isFile(String path) throws Exception {
        if (doesPathExist(path)) {
            return getFile(path).isFile();
        } else {
            throw new Exception("Path does not exist");
        }
    }

    public static boolean doesPathExist(String path) throws Exception {
        if (isPathValid(path)) {
            return getFile(path).exists();
        } else {
            throw new Exception("Invalid path");
        }
    }

    public static boolean isPathValid(String path) throws Exception {
        getFile(path);
        return true;

    }


}
