package parsers.jgraph;

import java.util.*;

public class ULogGraph {
    private final Map<Integer, ULogNode> nodes;
    private final Map<ULogNode, List<ULogLink>> adjLinks;
    private final Map<ULogNode, List<ULogLink>> inLinks;
    private final Map<String, ULogFunction> functions;

    private List<ULogNode> candidateCache;

    // error codes
    public static final int OpOkay = 0;
    public static final int NodeAlreadyPresent = 1;
    public static final int NodeNotFoundError = 2;

    public ULogGraph() {
        nodes = new HashMap<>();
        adjLinks = new HashMap<>();
        inLinks = new HashMap<>();
        functions = new HashMap<>();
        candidateCache = null;
    }

    public ULogFunction getNodeFunction(ULogNode node) {
        if (functions.isEmpty())
            fillFunctions();
        if (functions.containsKey(node.getFunction())) {
            return functions.get(node.getFunction());
        }
        return null;
    }

    public boolean hasEdge(ULogNode u, ULogNode v) {
        // check if u->v is in the list
        for (ULogLink link : GetOutEdges(u)) {
            if (link.dst == v)
                return true;
        }
        return false;
    }

    public enum ReturnPathType {
        EXACT,
        /**
         * exact match from the return of the function
         */
        UNRESOLVED,
        /**
         * unresolved match from the return of the function
         */
        NO_MATCH,        /** no match at all */
    }

    public ReturnPathType hasReturnPath(ULogNode u, ULogNode v) {
        // check if there is an edge from u's function that returns into v.
        // the goal of this function is to resync the blocks between PT and angr.
        ULogFunction fn = getNodeFunction(u);
        if (fn == null)
            return ReturnPathType.NO_MATCH;
        for (ULogNode n : fn.Returns()) {
            if (hasEdge(n, v)) {
                return ReturnPathType.EXACT;
            }
            if (GetOutEdges(n).size() == 0) {
                return ReturnPathType.UNRESOLVED;
            }
        }
        return ReturnPathType.NO_MATCH;
    }

    public Map<String, ULogFunction> functions() {
        if (functions.isEmpty())
            fillFunctions();
        return functions;
    }

    private void fillFunctions() {
        for (Map.Entry<Integer, ULogNode> entry : nodes.entrySet()) {
            ULogNode n = entry.getValue();
            String fname = n.getFunction();
            if (fname.equals(""))
                continue;
            if (functions.containsKey(fname)) {
                ULogFunction fn = functions.get(fname);
                fn.AddNode(n);
            } else {
                ULogFunction fn = new ULogFunction(fname);
                fn.AddNode(n);
                functions.put(fname, fn);
            }
        }
    }

    /**
     * Emulate networkx as much as possible
     */
    public Map<Integer, ULogNode> Nodes() {
        return nodes;
    }

    /**
     * Caller should handle the null case
     */
    public ULogNode GetNode(int id) {
        return nodes.get(id);
    }

    public int GetNumEdges() {
        int numEdges = 0;
        for (Map.Entry<ULogNode, List<ULogLink>> entry : adjLinks.entrySet()) {
            numEdges += entry.getValue().size();
        }
        return numEdges;
    }

    public int AddNode(ULogNode n) {
        if (nodes.get(n.getId()) == null) {
            nodes.put(n.getId(), n);
            return OpOkay;
        }

        return NodeAlreadyPresent;
    }

    public int AddEdge(int srcId, int dstId) {
        ULogNode src = nodes.get(srcId);
        ULogNode dst = nodes.get(dstId);

        if (src == null || dst == null)
            return NodeNotFoundError;
        return AddEdge(src, dst);
    }

    public ULogLink AddAndGetEdge(ULogNode src, ULogNode dst) {
        if (nodes.containsKey(src.getId()) &&
                nodes.containsKey(dst.getId())) {
            // create the edge
            ULogLink edge = new ULogLink(src, dst);
            _addAdjEdge(edge);
            return edge;
        }
        return null;

    }

    public int AddEdge(ULogNode src, ULogNode dst) {
        if (nodes.containsKey(src.getId()) &&
                nodes.containsKey(dst.getId())) {
            // create the edge
            ULogLink edge = new ULogLink(src, dst);
            _addAdjEdge(edge);
            return OpOkay;
        }
        return NodeNotFoundError;
    }

    public List<ULogLink> GetInEdges(ULogNode n) {
        if (!inLinks.containsKey(n)) {
            return new LinkedList<>();
        }
        return new LinkedList<>(inLinks.get(n));
    }

    public List<ULogLink> GetInEdges(int id) {
        ULogNode n = nodes.get(id);

        return GetInEdges(n);
    }

    public List<ULogLink> GetOutEdges(ULogNode n) {
        if (!adjLinks.containsKey(n)) {
            return new LinkedList<>();
        }
        return new LinkedList<>(adjLinks.get(n));
    }

    public List<ULogLink> GetOutEdges(int id) {
        ULogNode n = nodes.get(id);

        return GetOutEdges(n);
    }

    public ULogNode FindStartNode() {
        // iterate over the nodes and find the starting one
        for (Map.Entry<Integer, ULogNode> entry : nodes.entrySet()) {
            if (entry.getValue().isStartNode())
                return entry.getValue();
        }

        return null;
    }

    public List<ULogNode> GetCache() {
        if (candidateCache == null) {
            candidateCache = new LinkedList<ULogNode>();
            populateCache();
        }

        return candidateCache;
    }

    private void _addAdjEdge(ULogLink edge) {
        ULogNode src = edge.src;
        ULogNode dst = edge.dst;

        // add it the adjacent links
        List<ULogLink> outEdges;
        if (adjLinks.containsKey(src)) {
            // already in there
            outEdges = adjLinks.get(src);
            outEdges.add(edge);
        } else {
            // not found there
            outEdges = new LinkedList<ULogLink>();
            outEdges.add(edge);
            adjLinks.put(src, outEdges);
        }

        List<ULogLink> inEdges = inLinks.get(dst);
        if (inEdges == null) {
            // not found there
            inEdges = new LinkedList<ULogLink>();
            inEdges.add(edge);
            inLinks.put(dst, inEdges);
        } else {
            // already in there
            inEdges.add(edge);
        }
    }

    /**
     * Check if there is a path in the graph between src and dst
     *
     * @param src The source node of the path
     * @param dst The destination node of the path
     * @return true if there is a path in graph from src to dst, false otherwise.
     */
    public boolean hasPath(ULogNode src, ULogNode dst) {
        Set<ULogNode> visitedSet = new HashSet<>();
        Queue<ULogLink> edges = new LinkedList<>(this.GetOutEdges(src));

        while (!edges.isEmpty()) {
            ULogNode node = edges.remove().dst;
            // if hit the destination node, done and return
            if (node == dst)
                return true;
            // skip over visited nodes
            if (visitedSet.contains(node))
                continue;
            // if not, then add the out edges to the list of outputs
            visitedSet.add(node);
            edges.addAll(this.GetOutEdges(node));
        }
        return false;
    }

    /**
     * Check if there is path between src and dst and return it.
     *
     * @param src  The source node on the path.
     * @param node The destination node on the path.
     * @param path The path list to fill up if the path is found.
     * @return true if there is a path in graph from src to dst, false otherwise.
     */
    public boolean getPath(ULogNode src, ULogNode node, List<ULogNode> path) {
        Set<ULogNode> visitedSet = new HashSet<>();
        Stack<ULogLink> edges = new Stack<>();
        for (ULogLink l : GetOutEdges(src)) {
            edges.push(l);
        }
        Stack<ULogNode> stack = new Stack<>();
        stack.push(src);
        while (!edges.isEmpty()) {
            ULogLink link = edges.pop();
            if (link.src != stack.peek()) {
                while (stack.peek() != link.src)
                    stack.pop();
            }
            if (link.dst == node) {
                path.addAll(stack);
                return true;
            }
            if (visitedSet.contains(link.dst))
                continue;
            stack.push(link.dst);
            visitedSet.add(link.dst);
            edges.addAll(GetOutEdges(link.dst));
        }
        return false;
    }

    private void populateCache() {
        for (Map.Entry<Integer, ULogNode> entry : nodes.entrySet()) {
            ULogNode node = entry.getValue();

            if (node.isStartNode() || node.isLikelyExec()) {
                candidateCache.add(node);
            }
        }
    }
}
