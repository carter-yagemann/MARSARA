package parsers.partitioner;

import parsers.jgraph.ULogNode;
import parsers.jparser.JValidator;

import java.util.HashMap;
import java.util.ListIterator;
import java.util.Map;

/**
 * This is the main worker that perform execution partitioning for the list of events.
 */
public class JPartitioner {
    /**
     * A partitioner node. This contains either a node from the audit log or a application log node
     */
    public interface PartitionerNode {
        /**
         * Type check for a omega log node
         */
        default Boolean isULogNode() {
            return false;
        }

        /**
         * Type check for an audit event log node
         */
        default Boolean isAuditNode() {
            return false;
        }

        /**
         * Get the node's unique id
         */
        int getId();

        Object getNode();
    }

    public static class PartitionerULogNode implements PartitionerNode {
        /**
         * The underlying omegalog node
         */
        private final ULogNode node;

        public PartitionerULogNode(ULogNode node) {
            this.node = node;
        }

        @Override
        public Boolean isULogNode() {
            return true;
        }

        @Override
        public int getId() {
            if (node == null)
                return -1;
            return node.getId();
        }

        @Override
        public Object getNode() {
            return node;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj instanceof PartitionerULogNode) {
                PartitionerNode objNode = (PartitionerULogNode) obj;
                return (this.getId() == objNode.getId());
            }
            return false;
        }
    }

    public static class PartitionerAuditNode implements PartitionerNode {
        /**
         * The actual event
         */
        private final Map<String, String> auditEvent;
        /**
         * The last visited block node from omegalog
         */
        private final ULogNode lastVisitedNode;

        public PartitionerAuditNode(Map<String, String> auditEvent, ULogNode lastVisitedNode) {
            this.auditEvent = auditEvent;
            this.lastVisitedNode = lastVisitedNode;
        }

        @Override
        public Boolean isAuditNode() {
            return true;
        }

        @Override
        public int getId() {
            if (lastVisitedNode == null)
                return -1;
            return this.lastVisitedNode.getId();
        }

        @Override
        public Object getNode() {
            return auditEvent;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj instanceof PartitionerAuditNode) {
                PartitionerAuditNode objNode = (PartitionerAuditNode) obj;
                return (this.getId() == objNode.getId());
            }
            return false;
        }
    }


    /**
     * The top application node that is currently used for splitting executions
     */
    private PartitionerNode topNode;
    /**
     * The number of times we have visited the top node so far
     */
    private int topVisits;
    /**
     * A map that counts the number of times an application log message has been spotted
     */
    private final Map<PartitionerNode, Integer> visitedNodeCount;
    /**
     * A flag that says if this is the first time we add a log node
     */
    private Boolean firstVisit;
    /**
     * The map from node id to the corresponding partitioner node
     */
    private final Map<Integer, PartitionerNode> idToPartitionerNode;
    /**
     * The parent validator
     */
    private final JValidator parent;

    /**
     * Constructor
     */
    public JPartitioner(JValidator jValidator) {
        this.topNode = null;
        this.visitedNodeCount = new HashMap<>();
        this.firstVisit = true;
        this.idToPartitionerNode = new HashMap<>();
        this.parent = jValidator;
    }

    private int __addNode(PartitionerNode pNode) {
        int numVisits = 1;
        if (visitedNodeCount.containsKey(pNode)) {
            numVisits = visitedNodeCount.get(pNode);
            visitedNodeCount.put(pNode, ++numVisits);
        } else {
            visitedNodeCount.put(pNode, 1);
        }
        // check if we need to update the topNode
        if (numVisits > topVisits) {
            this.topNode = pNode;
            this.topVisits = numVisits;
        }
        return numVisits;
    }

    private PartitionerNode grabNode(ULogNode node) {
        if (idToPartitionerNode.containsKey(node.getId())) {
            return idToPartitionerNode.get(node.getId());
        }
        PartitionerNode pNode = new PartitionerULogNode(node);
        idToPartitionerNode.put(node.getId(), pNode);
        return pNode;
    }

    private PartitionerNode grabNode(Map<String, String> auditEvent, ULogNode node) {
        int eId;
        if (node == null) {
            eId = -1;
        } else {
            eId = node.getId();
        }
        if (idToPartitionerNode.containsKey(eId)) {
            return idToPartitionerNode.get(eId);
        }
        PartitionerNode pNode = new PartitionerAuditNode(auditEvent, node);
        idToPartitionerNode.put(eId, pNode);
        return pNode;
    }

    /**
     * Add a node to the counting map
     *
     * @param node the node to insert.
     * @return the created partitioner node.
     */
    public PartitionerNode addNode(ULogNode node, int[] numVisited) {
        PartitionerNode pNode = grabNode(node);
        numVisited[0] = __addNode(pNode);
        return pNode;
    }

    /**
     * Add a node to the counting map
     *
     * @param auditEvent the audit event node from the log.
     * @return the created partitioner node.
     */
    public PartitionerNode addNode(Map<String, String> auditEvent, int[] numVisited) {
        // find the last visited ulog node
        ULogNode prevNode = FindLastULogNode();
        PartitionerNode pNode = grabNode(auditEvent, prevNode);
        numVisited[0] = __addNode(pNode);
        return pNode;
    }

    private ULogNode FindLastULogNode() {
        ListIterator<JValidator.ValidationState> it = parent.path.listIterator(parent.path.size());
        if (it.hasPrevious()) {
            JValidator.ValidationState validationState = it.previous();
            return validationState.getNode();
        }
        return null;
    }

    /**
     * Check for whether this is the first visit to the partitioner and update the flag.
     *
     * @return true if this is the first visit, false subsequently.
     */
    public Boolean isFirstVisit() {
        if (this.firstVisit) {
            this.firstVisit = false;
            return true;
        }
        return false;
    }

    /**
     * Check if a node matches with the top node of the partitioner
     *
     * @param node The node to check.
     * @return true if the node is the top node, false otherwise.
     */
    public Boolean checkTopNode(PartitionerNode node) {
        return node.equals(this.topNode);
    }
}

