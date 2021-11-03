package parsers.jparser;

import event.PTAppLogEvent;
import event.PTEvent;
import event.SYSCALL;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import parsers.AuditEventReader;
import parsers.jgraph.ULogGraph;
import parsers.jgraph.ULogLink;
import parsers.jgraph.ULogNode;
import parsers.partitioner.JPartitioner;
import tracker.PTAnalyzer;
import utils.CommonFunctions;
import utils.Statistics;
import utils.Utils;

import java.text.MessageFormat;
import java.util.*;

public class JValidator {
    private static final Logger l = LoggerFactory.getLogger(JValidator.class);
    private static final int arch = 64;

    // the omega log graph we are processing
    private final ULogGraph graph;
    // the regex expression matcher
    private final FormatMatcher expr;
    // the current state path in the verifier
    public List<ValidationState> path;
    // The current state we are working with
    private ValidationState currState;
    // A queue of unconfirmed states.
    public Queue<ValidationState> pendingStates;
    /**
     * Keep track of pending system calls
     */
    public Stack<ValidationState> pendingSyscalls;
    /**
     * Kepp track of the execution paritioning state
     */
    private final JPartitioner jPartitioner;
    /**
     * Keep a reference to the stats collector of the parent analyzer
     */
    private final Statistics statsCollector;

    public JValidator(ULogGraph graph, FormatMatcher expr, Statistics statsCollector) {
        this.graph = graph;
        this.expr = expr;
        this.path = new LinkedList<>();
        this.currState = null;
        this.pendingStates = new LinkedList<>();
        this.pendingSyscalls = new Stack<>();
        this.jPartitioner = new JPartitioner(this);
        this.statsCollector = statsCollector;
    }

    public ValidationState getCurrState() {
        return currState;
    }

    public static ULogNode grabEventNode(PTAppLogEvent event, ULogGraph graph) {
        int nodeId = event.getWNodeId();
        return graph.GetNode(nodeId);
    }

    public Boolean consumeEvent(PTEvent ptEvent, Map<String, String> auditEvent) {
        if (ptEvent.isAppLogEvent()) {
            // need to handle an application log event, this can be tow things, a
            // code block or a log message block. If it is a code block, then
            // the audit event must necessarily be null. If not, then the auditEvent
            // can be a system call event or an applog write event.
            PTAppLogEvent ptAppLogEvent = (PTAppLogEvent) ptEvent;
            int nodeId = ptAppLogEvent.getWNodeId();

            // grab the omega log node
            ULogNode node = graph.GetNode(nodeId);
            if (node == null) {
                l.error(MessageFormat.format("Cannot find log node for event {0}", ptAppLogEvent.toString()));
                // TODO: throw an exception here!
                return false;
            }

            // check if it is an application log message, which it should be
//            if (node.isRegex() && node.getId() != 7) {
            if (node.isRegex()) {
                // application log event
                assert (auditEvent != null);
                ValidationState validationState = popAndCheckState(node); //  new ValidationState(node);
                if (validationState == null) {
                    validationState = new ValidationState(node, currState);
                }
                validateApplicationEvent(auditEvent, validationState);
                return resolveExecutionUnits(validationState);
            } else if (node.isSyscall() && auditEvent != null) {
                ValidationState validationState = new ValidationState(node);
                validateSystemCallEvent(auditEvent, validationState);
                return resolveExecutionUnits(validationState);
            }

            // this is a code event, keep moving through the path
            assert (auditEvent == null); // this shouldn't be relevant at this point
            l.debug("Processing code block node: " + node.getStr());
            ValidationState validationState = new ValidationState(node);
            validateCodeEvent(validationState);
            return resolveExecutionUnits(validationState);
        } else {
            // should not reach here
            l.error("Reached JValidator.consumeEvent without an application log event");
        }
        return false;
    }

    public Boolean consumeAppWriteEvent(Map<String, String> auditEvent) {
        // add it to the execution partitioner
        int[] numVisited = new int[1];
        JPartitioner.PartitionerNode pNode = jPartitioner.addNode(auditEvent, numVisited);
        return jPartitioner.isFirstVisit() || (numVisited[0] > 1 && jPartitioner.checkTopNode(pNode));
    }

    private void validateSystemCallEvent(Map<String, String> auditEvent, ValidationState validationState) {
        int sysNum = CommonFunctions.parseInt(auditEvent.get("syscall"), -1);
        SYSCALL syscall = SYSCALL.getSyscall(sysNum, arch);
        Set<String> libCall = PTAnalyzer.getLibcCall(syscall);

        ULogNode node = validationState.getNode();
        if ((libCall == null) || !libCall.contains(node.getSyscallName())) {
//        if ((libCall == null) || !node.getStr().equals(libCall)) {
            // no match, raise a problem
            l.error(MessageFormat.format("Expected Libc call {0} does not match audit log {1}",
                    node.getStr(), libCall));
            System.exit(-1);
        }

        // check if this is the first match in a loop
        if (this.currState == null) {
            // we are done, update the internal state and return
            updateInternalState(validationState);
            return;
        }

        if (checkSequentialPath(validationState, this.currState))
            return;

        // reached here, means no sequential match from before, so this can be:
        // (1) start of a new execution unit
        // (2) a path discovered that is not covered by the LMS graph
        handleNonSequentialMatch(validationState, node, this.currState);
    }

    /**
     * Validate a block code event in the wlog graph
     *
     * @param validationState The next expected state
     */
    private void validateCodeEvent(ValidationState validationState) {
        if (this.currState == null) {
            l.debug("We got our first internal state");
            updateInternalState(validationState);
            return;
        }

        if (checkSequentialPath(validationState, this.currState))
            return;

        // reached here, means no sequential match from before, so this can be:
        // (1) start of a new execution unit
        // (2) a path discovered that is not covered by the LMS graph
        ULogNode node = validationState.getNode();
        handleNonSequentialMatch(validationState, node, this.currState);
    }

    /**
     * Verify an application log event and update the states accordingly.
     *
     * @param auditEvent      The auditd log event corresponding to the application log
     * @param validationState The newly created verifier state
     */
    private void validateApplicationEvent(Map<String, String> auditEvent,
                                          ValidationState validationState) {
        // grab the data from the audit event
        String data = Utils.decodeHex(auditEvent.get(AuditEventReader.DATA));

        // grab the node's format specifier
        ULogNode node = validationState.getNode();
        String fmt = (String) node.getAttribute("val");

        // make sure they match, if they do not then we have a problem
        if (expr.IsMatch(fmt, data) < 0) {
            // no match, raise a problem
            l.error(MessageFormat.format("Log message ({0}) does not match format ({1})",
                    data, fmt));
            statsCollector.setNumCriticalAlerts(statsCollector.getNumCriticalAlerts()+1);
        }
        l.debug("Matched {} with {}", fmt, data);

        // check if this is the first match in a loop
        if (this.currState == null) {
            // we are done, update the internal state and return
            updateInternalState(validationState);
            return;
        }

        if (checkSequentialPath(validationState, this.currState))
            return;

        // reached here, means no sequential match from before, so this can be:
        // (1) start of a new execution unit
        // (2) a path discovered that is not covered by the LMS graph
        handleNonSequentialMatch(validationState, node, this.currState);
    }

    /**
     * Handle the case where we do not have a sequential match between the previous state and the
     * currently matched node. This is will check for multiple options in order. Check the documentation
     * of each check for more information.
     *
     * @param validationState The currently matched validation state.
     * @param node            The matched node.
     */
    private void handleNonSequentialMatch(ValidationState validationState, ULogNode node, ValidationState prevState) {
        // first check if jumping into the head of a function (i.e., resolving an indirect jump)
        if (isJumpIntoFunction(node)) {
            statsCollector.incrementForwardEdges(prevState, validationState);
            statsCollector.setNumLowAlerts(statsCollector.getNumLowAlerts() + 1);
            statsCollector.addLowAlert(prevState, validationState);
            updateInternalState(validationState);
            return;
        }

        // now check if we are returning from a function and but we have an unresolved return
        if (isIndirectJumpTarget(node, prevState)) {
            statsCollector.incrementBackwardEdges(prevState, validationState);
            statsCollector.setNumLowAlerts(statsCollector.getNumLowAlerts() + 1);
            statsCollector.addLowAlert(prevState, validationState);
            updateInternalState(validationState);
            return;
        }

        if (this.graph.hasPath(prevState.getNode(), node)) {
            // the graph already has a path from the previous node to the current one and there is a mismatch
            // between the possible path. THis means that there is a broken path
            l.warn(MessageFormat.format("***** Path with missing node detected from {0} to {1} *****",
                    prevState.getNode().getStr(), node.getStr()));
            statsCollector.setNumLowAlerts(statsCollector.getNumLowAlerts() + 1);
            statsCollector.addLowAlert(prevState, validationState);
            statsCollector.increaseUncategorizedEdges(prevState, validationState);
            updateInternalState(validationState);
            return;
        }
        l.warn(MessageFormat.format("(2) BROKEN PATH DETECTED on path from {0} to {1}",
                prevState.getNode().getStr(), node.getStr()));
        statsCollector.setNumLowAlerts(statsCollector.getNumLowAlerts() + 1);
        statsCollector.addLowAlert(prevState, validationState);
        statsCollector.increaseUncategorizedEdges(prevState, validationState);
        updateInternalState(validationState);
    }

    /**
     * \brief Check if the node is the target of an indirect jump.
     * <p>
     * This function will check if the node is a likely target of an indirect jump. The way to handle this is by
     * checking for three conditions:
     * (1) is the prev node a function return block?
     * (2) does the prev node have no forward edges?
     * (3) are all the forward edges from the previous node shadow ones?
     *
     * @param node The node to check for
     * @return true if the node is a likely target of an indirect jump, false otherwise.
     */
    private boolean isIndirectJumpTarget(ULogNode node, ValidationState prevState) {
        ULogNode prevNode = prevState.getNode();
        // check if already marked as a function node out
        if (prevNode.isFuncOut()) {
            l.debug(MessageFormat.format("Node {0} is likely the target of a indirect jump...", node));
            return true;
        }

        // check if prev node has no out edges, i.e., it is stuck
        List<ULogLink> outEdges = graph.GetOutEdges(prevNode);
        int size = outEdges.size();
        if (this.graph.GetOutEdges(prevNode).size() == 0) {
            l.debug(MessageFormat.format("Node {0} is likely the target of a indirect jump from {1}...", node, prevNode));
            return true;
        }

        // check if all out edges are shadow ones
        for (ULogLink link : this.graph.GetOutEdges(prevNode)) {
            if (!link.isShadow())
                return false;
        }
//        l.debug(MessageFormat.format("Node {0} is likely the head of a indirect function...", node));
//        return true;
        return false;
    }

    /**
     * \brief Check if the node is likely the head of a function pointer
     * <p>
     * This function checks whether the given node is likely to be the head of a function pointer that was not
     * resolved during the CFG construction. A node is labeled to be likely the head of a function pointer if
     * any of these conditions hold:
     * (1) The node is the head block of a function.
     * (2) The node has no input edges.
     * (3) All input edges to the node are shadow edges.
     *
     * @param node The node to check
     * @return true if the node is likely to be the head of a function pointer, false otherwise.
     */
    private boolean isJumpIntoFunction(ULogNode node) {
        if (node.isFuncHead()) {
            l.debug(MessageFormat.format("Node {0} is likely the head of a indirect function...", node));
            return true;
        }

        if (this.graph.GetInEdges(node).size() == 0) {
            l.debug(MessageFormat.format("Node {0} is likely the head of a indirect function...", node));
            return true;
        }

        // check if all input edges are shadow edges
        for (ULogLink link : this.graph.GetInEdges(node)) {
            if (!link.isShadow())
                return false;
        }
        return false;
    }

    /**
     * Check if the next state is a sequential match of the current one.
     *
     * @param validationState The state to match for.
     * @param prevState       The previous state to use for matching.
     * @return true if matched, false otherwise
     */
    private boolean checkSequentialPath(ValidationState validationState, ValidationState prevState) {
        if (prevState == null)
            return false;

        // now need to perform a pattern match
        ULogNode nextNode = validationState.getNode();
        ULogNode prevNode = prevState.getNode();

        // check that the current node is a direct descendant of the previous node
        Queue<ULogLink> out_edges = new LinkedList<>();
        Set<ULogNode> visited = new HashSet<>();
        List<ULogLink> ee = graph.GetOutEdges(prevNode);
        // check if the out edge is a loop, we then need to check its children as well
        if (prevNode.isLoop()) {
            for (ULogLink link : graph.GetOutEdges(prevNode)) {
                ee.addAll(graph.GetOutEdges(link.dst));
            }
        }
        if (out_edges.addAll(ee)) {
            while (!out_edges.isEmpty()) {
                ULogNode neighbor = out_edges.remove().dst;
                visited.add(neighbor);
                // if match, then we are done
                if (neighbor == nextNode) {
                    l.debug("Found sequential match, no need to split into new execution unit");
                    // update the internal states
                    updateInternalState(validationState);
                    return true;
                }
                // if not, skip over loop nodes
                if (neighbor.isLoop()) {
                    for (ULogLink link : graph.GetOutEdges(neighbor)) {
                        ULogNode grandChild = link.dst;
                        if (!visited.contains(grandChild)) {
                            out_edges.add(link);
                        }
                    }
                }
            }
        }
//        if (graph.getNodeFunction(prevNode) != null) {
//            ULogGraph.ReturnPathType type = graph.hasReturnPath(prevNode, nextNode);
//            if (type == ULogGraph.ReturnPathType.EXACT) {
//                updateInternalState(validationState);
//                return true;
//            } else if (type == ULogGraph.ReturnPathType.UNRESOLVED) {
//                updateInternalState(validationState);
//                statsCollector.setNumLowAlerts(statsCollector.getNumLowAlerts()+1);
//                return true;
//            }
//        } else {
//            // find the name of the last function
//            ValidationState grandParentState = prevState.getPrevState();
//            while ((grandParentState != null) && (graph.getNodeFunction(grandParentState.getNode()) == null)) {
//                grandParentState = grandParentState.getPrevState();
//            }
//            // find the first grand parent that has a function, this is the one we should check
//            if (grandParentState != null) {
//                ULogGraph.ReturnPathType type = graph.hasReturnPath(grandParentState.getNode(), nextNode);
//                if (type == ULogGraph.ReturnPathType.EXACT) {
//                    updateInternalState(validationState);
//                    return true;
//                } else if (type == ULogGraph.ReturnPathType.UNRESOLVED) {
//                    updateInternalState(validationState);
//                    statsCollector.setNumLowAlerts(statsCollector.getNumLowAlerts()+1);
//                    return true;
//                }
//            }
//        }
        return false;
    }

    private boolean resolveExecutionUnits(ValidationState state) {
        ULogNode node = state.getNode();
//        if (node.isLikelyExec()) {
//            state.breakExecUnit();
//        }

        if (node.isRegex()) {
            // add it to the execution partitioner
            int[] numVisited = new int[1];
            JPartitioner.PartitionerNode pNode = jPartitioner.addNode(node, numVisited);
            if (jPartitioner.isFirstVisit() || (numVisited[0] > 1 && jPartitioner.checkTopNode(pNode))) {
                state.breakExecUnit();
            }
        }
        return state.isNewExecUnit();
    }

    private void updateInternalState(ValidationState nextState) {
        nextState.setPrevState(currState);
        currState = nextState;

        // keep track of all the states
        path.add(nextState);
    }

    /**
     * Create a pending and unconfirmed state and push it onto the pending states queue.
     *
     * @param appNode The application node with the regex in it.
     */
    public void createAndSavePendingState(ULogNode appNode) {
        ValidationState validationState = new ValidationState(appNode, currState);
        validationState.markUnconfirmed();
        pendingStates.add(validationState);
        validationState.setPrevState(currState);
        currState = validationState;
    }

    /**
     * Save the current state to the list of pending system calls.
     *
     * @param syscallNode The system call node from omegalog.
     */
    public void savePendingSyscall(ULogNode syscallNode) {
        ULogNode currNode = currState.getNode();
        if (currNode.getId() != syscallNode.getId()) {
            l.error("Discrepancy between curr state and system call node...");
            System.exit(-1);
        }
        currState.markUnconfirmed();
        pendingSyscalls.push(currState);
    }

    public ValidationState popAndCheckState(ULogNode appNode) {
        if (pendingStates.isEmpty())
            return null;
        ValidationState vState = pendingStates.peek();
        if (vState.getNode().getId() == appNode.getId()) {
            currState = vState.prevState;
            return pendingStates.remove();
        }

        // no match between the state's node and passed node's id
        l.error("Validation state node does not match input application node");
        return null;
    }

    public boolean performSanityCheck() {
        if (!pendingStates.isEmpty())
            return false;

        if (path.isEmpty())
            return true;

        // make sure all states are confirmed.
        for (ValidationState vState : path) {
            if (!vState.isConfirmed())
                return false;
            vState = vState.prevState;
        }
        return true;
    }

    /**
     * Get the top of the pending syscall queue.
     *
     * @return the top of the pending syscall queue, null if empty.
     */
    public ValidationState getPendingSyscall() {
        if (pendingSyscalls.isEmpty())
            return null;
        return pendingSyscalls.peek();
    }

    /**
     * Pop the top pending syscall state from the queue of syscall states.
     */
    public void popPendingSyscall() {
        pendingSyscalls.pop();
    }

    private static final Set<String> allowedToRemain = new HashSet<>() {{
        add("fgets");
        add("__getdelim");
        add("exit"); // since we might actually leave before exit is recorded by PT
        add("fflush");
    }};
    public boolean checkPendingSyscallValidity() {
        if (pendingSyscalls.isEmpty())
            return true;

        for (ValidationState vs : pendingSyscalls) {
            if (!allowedToRemain.contains(vs.getNode().getStr()))
                return false;
        }
        return true;
    }

    public static class ValidationState {
        // the matched ulognode in this state
        private final ULogNode node;
        // a pointer to the previous state
        private ValidationState prevState;
        // checking if the state creates a new execution unit
        private boolean isNewExecUnit = false;
        // checking if the state has been confirmed
        private boolean confirmed = true;

        public ValidationState(ULogNode node, ValidationState prevState) {
            this.node = node;
            this.prevState = prevState;
        }

        public ValidationState(ULogNode node) {
            this.node = node;
            this.prevState = null;
        }

        /**
         * Mark the state unconfirmed.
         */
        public void markUnconfirmed() {
            this.confirmed = true;
        }

        /**
         * Check if the state is confirmed.
         *
         * @return the confirmed status of the state.
         */
        public boolean isConfirmed() {
            return this.confirmed;
        }

        public void setPrevState(ValidationState prevState) {
            this.prevState = prevState;
        }

        public ULogNode getNode() {
            return node;
        }

        public ValidationState getPrevState() {
            return prevState;
        }

        public boolean isNewExecUnit() {
            return this.isNewExecUnit;
        }

        public void breakExecUnit() {
            this.isNewExecUnit = true;
        }
    }
}
