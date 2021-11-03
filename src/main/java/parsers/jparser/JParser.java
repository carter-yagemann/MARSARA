package parsers.jparser;

import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.impl.Arguments;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import net.sourceforge.argparse4j.inf.Namespace;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import parsers.jgraph.GraphParser;
import parsers.jgraph.ULogGraph;
import parsers.jgraph.ULogLink;
import parsers.jgraph.ULogNode;

import java.text.MessageFormat;
import java.util.*;
import java.util.regex.Pattern;

public class JParser {
    private static final Pattern appLogPattern = Pattern.compile(".*msg='PID:\\d+##");
    private static final Logger l = LoggerFactory.getLogger(JParser.class.getName());

    private static final int UnsupportedOperation = 1;

    private final String inFile;
    private final String logFile;
    private final boolean watch;
    private final int lookahead;
    private final FormatMatcher expr;

    public String getInFile() {
        return inFile;
    }


    public String getLogFile() {
        return logFile;
    }


    public boolean isWatch() {
        return watch;
    }


    public int getLookahead() {
        return lookahead;
    }

    public FormatMatcher getExprMatcher() {
        return expr;
    }

    // @path is the current path being built by the parser as it is parsing and matching!
    private final List<State> path;

    // @history is a vector of vectors containing all of the previous paths taken by the parse.
    // Note that is history contains more than one vector, then it is likely that the start of each
    // vector is the head of a new execution unit.
    private final List<List<State>> history;

    // @curr_log_id is the id of the current log entry being parsed. This will generally correspond to
    // the line number of the entry in the log file for fast lookup later on.
    private int curr_log_id;

    // @id_to_log maps each identifier to a log message. This is a one to one mapping.
    private final Map<Integer, String> id_to_log;

    // @log_to_id is the reverse of above map, however it might not maintain the one to
    // one mapping since two log messages might have the same text. In that case, the
    // map will hold all the possible identifier values.
    private final Map<String, List<Integer>> log_to_id;

    // @id_to_state is a mapping from a log message identifier (assumed to be an integer in
    // this case) to the corresponding matched state.
    private final Map<Integer, State> id_to_state;

    private final Map<String, Integer> eventId_to_logId;

    private final ULogGraph graph;

    public int getLogIdforEvent(String splitEventid) {
        return eventId_to_logId.get(splitEventid);
    }

    public boolean noPaths() {
        if (history.isEmpty())
            return true;
        for (List<State> path : history) {
            if (!path.isEmpty())
                return false;
        }
        return true;
    }

    public enum JMatchType {
        Sequential, /* matched sequentially in the graph */
        Lookahead,  /* matched by performing lookahead */
        Exhaustive, /* matched by performing exhaustive search */
        Heuristic,  /* matched by a heuristic on metada */
        Starting,   /* Base starting state for parsing */
        Failed,     /* Failed matching */
        Unknown,    /* Yet to be known match type */
        Last_One    /* Keep this last one */
    }

    public JParser(String _if, String _lf, boolean _w, FormatMatcher _e, int _lk) {
        inFile = _if;
        logFile = _lf;
        watch = _w;
        expr = _e;
        lookahead = _lk;

        // maintain the mappings
        curr_log_id = 0;
        id_to_log = new HashMap<>();
        log_to_id = new HashMap<>();
        id_to_state = new HashMap<>();
        eventId_to_logId = new HashMap<>();

        if (watch) {
            l.error("Watch mode is not yet supported");
            System.exit(-UnsupportedOperation);
        }

        l.debug("Read lms graph from {}", inFile);
        graph = GraphParser.ReadGraph(inFile);

        // init path and history
        path = new LinkedList<State>();
        history = new LinkedList<List<State>>();
    }

    /**
     * GetNextLogId - Get the next available ID for the log messages.
     * Overload this function if we need to change the type of the identifier
     * for each log message
     *
     * @return the next identifier to be used
     */
    private int GetNextLogId() {
        return curr_log_id++;
    }

    /**
     * Add a log entry to maintained list of entries and update the reverse map
     *
     * @param logMsg: The log message to keep track of
     */
    public void AddLogEntry(int id, String logMsg) {
        // keep the direct mapping
        id_to_log.put(id, logMsg);

        // maintain the reverse mapping
        if (log_to_id.containsKey(logMsg)) {
            List<Integer> llist = log_to_id.get(logMsg);
            llist.add(id);
        } else {
            List<Integer> llist = new LinkedList<>();
            llist.add(id);
            log_to_id.put(logMsg, llist);
        }
    }

    /**
     * GetMatchingIds - Helper to get the possible matching ids for a log message
     *
     * @param logMsg: The log message we are working with
     * @return a list of possible matching ids.
     */
    public List<Integer> GetMatchingIds(String logMsg) {
        return log_to_id.get(logMsg);
    }


    /**
     * GetStateForLog - Get the matching state for a given log message using its identifier
     *
     * @param logId: The identifier for the log message
     * @return a unique state matching for the log message or None
     */
    public State GetStateForLog(int logId) {
        return id_to_state.get(logId);
    }

    /**
     * GetStateForLog - Get the possible matching states for a given log message.
     *
     * @param logMsg: The log message to check for
     * @return a list of possible matching states.
     */
    public List<State> GetStateForLog(String logMsg) {
        List<Integer> llist = GetMatchingIds(logMsg);

        if (llist != null) {
            List<State> listOfStates = new LinkedList<>();
            for (int id : llist) {
                State s = GetStateForLog(id);
                if (s != null) {
                    listOfStates.add(s);
                }
            }

            return listOfStates;
        }

        return null;
    }

    /**
     * GetLogFromStatet - Get the log message that matched to this state
     *
     * @param s: The state we are working with
     * @return the log message that matched to the state, null otherwise.
     */
    public String GetLogFromState(State s) {
        int logId = s.GetMatchId();

        return id_to_log.get(logId);
    }

    public class State {
        private final ULogNode node;
        private final ULogGraph graph;
        private final int matchLen;
        private JMatchType matchType;
        // the number of times we couldn't get out of this state
        private int holdingTime;

        // the id of the log message that matched to this state
        private int matchId;

        // should never be access publicly
        private Set<ULogNode> visited;

        public State(ULogNode _n, ULogGraph _g, int _m) {
            node = _n;
            graph = _g;
            matchLen = _m;
            visited = null;
            matchType = JMatchType.Unknown;
            holdingTime = 0;
            matchId = -1;
        }

        public ULogNode GetData() {
            return node;
        }

        public Boolean IsPhonyNode(ULogNode n) {
            return n.isPhonyNode() || n.isFuncHead() || n.isFuncOut();
        }

        public JMatchType GetMatchType() {
            return matchType;
        }

        public void SetMatchType(JMatchType type) {
            matchType = type;
        }

        public int GetMatchLen() {
            return matchLen;
        }

        public int GetHoldingTime() {
            return holdingTime;
        }

        public int GetMatchId() {
            return matchId;
        }

        public void SetMatchId(int id) {
            matchId = id;
        }

        public int IncreaseHoldingTime() {
            holdingTime++;
            return holdingTime;
        }

        public List<ULogNode> GetPossibleTransitions() {
            ClearHashSet();
            return GetPossibleTransitionsHelper(node);
        }

        public void ClearHashSet() {
            if (visited == null) visited = new HashSet<>();
            visited.clear();
        }

        private List<ULogNode> GetPossibleTransitionsHelper(ULogNode n) {
            List<ULogNode> listOfNodes = new LinkedList<>();
            for (ULogLink e : graph.GetOutEdges(n)) {
                if (visited.contains(e.dst)) {
                    continue;
                } else {
                    visited.add(e.dst);
                }

                if (IsPhonyNode(e.dst)) {
                    // skip over the phony nodes and fetch their successors
                    listOfNodes.addAll(GetPossibleTransitionsHelper(e.dst));
                } else {
                    listOfNodes.add(e.dst);
                }
            }
            return listOfNodes;
        }

        public String toString() {
            return MessageFormat.format("< {0} >", node.getAttribute("val"));
        }

        /**
         * IsLikelyNewExecutionUnit - Check if this state is likely the start of a new execution unit
         *
         * @return true if it might be an execution unit, false otherwise.
         */
        public Boolean IsLikelyNewExecutionUnit() {
            // TODO: update this to capture loop edges as well.
            return matchType == JMatchType.Exhaustive || matchType == JMatchType.Heuristic
                    || matchType == JMatchType.Starting;
        }
    }

   /* public void parseAndMatch(String start_from) {
        State sstate = null;
        if (start_from == "start") {
            sstate = new State(graph.FindStartNode(), graph, 0);
            l.debug("Starting from: {}", sstate);
        } else {
            l.info("Will try to find the start state from the first line...");
        }

        // start matching from here
        if (sstate != null) path.add(sstate);

        //---- Main parsing loop starts here -------//
        try (BufferedReader br = new BufferedReader(new FileReader(logFile))) {
            for (String line; (line = br.readLine()) != null; ) {

                // Process log string (Added by pubali)
                // and return (eventId, application log)
                Pair<String,String> lineTuple = processAuditLogStringFromFile(line);
                if(lineTuple==null)
                    continue;

                line = lineTuple.getValue();
                l.debug("==> Processing line: {} with eventid {}", lineTuple.getValue(),lineTuple.getKey());

                // register the log message
                int lineId = GetNextLogId(); // this will start from 0!
                AddLogEntry(lineId, line);
                // Add eventId to logid mapping
                eventId_to_logId.put(lineTuple.getKey(),lineId);

                State nstate = sstate;
                if (sstate == null) {
                    sstate = FindStartingState(line);
                    if (sstate == null) {
                        l.warn("Performing exhaustive search...");
                        sstate = DoExhaustiveSearch(line);
                    }
                    nstate = sstate;
                    // set the match type to starting state
                    nstate.SetMatchType(JMatchType.Starting);
                } else {
                    nstate = LookupNextState(sstate, line);
                }

                if (nstate == null && sstate == null) {
                    l.warn("Could not find a starting state with the current log message, ignoring...");
                } else if (nstate == null) {
                    l.debug("No next state found, performing lookahead...");
                    if ((nstate = FindExecStates(line)) != null) {
                        l.debug("=> Switching path to a new start state.");
                        sstate = nstate;

                        // add current path to history
                        history.add(new LinkedList<State>(path));

                        l.debug("Clearing the current path and resetting");
                        path.clear();
                        path.add(nstate);
                        nstate.SetMatchType(JMatchType.Heuristic);
                        id_to_state.put(lineId, nstate);
                        nstate.SetMatchId(lineId);

                        continue;
                    }

                    // now try lookahead
                    nstate = PerformLookahead(sstate, line);
                    if (nstate == null) {
                        l.debug("Finally trying to perform an exhaustive search...");
                        nstate = DoExhaustiveSearch(line);
                        if (nstate != null) {
                            nstate.SetMatchType(JMatchType.Exhaustive);
                        }
                    } else {
                        nstate.SetMatchType(JMatchType.Lookahead);
                    }

                    if (nstate == null) {
                        // still couldn't find anything
                        l.debug("Could not find next state even with lookahead and exhaustive search, ignoring...");
                        sstate.IncreaseHoldingTime();
                    } else {
                        l.debug("=> Advancing with lookahead from {} to {}", sstate, nstate);
                        sstate = nstate;
                        path.add(nstate);
                        id_to_state.put(lineId, nstate);
                        nstate.SetMatchId(lineId);
                    }
                } else {
                    l.debug("=> Advancing sequentially from {} to {}", sstate, nstate);
                    if (sstate != nstate) { // only do this when not starting!
                        sstate = nstate;
                        nstate.SetMatchType(JMatchType.Sequential);
                    }
                    path.add(nstate);
                    id_to_state.put(lineId, nstate);
                    nstate.SetMatchId(lineId);
                }
                l.debug(path);
            }

            // add the last parsed path to history
            history.add(new LinkedList<State>(path));

            // print the states and their corresponding log messages!
			//
			for (List<State> llist : history) {
				for (State s : llist) {
					l.debug("State {} matched with log message: {}",
							s, GetLogFromState(s));
				}
			}
			l.debug(history);

        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return;
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }
    }*/

    public void parseAndMatch(String start_from, List<String> logs) {
        if (logs == null || logs.isEmpty())
            return;

        State sstate = null;
        if (start_from.equals("start")) {
            sstate = new State(graph.FindStartNode(), graph, 0);
            l.debug("Starting from: {}", sstate);
        } else {
            l.info("Will try to find the start state from the first line...");
        }

        // start matching from here
        if (sstate != null) path.add(sstate);

        /* Main parsing loop starts here **/
        for (String line : logs) {

            l.debug("==> Processing line: {}", line);

            // register the log message
            int lineId = GetNextLogId(); // this will start from 0!
            AddLogEntry(lineId, line);

            State nstate = sstate;
            if (sstate == null) {
                sstate = FindStartingState(line);
                if (sstate == null) {
                    l.warn("Performing exhaustive search...");
                    sstate = DoExhaustiveSearch(line);
                }
                nstate = sstate;
                // set the match type to starting state
                if (nstate != null)
                    nstate.SetMatchType(JMatchType.Starting);
            } else {
                nstate = LookupNextState(sstate, line);
            }

            if (nstate == null && sstate == null) {
                l.warn("Could not find a starting state with the current log message, ignoring...");
            } else if (nstate == null) {
                l.debug("No next state found, performing lookahead...");
                if ((nstate = FindExecStates(line)) != null) {
                    l.debug("=> Switching path to a new start state.");
                    sstate = nstate;

                    // add current path to history
                    history.add(new LinkedList<>(path));

                    l.debug("Clearing the current path and resetting");
                    path.clear();
                    path.add(nstate);
                    nstate.SetMatchType(JMatchType.Heuristic);
                    id_to_state.put(lineId, nstate);
                    nstate.SetMatchId(lineId);

                    continue;
                }

                // now try lookahead
                nstate = PerformLookahead(sstate, line);
                if (nstate == null) {
                    l.debug("Finally trying to perform an exhaustive search...");
                    nstate = DoExhaustiveSearch(line);
                    if (nstate != null) {
                        nstate.SetMatchType(JMatchType.Exhaustive);
                    }
                } else {
                    nstate.SetMatchType(JMatchType.Lookahead);
                }

                if (nstate == null) {
                    // still couldn't find anything
                    l.debug("Could not find next state even with lookahead and exhaustive search, ignoring...");
                    sstate.IncreaseHoldingTime();
                } else {
                    l.debug("=> Advancing with lookahead from {} to {}", sstate, nstate);
                    sstate = nstate;
                    path.add(nstate);
                    id_to_state.put(lineId, nstate);
                    nstate.SetMatchId(lineId);
                }
            } else {
                l.debug("=> Advancing sequentially from {} to {}", sstate, nstate);
                if (sstate != nstate) { // only do this when not starting!
                    sstate = nstate;
                    nstate.SetMatchType(JMatchType.Sequential);
                }
                path.add(nstate);
                id_to_state.put(lineId, nstate);
                nstate.SetMatchId(lineId);
            }
            l.debug(MessageFormat.format("{0}", path));
        }

        // add the last parsed path to history
        history.add(new LinkedList<>(path));

        //l.debug(history);
        //l.debug(id_to_state);
    }

    // Process audit.log string to remove metadata and make it compatible with jparser (Pubali)
    /*
    public Pair<String, String> processAuditLogStringFromFile(String line) {
        String data = null;
        String eventId = null;

        // Is this log line an app log?
        Matcher applogMatcher = appLogPattern.matcher(line);
        if(!applogMatcher.find())
            return null;

        Matcher event_start_matcher = AuditEventReader.getMatcherPattern().matcher(line);
        if (event_start_matcher.find()) {
            eventId = event_start_matcher.group(4);
            int logstartidx = line.indexOf("##");
            int exeidx = line.indexOf("exe");

            data = line.substring(logstartidx+2,exeidx);
            data.trim();
        }
        return new Pair<>(eventId,data);
    }
    */

    /**
     * GetMaxMatchingState - Return the matching state with the longest constant match
     * Complexity is O(n)
     *
     * @param matchingStates: List:		The list of all possible matching states
     * @return State: Returns the state with maximum match length or null if there are none
     */
    private State GetMaxMatchingState(List<State> matchingStates) {
        // check the longest match and return it
        int maxMatch = -1;
        State mState = null;
        for (State s : matchingStates) {
            if (s.GetMatchLen() > maxMatch) {
                maxMatch = s.GetMatchLen();
                mState = s;
            }
        }
        return mState;
    }

    /**
     * LookupNextState - lookup the next state to go to given the current line
     *
     * @param s:    The current state
     * @param line: The line we are currently working with
     * @return The next state if found, null if cannot find it
     */
    public State LookupNextState(State s, String line) {
        // use expr.IsMatch(fmt, line)
        List<ULogNode> nextStates = s.GetPossibleTransitions();

        l.debug("====> Looking up next possible state using line = {}", line);
        List<State> matchingStates = new LinkedList<>();
        for (ULogNode n : nextStates) {

            String fmt = (String) n.getAttribute("val");
            // TODO WAJIH make sure that there is a best possible match here.
            // TODO count the number of non-format specifier and pick the one which has best word match
            int matchLength = expr.IsMatch(fmt, line);
            if (matchLength >= 0) {
                // found it, return it
                l.debug("Found a match for {} in {}.", line, fmt);
                matchingStates.add(new State(n, graph, matchLength));
            }
        }

        // return the max matching state, this will return null if there's none
        return GetMaxMatchingState(matchingStates);
    }

    /**
     * Perform lookahead from the given state to check if we can match
     * somewhere in the given future. This will keep trying until it hits
     * the lookahead depth
     *
     * @param state: The current state to start from
     * @param line:  The line we are currently working with
     * @return a new state to process if any, null otherwise
     */
    public State PerformLookahead(State state, String line) {
        l.debug("Performing lookahead using depth={}", lookahead);
        List<ULogNode> possibleStates = state.GetPossibleTransitions();

        List<State> matchingStates = new LinkedList<>();
        Set<ULogNode> visited = new HashSet<>();
        for (ULogNode n : possibleStates) {
            // check for self loops
            if (n == state.GetData()) {
                int matchLength = CheckLogMatch(n, line);
                if (matchLength >= 0) {
                    matchingStates.add(new State(state.GetData(), graph, matchLength));
                }
            } else {
                if (!visited.contains(n)) {
                    State nxt = LookaheadHelper(n, line, lookahead, visited);
                    if (nxt != null) matchingStates.add(nxt);
                    visited.add(n);
                }
            }
        }

        return GetMaxMatchingState(matchingStates);
    }

    /**
     * LookaheadHelper - Helper function for performing lookahead computation
     * <p>
     * \param node:  The node we are working with
     * \param line:  The line we are currently processing
     * \param lkhd:  The current lookahead value, if 0 then return
     * \return A state if a match is found, null if not found
     */
    private State LookaheadHelper(ULogNode node, String line, int lkhd, Set<ULogNode> visited) {
        if (lkhd == 0) return null;

        // l.debug("Entering lookahead with lkhd = {}", lkhd);
        List<ULogNode> possibleStates = (new State(node, graph, 0)).GetPossibleTransitions();
        List<State> matchingStates = new LinkedList<>();
        for (ULogNode n : possibleStates) {
            // essentially, there's no point checking if the state matches since if it would, it should
            // have been caught by the caller before jumping in here, so only move forward if not self
            // loop in this case
            if (n != node) {
                int matchLength = CheckLogMatch(n, line);
                if (matchLength >= 0) {
                    matchingStates.add(new State(n, graph, matchLength));
                } else {
                    if (!visited.contains(n)) {
                        State nxt = LookaheadHelper(n, line, lkhd - 1, visited);
                        if (nxt != null) matchingStates.add(nxt);
                        visited.add(n);
                    }
                }
            }
        }

        return GetMaxMatchingState(matchingStates);
    }

    /**
     * Find states that are likely to be heads of execution units
     * <p>
     * \param line: The current line to match against
     * \return A state containing the matched node, if any
     */
    private State FindExecStates(String line) {
        List<State> matchingStates = new LinkedList<>();
        for (ULogNode node : graph.GetCache()) {
            int matchLength = CheckLogMatch(node, line);
            if (matchLength >= 0 && !node.isStartNode()) {
                matchingStates.add(new State(node, graph, matchLength));
            }
        }
        return GetMaxMatchingState(matchingStates);
    }


    /**
     * Find the starting state from a given line of the log file
     * <p>
     * \param line The line currently being processed
     * \return a state if found, null if none
     */
    public State FindStartingState(String line) {
        List<State> matchingStates = new LinkedList<>();
        for (ULogNode node : graph.GetCache()) {
            int matchLength = CheckLogMatch(node, line);
            if (matchLength >= 0) {
                matchingStates.add(new State(node, graph, matchLength));
            }
        }
        return GetMaxMatchingState(matchingStates);
    }

    /**
     * Perform an exhaustive search over all of the lms in the graph
     * <p>
     * \param line: The line to match against
     * \return returns a state with the matched node if any, null otherwise.
     */
    private State DoExhaustiveSearch(String line) {
        long startTime = System.nanoTime();

        List<State> matchingStates = new LinkedList<>();
        for (Map.Entry<Integer, ULogNode> entry : graph.Nodes().entrySet()) {
            ULogNode node = entry.getValue();
            if (!(node.isPhonyNode() || node.isEndNode() || node.isFuncHead() || node.isFuncOut())) {
                int matchLength = CheckLogMatch(node, line);
                if (matchLength >= 0) {
                    matchingStates.add(new State(node, graph, matchLength));
                }
            }
        }
        State s = GetMaxMatchingState(matchingStates);

        long endTime = System.nanoTime();
        long duration = (endTime - startTime);

        l.debug("Ran exhaustive search in {} milliseconds", (duration / 1000000.0));
        return s;
    }

    private int CheckLogMatch(ULogNode node, String line) {
        String fmt = (String) node.getAttribute("val");
        return CheckLogMatch(fmt, line);
    }

    private int CheckLogMatch(String fmt, String line) {
        l.debug("fmt={} line={}", fmt, line);
        return expr.IsMatch(fmt, line);
    }

    public static void main(String[] args) {
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
            l.debug(MessageFormat.format("{0}", res));

            // get a new matcher
            RegexMatcher matcher = new RegexMatcher();

            JParser jparser = new JParser(res.getString("input"), res.getString("log"),
                    res.getBoolean("watch"), matcher, res.getInt("lookahead"));

            String start = res.getBoolean("simulate") ? "start" : "first";
            //jparser.parseAndMatch(start);
        } catch (ArgumentParserException e) {
            parser.handleError(e);
        }
    }

}
