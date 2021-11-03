package tracker;

import event.PTAppLogEvent;
import event.PTEvent;
import event.PTSyscallEvent;
import event.SYSCALL;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import parsers.AuditEventReader;
import parsers.PTEventParser;
import parsers.PTEventSequence;
import parsers.ParseLinuxAudit;
import parsers.jgraph.ULogGraph;
import parsers.jgraph.ULogNode;
import parsers.jparser.JValidator;
import parsers.jparser.RegexMatcher;
import record.AppLogRecord;
import record.AuditRecord;
import record.PTRecord;
import record.UnitManager;
import utils.CommonFunctions;
import utils.LibcHandlers;
import utils.Statistics;
import utils.Utils;

import org.apache.commons.io.FilenameUtils;
import java.text.MessageFormat;
import java.util.*;

public class PTAnalyzer {
    private static final Logger l = LoggerFactory.getLogger(PTAnalyzer.class);
    private final int arch = 64;

    private final PTEventSequence ptSeq;                 //! The sequence of PT events.
    private final Map<Long, ULogNode> ptMap;                   //! The map from pt events to wlog nodes.
    private final ParseLinuxAudit auditParser;           //! The linux audit parser.
    private final Set<Integer> ptThreads;                //! The ids of the threads that we care about.
    private final ULogGraph omGraph;                     //! The omega log graph
    private final Map<Integer, JValidator> validatorMap; //! The path validator
    private final Queue<PTAppLogEvent> pendingQ;         //! The queue of pending application log events
    private final UnitManager unitManager;               //! The unit manager for execution units.
    private final Set<String> processedWrites;           //! A set of processed write calls to handle regex nodes
    private final String binary;                         //! The binary name
    private final List<PTEvent> path;                    //! The current path

    private final Statistics statCollector;              //! Collect different statistics about the run.

    // from rules.sh common calls
    private static final Set<SYSCALL> relevantSyscalls = new HashSet<SYSCALL>() {{
        add(SYSCALL.CLONE);
        add(SYSCALL.CLOSE);
        add(SYSCALL.CREAT);
        add(SYSCALL.DUP);
        add(SYSCALL.DUP2);
        add(SYSCALL.DUP3);
        add(SYSCALL.EXECVE);
        add(SYSCALL.EXIT);
        add(SYSCALL.EXIT_GROUP);
        add(SYSCALL.FORK);
        add(SYSCALL.VFORK);
        add(SYSCALL.OPEN);
        add(SYSCALL.OPENAT);
        add(SYSCALL.RENAME);
        add(SYSCALL.RENAMEAT);
        add(SYSCALL.UNLINK);
        add(SYSCALL.UNLINKAT);
        add(SYSCALL.ACCEPT);
        add(SYSCALL.ACCEPT4);
        add(SYSCALL.CONNECT);
        add(SYSCALL.BIND);
        add(SYSCALL.WRITE);
        add(SYSCALL.READ);
//        add(SYSCALL.WRITEV);
    }};

    private static final Map<SYSCALL, Set<String>> syscallToLibc = new HashMap<>() {{
        put(SYSCALL.CLONE, new HashSet<>(Arrays.asList("clone", "fork", "pthread_create")));
        put(SYSCALL.CLOSE, new HashSet<>(Arrays.asList("close", "fgets", "fclose", "getpwuid", "__close", "closedir")));
        put(SYSCALL.CREAT, new HashSet<>(Arrays.asList("creat")));
        put(SYSCALL.DUP, new HashSet<>(Arrays.asList("dup")));
        put(SYSCALL.DUP2, new HashSet<>(Arrays.asList("dup2")));
        put(SYSCALL.DUP3, new HashSet<>(Arrays.asList("dup3")));
        put(SYSCALL.EXECVE, new HashSet<>(Arrays.asList("execve")));
        put(SYSCALL.EXIT, new HashSet<>(Arrays.asList("exit")));
        put(SYSCALL.EXIT_GROUP, new HashSet<>(Arrays.asList("exit_group")));
        put(SYSCALL.FORK, new HashSet<>(Arrays.asList("fork")));
        put(SYSCALL.VFORK, new HashSet<>(Arrays.asList("vfork")));
        put(SYSCALL.OPEN, new HashSet<>(Arrays.asList("open", "fopen", "fdopen", "freopen")));
        put(SYSCALL.OPENAT, new HashSet<>(Arrays.asList("openat", "fopen", "open", "fdopen", "freopen",
                "open64", "glob", "glob64", "getpwuid", "gethostbyname", "setbuf", "opendir", "fopendir")));
        put(SYSCALL.RENAME, new HashSet<>(Arrays.asList("rename")));
        put(SYSCALL.RENAMEAT, new HashSet<>(Arrays.asList("renameat")));
        put(SYSCALL.UNLINK, new HashSet<>(Arrays.asList("unlink")));
        put(SYSCALL.UNLINKAT, new HashSet<>(Arrays.asList("unlinkat")));
        put(SYSCALL.ACCEPT, new HashSet<>(Arrays.asList("accept")));
        put(SYSCALL.ACCEPT4, new HashSet<>(Arrays.asList("accept4")));
        put(SYSCALL.CONNECT, new HashSet<>(Arrays.asList("connect")));
        put(SYSCALL.BIND, new HashSet<>(Arrays.asList("bind", "getaddrinfo")));
        put(SYSCALL.WRITE, new HashSet<>(Arrays.asList("write", "vfprintf", "fprintf", "fputs", "fputc", "fwrite",
                "putc", "ungetc", "fflush", "send", "sendmsg", "sendto", "__fprintf_chk", "__vfprintf_chk", "mkdir")));
        put(SYSCALL.READ, new HashSet<>(Arrays.asList("read", "fgets", "fgetc", "fread",
                "fstat", "stat", "lstat", "getc", "getline", "__getdelim", "recv", "recvfrom", "getpwuid")));
    }};

    /**
     * Constructor with trace file and log file
     * \param binary    The binary to study
     * \param traceFile The input trace file in json format
     * \param auditFile The input log file as generated by auditd
     * \param args      command line arguments to be passed to the audit parser
     */
    public PTAnalyzer(String binary, String traceFile, String auditFile, String wlogFile, String[] args) {
        // parse the pt trace
        this.ptSeq = PTEventParser.parsePTTrace(traceFile);
        this.ptThreads = ptSeq.getPids();
        this.omGraph = PTEventParser.parseOmegaLogGraph(wlogFile);
        this.ptMap = PTEventParser.parsePTMap(traceFile, omGraph);
        this.validatorMap = new HashMap<>();
        this.pendingQ = new LinkedList<>();
        this.unitManager = new UnitManager(this.omGraph);
        this.processedWrites = new HashSet<>();
        this.binary = binary;
        this.statCollector = new Statistics(binary);
        this.path = new LinkedList<>();

        // parse the audit log
        Configuration config = new Configuration();
        config.parseCommandLineArgs(args);
        auditParser = new ParseLinuxAudit(config);
        try {
            auditParser.parseLogFile(auditFile);
        } catch (Exception e) {
            l.error("Parsing linux audit file failed...");
            e.printStackTrace();
        }
        // fill the graph stats
        FillGraphStatistics();
    }

    private void FillGraphStatistics() {
        statCollector.setNumVertices(omGraph.Nodes().size());
        statCollector.setNumEdges(omGraph.GetNumEdges());
    }

    public static Boolean isRelevantSyscall(SYSCALL sysNum) {
        return relevantSyscalls.contains(sysNum);
    }

    public static Set<String> getLibcCall(SYSCALL syscall) {
        return syscallToLibc.getOrDefault(syscall, null);
    }

    private Boolean consumeAppWriteEvent(int pid, Map<String, String> auditEvent) {
        JValidator jValidator;
        if (validatorMap.containsKey(pid)) {
            jValidator = validatorMap.get(pid);
        } else {
            jValidator = new JValidator(this.omGraph, new RegexMatcher(), statCollector);
            validatorMap.put(pid, jValidator);
        }

        // should match a write call here!
        JValidator.ValidationState validationState = jValidator.getPendingSyscall();
        if (validationState == null) {
            l.warn("Found libc system call {} that does not have an omegalog match!",
                    SYSCALL.getSyscall(1, arch));
            statCollector.setNumCriticalAlerts(statCollector.getNumCriticalAlerts() + 1);
            dumpDebugInfo(pid);
        } else {
            ULogNode sysNode = validationState.getNode();
            assert (sysNode.isSyscall());
            Set<String> libcCall = PTAnalyzer.getLibcCall(SYSCALL.getSyscall(1, arch));
            if (libcCall.contains(sysNode.getSyscallName())) {
                l.debug("Matched omegalog syscall {} to audit event syscall {}",
                        sysNode.getStr(), SYSCALL.getSyscall(1, arch));
                jValidator.popPendingSyscall();
            } else {
                l.warn("Found libc system call {} that does not have an omegalog match: expecting {}!",
                        SYSCALL.getSyscall(1, arch), sysNode.getSyscallName());
                statCollector.setNumCriticalAlerts(statCollector.getNumCriticalAlerts() + 1);
                dumpDebugInfo(pid);
            }
        }

        return jValidator.consumeAppWriteEvent(auditEvent);
    }

    private void consumeEvent(PTEvent ptEvent, int pid, Map<String, String> auditData) {
        JValidator jValidator;
        if (validatorMap.containsKey(pid)) {
            jValidator = validatorMap.get(pid);
        } else {
            jValidator = new JValidator(this.omGraph, new RegexMatcher(), statCollector);
            validatorMap.put(pid, jValidator);
        }

        if (jValidator.consumeEvent(ptEvent, auditData)) {
            // must break the execution unit
            if (ptEvent.isAppLogEvent()) {
                PTAppLogEvent ptAppLogEvent = (PTAppLogEvent) ptEvent;
                ULogNode node = omGraph.GetNode(ptAppLogEvent.getWNodeId());
                if (node.isRegex()) {
                    unitManager.startNewExecUnit(pid, new AppLogRecord(pid, node, auditData));
                } else {
                    unitManager.startNewExecUnit(pid, new PTRecord(pid, node));
                }
            }
        } else {
            if (ptEvent.isAppLogEvent()) {
                PTAppLogEvent ptAppLogEvent = (PTAppLogEvent) ptEvent;
                ULogNode node = omGraph.GetNode(ptAppLogEvent.getWNodeId());
                if (node.isRegex()) {
                    unitManager.appendUnitEvent(pid, new AppLogRecord(pid, node, auditData));
                } else {
                    unitManager.appendUnitEvent(pid, new PTRecord(pid, node));
                }
            }
        }
    }

    public static boolean isAuditWriteApplog(Map<String, String> auditEvent) {
        String data = Utils.decodeHex(auditEvent.get(AuditEventReader.DATA));
        return data != null;
    }

    /**
     * \brief Consume a system call event from the PT trace and advance the audit log trace accordingly.
     * <p>
     * This function will match the system call from the pt trace to the one matching it from the audit
     * log. It will keep advancing the audit log trace until we hit that specific system log. If it
     * not found, then we flag to the user that something is wrong!
     * <p>
     * \param pid               The process id
     * \param sysNum            The system call number from pt trace
     * \param pAuditIterator    The audit iterator for the process. THIS WILL BE ADVANCED
     */
    public Map<String, String> handleSyscallEvent(int pid, int sysNum,
                                                  ListIterator<Map<String, String>> pAuditIterator,
                                                  String currObj, String prevObj, Boolean[] shouldBreak) {
        SYSCALL sys = SYSCALL.getSyscall(sysNum, arch);
        shouldBreak[0] = false;
        if (sys == SYSCALL.UNSUPPORTED || !isRelevantSyscall(sys)) {
            // not forensically relevant
            return null;
        }

        // system call is forensically relevant
        while (pAuditIterator.hasNext()) {
            Map<String, String> auditEvent = pAuditIterator.next();
            String eventid = auditEvent.get("eventid");

            int auditSysnum = CommonFunctions.parseInt(auditEvent.get("syscall"), -1);
            // ignore if not a system call
            if (auditSysnum == -1)
                continue;

            if (auditSysnum == sysNum) {
                // matched, validate and move on
                l.debug(MessageFormat.format("[{0}]: Matched syscall {1} ({2})",
                        pid, sysNum, SYSCALL.getSyscall(sysNum, arch)));

                if (auditSysnum == 1 && pendingQ.size() > 0 && isAuditWriteApplog(auditEvent)) {
                    // write system call
                    // this is the first write after an application log event, might also be ignored
                    // later on by the validator, but it is a candidate for path validation.
                    PTAppLogEvent appLogEvent = pendingQ.remove();
                    // check if there is matching libc call we must remove
                    checkForPendingWrite(pid);
                    // if already processed, just return
                    if (processedWrites.contains(eventid))
                        return null;
                    consumeEvent(appLogEvent, pid, auditEvent);
                } else if (auditSysnum == 1 && isAuditWriteApplog(auditEvent)) {
                    l.debug("Detected an application log event that is not captured by omegalog");
                    String data = Utils.decodeHex(auditEvent.get(AuditEventReader.DATA));
                    l.debug("Application log message: {}", data);
                    shouldBreak[0] = consumeAppWriteEvent(pid, auditEvent);
                } else {
                    handleNonWriteSyscall(pid, sysNum, auditEvent, currObj, prevObj);
                }
                return auditEvent;
            } else {
                // no match, keep going in the log
                l.debug(MessageFormat.format("[{0}]: No match on syscall: PT trace {1}, Audit {2}",
                        pid, SYSCALL.getSyscall(sysNum, arch), SYSCALL.getSyscall(auditSysnum, arch)));
            }
        }

        // audit log consumed before hitting the match -- report error to the user
        l.warn(MessageFormat.format("[{0}]: Audit log is invalid, forensically relevant system call {1} " +
                "from PT trace is not found in the audit log", pid, SYSCALL.getSyscall(sysNum, arch)));
        System.exit(-1);

        // dead code
        return null;
    }

    private void checkForPendingWrite(int pid) {
        JValidator jValidator;
        if (validatorMap.containsKey(pid)) {
            jValidator = validatorMap.get(pid);
        } else {
            jValidator = new JValidator(this.omGraph, new RegexMatcher(), statCollector);
            validatorMap.put(pid, jValidator);
        }
        JValidator.ValidationState validationState = jValidator.getPendingSyscall();
        if (validationState == null) {
            l.warn("Found libc system call {} that does not have an omegalog match!",
                    SYSCALL.getSyscall(1, arch));
            statCollector.setNumCriticalAlerts(statCollector.getNumCriticalAlerts() + 1);
            dumpDebugInfo(pid);
            return;
        }
        // in this case, check for a match
        ULogNode sysNode = validationState.getNode();
        assert (sysNode.isSyscall());
        Set<String> libcCall = PTAnalyzer.getLibcCall(SYSCALL.getSyscall(1, arch));
        if (libcCall.contains(sysNode.getSyscallName())) {
            l.debug("Matched omegalog syscall {} to audit event syscall {}",
                    sysNode.getStr(), SYSCALL.getSyscall(1, arch));
            jValidator.popPendingSyscall();
        } else {
            // if we have a mistmatch and it is due to fgets, this might mean that fgets
            if (sysNode.getStr().equals("fgets") || sysNode.getStr().equals("__getdelim")) {
                // pop those fgets since they don't mean much
                validationState = popPendingFgets(jValidator);
                l.debug("Poping fgets and searching... Reached {}", validationState.getNode().getStr());
                if (libcCall.contains(validationState.getNode().getSyscallName())) {
                    l.debug("Matched omegalog syscall {} to audit event syscall {}",
                            sysNode.getStr(), SYSCALL.getSyscall(1, arch));
                    jValidator.popPendingSyscall();
                } else {
                    l.warn("Found libc system call {} that does not have an omegalog match: expecting {}!",
                            SYSCALL.getSyscall(1, arch), validationState.getNode().getStr());
                    statCollector.setNumCriticalAlerts(statCollector.getNumCriticalAlerts() + 1);
                    dumpDebugInfo(pid);
                }
            } else {
                l.warn("Found libc system call {} that does not have an omegalog match: expecting {}!",
                        SYSCALL.getSyscall(1, arch), sysNode.getStr());
                statCollector.setNumCriticalAlerts(statCollector.getNumCriticalAlerts() + 1);
                dumpDebugInfo(pid);
            }
        }
    }

    private JValidator.ValidationState popPendingFgets(JValidator jValidator)
    {
        JValidator.ValidationState validationState = jValidator.getPendingSyscall();
        ULogNode node = validationState.getNode();
        while (node.getStr().equals("fgets") || node.getStr().equals("__getdelim")) {
            jValidator.popPendingSyscall();
            validationState = jValidator.getPendingSyscall();
            node = validationState.getNode();
        }
        return validationState;
    }

    /**
     * Handle a system call that is not an application log message.
     *
     * @param pid        The pid of the process.
     * @param sysNum     The system call number.
     * @param auditEvent The audit event.
     * @param currObj   The current object making the syscall
     * @param prevObj   The previous object that launched the call
     */
    private void handleNonWriteSyscall(int pid, int sysNum, Map<String, String> auditEvent, String currObj, String prevObj) {
        /* The idea here is that we first want to check the pending system calls that have been collected
         * from the omegalog nodes. If there is a match, we are good! If there is no match, we are only
         * interested in those non-matches that comes from either `libc` or the binary itself.
         */
        JValidator jValidator;
        if (validatorMap.containsKey(pid)) {
            jValidator = validatorMap.get(pid);
        } else {
            jValidator = new JValidator(this.omGraph, new RegexMatcher(), statCollector);
            validatorMap.put(pid, jValidator);
        }
        JValidator.ValidationState validationState = jValidator.getPendingSyscall();
        if (validationState == null) {
//            if (objName.contains("libc") || objName.contains(this.binary)) {
            if (currObj.contains(this.binary)) {
                // also need to check the previous object
                l.warn("Found libc system call {} that does not have an omegalog match!: curr {}, prev {}",
                        SYSCALL.getSyscall(sysNum, arch), currObj, prevObj);
                statCollector.setNumCriticalAlerts(statCollector.getNumCriticalAlerts() + 1);
            } else if (currObj.contains("libc")) {
                if (FilenameUtils.getBaseName(prevObj).contains(this.binary)) {
                    // need to check if the current state was a write or flush because flush can generate multiple
                    // writes
                    // check for fflush or write
                    if (jValidator.getCurrState() != null && jValidator.getCurrState().getNode().isSyscall()) {
                        ULogNode currNode = jValidator.getCurrState().getNode();
                        // curr state was a syscall
                        Set<String> libcCall = PTAnalyzer.getLibcCall(SYSCALL.getSyscall(sysNum, arch));
                        ULogNode node = jValidator.getCurrState().getNode();
                        if (currNode.isSyscall() && libcCall.contains(currNode.getSyscallName())) {
                            // found! do not pop
                            l.info("Retrospective match: {} with {}", SYSCALL.getSyscall(sysNum, arch), currNode.getStr());
                        } else if (currNode.isSyscall()) {
                            Set<SYSCALL> allowedSyscalls = LibcHandlers.getAllowedSyscalls(currNode.getSyscallName());
                            if (allowedSyscalls != null && allowedSyscalls.contains(SYSCALL.getSyscall(sysNum, arch))) {
                                l.info("Retrospective match: {} with {}", SYSCALL.getSyscall(sysNum, arch), currNode.getStr());
                            } else {
                                l.warn("Found libc system call {} that does not have an omegalog match!: curr {}, prev {}, expecting {}",
                                        SYSCALL.getSyscall(sysNum, arch), currObj, prevObj, currNode.getSyscallName());
                                dumpDebugInfo(pid);
                                statCollector.setNumCriticalAlerts(statCollector.getNumCriticalAlerts() + 1);
                            }
                        } else {
                            l.warn("Found libc system call {} that does not have an omegalog match!: curr {}, prev {}.",
                                    SYSCALL.getSyscall(sysNum, arch), currObj, prevObj);
                            dumpDebugInfo(pid);
                            statCollector.setNumCriticalAlerts(statCollector.getNumCriticalAlerts() + 1);
                        }
                        return;
                    }
                    l.warn("Found libc system call {} that does not have an omegalog match!: curr {}, prev {}",
                            SYSCALL.getSyscall(sysNum, arch), currObj, prevObj);
                    statCollector.setNumCriticalAlerts(statCollector.getNumCriticalAlerts() + 1);
                    dumpDebugInfo(pid);
//                    JValidator.ValidationState currState = jValidator.getCurrState();
                }
            }
            return;
        }
        // in this case, check for a match
        ULogNode sysNode = validationState.getNode();
        assert (sysNode.isSyscall());
        Set<String> libcCall = PTAnalyzer.getLibcCall(SYSCALL.getSyscall(sysNum, arch));
        if (libcCall.contains(sysNode.getSyscallName())) {
            l.debug("Matched omegalog syscall {} to audit event syscall {}",
                    sysNode.getStr(), SYSCALL.getSyscall(sysNum, arch));
            jValidator.popPendingSyscall();
//        } else if (objName.contains("libc") || objName.contains(this.binary)) {
        } else if (currObj.contains(this.binary)) {
            l.warn("Found libc system call {} that does not have an omegalog match!: curr {}, prev {}",
                    SYSCALL.getSyscall(sysNum, arch), currObj, prevObj);
            dumpDebugInfo(pid);
            statCollector.setNumCriticalAlerts(statCollector.getNumCriticalAlerts() + 1);
        } else if (currObj.contains("libc")) {
            if (prevObj.contains(this.binary)) {
                // check for fflush or write
                JValidator.ValidationState currState = jValidator.getCurrState();
                ULogNode currNode = currState.getNode();
                if (currNode.isSyscall() && libcCall.contains(currNode.getSyscallName())) {
                    // found! do not pop
                    l.info("Retrospective match: {} with {}", SYSCALL.getSyscall(sysNum, arch), currNode.getStr());
                } else if (currNode.isSyscall()) {
                    Set<SYSCALL> allowedSyscalls = LibcHandlers.getAllowedSyscalls(currNode.getSyscallName());
                    if (allowedSyscalls != null && allowedSyscalls.contains(SYSCALL.getSyscall(sysNum, arch))) {
                        l.info("Retrospective match: {} with {}", SYSCALL.getSyscall(sysNum, arch), currNode.getStr());
                        if (currNode.getSyscallName().equals(sysNode.getSyscallName()))
                            jValidator.popPendingSyscall();
                    } else {
                        l.warn("Found libc system call {} that does not have an omegalog match!: curr {}, prev {}: Expecting {}",
                                SYSCALL.getSyscall(sysNum, arch), currObj, prevObj, sysNode.getSyscallName());
                        dumpDebugInfo(pid);
                        statCollector.setNumCriticalAlerts(statCollector.getNumCriticalAlerts() + 1);
                    }
                } else {
                    l.warn("Found libc system call {} that does not have an omegalog match!: curr {}, prev {}: Expecting {}",
                            SYSCALL.getSyscall(sysNum, arch), currObj, prevObj, sysNode.getSyscallName());
                    dumpDebugInfo(pid);
                    statCollector.setNumCriticalAlerts(statCollector.getNumCriticalAlerts() + 1);
                }
            }
        }
    }

    private void dumpDebugInfo(int pid) {
        JValidator jValidator = validatorMap.getOrDefault(pid, null);
        if (jValidator != null) {
            JValidator.ValidationState validationState =jValidator.getCurrState();
            if (validationState != null) {
                ULogNode node = validationState.getNode();
                while (node.isRegex()) {
                    l.warn("Path object is: {}, RVA is {}", node.getStr(), node.getRVA());
                    validationState = validationState.getPrevState();
                    node = validationState.getNode();
                }
                l.warn("Last encountered code object is: {}, RVA is {}", node.getSyscallName(), node.getRVA());
            } else {
                l.warn("No code block has been processed yet...");
            }
        } else {
            l.warn("No code block has been processed yet...");
        }
    }

    /**
     * Look for the corresponding write event for a given application log node.
     *
     * @param auditIt The current audit iterator.
     * @param pidList The list of of audit events to read from.
     * @return The next applog write syscall event if found, null if none.
     */
    private Map<String, String> FindWriteEvent(ListIterator<Map<String, String>> auditIt,
                                               List<Map<String, String>> pidList) {
        ListIterator<Map<String, String>> copyIt = pidList.listIterator(auditIt.nextIndex());
        while (copyIt.hasNext()) {
            Map<String, String> event = copyIt.next();
            int sysNum = CommonFunctions.parseInt(event.get("syscall"), -1);
            if (sysNum == 1 && isAuditWriteApplog(event))
                return event;
        }
        return null;
    }

    private void saveAppLogEvent(int pid, PTAppLogEvent appLogEvent) {
        ULogNode appNode = JValidator.grabEventNode(appLogEvent, this.omGraph);
        pendingQ.add(appLogEvent);

        // create a pending state and mark it as the current state.
        JValidator jValidator = validatorMap.get(pid);
        jValidator.createAndSavePendingState(appNode);
    }

    private int removeDuplicateEvents(Map<Integer, List<Map<String, String>>> pidEvents) {
        int num_removed = 0;
        for (Map.Entry<Integer, List<Map<String, String>>> entry : pidEvents.entrySet()) {
            List<Map<String, String>> events = entry.getValue();

            ListIterator<Map<String, String>> iterator = events.listIterator();
            Map<String, String> lastWrite = null;
            while (iterator.hasNext()) {
                Map<String, String> event = iterator.next();
                int sysNum = CommonFunctions.parseInt(event.get("syscall"), -1);
                // check if this is a write
                if (sysNum == 1) {
                    // write syscall, check its type
                    String type = event.get("type");
                    if (type != null && type.equals("netio_module_record")) {
                        // applog event
                        if (lastWrite != null) {
                            l.warn("A application log event has no matching write: Outcomes are not to be trusted");
                        }
                        lastWrite = event;
                    } else {
                        if (lastWrite != null) {
                            // there was an applog before it, check fd, delete and reset
                            String arg0 = event.get("a0");
                            String fd = lastWrite.get("fd");
                            if (arg0.equals(fd)) {
                                // got it, remove this one and unset lastWrite since there is only one
                                iterator.remove();
                                num_removed += 1;
                                lastWrite = null;
                            }
                        }
                    }
                }
            }
        }
        return num_removed;
    }

    private Map<Integer, List<Map<String, String>>> buildPerPIDLists(ListIterator<Map<String, String>> auditIterator) {
        // build a list of events per PID from the audit list
        Map<Integer, List<Map<String, String>>> pidEvents = new HashMap<>();

        while (auditIterator.hasNext()) {
            // grab the event
            Map<String, String> event = auditIterator.next();

            int pid = CommonFunctions.parseInt(event.get("pid"), -1);
            if (pid == -1) {
                l.error("Event with unknown pid!");
                continue;
            }

            if (pidEvents.containsKey(pid)) {
                pidEvents.get(pid).add(event);
            } else {
                List<Map<String, String>> list = new ArrayList<>();
                list.add(event);
                pidEvents.put(pid, list);
            }
        }

        l.info("Consumed the audit log....");
        l.info(MessageFormat.format("There are {0} processses in the audit logs", pidEvents.size()));
        for (Map.Entry<Integer, List<Map<String, String>>> entry : pidEvents.entrySet()) {
            if (ptThreads.contains(entry.getKey()))
                l.info(MessageFormat.format("Pid: {0} has {1} events in total ...",
                        entry.getKey(), entry.getValue().size()));
        }

        return pidEvents;
    }

    /**
     * Analyze a trace and return the set of execution partitions for each PID.
     *
     * @return The filled execution partitions for each process.
     */
    public UnitManager analyzeTrace() {
        long startTime = System.nanoTime();
        // grab the sequence of pt events
        ArrayList<Map<String, String>> auditList = auditParser.getEventlist();

        l.info("###################### Starting PT+WLOG Analysis ########################");
        l.info(MessageFormat.format("{0}", ptThreads));
        l.info(MessageFormat.format("There are {0} pt trace events: {1} syscalls, {2} app logs, {3} thread events",
                ptSeq.getSize(), ptSeq.getNumSyscalls(), ptSeq.getNumAppLogs(), ptSeq.getNumThreadEvents()));
        l.info(MessageFormat.format("There are {0} audit trace events", auditList.size()));

        ListIterator<Map<String, String>> auditIterator = auditList.listIterator();
        Map<Integer, List<Map<String, String>>> pidEvents = buildPerPIDLists(auditIterator);
        int numRemoved = removeDuplicateEvents(pidEvents);
        l.info(MessageFormat.format("Removed {0} duplicate write events from the audit log", numRemoved));
//        for (int pid : ptThreads) {
//            printAuditEvents(pidEvents, pid);
//            printPTSysCalls(pid);
//            printPTEvents(pid);
//        }

//        System.exit(0);

        /*
          Main analysis algorithm starts here!
          Starting from each PT trace event, we will traverse the audit log and make sure that the specific
          system call is there.
         */
        for (int pid : ptThreads) {
            // check if the process is forensically relevant
            l.info("\n");
            if (!pidEvents.containsKey(pid)) {
                l.debug(MessageFormat.format("Audit log considers process {0} not to be forensically relevant!",
                        pid));
                continue;
            }
            l.info(MessageFormat.format("==================== Analyzing {0} ===================", pid));

            // process is forensically relevant
            ListIterator<PTEvent> eventListIterator = ptSeq.listIterator(pid);
            ListIterator<Map<String, String>> processAuditIt = pidEvents.get(pid).listIterator();
            path.clear();

            // pt events subsume audit events
            while (eventListIterator.hasNext()) {
                PTEvent event = eventListIterator.next();
                this.statCollector.incrementTotalEvents();
                path.add(event);
                if (event.isSyscallEvent()) {
                    PTSyscallEvent sysEvent = (PTSyscallEvent) event;
                    int sysNum = sysEvent.getSyscallNumber();
                    String currObj = sysEvent.getCurrObject();
                    String prevObj = sysEvent.getPrevObject();

                    // handle the system call event
                    Boolean[] shouldBreak = new Boolean[1];
                    Map<String, String> auditEvent = handleSyscallEvent(pid, sysNum, processAuditIt,
                            currObj, prevObj, shouldBreak);
                    if (auditEvent != null) {
                        if (shouldBreak[0])
                            this.unitManager.startNewExecUnit(pid, new AuditRecord(auditEvent, pid));
                        else
                            this.unitManager.appendUnitEvent(pid, new AuditRecord(auditEvent, pid));
                    }
                } else if (event.isAppLogEvent()) {
                    PTAppLogEvent appEvent = (PTAppLogEvent) event;
                    ULogNode appNode = JValidator.grabEventNode(appEvent, this.omGraph);
                    assert (appNode != null);

                    l.debug(MessageFormat.format("Handling: {0}", appNode.getStr()));
                    if (appNode.isRegex()) {
                        /* a small hack for thttpd because logs are not necessarily printed! */
//                        if (this.binary.equals("thttpd") && appNode.getId() == 7) {
//                            consumeEvent(appEvent, pid, null);
//                            continue;
//                        }
                        saveAppLogEvent(pid, appEvent);
                        Map<String, String> auditEvent = FindWriteEvent(processAuditIt, pidEvents.get(pid));
                        if (auditEvent == null) {
                            l.error("Cannot find matching write syscall for an applog node: {}", appNode);
//                            statCollector.setNumCriticalAlerts(statCollector.getNumCriticalAlerts() + 1);
                            continue;
                        } else {
                            consumeEvent(appEvent, pid, auditEvent);
                        }
                        String eventid = auditEvent.get("eventid");
                        l.debug("Adding event with eventid {}", eventid);
                        processedWrites.add(eventid);
                    } else if (appNode.isSyscall()) {
                        ULogNode node = JValidator.grabEventNode(appEvent, this.omGraph);
                        if (node.getStr().equals("listen") || node.getStr().equals("socket")) {
                            l.warn("Skipping over listen system calls as they are not handle by audit log parser");
                            consumeEvent(appEvent, pid, null);
                        } else {
                            consumeEvent(appEvent, pid, null);
                            saveSyscallToQueue(pid, node);
                        }
                    } else {
                        consumeEvent(appEvent, pid, null);
                    }
                } else {
                    l.warn("Thread event detected, should handle these!");
                }
            }

            if (processAuditIt.hasNext()) {
                l.warn("The audit event still has more events to process!");
            }
            JValidator jValidator = validatorMap.getOrDefault(pid, null);
            if ((jValidator != null) && !jValidator.checkPendingSyscallValidity()) {
                l.error("There are pending syscalls that are not fgets or __getdelim");
            }
        }

        long endTime = System.nanoTime();
        long timeElapsed = endTime - startTime;
        double runtimeSec = (double) timeElapsed / 1000000000.0;
        statCollector.setAnalysisTime_sec(runtimeSec);
        l.debug("Dumping execution units:\n" + this.unitManager.toString());
        l.info("Collected analysis statistics:\n{}", statCollector.toString());
        statCollector.writeTexMacros();
        return this.unitManager;
    }

    /**
     * Save a system call validation state to the validator's queue of events.
     *
     * @param pid  The pid of the current process.
     * @param node The node to check for validation.
     */
    private void saveSyscallToQueue(int pid, ULogNode node) {
        JValidator jValidator;
        if (validatorMap.containsKey(pid)) {
            jValidator = validatorMap.get(pid);
        } else {
            jValidator = new JValidator(this.omGraph, new RegexMatcher(), statCollector);
            validatorMap.put(pid, jValidator);
        }
        jValidator.savePendingSyscall(node);
    }

    private void printPTEvents(int pid) {
        ListIterator<PTEvent> eventListIterator = ptSeq.listIterator(pid);
        if (eventListIterator == null)
            return;

        l.info(MessageFormat.format("PT Trace for process: ({0})", pid));
        while (eventListIterator.hasNext()) {
            PTEvent event = eventListIterator.next();
            if (event.isSyscallEvent()) {
                PTSyscallEvent syscallEvent = (PTSyscallEvent) event;
                int syscallNum = syscallEvent.getSyscallNumber();
                SYSCALL sys = SYSCALL.getSyscall(syscallNum, arch);
                String object = syscallEvent.getCurrObject();
                l.info(MessageFormat.format("\tSyscall {0}({1}): {2}", sys, syscallNum, object));
            } else if (event.isAppLogEvent()) {
                PTAppLogEvent appLogEvent = (PTAppLogEvent) event;
                int wlog = appLogEvent.getWNodeId();
                ULogNode node = omGraph.GetNode(wlog);
                l.info(MessageFormat.format("\tLog Node: {0}", node.getStr()));
//                if (node.isRegex()) {
//                    l.info(MessageFormat.format("\tLog Node: {0}", node.getStr()));
//                } else if (node.isSyscall()) {
//                    l.info(MessageFormat.format("\tSyscall Node: {0}", node.getStr()));
//                }
            }
        }
    }

    private void printPTSysCalls(int pid) {
        ListIterator<PTEvent> eventListIterator = ptSeq.listIterator(pid);
        if (eventListIterator == null)
            return;

        l.info(MessageFormat.format("PT Trace for process: ({0})", pid));
        while (eventListIterator.hasNext()) {
            PTEvent event = eventListIterator.next();
            if (event.isSyscallEvent()) {
                PTSyscallEvent syscallEvent = (PTSyscallEvent) event;
                int syscallNum = syscallEvent.getSyscallNumber();
                SYSCALL sys = SYSCALL.getSyscall(syscallNum, arch);
                if (sys == SYSCALL.UNSUPPORTED)
                    continue;
                String objectName = ((PTSyscallEvent) event).getCurrObject();
                if (objectName.contains("libc"))
                    l.info("\tSyscall {}({}) : {}", sys, syscallNum, objectName);
            }
        }
    }

    private void printAuditEvents(Map<Integer, List<Map<String, String>>> pidEvents, int pid) {
        // print the audit events for a pid: [time]: syscall number, syscall name
        Iterator<Map<String, String>> eventIterator = pidEvents.get(pid).listIterator();
        while (eventIterator.hasNext()) {
            Map<String, String> event = eventIterator.next();
            String time = event.get("time");
            int sysNum = CommonFunctions.parseInt(event.get("syscall"), -1);

            l.debug(MessageFormat.format("[{0}]: At {1}, syscall {2}..", pid, time,
                    SYSCALL.getSyscall(sysNum, arch)));
            if (sysNum ==1 && isAuditWriteApplog(event)) {
                l.info("Found application write event!");
            }
        }
    }

    public static void runServer(String[] args) {
        String traceFile = "logs/server/server_trace.json";
        String auditFile = "logs/server/audit.log";
        String wlogFile = "logs/server/server.json";

        PTAnalyzer ptAnalyzer = new PTAnalyzer("server", traceFile, auditFile, wlogFile, args);
        ptAnalyzer.analyzeTrace();
    }

    public static void runNginx(String[] args) {
        String traceFile = "logs/nginx/nginx_trace.json";
        String auditFile = "logs/nginx/audit.log";
        String wlogFile = "logs/nginx/nginx.json";

        PTAnalyzer ptAnalyzer = new PTAnalyzer("nginx", traceFile, auditFile, wlogFile, args);
        ptAnalyzer.analyzeTrace();
    }

    public static void runTransmission(String[] args) {
        String traceFile = "logs/transmission-daemon/transmission-daemon_trace.json";
        String auditFile = "logs/transmission-daemon/audit.log";
        String wlogFile = "logs/transmission-daemon/transmission-daemon.json";

        PTAnalyzer ptAnalyzer = new PTAnalyzer("transmission-daemon", traceFile, auditFile, wlogFile, args);
        ptAnalyzer.analyzeTrace();
    }

    public static void runWget(String[] args) {
        String traceFile = "logs/wget/wget_trace.json";
        String auditFile = "logs/wget/audit.log";
        String wlogFile = "logs/wget/wget.json";

        PTAnalyzer ptAnalyzer = new PTAnalyzer("wget", traceFile, auditFile, wlogFile, args);
        ptAnalyzer.analyzeTrace();
    }

    public static void runRedis(String[] args) {
        String traceFile = "logs/redis-server/redis-server_trace.json";
        String auditFile = "logs/redis-server/audit.log";
        String wlogFile = "logs/redis-server/redis-server.json";

        PTAnalyzer ptAnalyzer = new PTAnalyzer("redis-server", traceFile, auditFile, wlogFile, args);
        ptAnalyzer.analyzeTrace();
    }

    public static void runProftpd(String[] args) {
        String traceFile = "logs/proftpd/proftpd_trace.json";
        String auditFile = "logs/proftpd/audit.log";
        String wlogFile = "logs/proftpd/proftpd.json";

        PTAnalyzer ptAnalyzer = new PTAnalyzer("proftpd", traceFile, auditFile, wlogFile, args);
        ptAnalyzer.analyzeTrace();
    }

    public static void runthttpd(String[] args) {
        String traceFile = "logs/thttpd/thttpd_trace.json";
        String auditFile = "logs/thttpd/audit.log";
        String wlogFile = "logs/thttpd/proftpd.json";

        PTAnalyzer ptAnalyzer = new PTAnalyzer("thttpd", traceFile, auditFile, wlogFile, args);
        ptAnalyzer.analyzeTrace();
    }

    public static void runBinary(String binary, String[] args) {
        String traceFile = "logs/" + binary + "/" + binary + "_trace.json";
        String auditFile = "logs/" + binary + "/audit.log";
        String wlogFile = "logs/" + binary + "/" + binary + ".json";

        PTAnalyzer ptAnalyzer = new PTAnalyzer(binary, traceFile, auditFile, wlogFile, args);
        ptAnalyzer.analyzeTrace();
    }

    public static void main(String[] args) {
//        runServer(args);
//        runNginx(args);
//        runTransmission(args);
//        runWget(args);
//        runRedis(args);
//        runProftpd(args);
        String[] benchmarks = {"apache2", "cupsd", "haproxy", "lighttpd", "memcached", "nginx", "postfix",
        "proftpd", "redis-server", "squid", "thttpd", "transmission-daemon", "wget", "yafc"};
        assert benchmarks.length == 14;
        for (String bench : benchmarks) {
            runBinary(bench, args);
        }
    }
}
