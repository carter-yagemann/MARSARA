package parsers;

import event.GraphEventType;
import event.SYSCALL;
import org.apache.tinkerpop.gremlin.structure.Graph;
import org.apache.tinkerpop.gremlin.structure.Vertex;
import org.apache.tinkerpop.gremlin.tinkergraph.structure.TinkerGraph;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import provgraph.GraphStructure;
import provgraph.NodeProperty;
import record.AddressPort;
import record.NetworkID;
import record.PathRecord;
import record.ProcessManager;
import tracker.Configuration;
import utils.CommonFunctions;
import utils.Utils;

import java.io.File;
import java.math.BigInteger;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class ParseLinuxAudit {
    GraphStructure graph;
    Graph prov_graph;
    Configuration config;
    private static final Logger logger = LoggerFactory.getLogger(ParseLinuxAudit.class);
    ProcessManager pm = new ProcessManager();


    private final Map<String, Integer> syscall_stats = new HashMap<>();
    private final Map<String, Map<String, NetworkID>> descriptorsN = new HashMap<>();
    private final Map<String, Map<String, Map<String, String>>> descriptorsF = new HashMap<>();
    private final HashSet<String> unsupportedsyscalls = new HashSet<>();
    private final int SIGCHLD = 17, CLONE_VFORK = 0x00004000, CLONE_VM = 0x00000100;
    private final int AT_FDCWD = -100;
    private final int O_RDONLY = 00000000, O_WRONLY = 00000001, O_RDWR = 00000002, O_CREAT = 00000100, O_TRUNC = 00001000, O_APPEND = 00002000;
    private static final String PROTOCOL_NAME_UDP = "udp", PROTOCOL_NAME_TCP = "tcp";
    private final int SOCK_STREAM = 1, SOCK_DGRAM = 2, SOCK_SEQPACKET = 5;

    private final ArrayList<Map<String, String>> eventlist = new ArrayList<>();

    public ParseLinuxAudit(Configuration config) {
        this.config = config;
        this.prov_graph = TinkerGraph.open();
        this.graph = new GraphStructure(prov_graph);
    }

    public void collectStats(String syscall) {
        if (syscall_stats.containsKey(syscall)) {
            int curr = syscall_stats.get(syscall);
            curr += 1;
            syscall_stats.put(syscall, curr);
        } else {
            syscall_stats.put(syscall, 1);
        }
    }

    public ArrayList<Map<String, String>> getEventlist() {
        return eventlist;
    }

    public Graph getProvGraph() {
        return prov_graph;
    }


    public Graph parseLogFile(String path) throws Exception {
        if (path == null)
            return prov_graph;
        logger.debug("======= Parsing ======\n " + path);
        AuditEventReader auditEventReader = new AuditEventReader(path);
        Map<String, String> eventData = new HashMap<String, String>();
        while ((eventData = auditEventReader.readEventData()) != null) {
            //System.out.println("Handling Event: " + eventData.toString());
            finishEvent(eventData);
        }
        logger.debug("================================\n");
        logger.debug("Final Graph Size: " + Utils.getListFromIterator(prov_graph.edges()).size());
        logger.debug("Seen vertices: " + graph.seen_vertices.size());
        logger.debug("Seen Edges: " + graph.seen_edges.size());
        logger.debug("Total Syscalls: " + syscall_stats.toString());
        logger.debug("Unsupported syscall: " + unsupportedsyscalls.toString());
        logger.debug("================================\n");
//        System.out.println(pm);
        return prov_graph;
    }

    public void finishEvent(Map<String, String> eventData) {
        if (eventData == null) {
            logger.info("Null event data read");
            return;
        }
        handleSyscallEvent(eventData);
    }

    private void handleSyscallEvent(Map<String, String> eventData) {
        String eventId = eventData.get("eventid");
        try {
            int syscallNum = CommonFunctions.parseInt(eventData.get("syscall"), -1);
            int arch = 64;
            if (syscallNum == -1) {
                //System.out.println("A non-syscall audit event OR missing syscall record with for event with id '" + eventId + "'" + eventData.toString());
                return;
            }
            SYSCALL syscall = SYSCALL.getSyscall(syscallNum, arch);
            if (syscall.name().contains("UNSUPPORT")) {
                unsupportedsyscalls.add(String.valueOf(syscallNum));
            }
            //convert all arguments from hexadecimal format to decimal format and replace them. done for convenience here and to avoid issues.
            for (int argumentNumber = 0; argumentNumber < 4; argumentNumber++) { //only 4 arguments received from linux audit
                try {
                    eventData.put("a" + argumentNumber, String.valueOf(new BigInteger(eventData.get("a" + argumentNumber), 16).longValue()));
                } catch (Exception e) {
                    if (eventData.containsKey(AuditEventReader.RECORD_TYPE_KEY) && eventData.get(AuditEventReader.RECORD_TYPE_KEY).contains(AuditEventReader.KMODULE_RECORD_TYPE)) {

                    } else {
                        logger.info("Missing/Non-numerical argument#" + argumentNumber + " for event id '" + eventId + "'" + eventData.toString());
                    }
                }
            }
            //System.out.println("Syscall: " + syscall.name());
            collectStats(syscall.name());
            // Add it to the list of events to be read sequentially
            eventlist.add(eventData);
            switch (syscall) {
                case EXIT:
                case EXIT_GROUP:
                    handleExit(eventData, syscall);
                    break;
                case UNLINK:
                case UNLINKAT:
                    //handleUnlink(eventData, syscall);
                    break;
                case VFORK:
                case FORK:
                case CLONE:
                    handleForkClone(eventData, syscall);
                    break;
                case EXECVE:
                    handleExecve(eventData);
                    break;
                case OPEN:
                    handleOpen(eventData, syscall);
                    break;
                case CLOSE:
                    handleClose(eventData);
                    break;
                case CREAT:
                    handleCreat(eventData);
                    break;
                case OPENAT:
                    //handleOpenat(eventData, syscall);
                    break;
                case DUP:
                case DUP2:
                case DUP3:
                    handleDup(eventData, syscall);
                    break;
                case BIND:
                    if (eventData.containsKey(AuditEventReader.RECORD_TYPE_KEY) && eventData.get(AuditEventReader.RECORD_TYPE_KEY).contains(AuditEventReader.KMODULE_RECORD_TYPE)) {
                        handleBindNetIO(eventData, syscall);
                    } else {
                        handleBind(eventData, syscall);
                    }
                    break;
                case SOCKET:
                    handleSocket(eventData, syscall);
                    break;
                case SOCKETPAIR:
                    handleSocketPair(eventData, syscall);
                    break;
                case ACCEPT:
                case ACCEPT4:
                    handleAccept(eventData, syscall);
                    break;
                case CONNECT:
                    if (eventData.containsKey(AuditEventReader.RECORD_TYPE_KEY) && eventData.get(AuditEventReader.RECORD_TYPE_KEY).contains(AuditEventReader.KMODULE_RECORD_TYPE)) {
                        handleConnectNetIO(eventData, syscall);
                    } else {
                        handleConnect(eventData, syscall);
                    }
                    break;
                case WRITE:
                    if (eventData.containsKey(AuditEventReader.RECORD_TYPE_KEY) && eventData.get(AuditEventReader.RECORD_TYPE_KEY).contains(AuditEventReader.KMODULE_RECORD_TYPE)) {
                        handleWriteNetIO(eventData, syscall);
                    }
                    break;
                case RENAME:
                case RENAMEAT:
                    handleRename(eventData, syscall);
                    break;
                default: //SYSCALL.UNSUPPORTED
                    logger.debug("Unsupported syscall: " + syscallNum);
            }
        } catch (Exception e) {
            logger.error("Error processing finish syscall event with eventid '" + eventId + "'", e);
        }
    }

    private void handleWriteNetIO(Map<String, String> eventData, SYSCALL syscall) {
//        System.out.println("Wajih: " + eventData.toString());
        String time = eventData.get("time");
        String eventId = eventData.get("eventid");
        String pid = eventData.get("pid");
        String data = eventData.get(AuditEventReader.DATA);
        data = Utils.decodeHex(data);
        // Following hack is just for sshd because it uses Rsyslog
        if (data.contains("sshd[")) {
            Pattern p = Pattern.compile("\\[(.*?)\\]");
            Matcher m = p.matcher(data);
            while (m.find()) {
                //System.out.println( "PID new: " + m.group(1));
                pid = m.group(1);
                break;
            }
        }
        String ppid = eventData.get("ppid");
        String key = pid;
        if (graph.seen_proc_vertices.containsKey(key)) {
            Vertex process = graph.seen_proc_vertices.get(key);
            Vertex object = graph.addApplogVertex(eventData);
            graph.addEdge(process, object, time, syscall.name(), GraphEventType.FILE_WRITE.name(), eventId);
            // if (start)
            // {start unit}
            // if (end)
//            pm.addEndUnit(pid,time);
        } else {
            Vertex process = graph.addProcessVertex(eventData);
            Vertex object = graph.addApplogVertex(eventData);
            graph.addEdge(process, object, time, syscall.name(), GraphEventType.FILE_WRITE.name(), eventId);
//            System.out.println("Can find pid: "+ key);
        }
    }

    private void handleSocketPair(Map<String, String> eventData, SYSCALL syscall) {
        String pid = eventData.get(AuditEventReader.PID);
        String fd0 = eventData.get(AuditEventReader.FD0);
        String fd1 = eventData.get(AuditEventReader.FD1);
        String domainString = eventData.get(AuditEventReader.ARG0);
        String sockTypeString = eventData.get(AuditEventReader.ARG1);
    }

    private void handleClose(Map<String, String> eventData) {
        String pid = eventData.get(AuditEventReader.PID);
        String fd = String.valueOf(CommonFunctions.parseLong(eventData.get(AuditEventReader.ARG0), -1L));
        SYSCALL syscall = SYSCALL.CLOSE;
        String time = eventData.get(AuditEventReader.TIME);
        String eventId = eventData.get(AuditEventReader.EVENT_ID);
        String path = eventData.get(AuditEventReader.PATH_PREFIX);
        Map<String, String> fileEventData = removeFileDescriptors(pid, fd);
        if (fileEventData == null) {
            NetworkID networkID = removeNetworkDescriptors(pid, fd);
            if (networkID != null) {
                Vertex process = graph.addProcessVertex(eventData);
                Vertex network = graph.addNetworkVertex("CLOSE", networkID.getLocalHost(), networkID.getLocalPort(),
                        networkID.getRemoteHost(), networkID.getRemotePort(), "", networkID.getProtocol());
                graph.addEdge(process, network, time, syscall.name(), GraphEventType.NETWORK_CLOSE.name(), eventId);
            }
        } else {
            Vertex process = graph.addProcessVertex(eventData);

            if ((path != null) && (path.contains(".so.") || path.endsWith(".so"))) {
                Vertex module = graph.addModuleVertex(eventData);
                graph.addEdge(module, process, time, syscall.name(), GraphEventType.MODULE_UNLOAD.name(), eventId);
            } else {
                Vertex file = graph.addFileVertex(fileEventData);
                graph.addEdge(process, file, time, syscall.name(), GraphEventType.FILE_CLOSE.name(), eventId);
            }
        }
    }

    private void handleUnlink(Map<String, String> eventData, SYSCALL syscall) {
        String time = eventData.get("time");
        String eventId = eventData.get("eventid");
        String pid = eventData.get("pid");
        String cwd = eventData.get("cwd");
        String deletedPath = null;
        deletedPath = getPathsWithNametype(eventData, "DELETE").get(0).getPath();
        if (deletedPath == null) {
            logger.info("PATH record with nametype DELETE missing", null, eventData.get("time"), eventId, syscall);
            return;
        }
        if (syscall == SYSCALL.UNLINK) {
            deletedPath = constructPath(deletedPath, cwd);
        } else if (syscall == SYSCALL.UNLINKAT) {
            deletedPath = constructPathSpecial(deletedPath, eventData.get("a0"), cwd, pid, time, eventId, syscall);
        } else {
            logger.info("Unexpected syscall '" + syscall + "' in UNLINK handler", null, eventData.get("time"), eventId, syscall);
            return;
        }
        if (deletedPath == null) {
            logger.info("Failed to build absolute path from log data", null, eventData.get("time"), eventId, syscall);
            return;
        }
        Vertex process = graph.addProcessVertex(eventData);
        eventData.put(AuditEventReader.PATH_PREFIX, deletedPath);
        Vertex file = graph.addFileVertex(eventData);
        graph.addEdge(process, file, time, syscall.name(), GraphEventType.FILE_UNLINK.name(), eventId);
    }

    private void handleRename(Map<String, String> eventData, SYSCALL syscall) {
        String time = eventData.get(AuditEventReader.TIME);
        String eventId = eventData.get(AuditEventReader.EVENT_ID);
        String pid = eventData.get(AuditEventReader.PID);
        String cwd = eventData.get(AuditEventReader.CWD);
        String oldFilePath = eventData.get(AuditEventReader.PATH_PREFIX + "2");
        String oldFilePathModeStr = eventData.get(AuditEventReader.MODE_PREFIX + "2");
        //if file renamed to already existed then path4 else path3. Both are same so just getting whichever exists
        String newFilePath = eventData.get(AuditEventReader.PATH_PREFIX + "4") == null ?
                eventData.get(AuditEventReader.PATH_PREFIX + "3") :
                eventData.get(AuditEventReader.PATH_PREFIX + "4");
        String newFilePathModeStr = eventData.get(AuditEventReader.MODE_PREFIX + "4") == null ?
                eventData.get(AuditEventReader.MODE_PREFIX + "3") :
                eventData.get(AuditEventReader.MODE_PREFIX + "4");

        if (syscall == SYSCALL.RENAME) {
            oldFilePath = Utils.constructAbsolutePath(oldFilePath, cwd, pid);
            newFilePath = Utils.constructAbsolutePath(newFilePath, cwd, pid);
        } else if (syscall == SYSCALL.RENAMEAT) {
            oldFilePath = constructPathSpecial(oldFilePath, eventData.get(AuditEventReader.ARG0), cwd, pid, time, eventId, syscall);
            newFilePath = constructPathSpecial(newFilePath, eventData.get(AuditEventReader.ARG2), cwd, pid, time, eventId, syscall);
        } else {
            logger.info("Unexpected syscall '" + syscall + "' in RENAME handler", null, time, eventId, syscall);
            return;
        }

        if (oldFilePath == null || newFilePath == null) {
            logger.info("Failed to create path(s)", null, time, eventId, syscall);
            return;
        }
        Vertex process = graph.addProcessVertex(eventData);
        eventData.put(AuditEventReader.PATH_PREFIX, oldFilePath);
        Vertex srcFile = graph.addFileVertex(eventData);
        eventData.put(AuditEventReader.PATH_PREFIX, newFilePath);
        Vertex dstFile = graph.addFileVertex(eventData);
        graph.addEdge(process, dstFile, time, syscall.name(), GraphEventType.FILE_RENAME.name(), eventId);
    }

    private void handleForkClone(Map<String, String> eventData, SYSCALL syscall) {
        String eventId = eventData.get("eventid");
        String time = eventData.get("time");
        String oldPID = eventData.get("pid");
        String newPID = eventData.get("exit");
        if (syscall == SYSCALL.CLONE) {
            Long flags = CommonFunctions.parseLong(eventData.get("a0"), 0L);
            //source: http://www.makelinux.net/books/lkd2/ch03lev1sec3
            if ((flags & SIGCHLD) == SIGCHLD && (flags & CLONE_VM) == CLONE_VM && (flags & CLONE_VFORK) == CLONE_VFORK) { //is vfork
                syscall = SYSCALL.VFORK;
            } else if ((flags & SIGCHLD) == SIGCHLD) { //is fork
                syscall = SYSCALL.FORK;
            }
            //otherwise it is just clone
        }
        Vertex oldProcess = graph.addProcessVertex(eventData); //will create if doesn't exist
        Map<String, String> newEventData = new HashMap<String, String>();
        newEventData.putAll(eventData);
        newEventData.put("pid", newPID);
        newEventData.put("ppid", oldPID);
        newEventData.put("commandline", eventData.get("commandline"));
        newEventData.put("cwd", eventData.get("cwd"));
        newEventData.put("start time", time);
        Vertex newProcess = graph.addProcessVertex(newEventData);
        graph.addEdge(oldProcess, newProcess, time, syscall.toString(), GraphEventType.PROCESS_LAUNCH.name(), eventId);
    }

    private void handleExecve(Map<String, String> eventData) {
        String eventId = eventData.get("eventid");
        String time = eventData.get("time");
        Vertex oldProcess = graph.addProcessVertex(eventData);
        String commandline = null;
        if (eventData.get("execve_argc") != null) {
            Long argc = CommonFunctions.parseLong(eventData.get("execve_argc"), 0L);
            commandline = "";
            for (int i = 0; i < argc; i++) {
                commandline += eventData.get("execve_a" + i) + " ";
            }
            commandline = commandline.trim();
        } else {
            commandline = "[Record Missing]";
        }
        eventData.put("commandline", commandline);
        eventData.put("start time", time);
        Vertex newProcess = graph.addProcessVertex(eventData);
        graph.addEdge(oldProcess, newProcess, time, SYSCALL.EXECVE.name(), GraphEventType.PROCESS_LAUNCH.name(), eventId);
    }

    private void handleDup(Map<String, String> eventData, SYSCALL syscall) {
        String pid = eventData.get("pid");
        String fd = eventData.get("a0");
        String newFD = eventData.get("exit"); //new fd returned in all: dup, dup2, dup3
        if (!fd.equals(newFD)) { //if both fds same then it succeeds in case of dup2 and it does nothing so do nothing here too
            if (checkInFileDescriptors(pid, fd)) {
                addToFileDescriptors(pid, newFD, eventData);
            } else if (checkInNetworkDescriptors(pid, fd)) {
                addToNetworkDescriptors(pid, newFD, getInNetworkDescriptor(pid, fd));
            } else {
                //descriptors.duplicateDescriptor(pid, fd, newFD);
                //System.out.println("need to add duplicate descriptors " + pid);
            }
        }
    }

    private void handleBind(Map<String, String> eventData, SYSCALL syscall) {
    }

    private void handleBindNetIO(Map<String, String> eventData, SYSCALL syscall) {
        System.out.println("In ==== " + syscall.name());
        String lsaddr = eventData.get(AuditEventReader.KMODULE_LOCAL_SADDR);
        String rsaddr = eventData.get(AuditEventReader.KMODULE_REMOTE_SADDR);
        String pid = eventData.get(AuditEventReader.PID);
        AddressPort lap = Utils.parseSaddr(lsaddr);
        AddressPort rap = Utils.parseSaddr(rsaddr);
        System.out.println(lap);
        System.out.println(rap);
    }

    private void handleCreat(Map<String, String> eventData) {
        int defaultFlags = O_CREAT | O_WRONLY | O_TRUNC;
        eventData.put(AuditEventReader.ARG2, eventData.get(AuditEventReader.ARG1)); //set mode to argument 3 (in open) from 2 (in creat)
        eventData.put(AuditEventReader.ARG1, String.valueOf(defaultFlags)); //flags is argument 2 in open
        handleOpen(eventData, SYSCALL.CREATE); //TODO change to creat. kept as create to keep current CDM data consistent

    }

    private void handleOpen(Map<String, String> eventData, SYSCALL syscall) {
        Long flags = CommonFunctions.parseLong(eventData.get(AuditEventReader.ARG1), 0L);
        Long modeArg = CommonFunctions.parseLong(eventData.get(AuditEventReader.ARG2), 0L);
        String eventId = eventData.get(AuditEventReader.EVENT_ID);
        String pid = eventData.get(AuditEventReader.PID);
        String cwd = eventData.get(AuditEventReader.CWD);
        String fd = eventData.get(AuditEventReader.EXIT);
        String time = eventData.get(AuditEventReader.TIME);
        boolean isCreate = syscall == SYSCALL.CREATE || syscall == SYSCALL.CREAT; //TODO later on change only to CREAT only
        PathRecord pathRecord = getFirstPathWithNametype(eventData, AuditEventReader.NAMETYPE_CREATE);
        if (pathRecord == null) {
            isCreate = false;
            pathRecord = getFirstPathWithNametype(eventData, AuditEventReader.NAMETYPE_NORMAL);
            if (pathRecord == null) {
                logger.info("Missing PATH record", null, time, eventId, syscall);
                return;
            }
        } else {
            isCreate = true;
        }

        String path = pathRecord.getPath();
        path = Utils.constructAbsolutePath(path, cwd, pid);

        if (path == null) {
            logger.info("Missing CWD or PATH record", null, time, eventId, syscall);
            return;
        }

        Vertex process = graph.addProcessVertex(eventData);
        eventData.put(AuditEventReader.PATH_PREFIX, path);
        boolean openedForRead = false;
        String flagsArgs = "";
        flagsArgs += ((flags & O_WRONLY) == O_WRONLY) ? "O_WRONLY|" : "";
        flagsArgs += ((flags & O_RDWR) == O_RDWR) ? "O_RDWR|" : "";
        // if neither write only nor read write then must be read only
        if (((flags & O_WRONLY) != O_WRONLY) &&
                ((flags & O_RDWR) != O_RDWR)) {
            // O_RDONLY is 0, so always true
            flagsArgs += ((flags & O_RDONLY) == O_RDONLY) ? "O_RDONLY|" : "";
        }

        flagsArgs += ((flags & O_APPEND) == O_APPEND) ? "O_APPEND|" : "";
        flagsArgs += ((flags & O_TRUNC) == O_TRUNC) ? "O_TRUNC|" : "";
        flagsArgs += ((flags & O_CREAT) == O_CREAT) ? "O_CREAT|" : "";

        if (!flagsArgs.isEmpty()) {
            flagsArgs = flagsArgs.substring(0, flagsArgs.length() - 1);
        }
        String modeAnnotation = null;
        if ((flags & O_WRONLY) == O_WRONLY ||
                (flags & O_RDWR) == O_RDWR ||
                (flags & O_APPEND) == O_APPEND ||
                (flags & O_TRUNC) == O_TRUNC) {
            Vertex file = graph.addFileVertex(eventData);
            graph.addEdge(process, file, time, syscall.name(), GraphEventType.FILE_OPEN.name(), eventId);
            pm.addSyscall(pid, syscall);
            openedForRead = false;
        } else if ((flags & O_RDONLY) == O_RDONLY) {
            Vertex file = graph.addFileVertex(eventData);
            if (isCreate) {
                graph.addEdge(process, file, time, syscall.name(), GraphEventType.FILE_CREATE.name(), eventId);
            } else {
                //System.out.println("I AM HERE " + path);
                if (path.contains(".so.") || path.endsWith(".so")) {
                    Vertex module = graph.addModuleVertex(eventData);
                    graph.addEdge(module, process, time, syscall.name(), GraphEventType.MODULE_LOAD.name(), eventId);
                    pm.addSyscall(pid, syscall);
                } else {
                    graph.addEdge(file, process, time, syscall.name(), GraphEventType.FILE_OPEN.name(), eventId);
                    pm.addSyscall(pid, syscall);
                }

            }
            openedForRead = true;
        } else {
            logger.info("Unhandled value of FLAGS argument '" + flags + "'", null, time, eventId, syscall);
            return;
        }
        addToFileDescriptors(pid, fd, eventData);
    }


    private void handleOpenat(Map<String, String> eventData, SYSCALL syscall) {
        String time = eventData.get(AuditEventReader.TIME);
        String eventId = eventData.get(AuditEventReader.EVENT_ID);

        PathRecord pathRecord = getPathWithCreateOrNormalNametype(eventData);

        if (pathRecord == null) {
            logger.info("Missing PATH record", null, time, eventId, syscall);
            return;
        }

        String path = pathRecord.getPath();

        // If not absolute then only run the following logic according to the manpage
        if (!path.startsWith(File.separator)) {
            Long dirFd = CommonFunctions.parseLong(eventData.get(AuditEventReader.ARG0), -1L);

            //according to manpage if following true then use cwd if path not absolute, which is already handled by open
            if (dirFd != AT_FDCWD) { //checking if cwd needs to be replaced by dirFd's path
                String pid = eventData.get(AuditEventReader.PID);
                String dirFdString = String.valueOf(dirFd);
                //if null of if not file then cannot process it
                Map<String, String> fd_eventdata = getInFileDescriptor(pid, dirFdString);
                if (fd_eventdata == null) {
                    logger.info("Expected 'dir' type fd: '", null, time, eventId, syscall);
                    return;
                } else { //is file
                    String dirPath = fd_eventdata.get(AuditEventReader.PATH_PREFIX);
                    eventData.put(AuditEventReader.CWD, dirPath); //replace cwd with dirPath to make eventData compatible with open
                }
            }
        }

        //modify the eventData to match open syscall and then call it's function
        eventData.put(AuditEventReader.ARG0, eventData.get(AuditEventReader.ARG1)); //moved pathname address to first like in open
        eventData.put(AuditEventReader.ARG1, eventData.get(AuditEventReader.ARG2)); //moved flags to second like in open
        eventData.put(AuditEventReader.ARG2, eventData.get(AuditEventReader.ARG3)); //moved mode to third like in open
        handleOpen(eventData, syscall);
    }


    private void handleConnect(Map<String, String> eventData, SYSCALL syscall) {
        String eventId = eventData.get(AuditEventReader.EVENT_ID);
        String time = eventData.get(AuditEventReader.TIME);
        String pid = eventData.get(AuditEventReader.PID);
        String sockFd = eventData.get(AuditEventReader.ARG0);
        String saddr = eventData.get(AuditEventReader.SADDR);
        if (Utils.isNetlinkSaddr(saddr)) {
            System.out.println("wrong lsaddr or rsaddr");
            return;
        }
        AddressPort addressPort = Utils.parseSaddr(saddr);
        if (addressPort == null)
            return;
        Vertex process = graph.addProcessVertex(eventData);
        Vertex network = graph.addNetworkVertex("CONNECT", addressPort.address, addressPort.port, "", "", "", eventId);
        graph.addEdge(process, network, time, syscall.name(), GraphEventType.NETWORK_CONNECT.name(), eventId);
        pm.addSyscall(pid, syscall);
    }

    private void handleConnectNetIO(Map<String, String> eventData, SYSCALL syscall) {
        String eventId = eventData.get(AuditEventReader.EVENT_ID);
        String time = eventData.get(AuditEventReader.TIME);
        String pid = eventData.get(AuditEventReader.PID);
        String lsaddr = eventData.get(AuditEventReader.KMODULE_LOCAL_SADDR);
        String rsaddr = eventData.get(AuditEventReader.KMODULE_REMOTE_SADDR);
        AddressPort lap = Utils.parseSaddr(lsaddr);
        AddressPort rap = Utils.parseSaddr(rsaddr);
        String sockType = eventData.get(AuditEventReader.KMODULE_SOCKTYPE);
        if (Utils.isNetlinkSaddr(lsaddr) || Utils.isNetlinkSaddr(rsaddr)) {
            System.out.println("wrong lsaddr or rsaddr");
            return;
        }
        Vertex process = graph.addProcessVertex(eventData);
        Vertex network = graph.addNetworkVertex("CONNECT", lap.address, lap.port, rap.address, rap.port, "", sockType);
        graph.addEdge(process, network, time, syscall.name(), GraphEventType.NETWORK_CONNECT.name(), eventId);
        pm.addSyscall(pid, syscall);
    }

    private void handleAcceptNetIO(Map<String, String> eventData, SYSCALL syscall) {
        System.out.println("in accept netio");
        String eventId = eventData.get(AuditEventReader.EVENT_ID);
        String time = eventData.get(AuditEventReader.TIME);
        String pid = eventData.get(AuditEventReader.PID);
        String lsaddr = eventData.get(AuditEventReader.KMODULE_LOCAL_SADDR);
        String rsaddr = eventData.get(AuditEventReader.KMODULE_REMOTE_SADDR);
        AddressPort lap = Utils.parseSaddr(lsaddr);
        AddressPort rap = Utils.parseSaddr(rsaddr);
        String sockType = eventData.get(AuditEventReader.KMODULE_SOCKTYPE);
        if (Utils.isNetlinkSaddr(lsaddr) || Utils.isNetlinkSaddr(rsaddr)) {
            System.out.println("wrong lsaddr or rsaddr");
            return;
        }
        Vertex process = graph.addProcessVertex(eventData);
        Vertex network = graph.addNetworkVertex("ACCEPT", lap.address, lap.port, rap.address, rap.port, "", sockType);
        graph.addEdge(network, process, time, syscall.name(), GraphEventType.NETWORK_ACCEPT.name(), eventId);
        pm.addSyscall(pid, syscall);
    }

    private void handleSocket(Map<String, String> eventData, SYSCALL syscall) {
        String sockFd = eventData.get("exit");
        Integer socketType = CommonFunctions.parseInt(eventData.get("a1"), null);
        String protocolName = getProtocolNameBySockType(socketType);
        String pid = eventData.get("pid");
        NetworkID networkID = new NetworkID("", "", "", "", protocolName);
        addToNetworkDescriptors(pid, sockFd, networkID); // no close edge
    }

    private void handleAccept(Map<String, String> eventData, SYSCALL syscall) {
        if (eventData.containsKey(AuditEventReader.RECORD_TYPE_KEY) && eventData.get(AuditEventReader.RECORD_TYPE_KEY).contains(AuditEventReader.KMODULE_RECORD_TYPE)) {
            handleAcceptNetIO(eventData, syscall);
            return;
        }
        String eventId = eventData.get(AuditEventReader.EVENT_ID);
        String time = eventData.get(AuditEventReader.TIME);
        String pid = eventData.get(AuditEventReader.PID);
        String sockFd = eventData.get(AuditEventReader.ARG0);
        String saddr = eventData.get(AuditEventReader.SADDR);
        if (Utils.isNetlinkSaddr(saddr)) {
            System.out.println("wrong lsaddr or rsaddr");
            return;
        }
        if (Utils.isNetworkSaddr(saddr)) {
            AddressPort addressPort = Utils.parseSaddr(saddr);
            Vertex process = graph.addProcessVertex(eventData);
            Vertex network = graph.addNetworkVertex("ACCEPT", "", "", addressPort.address, addressPort.port, "", eventId);
            graph.addEdge(network, process, time, syscall.name(), GraphEventType.NETWORK_ACCEPT.name(), eventId);
            pm.addSyscall(pid, syscall);
        } else if (Utils.isUnixSaddr(saddr)) {
            logger.warn("Encountered Unix Socket Accept rather than Network Socket; Still need to handle it");
        }
    }

    private void handleExit(Map<String, String> eventData, SYSCALL syscall) {
        String uid = Utils.getIdentifierProcess(eventData);
        String time = eventData.get("time");
        if (graph.seen_vertices.containsKey(uid)) {
            Vertex vertex = graph.seen_vertices.get(uid);
            vertex.property(NodeProperty.TERMINATE.name(), "TRUE");
            vertex.property(NodeProperty.TERMINATE_TIME.name(), time);
        } else {
            // If the process was never seen before just make a vertex
            Vertex vertex = graph.addProcessVertex(eventData);
            vertex.property(NodeProperty.TERMINATE.name(), "TRUE");
            vertex.property(NodeProperty.TERMINATE_TIME.name(), time);
        }
    }


    /// DONE=======================================================
    /// DONE=======================================================

    private boolean checkInFileDescriptors(String pid, String fd) {
        if (descriptorsF.containsKey(pid)) {
            return descriptorsF.get(pid).containsKey(fd);
        }
        return false;
    }

    private Map<String, String> removeFileDescriptors(String pid, String fd) {
        if (descriptorsF.get(pid) == null) {
            return null;
        }
        return descriptorsF.get(pid).remove(fd);
    }

    private Map<String, String> getInFileDescriptor(String pid, String fd) {
        if (descriptorsF.containsKey(pid)) {
            if (descriptorsF.get(pid).containsKey(fd)) {
                return descriptorsF.get(pid).get(fd);
            }
        }
        return null;
    }

    private void addToFileDescriptors(String pid, String fd, Map<String, String> eventData) {
        HashMap<String, Map<String, String>> map = new HashMap<>();
        map.put(fd, eventData);
        if (descriptorsF.containsKey(pid))
            descriptorsF.get(pid).put(fd, eventData);
        else
            descriptorsF.put(pid, map);
    }

    private NetworkID removeNetworkDescriptors(String pid, String fd) {
        if (descriptorsN.get(pid) == null) {
            return null;
        }
        return descriptorsN.get(pid).remove(fd);
    }

    private boolean checkInNetworkDescriptors(String pid, String fd) {
        if (descriptorsN.containsKey(pid)) {
            return descriptorsN.get(pid).containsKey(fd);
        }
        return false;
    }

    private NetworkID getInNetworkDescriptor(String pid, String fd) {
        if (descriptorsN.containsKey(pid)) {
            if (descriptorsN.get(pid).containsKey(fd)) {
                return descriptorsN.get(pid).get(fd);
            }
        }
        return null;
    }

    private NetworkID addToNetworkDescriptors(String pid, String fd, NetworkID netid) {
        HashMap<String, NetworkID> map = new HashMap<>();
        if (netid == null) {
            return null;
        }
        map.put(fd, netid);
        if (descriptorsN.containsKey(pid))
            descriptorsN.get(pid).put(fd, netid);
        else {
            System.out.println(pid + " Adding new " + netid);
            descriptorsN.put(pid, map);
        }
        return netid;
    }


    private List<PathRecord> getPathsWithNametype(Map<String, String> eventData, String nametypeValue) {
        List<PathRecord> pathRecords = new ArrayList<PathRecord>();
        if (eventData != null && nametypeValue != null) {
            Long items = CommonFunctions.parseLong(eventData.get(AuditEventReader.ITEMS), 0L);
            for (int itemcount = 0; itemcount < items; itemcount++) {
                if (nametypeValue.equals(eventData.get(AuditEventReader.NAMETYPE_PREFIX + itemcount))) {
                    PathRecord pathRecord = new PathRecord(itemcount,
                            eventData.get(AuditEventReader.PATH_PREFIX + itemcount),
                            eventData.get(AuditEventReader.NAMETYPE_PREFIX + itemcount),
                            eventData.get(AuditEventReader.MODE_PREFIX + itemcount));
                    pathRecords.add(pathRecord);
                }
            }
        }
        Collections.sort(pathRecords);
        return pathRecords;
    }

    private PathRecord getFirstPathWithNametype(Map<String, String> eventData, String nametypeValue) {
        List<PathRecord> pathRecords = getPathsWithNametype(eventData, nametypeValue);
        if (pathRecords == null || pathRecords.size() == 0) {
            return null;
        } else {
            return pathRecords.get(0);
        }
    }

    private String constructPath(String path, String parentPath) {
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
            logger.info("Failed to create resolved path. path:" + path + ", parentPath:" + parentPath, e);
        }
        return null;
    }

    private String constructPathSpecial(String path, String fdString, String cwd, String pid, String time, String eventId, SYSCALL syscall) {
        if (path == null) {
            logger.info("Missing PATH record", null, time, eventId, syscall);
            return null;
        } else if (path.startsWith(File.separator)) { //is absolute
            return constructPath(path, cwd); //just getting the path resolved if it has .. or .
        } else { //is not absolute
            if (fdString == null) {
                logger.info("Missing FD", null, time, eventId, syscall);
                return null;
            } else {
                Long fd = CommonFunctions.parseLong(fdString, -1L);
                if (fd == AT_FDCWD) {
                    if (cwd == null) {
                        logger.info("Missing CWD record", null, time, eventId, syscall);
                        return null;
                    } else {
                        path = constructPath(path, cwd);
                        return path;
                    }
                } else {
                    Map<String, String> eventData = getInFileDescriptor(pid, String.valueOf(fd));
                    if (eventData == null) {
                        logger.info("No FD with number '" + fd + "' for pid '" + pid + "'", null, time, eventId, syscall);
                        return null;
                    } else {
                        path = eventData.get(AuditEventReader.PATH_PREFIX);
                        if (path == null) {
                            logger.info("Invalid Path");
                            return null;
                        } else {
                            return path;
                        }
                    }
                }
            }
        }
    }

    private PathRecord getPathWithCreateOrNormalNametype(Map<String, String> eventData) {
        PathRecord pathRecord = getFirstPathWithNametype(eventData, AuditEventReader.NAMETYPE_CREATE);
        if (pathRecord != null) {
            return pathRecord;
        } else {
            pathRecord = getFirstPathWithNametype(eventData, AuditEventReader.NAMETYPE_NORMAL);
            return pathRecord;
        }
    }

    private String getProtocolNameBySockType(Integer sockType) {
        if (sockType != null) {
            if ((sockType & SOCK_SEQPACKET) == SOCK_SEQPACKET) { // check first because seqpacket matches stream too
                return PROTOCOL_NAME_TCP;
            } else if ((sockType & SOCK_STREAM) == SOCK_STREAM) {
                return PROTOCOL_NAME_TCP;
            } else if ((sockType & SOCK_DGRAM) == SOCK_DGRAM) {
                return PROTOCOL_NAME_UDP;
            }
        }
        return null;
    }


}
