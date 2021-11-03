package parsers;

import utils.CommonFunctions;

import java.io.*;
import java.util.AbstractMap.SimpleEntry;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Audit log reader which reads the log and sorts it in a sliding window of 'x' audit records
 */
public class AuditEventReader {
    public static final String ARG0 = "a0",
            ARG1 = "a1",
            ARG2 = "a2",
            ARG3 = "a3",
            COMM = "comm",
            CWD = "cwd",
            EVENT_ID = "eventid",
            EXECVE_PREFIX = "execve_",
            EXIT = "exit",
            FD = "fd",
            FD0 = "fd0",
            FD1 = "fd1",
            ITEMS = "items",
            MODE_PREFIX = "mode",
            NAMETYPE_CREATE = "CREATE",
            NAMETYPE_NORMAL = "NORMAL",
            NAMETYPE_PREFIX = "nametype",
            PATH_PREFIX = "path",
            PID = "pid",
            PPID = "ppid",
            RECORD_TYPE_CWD = "CWD",
            RECORD_TYPE_EXECVE = "EXECVE",
            RECORD_TYPE_FD_PAIR = "FD_PAIR",
            RECORD_TYPE_MMAP = "MMAP",
            RECORD_TYPE_NETFILTER_PKT = "NETFILTER_PKT",
            RECORD_TYPE_PATH = "PATH",
            RECORD_TYPE_SOCKADDR = "SOCKADDR",
            RECORD_TYPE_SOCKETCALL = "SOCKETCALL",
            RECORD_TYPE_SYSCALL = "SYSCALL",
            RECORD_TYPE_USER = "USER",
            RECORD_TYPE_KEY = "type",
            SADDR = "saddr",
            SYSCALL = "syscall",
            TIME = "time",
            KMODULE_RECORD_TYPE = "netio_module_record",
            KMODULE_DATA_KEY = "netio_intercepted",
            KMODULE_APPLOG_KEY = "applog",
            KMODULE_SOCKTYPE = "sock_type",
            KMODULE_LOCAL_SADDR = "local_saddr",
            DATA = "data",
            KMODULE_REMOTE_SADDR = "remote_saddr";


    private final Logger logger = Logger.getLogger(this.getClass().getName());

    // Group 1: key
    // Group 2: value
    private static final Pattern pattern_key_value = Pattern.compile("(\\w+)=\"*((?<=\")[^\"]+(?=\")|([^\\s]+))\"*");

    // Group 1: node
    // Group 2: type
    // Group 3: time
    // Group 4: recordid
    private static final Pattern pattern_message_start = Pattern.compile("(?:node=(\\S+) )?type=(.+) msg=audit\\(([0-9\\.]+)\\:([0-9]+)\\):\\s*");

    // Group 1: cwd
    //cwd is either a quoted string or an unquoted string in which case it is in hex format
    private static final Pattern pattern_cwd = Pattern.compile("cwd=(\".+\"|[a-zA-Z0-9]+)");

    // Group 1: item number
    // Group 2: name
    // Group 3: nametype
    //name is either a quoted string or an unquoted string in which case it is in hex format
    private static final Pattern pattern_path = Pattern.compile("item=([0-9]*) name=(\".+\"|[a-zA-Z0-9]+) .*objtype=([a-zA-Z]*)");

    // Group 1: eventid
    private static final Pattern pattern_eventid = Pattern.compile("msg=audit\\([0-9\\.]+\\:([0-9]+)\\):");

    /**
     * Reference to the current input stream entry alone with key
     * which is being read. Null means that either it has not been
     * initialized yet (constructor ensures that this doesn't happen)
     * or all streams have been read completely.
     */
    private SimpleEntry<String, BufferedReader> currentInputStreamReaderEntry;

    /**
     * List of key value pairs of <stream identifier, input streams> to read from in the order in the list.
     * In case of files the stream identifier is the path of the file
     */
    private final LinkedList<SimpleEntry<String, InputStream>> inputStreamEntries = new LinkedList<SimpleEntry<String, InputStream>>();

    /**
     * Sorted event ids in the current window
     */
    private final TreeSet<Long> eventIds = new TreeSet<Long>();

    /**
     * List of audit records for event ids received in the current window
     */
    private final Map<Long, Set<String>> eventIdToEventRecords = new HashMap<Long, Set<String>>();

    /**
     * Number of audit records read so far out of the window size
     */
    private long currentlyBufferedRecords = 0;


    /**
     * Id of the last event that was output. Used to discard out of order event
     * records across window size. So, if event with id 'x' has been sent out
     * then if any event with id 'y' is read, where y < x, then 'y' is discarded
     */
    private long lastEventId = -1;

    /**
     * Used to tell if we saw a DAEMON_START type event
     * When this is seen, we stop reading from the file and empty the buffer and once
     * buffer has been empty, the lastEventId is reset and we start reading from the file
     * again. Done this because after DAEMON_START event IDs start from a smaller number.
     */
    private boolean sawDaemonRising = false;

    /**
     * Create instance of the class that reads the given list of files in the given order
     */
    public AuditEventReader(String logFile) throws Exception {
        File file = new File(logFile);
        if (file.exists()) {
            this.inputStreamEntries.addLast(new SimpleEntry<String, InputStream>(logFile, new FileInputStream(file)));
        } else {
            throw new IllegalArgumentException("Log file " + file.getAbsolutePath() + " doesn't exist");
        }
        // Making sure that the current inputstream reader is non-null when readEventData is called afterwards
        initializeCurrentStreamReader();
    }


    /**
     * Convenience function to get the next stream and to initialize(open) it.
     * <p>
     * It closes the current stream if not null.
     *
     * @throws Exception IOException
     */
    private void initializeCurrentStreamReader() throws Exception {
        if (currentInputStreamReaderEntry != null) {
            currentInputStreamReaderEntry.getValue().close();
            currentInputStreamReaderEntry = null; //set to null
        }
        if (inputStreamEntries.size() > 0) {
            SimpleEntry<String, InputStream> nextEntry = inputStreamEntries.removeFirst();
            currentInputStreamReaderEntry = new SimpleEntry<String, BufferedReader>(
                    nextEntry.getKey(), new BufferedReader(new InputStreamReader(nextEntry.getValue())));
        }
    }


    /**
     * Returns a map of key values for the event that is read from the stream(s)
     * <p>
     * Null return value means EOF for all streams
     *
     * @return map of key values of the read audit event
     * @throws Exception IOException
     */
    public Map<String, String> readEventData() throws Exception {
        if (currentInputStreamReaderEntry == null
                || sawDaemonRising) { //all streams processed or emptying the buffer because of DAEMON_START
            return getEventData();
        } else { // not all streams processed
            while (true) { //read audit records until max amount read
                String line = currentInputStreamReaderEntry.getValue().readLine();
                if (line == null) { //if input stream read completely
//                    logger.log(Level.INFO, "Reading succeeded of '" + currentInputStreamReaderEntry.getKey() + "'");
                    initializeCurrentStreamReader(); //initialize the next stream
                    if (currentInputStreamReaderEntry == null) { //if there was no next stream to be initialized
                        break;
                    }
                } else { //if input stream not completely read yet
                    if (line.contains("type=EOE")) {
                        //Ignoring EOE records since we don't use them
                        //and because EOE of DAEMON_START would break the code
                        continue;
                    }
                    if (line.contains("type=DAEMON_START")) {
                        //Going to stop reading until the buffer is empty
                        //Check if the buffer is already empty
                        //If already empty then continue reading from the stream else break
                        if (eventIds.size() > 0) {
                            sawDaemonRising = true;
                            break; //stop reading from the stream and empty the buffer
                        } else { //if buffer already empty
                            lastEventId = -1; //reset because event ids would start from a smaller number now
                            continue;
                        }
                    }
                    Matcher event_start_matcher = pattern_eventid.matcher(line);
                    if (event_start_matcher.find()) { //get the event id
                        Long eventId = CommonFunctions.parseLong(event_start_matcher.group(1), null);
                        if (eventId == null) { //if event id null then don't process
                            logger.log(Level.SEVERE, "Event id null for line -> " + line);
                        } else {
                            if (eventId <= lastEventId) {
                                logger.log(Level.WARNING, "Out of order event beyond the window size -> " + line);
                            } else {
                                currentlyBufferedRecords++; //increment the record count
                                if (eventIdToEventRecords.get(eventId) == null) {
                                    eventIdToEventRecords.put(eventId, new HashSet<String>());
                                    eventIds.add(eventId); //add event id
                                }
                                eventIdToEventRecords.get(eventId).add(line); //add audit record
                            }
                        }
                    }
                }
            }
            //just return the one event
            return getEventData();
        }
    }

    /**
     * Returns the map of key values for the event with the smallest event id
     * <p>
     * Because of DAEMON_START logic, make sure this function is called knowing that
     * the buffer isn't empty. Because if it is then this function would return null
     * and that would indicate the user of this class that EOF has been reached but in
     * reality it hasn't been because we had stopped reading the input stream(s) to
     * empty the buffer because of DAEMON_START and we intend to start reading the
     * input stream again after that. Done to avoid false reordering of events based
     * on event ids.
     *
     * @return map of key values for the event. Null if none found.
     * @throws Exception
     */
    private Map<String, String> getEventData() throws Exception {
        Long eventId = eventIds.pollFirst();
        if (eventId == null) { //empty
            return null;
        } else {
            lastEventId = eventId;
            Set<String> eventRecords = eventIdToEventRecords.remove(eventId);
            currentlyBufferedRecords -= eventRecords.size();

            Map<String, String> eventData = new HashMap<String, String>();

            if (eventRecords != null) {
                for (String eventRecord : eventRecords) {
                    eventData.putAll(parseEventLine(eventRecord));
                }
            }
            if (eventIds.size() == 0) { //Buffer emptied
                if (sawDaemonRising) { //Check if we had stopped reading because of DAEMON_START
                    sawDaemonRising = false;
                    lastEventId = -1; //reset
                    //Doing this here because we don't want to return null before starting to read
                    //from the file again
                }
            }

            return eventData;
        }
    }

    /**
     * Creates a map with key values as needed by the Audit reporter from audit records of an event
     *
     * @param line event record to parse
     * @return map of key values for the argument record
     */
    private Map<String, String> parseEventLine(String line) {
        Map<String, String> auditRecordKeyValues = new HashMap<String, String>();

        Matcher event_start_matcher = pattern_message_start.matcher(line);
        if (event_start_matcher.find()) {
            String node = event_start_matcher.group(1);
            String type = event_start_matcher.group(2);
            String time = event_start_matcher.group(3);
            String eventId = event_start_matcher.group(4);
            String messageData = line.substring(event_start_matcher.end());

            auditRecordKeyValues.put("eventid", eventId);
            auditRecordKeyValues.put("node", node);

            if (type.equals(RECORD_TYPE_USER)) {
                int indexOfData = messageData.indexOf(KMODULE_DATA_KEY);
                if (indexOfData != -1) {
                    String data = messageData.substring(indexOfData + KMODULE_DATA_KEY.length() + 1);
                    data = data.substring(1, data.length() - 1);// remove quotes
                    Map<String, String> eventData = CommonFunctions.parseKeyValPairs(data);
                    eventData.put(RECORD_TYPE_KEY, KMODULE_RECORD_TYPE);
                    eventData.put(COMM, CommonFunctions.decodeHex(eventData.get(COMM)));
                    eventData.put(TIME, time);
                    auditRecordKeyValues.putAll(eventData);
                }
                int indexOfApplog = messageData.indexOf(KMODULE_APPLOG_KEY);
                if (indexOfApplog != -1) {
                    String data = messageData.substring(indexOfData + KMODULE_APPLOG_KEY.length() + 1);
                    data = data.substring(1, data.length() - 1);// remove quotes
                    Map<String, String> eventData = CommonFunctions.parseKeyValPairs(data);
                    eventData.put(RECORD_TYPE_KEY, KMODULE_RECORD_TYPE);
                    eventData.put(TIME, time);
                    auditRecordKeyValues.putAll(eventData);
                }
            } else if (type.equals(RECORD_TYPE_SYSCALL)) {
                Map<String, String> eventData = CommonFunctions.parseKeyValPairs(messageData);
                if (messageData.contains(COMM + "=") && !messageData.contains(COMM + "=\"")
                        && !"(null)".equals(eventData.get(COMM))) { // comm has a hex encoded value
                    // decode and replace value
                    eventData.put(COMM, CommonFunctions.decodeHex(eventData.get(COMM)));
                }
                eventData.put(TIME, time);
                auditRecordKeyValues.putAll(eventData);
            } else if (type.equals(RECORD_TYPE_CWD)) {
                Matcher cwd_matcher = pattern_cwd.matcher(messageData);
                if (cwd_matcher.find()) {
                    String cwd = cwd_matcher.group(1);
                    cwd = cwd.trim();
                    if (cwd.startsWith("\"") && cwd.endsWith("\"")) { //is a string path
                        cwd = cwd.substring(1, cwd.length() - 1);
                    } else { //is in hex format
                        try {
                            cwd = CommonFunctions.decodeHex(cwd);
                        } catch (Exception e) {
                            //failed to parse
                        }
                    }
                    auditRecordKeyValues.put(CWD, cwd);
                }
            } else if (type.equals(RECORD_TYPE_PATH)) {
                Map<String, String> pathKeyValues = CommonFunctions.parseKeyValPairs(messageData);
                String itemNumber = pathKeyValues.get("item");
                String name = pathKeyValues.get("name");
                String mode = pathKeyValues.get("mode");
                mode = mode == null ? "0" : mode;
                String nametype = pathKeyValues.get("nametype");

                name = name.trim();
                if (messageData.contains(" name=") &&
                        !messageData.contains(" name=\"") &&
                        !messageData.contains(" name=(null)")) {
                    //is a hex path if the value of the key name doesn't start with double quotes
                    try {
                        name = CommonFunctions.decodeHex(name);
                    } catch (Exception e) {
                        //failed to parse
                    }
                }

                auditRecordKeyValues.put(PATH_PREFIX + itemNumber, name);
                auditRecordKeyValues.put(NAMETYPE_PREFIX + itemNumber, nametype);
                auditRecordKeyValues.put(MODE_PREFIX + itemNumber, mode);
            } else if (type.equals(RECORD_TYPE_EXECVE)) {
                Matcher key_value_matcher = pattern_key_value.matcher(messageData);
                while (key_value_matcher.find()) {
                    auditRecordKeyValues.put(EXECVE_PREFIX + key_value_matcher.group(1), key_value_matcher.group(2));
                }
            } else if (type.equals(RECORD_TYPE_FD_PAIR)) {
                Matcher key_value_matcher = pattern_key_value.matcher(messageData);
                while (key_value_matcher.find()) {
                    auditRecordKeyValues.put(key_value_matcher.group(1), key_value_matcher.group(2));
                }
            } else if (type.equals(RECORD_TYPE_SOCKETCALL)) {
                Matcher key_value_matcher = pattern_key_value.matcher(messageData);
                while (key_value_matcher.find()) {
                    auditRecordKeyValues.put("socketcall_" + key_value_matcher.group(1), key_value_matcher.group(2));
                }
            } else if (type.equals(RECORD_TYPE_SOCKADDR)) {
                Matcher key_value_matcher = pattern_key_value.matcher(messageData);
                while (key_value_matcher.find()) {
                    auditRecordKeyValues.put(key_value_matcher.group(1), key_value_matcher.group(2));
                }
            } else if (type.equals(RECORD_TYPE_NETFILTER_PKT)) {
                auditRecordKeyValues.put(TIME, time); // add time
                auditRecordKeyValues.put(RECORD_TYPE_KEY, RECORD_TYPE_NETFILTER_PKT); // type
                // rest of the keys as is below
                Matcher key_value_matcher = pattern_key_value.matcher(messageData);
                while (key_value_matcher.find()) {
                    auditRecordKeyValues.put(key_value_matcher.group(1), key_value_matcher.group(2));
                }
            } else if (type.equals(RECORD_TYPE_MMAP)) {
                Matcher key_value_matcher = pattern_key_value.matcher(messageData);
                while (key_value_matcher.find()) {
                    auditRecordKeyValues.put(key_value_matcher.group(1), key_value_matcher.group(2));
                }
            } else {
                //System.out.println("I CANNOT HANDLE THIS TYPE:"  + type+ " line " + line);
            }
        }

        return auditRecordKeyValues;
    }
}