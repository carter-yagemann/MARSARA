package record;

/**
 * A record event to be stored in the body of a single execution unit.
 */
public interface RecordEvent {
    /**
     * Check if the record event is a pt record
     *
     * @return true if the record event is a pt record.
     */
    boolean isPTRecord();

    /**
     * Check if the record event is an audit record
     *
     * @return true if the record event is an audit record.
     */
    boolean isAuditRecord();

    /**
     * Check if the record event is an application log record
     *
     * @return true if the record event is an application log record.
     */
    boolean isAppLogRecord();

    /**
     * Get the event that this record contains. The caller should cast it to the approriate type.
     *
     * @return The event that this record contains.
     */
    Object getEvent();

    /**
     * Get the process id of the process to which this event belongs to.
     *
     * @return the process id of the event.
     */
    int getPid();
}
