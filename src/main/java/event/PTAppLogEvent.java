package event;

public class PTAppLogEvent extends PTEvent {
    private final int m_wnode_id_;    //! The id of the wlog node associate with the event

    /**
     * Constructor with event id, name, and wlog node
     *
     * @param m_event_id_ The event id
     * @param m_name_     The event name
     * @param m_wnode_id_ The associate wlog node id
     */
    public PTAppLogEvent(int m_event_id_, String m_name_, int m_wnode_id_) {
        super(m_event_id_, m_name_, PTEventType.PT_APPLOG);
        this.m_wnode_id_ = m_wnode_id_;
    }

    //! Get the wlog node id
    public int getWNodeId() {
        return m_wnode_id_;
    }

    @Override
    public String toString() {
        return "Application Log Event {" +
                "id: " + getId() +
                ", Wlog node: " + m_wnode_id_ +
                '}';
    }
}
