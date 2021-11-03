package event;

public class PTEvent {

    //! The id of the event in the list
    private final int m_event_id_;
    //! The event's name
    private final String m_name_;
    //! The event's type
    private final PTEventType m_type_;

    /**
     * Default constructor
     */
    public PTEvent() {
        m_event_id_ = -1;
        m_name_ = "";
        m_type_ = PTEventType.PT_LAST_ONE;
    }

    /**
     * Create a PT Event with a specific, id, name, and type
     * <p>
     * \param m_event_id_   The id of the event
     * \param m_name_       The name of the event
     * \param m_type_       The type of the event
     */
    public PTEvent(int m_event_id_, String m_name_, PTEventType m_type_) {
        this.m_event_id_ = m_event_id_;
        this.m_name_ = m_name_;
        this.m_type_ = m_type_;
    }

    // ** Type Checks ** //
    public boolean isThreadEvent() {
        return m_type_ == PTEventType.PT_THREAD;
    }

    public boolean isSyscallEvent() {
        return m_type_ == PTEventType.PT_SYSCALL;
    }

    public boolean isAppLogEvent() {
        return m_type_ == PTEventType.PT_APPLOG;
    }

    // ** Getters ** //
    public int getId() {
        return m_event_id_;
    }

    public String getName() {
        return m_name_;
    }

}
