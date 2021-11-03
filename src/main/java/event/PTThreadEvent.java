package event;

public class PTThreadEvent extends PTEvent {
    private final int m_thread_num_;      //! The vent's thread number

    /**
     * Constructor with event id, name, and thread number
     *
     * @param m_event_id_   The id of the event
     * @param m_name_       The name of the event
     * @param m_thread_num_ The thread number for this event
     */
    public PTThreadEvent(int m_event_id_, String m_name_, int m_thread_num_) {
        super(m_event_id_, m_name_, PTEventType.PT_THREAD);
        this.m_thread_num_ = m_thread_num_;
    }

    public int getThreadNum() {
        return m_thread_num_;
    }

    @Override
    public String toString() {
        return "Thread event {" +
                "event id: " + getId() +
                ", thread number:" + m_thread_num_ +
                '}';
    }
}
