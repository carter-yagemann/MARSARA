package event;

public class PTSyscallEvent extends PTEvent {
    //! The system call number
    private final int m_syscall_num_;
    private final String currObject;
    private final String prevObject;

    /**
     * Constructor for the syscall event type
     *
     * @param m_event_id_    The event id
     * @param m_name_        The name of the event
     * @param m_syscall_num_ The syscall number for the event
     */
    public PTSyscallEvent(int m_event_id_, String m_name_, int m_syscall_num_, String currObject, String prevObject) {
        super(m_event_id_, m_name_, PTEventType.PT_SYSCALL);
        this.m_syscall_num_ = m_syscall_num_;
        this.currObject = currObject;
        this.prevObject = prevObject;
    }

    /**
     * Get the event's system call number
     *
     * @return the system call number
     */
    public int getSyscallNumber() {
        return m_syscall_num_;
    }

    /**
     * Return human readable syscall
     *
     * @param arch The architecture we are using (32, 64)
     * @return the systemcall enum corresponding to the number
     */
    public SYSCALL getSyscall(int arch) {
        return SYSCALL.getSyscall(getSyscallNumber(), arch);
    }

    public String getCurrObject() {
        return currObject;
    }

    public String getPrevObject() {
        return prevObject;
    }

    @Override
    public String toString() {
        return "Syscall event {" +
                "event id: " + getId() +
                ", syscall number: " + m_syscall_num_ +
                ", current object name: " + currObject +
                ", previous object name: " + prevObject +
                '}';
    }
}
