package parsers;

import event.PTAppLogEvent;
import event.PTEvent;
import event.PTSyscallEvent;
import event.PTThreadEvent;

import java.util.*;

/**
 * The sequence of PT events as seen by the PT trace
 */
public class PTEventSequence {
    private final Map<Integer, ArrayList<PTEvent>> m_events_;
    private int m_curr_id_;
    private final Set<Integer> m_pids_;
    private int m_num_syscalls_ = 0;
    private int m_num_applogs_ = 0;
    private int m_num_threadevents_ = 0;

    public PTEventSequence() {
        m_events_ = new HashMap<>();
        m_curr_id_ = 0;
        m_pids_ = new HashSet<>();
    }

    public int getNumSyscalls() {
        return m_num_syscalls_;
    }

    public int getNumAppLogs() {
        return m_num_applogs_;
    }

    public int getNumThreadEvents() {
        return m_num_threadevents_;
    }

    public void add(int pid, PTEvent e) {
        if (m_events_.containsKey(pid)) {
            m_events_.get(pid).add(e);
        } else {
            ArrayList<PTEvent> seq = new ArrayList<>();
            seq.add(e);
            m_events_.put(pid, seq);
        }
    }

    public void addPid(int pid) {
        m_pids_.add(pid);
    }

    public int getSize() {
        return (m_num_applogs_ + m_num_syscalls_ + m_num_threadevents_);
    }

    public ListIterator<PTEvent> listIterator(int pid) {
        if (m_events_.containsKey(pid)) {
            return m_events_.get(pid).listIterator();
        } else {
            return null;
        }
    }

    public PTEvent createAppLogEvent(String name, int wid, int pid) {
        PTAppLogEvent ev = new PTAppLogEvent(m_curr_id_, name, wid);
        this.add(pid, ev);
        m_curr_id_++;
        m_num_applogs_++;
        return ev;
    }

    public PTEvent createThreadEvent(String name, int tid, int pid) {
        PTThreadEvent ev = new PTThreadEvent(m_curr_id_, name, tid);
        this.add(pid, ev);
        m_curr_id_++;
        m_num_threadevents_++;
        return ev;
    }

    public PTEvent createSyscallEvent(String name, int sid, int pid, String curr_obj, String prev_obj) {
        PTSyscallEvent ev = new PTSyscallEvent(m_curr_id_, name, sid, curr_obj, prev_obj);
        this.add(pid, ev);
        m_curr_id_++;
        m_num_syscalls_++;
        return ev;
    }

    public Set<Integer> getPids() {
        return m_pids_;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();

        sb.append("List of events from the PT trace ");
        for (Map.Entry<Integer, ArrayList<PTEvent>> entry : m_events_.entrySet()) {
            sb.append(entry.getKey());
            sb.append(" {\n");
            for (PTEvent e : entry.getValue()) {
                sb.append("\t");
                sb.append(e);
            }
            sb.append("}\n");
        }

        return sb.toString();
    }
}
