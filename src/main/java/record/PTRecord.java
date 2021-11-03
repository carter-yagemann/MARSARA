package record;

import parsers.jgraph.ULogNode;

public class PTRecord implements RecordEvent {
    // The wlog node that the event references, this would not be a regex node
    private final ULogNode ulogNode;
    // The process id for the process to which the event belongs to.
    private final int pid;

    public PTRecord(int pid, ULogNode ulogNode) {
        this.pid = pid;
        this.ulogNode = ulogNode;
        assert (!this.ulogNode.isRegex());
    }

    @Override
    public int getPid() {
        return this.pid;
    }

    @Override
    public boolean isPTRecord() {
        return true;
    }

    @Override
    public boolean isAuditRecord() {
        return false;
    }

    @Override
    public boolean isAppLogRecord() {
        return false;
    }

    @Override
    public Object getEvent() {
        return ulogNode;
    }

    @Override
    public String toString() {
        return "< " + this.ulogNode.getStr() + " >";
    }
}
