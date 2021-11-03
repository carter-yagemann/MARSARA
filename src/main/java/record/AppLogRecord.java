package record;

import parsers.AuditEventReader;
import parsers.jgraph.ULogNode;
import utils.Utils;

import java.util.Map;

public class AppLogRecord implements RecordEvent {
    // The process id for the process to which the event belongs to.
    private final int pid;
    // The wlog node that this event is capturing
    private final ULogNode uLogNode;
    // The audit event associate with the event
    private final Map<String, String> auditEvent;

    public AppLogRecord(int pid, ULogNode uLogNode, Map<String, String> auditEvent) {
        this.pid = pid;
        this.uLogNode = uLogNode;
        this.auditEvent = auditEvent;
    }

    @Override
    public boolean isPTRecord() {
        return false;
    }

    @Override
    public boolean isAuditRecord() {
        return false;
    }

    @Override
    public boolean isAppLogRecord() {
        return true;
    }

    @Override
    public Object getEvent() {
        return uLogNode;
    }

    public Map<String, String> getAuditEvent() {
        return auditEvent;
    }

    @Override
    public int getPid() {
        return this.pid;
    }

    @Override
    public String toString() {
        String data = Utils.decodeHex(auditEvent.get(AuditEventReader.DATA));
        return "< " + this.uLogNode.getStr() + " |||| " + data.trim().stripTrailing() + " >";
    }
}
