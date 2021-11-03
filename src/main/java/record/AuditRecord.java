package record;

import event.SYSCALL;
import parsers.AuditEventReader;
import utils.CommonFunctions;
import utils.Utils;

import java.util.Map;

public class AuditRecord implements RecordEvent {
    private final int arch = 64;

    // The PT event that this record holds.
    private final Map<String, String> auditEvent;
    // The process id for the process to which the event belongs to.
    private final int pid;

    public AuditRecord(Map<String, String> auditEvent, int pid) {
        this.auditEvent = auditEvent;
        this.pid = pid;
    }

    @Override
    public boolean isPTRecord() {
        return false;
    }

    @Override
    public boolean isAuditRecord() {
        return true;
    }

    @Override
    public boolean isAppLogRecord() {
        return false;
    }

    @Override
    public Object getEvent() {
        return auditEvent;
    }

    @Override
    public int getPid() {
        return this.pid;
    }

    @Override
    public String toString() {
        int sysNum = CommonFunctions.parseInt(auditEvent.get("syscall"), -1);
        SYSCALL syscall = SYSCALL.getSyscall(sysNum, arch);
        if (sysNum == 1) {
            String data = Utils.decodeHex(auditEvent.get(AuditEventReader.DATA));
            if (data != null) {
                return "< WRITE: " + data.replace("\n", "\\n") + " >";
            }
        }
        return "< " + syscall + " >";
    }
}
