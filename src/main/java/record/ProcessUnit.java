package record;

import event.SYSCALL;

import java.util.ArrayList;
import java.util.List;

public class ProcessUnit {
    public int unit;
    public String time;
    public List<SYSCALL> syscalls = new ArrayList<>();

    @Override
    public String toString() {
        return "{" +
                "syscalls=" + syscalls +
                '}';
    }

    public ProcessUnit(String time) {
        this.time = time;
    }
}
