package record;

import event.SYSCALL;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ProcessManager {

    public Map<String, List<SYSCALL>> attached_syscalls = new HashMap<>();
    public Map<String, List<ProcessUnit>> process_units = new HashMap<>();

    public void addSyscall(String pid, SYSCALL syscall) {
        if (attached_syscalls.containsKey(pid)) {
            List<SYSCALL> curr = attached_syscalls.get(pid);
            curr.add(syscall);
        } else {
            List<SYSCALL> curr = new ArrayList<>();
            curr.add(syscall);
            attached_syscalls.put(pid, curr);
        }
    }

    public void addEndUnit(String pid, String time) {
        if (process_units.containsKey(pid)) {
            List<ProcessUnit> curr = process_units.get(pid);
            ProcessUnit newUnit = new ProcessUnit(time);
            curr.add(newUnit);
            if (attached_syscalls.containsKey(pid)) {
                List<SYSCALL> sys_list = attached_syscalls.get(pid);
                System.out.println("SYSCALL: " + newUnit.syscalls);
                newUnit.syscalls.addAll(sys_list);
                sys_list.clear();
            }
        } else {
            List<ProcessUnit> curr = new ArrayList<>();
            ProcessUnit newUnit = new ProcessUnit(time);
            curr.add(newUnit);
            process_units.put(pid, curr);
            if (attached_syscalls.containsKey(pid)) {
                List<SYSCALL> sys_list = attached_syscalls.get(pid);
                newUnit.syscalls.addAll(sys_list);
                System.out.println("SYSCALL: " + newUnit.syscalls);
                sys_list.clear();
            }
        }
    }


    public void addUnitSyscalls(String pid, SYSCALL syscall) {
        if (process_units.containsKey(pid)) {
            List<ProcessUnit> curr = process_units.get(pid);
            ProcessUnit last = curr.get(curr.size() - 1);
            last.syscalls.add(syscall);
        } else {
            System.out.println("Not part of unit..." + pid);
        }
    }

    @Override
    public String toString() {

        String str = "UNITS: \n";
        for (Map.Entry<String, List<ProcessUnit>> curr : process_units.entrySet()) {
            str += "PID: " + curr.getKey() + " \n";
            int counter = 1;
            for (ProcessUnit pu : curr.getValue()) {
                str += "UNIT " + counter + " : " + pu + "\n";
                counter += 1;
            }
        }
        return str;
    }


}
