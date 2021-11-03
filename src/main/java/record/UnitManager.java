package record;

import parsers.jgraph.ULogGraph;
import parsers.jgraph.ULogNode;

import java.text.MessageFormat;
import java.util.*;

public class UnitManager {
    // the full trace of execution units for each process id.
    Map<Integer, List<ExecutionUnit>> executionUnits;
    private final ULogGraph graph;

    public UnitManager(ULogGraph graph) {
        this.executionUnits = new HashMap<>();
        this.graph = graph;
    }

    public void appendUnitEvent(int pid, RecordEvent record) {
        if (executionUnits.containsKey(pid)) {
            List<ExecutionUnit> execList = this.executionUnits.get(pid);
            ExecutionUnit execUnit = execList.get(execList.size() - 1);
            execUnit.addEventToUnit(record);
        } else {
            List<ExecutionUnit> execList = new LinkedList<>();
            ExecutionUnit execUnit = new ExecutionUnit();
            execUnit.addEventToUnit(record);
            execList.add(execUnit);
            this.executionUnits.put(pid, execList);
        }
    }

    public void startNewExecUnit(int pid, RecordEvent record) {
        if (!executionUnits.containsKey(pid)) {
            // not in the table, create a new one, no need to do exec partitioning lookup
            List<ExecutionUnit> execList = new LinkedList<>();
            ExecutionUnit execUnit = new ExecutionUnit();
            execUnit.addEventToUnit(record);
            execList.add(execUnit);
            this.executionUnits.put(pid, execList);
        } else {
            List<ExecutionUnit> execList = this.executionUnits.get(pid);
            ExecutionUnit lastUnit = execList.get(execList.size() - 1);
            ExecutionUnit execUnit = new ExecutionUnit();
            while (true) {
                RecordEvent event = lastUnit.popBack();
                if (event == null)
                    break;
                // if it's an audit record, put it at the front of the new one
                if (event.isAuditRecord() || event.isAppLogRecord()) {
                    execUnit.pushFront(event);
                } else if (event.isPTRecord()) {
                    // code block record
                    PTRecord ptRecord = (PTRecord) event;
                    ULogNode node = (ULogNode) ptRecord.getEvent();
                    execUnit.pushFront(event);
                    if (node.isLikelyExec()) {
                        break;
                    } else if (node.isFuncHead()) {
                        // check if the node has no entry points, TODO: need the graph to do this!
                        if (this.graph.GetInEdges(node.getId()).size() == 0) {
                            break;
                        }
                    }
                }
            }
            execUnit.addEventToUnit(record);
            execList.add(execUnit);
        }
    }

    public Set<Map.Entry<Integer, List<ExecutionUnit>>> entrySet() {
        return executionUnits.entrySet();
    }

    @Override
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();
        for (Map.Entry<Integer, List<ExecutionUnit>> entry : executionUnits.entrySet()) {
            int pid = entry.getKey();
            List<ExecutionUnit> unitList = entry.getValue();

            stringBuilder.append(
                    MessageFormat.format("================ Execution Units [{0}] ==================\n", pid));
            int i = 0;
            for (ExecutionUnit unit : unitList) {
                if (unit.size() > 0) {
                    stringBuilder.append(MessageFormat.format("[Unit {0}]: ", i++));
                    stringBuilder.append(unit.toString() + '\n');
                }
            }
            stringBuilder.append("============================================================\n");
        }
        return stringBuilder.toString();
    }
}
