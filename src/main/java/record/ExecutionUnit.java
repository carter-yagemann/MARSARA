package record;

import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;

public class ExecutionUnit {
    private final List<RecordEvent> unitEvents;

    public ExecutionUnit() {
        this.unitEvents = new LinkedList<>();
    }

    public void addEventToUnit(RecordEvent event) {
        unitEvents.add(event);
    }

    public ListIterator<RecordEvent> getIterator() {
        return unitEvents.listIterator();
    }

    /**
     * Add an element to the front of the list.
     *
     * @param event The event to add to the front of the list.
     */
    public void pushFront(RecordEvent event) {
        unitEvents.add(0, event);
    }

    public int size() {
        return unitEvents.size();
    }

    /**
     * Pop and return the last element in the execution unit.
     *
     * @return The last element in the current execution unit.
     */
    public RecordEvent popBack() {
        if (!unitEvents.isEmpty())
            return unitEvents.remove(unitEvents.size() - 1);
        return null;
    }

    @Override
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("{\n[");
        for (RecordEvent event : unitEvents) {
            if (!event.isPTRecord()) {
                stringBuilder.append(event.toString() + ",");
            }
        }
        stringBuilder.deleteCharAt(stringBuilder.length() - 1);
        stringBuilder.append("]\n}");
        return stringBuilder.toString();
    }
}
