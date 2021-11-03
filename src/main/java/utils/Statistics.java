package utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import parsers.jgraph.ULogNode;
import parsers.jparser.JValidator;
import tracker.PTAnalyzer;

import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

public class Statistics {
    private static final Logger l = LoggerFactory.getLogger(PTAnalyzer.class);

    private static class PairOfStates {
        private JValidator.ValidationState left;
        private JValidator.ValidationState right;

        public PairOfStates(JValidator.ValidationState left, JValidator.ValidationState right) {
            this.left = left;
            this.right = right;
        }

        public JValidator.ValidationState getLeft() {
            return left;
        }

        public void setLeft(JValidator.ValidationState left) {
            this.left = left;
        }

        public JValidator.ValidationState getRight() {
            return right;
        }

        public void setRight(JValidator.ValidationState right) {
            this.right = right;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            PairOfStates that = (PairOfStates) o;
            return getLeft().equals(that.getLeft()) &&
                    getRight().equals(that.getRight());
        }

        @Override
        public int hashCode() {
            return left.hashCode() ^ right.hashCode();
        }
    }

    /**
     * The number of low alerts
     */
    private int numLowAlerts;
    /**
     * The number of forward edges from the low alerts
     */
    private int numForwardEdges;
    /** The number of backward edges from the low alerts */
    private int numBackwardEdges;
    /** The number of uncategorized low alert */
    private int numUncategorizedEdges;
    /** The number of critical alerts */
    private int numCriticalAlerts;
    /**
     * The analysis time in seconds
     */
    private double analysisTime_sec;
    /**
     * The number of vertices
     */
    private int numVertices;
    /**
     * The number of edges
     */
    private int numEdges;
    /**
     * The name of the binary
     */
    private final String binaryName;
    /** The total number of events */
    private int numEvents;
    /** Keep track of unique low alerts */
    private final Set<Map.Entry<ULogNode, ULogNode>> uniqueLowAlerts;
    private final Set<Map.Entry<ULogNode, ULogNode>> uniqueForwardEdges;
    private final Set<Map.Entry<ULogNode, ULogNode>> uniqueBackwardEdges;
    private final Set<Map.Entry<ULogNode, ULogNode>> uniqueUncatEdges;

    public Statistics(String binaryName) {
        this.numLowAlerts = 0;
        this.numForwardEdges = 0;
        this.numBackwardEdges = 0;
        this.numCriticalAlerts = 0;
        this.numVertices = 0;
        this.numEdges = 0;
        this.analysisTime_sec = 0.0;
        this.numEvents = 0;
        this.binaryName = binaryName;
        this.uniqueLowAlerts = new HashSet<>();
        this.uniqueForwardEdges = new HashSet<>();
        this.uniqueBackwardEdges = new HashSet<>();
        this.uniqueUncatEdges = new HashSet<>();
    }

    public int getNumLowAlerts() {
        return numLowAlerts;
    }

    public int getNumForwardEdges() {
        return numForwardEdges;
    }

    public int getNumBackwardEdges() {
        return numBackwardEdges;
    }

    public int getNumCriticalAlerts() {
        return numCriticalAlerts;
    }

    public double getAnalysisTime_sec() {
        return analysisTime_sec;
    }

    public int getNumVertices() {
        return numVertices;
    }

    public int getNumEdges() {
        return numEdges;
    }

    public String getBinaryName() {
        return binaryName;
    }

    public int getNumEvents() {
        return numEvents;
    }

    public void setNumEvents(int numEvents) {
        this.numEvents = numEvents;
    }

    public void setNumLowAlerts(int numLowAlerts) {
        this.numLowAlerts = numLowAlerts;
    }

    public void incrementForwardEdges(JValidator.ValidationState prev, JValidator.ValidationState curr) {
        this.numForwardEdges++;
        uniqueForwardEdges.add(new AbstractMap.SimpleEntry<>(prev.getNode(), curr.getNode()));
    }

    public void incrementBackwardEdges(JValidator.ValidationState prev, JValidator.ValidationState curr) {
        this.numBackwardEdges++;
        uniqueBackwardEdges.add(new AbstractMap.SimpleEntry<>(prev.getNode(), curr.getNode()));
    }

    public void setNumCriticalAlerts(int numCriticalAlerts) {
        this.numCriticalAlerts = numCriticalAlerts;
    }

    public void setAnalysisTime_sec(double analysisTime_sec) {
        this.analysisTime_sec = analysisTime_sec;
    }

    public void setNumVertices(int numVertices) {
        this.numVertices = numVertices;
    }

    public void setNumEdges(int numEdges) {
        this.numEdges = numEdges;
    }

    public void incrementTotalEvents() {
        this.numEvents += 1;
    }

    public void increaseUncategorizedEdges(JValidator.ValidationState prev, JValidator.ValidationState curr) {
        this.numUncategorizedEdges += 1;
        uniqueUncatEdges.add(new AbstractMap.SimpleEntry<>(prev.getNode(), curr.getNode()));
    }

    public int getNumUncategorizedEdges() {
        return numUncategorizedEdges;
    }

    public void setNumUncategorizedEdges(int numUncategorizedEdges) {
        this.numUncategorizedEdges = numUncategorizedEdges;
    }

    public void addLowAlert(JValidator.ValidationState prev, JValidator.ValidationState curr) {
        uniqueLowAlerts.add(new AbstractMap.SimpleEntry<>(prev.getNode(), curr.getNode()));
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("+========================================================================+\n");
        sb.append("Num vertices in EA-CFG graph: ").append(getNumVertices()).append("\n");
        sb.append("Num edges in EA-CFG graph: ").append(getNumEdges()).append("\n");
        sb.append("Total number of events: ").append(getNumEvents()).append("\n");
        sb.append("Num low alerts: ").append(getNumLowAlerts()).append("\n");
        sb.append("Num forward edges: ").append(getNumForwardEdges()).append("\n");
        sb.append("Num backward edges: ").append(getNumBackwardEdges()).append("\n");
        sb.append("Num uncategorized edges: ").append(getNumUncategorizedEdges()).append("\n");
        sb.append("Num unique low alerts: ").append(uniqueLowAlerts.size()).append("\n");
        sb.append("Num unique forward edges: ").append(uniqueForwardEdges.size()).append("\n");
        sb.append("Num unique backward edges: ").append(uniqueBackwardEdges.size()).append("\n");
        sb.append("Num unique uncategorized edges: ").append(uniqueUncatEdges.size()).append("\n");
        sb.append("Num critical alerts: ").append(getNumCriticalAlerts()).append("\n");
        sb.append("Total analysis time (sec): ").append(getAnalysisTime_sec()).append("\n");
        sb.append("+========================================================================+\n");
        return sb.toString();
    }

    public void writeTexMacros(String macrosFile) {
        l.info("Writing latex macros to {} ...", macrosFile);
        try {
            FileWriter macrosWriter = new FileWriter(macrosFile);
            // write the number of vertices
            String macroName = binaryName + "numVertices";
            macrosWriter.write("\\DefMacro{" + macroName + "}{\\num{" + Integer.toString(numVertices) + "}}\n");
            // number of edges
            macroName = binaryName + "numEdges";
            macrosWriter.write("\\DefMacro{" + macroName + "}{\\num{" + Integer.toString(numEdges) + "}}\n");
            // number of events
            macroName = binaryName + "numEvents";
            macrosWriter.write("\\DefMacro{" + macroName + "}{\\num{" + Integer.toString(numEvents) + "}}\n");
            // number of low alerts
            macroName = binaryName + "numLowAlerts";
            macrosWriter.write("\\DefMacro{" + macroName + "}{\\num{" + Integer.toString(uniqueLowAlerts.size()) + "}}\n");
            // number of forward edges
            macroName = binaryName + "numForwardEdges";
            macrosWriter.write("\\DefMacro{" + macroName + "}{\\num{" + Integer.toString(uniqueForwardEdges.size()) + "}}\n");
            // number of backward edges
            macroName = binaryName + "numBackwardEdges";
            macrosWriter.write("\\DefMacro{" + macroName + "}{\\num{" + Integer.toString(uniqueBackwardEdges.size()) + "}}\n");
            // number of uncat edges
            macroName = binaryName + "numUncatEdges";
            macrosWriter.write("\\DefMacro{" + macroName + "}{\\num{" + Integer.toString(uniqueUncatEdges.size()) + "}}\n");
            // number of critical alerts
            macroName = binaryName + "numCriticalAlerts";
            macrosWriter.write("\\DefMacro{" + macroName + "}{\\num{" + Integer.toString(numCriticalAlerts) + "}}\n");
            // execution time
            macroName = binaryName + "execTime";
            macrosWriter.write("\\DefMacro{" + macroName + "}{\\num{" + Double.toString(getAnalysisTime_sec()) + "}}\n");
            macrosWriter.close();
        } catch (IOException e) {
            l.error("Could not open file {} to write macros.", macrosFile);
            e.printStackTrace();
        }
        l.info("Macros written to {} ...", macrosFile);
    }

    public void writeTexMacros() {
        String macrosFile = "tex/" + binaryName + ".tex";
        writeTexMacros(macrosFile);
    }
}
