package dotgraph;

import org.apache.tinkerpop.gremlin.structure.Edge;
import org.apache.tinkerpop.gremlin.structure.Graph;
import utils.Utils;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

public class DotGraph {
    private final HashMap<String, Dotedge> hm_edges = new HashMap<String, Dotedge>();
    private final boolean minimal = false;

    public void addEdge(Dotedge edge) {
        if (!hm_edges.containsKey(edge.getId())) {
            hm_edges.put(edge.getId(), edge);
        }
    }

    public DotGraph() throws IOException {


    }

    public boolean writeToFile(String filePath) {
        try {
            Set<String> writtenNodes = new HashSet<>();
            File file = new File(filePath);
            BufferedWriter output = new BufferedWriter(new FileWriter(file));
            output.write("digraph  {\n");
            output.write("rankdir=LR;\n");
            output.write("ranksep=\"3\";\n");
            output.write("nodesep=\"1\";\n");
            output.write("edge [arrowhead=\"vee\", fontname=\"Arial\"];\n");
            output.write("node [fontname=\"Arial\"];\n");

            for (Dotedge edge : hm_edges.values()) {
                if (edge.getSrcVertex() == null)
                    continue;

                if (!writtenNodes.contains(edge.getSrcVertex().getId())) {
                    writtenNodes.add(edge.getSrcVertex().getId());
                    writeVertex(edge.getSrcVertex(), output);
                }

                if (!writtenNodes.contains(edge.getDstVertex().getId())) {
                    writtenNodes.add(edge.getDstVertex().getId());
                    writeVertex(edge.getDstVertex(), output);
                }

                writeEdge(edge, output);
            }

            output.write("}");
            output.close();
            return true;
        } catch (Exception ex) {
            System.err.println("Error writing dot file: " + ex.getMessage());
            ex.printStackTrace();
            return false;
        }
    }

    private void writeEdge(Dotedge edge, BufferedWriter output) {
        try {
            output.write("\"" + edge.getSrcVertex().getId() + "\"");
            output.write(" -> ");
            output.write("\"" + edge.getDstVertex().getId() + "\" ");
            output.write("[__obj=\"" + edge.getUid() + "\"");

            if (minimal) {
                if (edge.getColor().contains("fire")) {
                    output.write(",penwidth=5,arrowsize=5,weight=5,color=" + edge.getColor() + ",");
                } else {
                    output.write("color=black,");
                }
                output.write("label=\"" + "" + "\",");
            } else {
                output.write("color=" + edge.getColor() + ",");
//                output.write("label=\"" + "" + "\",");
                output.write("label=\"" + edge.getLabel() + "\",");
            }
            output.write("style=" + edge.getStyle() + "];");

            output.write("\n");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void writeVertex(Dotvertex node, BufferedWriter output) {
        try {
            output.write("\"" + node.getId() + "\"");
            if (minimal) {
                output.write("[");
                output.write("label=\"" + "" + "\",");
            } else {
                output.write("[label=\"" + Utils.replaceTrailing(node.getLabel().substring(0, Math.min(700, node.getLabel().length()))) + "\",");
                output.write("color=" + node.getColor() + ",");
            }
            output.write("shape=" + node.getShape() + ",");
            output.write("style=" + node.getStyle() + "];");
            output.write("\n");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public List<String> DotGraphFromTinkerGraph(Graph tinkergraph, boolean pdf, String outputGraph, String pdf_path)
            throws Exception {

        List<String> list = new ArrayList<>();


        List<Edge> list_edges = new ArrayList<>();
        Iterator<Edge> edges = tinkergraph.edges();
        while (edges.hasNext()) {
            list_edges.add(edges.next());
        }
        DotGraphFromEdges(list_edges, outputGraph);
        if (pdf) {
            String dot_graph = "dot -Tpdf " + outputGraph + " -o " + pdf_path;
            Process p3 = Runtime.getRuntime().exec(new String[]{"bash", "-c", dot_graph});
            System.out.println("Writing pdf file " + dot_graph);
        }
        return list;
    }

    public void DotGraphFromEdges(Iterable<Edge> edges, String outputGraph)
            throws Exception {
        hm_edges.clear();
        for (Edge e : edges) {
            Dotedge dotedge = new Dotedge(e);
            this.addEdge(dotedge);
        }
        System.out.println("Size of Dot edges: " + this.hm_edges.size());
        if (!this.writeToFile(outputGraph)) {
            System.err.println("Unable to save dotfile");
        }
    }

}
