package tracker;


import com.google.common.collect.Lists;
import org.apache.tinkerpop.gremlin.structure.Direction;
import org.apache.tinkerpop.gremlin.structure.Edge;
import org.apache.tinkerpop.gremlin.structure.Vertex;
import provgraph.NodeProperty;
import utils.Utils;

import java.util.*;

public class Algorithms {

    public Set seen = new HashSet();
    public Stack<Vertex> vertex_stack = new Stack<>();
    public Stack<Edge> edge_stack = new Stack<>();
    public ArrayList<ArrayList<Vertex>> paths = new ArrayList<>();

    public ArrayList<ArrayList<Edge>> backward_edges = new ArrayList<>();
    public ArrayList<ArrayList<Edge>> forward_edges = new ArrayList<>();

    public String getId(Vertex vertex) {
        return vertex.property(NodeProperty.ID.name()).toString();
    }


    public void recordBackwardPath() {
        ArrayList<Edge> path = new ArrayList<>();
        path.addAll(edge_stack);
        backward_edges.add(path);
    }

    public void recordForwardPath() {
        ArrayList<Edge> path = new ArrayList<>();
        ArrayList<Vertex> path_vertices = new ArrayList<>();
        path.addAll(edge_stack);
        path_vertices.addAll(vertex_stack);
        forward_edges.add(path);
        paths.add(path_vertices);
    }


    public ArrayList<ArrayList<Edge>> runBoth(Vertex start_vertex) {

        vertex_stack = new Stack<>();
        edge_stack = new Stack<>();
        runBackwardDFS(start_vertex, 0);

        vertex_stack = new Stack<>();
        edge_stack = new Stack<>();
        runForwardDFS(start_vertex, 0, "2001-03-07T16:45:56.070Z");
        System.out.println("Size of backward edges " + backward_edges.size());
        System.out.println("Size of forward edges " + forward_edges.size());
        backward_edges.addAll(forward_edges);
        return backward_edges;
    }

    public ArrayList<ArrayList<Edge>> runForward(Vertex start_vertex) {
        vertex_stack = new Stack<>();
        edge_stack = new Stack<>();
        runForwardDFS(start_vertex, 0, "2001-03-07T16:45:56.070Z");
        return forward_edges;
    }

    public ArrayList<ArrayList<Edge>> runBackward(Vertex start_vertex) {
        vertex_stack = new Stack<>();
        edge_stack = new Stack<>();
        runBackwardDFS(start_vertex, 0);
        return backward_edges;
    }

    public <T> List<T> getListFromIterator(Iterator<T> iterator) {
        return Lists.newArrayList(iterator);
    }

    public void runBackwardDFS(Vertex start_vertex, int depth) {

        seen.add(getId(start_vertex));
        vertex_stack.push(start_vertex);
        System.out.println("Pushing Backward DFS " + start_vertex + " : " + start_vertex.property(NodeProperty.PATH.name()));
        System.out.println("Pushing Backward DFS " + start_vertex + " : " + start_vertex.property(NodeProperty.ID.name()));

        if (depth == 8) {
            recordBackwardPath();
            vertex_stack.pop();
            if (!edge_stack.isEmpty())
                edge_stack.pop();
            return;
        }
        Iterator<Edge> edges = start_vertex.edges(Direction.IN);
        List<Edge> list = getListFromIterator(edges);
        if (list.size() == 0) {
            //System.out.println("I AM HERE");
            recordBackwardPath();
        } else {
            for (Edge edge : list) {
                Vertex current_vertex = edge.outVertex();
                if (seen.contains(getId(current_vertex)) && vertex_stack.contains(current_vertex)) {
                    // TODO
                } else {
                    edge_stack.push(edge);
                    runBackwardDFS(current_vertex, depth + 1);
                }
            }
        }
        vertex_stack.pop();
        if (!edge_stack.isEmpty())
            edge_stack.pop();
        return;
    }

    public void runForwardDFS(Vertex start_vertex, int depth, String begin_time) {
        seen.add(getId(start_vertex));
        vertex_stack.push(start_vertex);
//        if (start_vertex.property(NodeProperty.PATH.name()).isPresent())
//            System.out.println("Pushing Forward DFS " + start_vertex.property(NodeProperty.PATH.name()).value());
        //System.out.println("Pushing Forward DFS "+ start_vertex + " : " + start_vertex.property(NodeProperty.ID.name()).value());
        if (depth == 12) {
            recordForwardPath();
            vertex_stack.pop();
            if (!edge_stack.isEmpty())
                edge_stack.pop();
            return;
        }
        Iterator<Edge> edges = start_vertex.edges(Direction.OUT);
        //Iterator<Edge> in_edges  =  start_vertex.edges(Direction.IN);
        //edge_stack.addAll(getListFromIterator(in_edges));
        List<Edge> list = Utils.filterForwardEdges(Utils.getListFromIterator(edges), begin_time);
        //List<Edge> list = Utils.filterForwardEdges(getListFromIterator(edges), );
        //List<Edge> list = getListFromIterator(edges);
        if (list.size() == 0) {
            //System.out.println("I AM HERE");
            recordForwardPath();
        } else {
            //System.out.println("My Size is " + list.size());
            for (Edge edge : list) {
                Vertex current_vertex = edge.inVertex();
                String time = Utils.getTime(edge);
                if (seen.contains(getId(current_vertex)) && vertex_stack.contains(current_vertex)) {
                    // TODO
                } else {
                    edge_stack.push(edge);
                    runForwardDFS(current_vertex, depth + 1, time);
                }
            }
        }
        vertex_stack.pop();
        if (!edge_stack.isEmpty())
            edge_stack.pop();
        return;


    }

}
