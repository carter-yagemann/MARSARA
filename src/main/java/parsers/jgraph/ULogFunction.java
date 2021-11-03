package parsers.jgraph;

import java.util.LinkedList;
import java.util.List;

public class ULogFunction {
    private final String name;
    private final List<ULogNode> nodes;
    private final List<ULogNode> retNodes;
    private final List<ULogNode> headNodes;

    ULogFunction(String name) {
        this.name = name;
        this.nodes = new LinkedList<>();
        this.retNodes = new LinkedList<>();
        this.headNodes = new LinkedList<>();
    }

    public String getName() {
        return name;
    }

    public List<ULogNode> Nodes() {
        return this.nodes;
    }

    public List<ULogNode> Returns() {
        return this.retNodes;
    }

    public List<ULogNode> Heads() {
        return this.headNodes;
    }

    public void AddNode(ULogNode node) {
        nodes.add(node);
        if (node.isFuncHead())
            headNodes.add(node);
        if (node.isFuncOut())
            retNodes.add(node);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof ULogFunction) {
            ULogFunction fn = (ULogFunction) obj;
            return name.equals(fn.getName());
        }
        return false;
    }
}
