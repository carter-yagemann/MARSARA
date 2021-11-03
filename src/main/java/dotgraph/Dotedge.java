package dotgraph;


import event.GraphEventType;
import org.apache.tinkerpop.gremlin.structure.Edge;
import provgraph.EdgeProperty;
import utils.Utils;

public class Dotedge {
    private final Dotvertex srcVertex;
    private final Dotvertex dstVertex;
    private String label = "UndefinedLabel";
    private String style = "solid";
    private String color = "dodgerblue";
    private String id;
    private final String uid;

    public Dotedge(Edge edge) throws Exception {
        GraphEventType currentEventType = GraphEventType.valueOf(edge.property(EdgeProperty.EVENTTYPE.name()).value().toString());
        uid = Utils.getId(edge);
        String begin_time = "";
        String counter = "";

        if (edge.property(EdgeProperty.BEGIN_TIME.name()).isPresent())
            begin_time = edge.property(EdgeProperty.BEGIN_TIME.name()).value().toString();

        if (edge.property(EdgeProperty.COUNTER.name()).isPresent())
            counter = edge.property(EdgeProperty.COUNTER.name()).value().toString();

//        String time = begin_time.split(".")[0];
//        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd:HH:mm:ss");
//
//        begin_time = dateFormat.parse(time).toString();
        label = currentEventType.name() + " " + begin_time + "," + counter + ", " + edge.property(EdgeProperty.SYSCALL.name()).value().toString();
        srcVertex = new Dotvertex(edge.outVertex());
        dstVertex = new Dotvertex(edge.inVertex());
        id = srcVertex.getId() + dstVertex.getId() + currentEventType.toString();
        if (currentEventType.toString().contains("PROCESS")) {
            color = "red";
        } else if (currentEventType.toString().contains("FILE")) {
            color = "black";
        } else if (currentEventType.toString().contains("NETWORK")) {
            color = "gold";
        } else if (currentEventType.toString().contains("DUMMY")) {
            color = "springgreen";
            style = "dashed";
        }
    }

    public Dotvertex getSrcVertex() {
        return srcVertex;
    }

    public Dotvertex getDstVertex() {
        return dstVertex;
    }

    public String getLabel() {
        return label;
    }

    public String getStyle() {
        return style;
    }

    public String getColor() {
        return color;
    }

    public void setColor(String color) {
        this.color = color;
    }

    public String getId() {
        return id;
    }

    public String getUid() {
        return uid;
    }

    public void setId(String id) {
        this.id = id;
    }

}