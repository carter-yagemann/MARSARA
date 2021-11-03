package dotgraph;


import org.apache.tinkerpop.gremlin.structure.Vertex;
import provgraph.NodeProperty;
import record.ObjectType;
import utils.Utils;

public class Dotvertex {

    private String label = "UndefinedLabel";
    private String shape = "box";
    private String color = "red";
    private final String style = "filled";
    private String id = "NULL";

    public Dotvertex(Vertex vertex) throws Exception {
        ObjectType vertexType = ObjectType.valueOf(vertex.property(NodeProperty.OBJECT_TYPE.name()).value().toString());
        StringBuilder sb = new StringBuilder();
        if (vertexType == ObjectType.FILE) {
            sb.append("Path: " + Utils.escapeFilePath(vertex.property(NodeProperty.PATH.name()).value().toString()) + "\\n");
            //sb.append("type_id: " + vertex.property(NodeProperty.TYPE_ID.name()).value().toString() + "\\n");
            //sb.append("attributes_id: " + vertex.property(NodeProperty.ATTRIBUTES_ID.name()).value().toString() + "\\n");
            color = "lightpink";
            shape = "oval";
        } else if (vertexType == ObjectType.MODULE) {
            sb.append("Path: " + Utils.escapeFilePath(vertex.property(NodeProperty.PATH.name()).value().toString()) + "\\n");
            color = "limegreen";
            shape = "oval";
        } else if (vertexType == ObjectType.PROCESS) {
            sb.append("PID: " + vertex.property(NodeProperty.PID.name()).value() + "\\n");
            sb.append("PPID: " + vertex.property(NodeProperty.PPID.name()).value() + "\\n");
            sb.append("name: " + vertex.property(NodeProperty.NAME.name()).value() + "\\n");
//            sb.append( "SessionID: " + vertex.property(NodeProperty.SESSION_ID.name()).value() + "\\n");
            sb.append("Path: " + Utils.escapeFilePath(vertex.property(NodeProperty.PATH.name()).value().toString()) + "\\n");
//            sb.append( "NPath: " + Utils.escapeFilePath(vertex.property(NodeProperty.NORMALIZED_PATH.name()).value().toString()) + "\\n");
            sb.append("CMDLINE: " + Utils.escapeFilePath(vertex.property(NodeProperty.CMD_LINE.name()).value().toString()) + "\\n");
            String terminate = vertex.property(NodeProperty.TERMINATE.name()).value().toString();
            if (terminate.contains("TRUE"))
                color = "red";
            else
                color = "deepskyblue";
            shape = "box";
        } else if (vertexType == ObjectType.NETWORK) {
            sb.append("src: " + vertex.property(NodeProperty.SRC_IP.name()).value() + ":" + vertex.property(NodeProperty.SRC_PORT.name()).value() + "\\n");
            sb.append("dst: " + vertex.property(NodeProperty.DST_IP.name()).value() + ":" + vertex.property(NodeProperty.DST_PORT.name()).value() + "\\n");
            sb.append("protocol: " + vertex.property(NodeProperty.PROTOCOL.name()).value() + "");
            //sb.append( "proto: " + vertex.property(NodeProperty.DIRECTION.name()).value() + ":" + vertex.property(NodeProperty.PROTOCOL.name()).value() + "\\n");
            color = "khaki";
            shape = "diamond";
        } else if (vertexType == ObjectType.DUMMY) {
            sb.append("DUMMY ROOT" + "\\n");
            color = "red";
            shape = "tripleoctagon";
        } else {
            return;
        }
        if (vertex.property(NodeProperty.HOP_COUNT.name()).isPresent())
            sb.append("HC: " + vertex.property(NodeProperty.HOP_COUNT.name()).value() + "\\n");
        id = vertex.property(NodeProperty.ID.name()).value().toString();
        label = sb.toString();
    }

    public String getLabel() {
        return label;
    }

    public String getShape() {
        return shape;
    }

    public String getColor() {
        return color;
    }

    public String getStyle() {
        return style;
    }

    public String getId() {
        return id;
    }
}
