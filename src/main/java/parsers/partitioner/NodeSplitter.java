package parsers.partitioner;

/*
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import spade.core.AbstractEdge;
import spade.core.AbstractVertex;
import spade.core.Graph;
import spade.edge.cdm.SimpleEdge;
import spade.reporter.audit.AuditEventReader;
import spade.reporter.audit.OPMConstants;
import spade.storage.wlog.jparser.JParser;
import spade.vertex.opm.Process;

import java.util.*;

public class NodeSplitter {
    private static final Logger l = LogManager.getLogger(NodeSplitter.class.getName());

    private Graph g;
    private Map<String,String> pidVertexMap = null;
    private String splitLogKeyword = "";

    public NodeSplitter(Graph g){
        this.g = g;
        this.pidVertexMap = GraphWlog.scanPidNodes(g);
    }

    public Graph getGraph() {
        return g;
    }

    public void partitionExecution(String process, JParser jParser, String jparserStartString){
        for(Map.Entry<String,String> entry : pidVertexMap.entrySet()){
            String vertexhash = entry.getValue();
            AbstractVertex processNode = g.getVertex(vertexhash);

            if(processNode.getAnnotation(ConstantVals.ann_name).equalsIgnoreCase(process)){
                l.info("Found vertex with procname "+processNode.getAnnotation(ConstantVals.ann_name)+" "
                        +processNode.getAnnotation(ConstantVals.ann_pid));

                JParser parserForPid = new JParser(jParser.getInFile(), jParser.getLogFile(), jParser.isWatch(), jParser.getExprMatcher(),jParser.getLookahead());

                splitNode(processNode, entry.getValue(), parserForPid, jparserStartString);  // static analysis log split
            }
        }

    }

    private void splitNode(AbstractVertex procnode, String processhash, JParser jParser, String jparserStartString){
        int count = 1;
        AbstractVertex lastNewNode = procnode;

        // get children of the process (application logs are grafted as child nodes)
        Graph childSubgraph = g.getChildren(processhash);

        // The application logs are in the child subgraph
        Set<AbstractVertex> vertices = childSubgraph.vertexSet();

        // remove the process node itself
        vertices.remove(procnode);

        // remove nodes that are not application logs
        Iterator<AbstractVertex> itr = vertices.iterator();
        while(itr.hasNext()){
            AbstractVertex v = itr.next();
            if(!v.getAnnotation(ConstantVals.ann_type).equalsIgnoreCase(ConstantVals.ann_type_app))
                itr.remove();
        }


        // Sort the application logs according to event id
        // Find paths using parseAndMatch
        // Find the partitioning unit
        AbstractVertex[] vertexArr = buildVertexArray(vertices);
        Arrays.sort(vertexArr, Comparator.comparing(a -> Long.valueOf(a.getAnnotation(AuditEventReader.EVENT_ID))));
        //printArray(vertexArr);

        List<String> logList = new ArrayList<>();
        for(int i=0; i< vertexArr.length; i++){
            logList.add(vertexArr[i].getAnnotation(ConstantVals.ann_log));
        }
        //l.debug(logList);
        jParser.parseAndMatch(jparserStartString,logList);
        boolean didJparserFail = jParser.noPaths();


        for(int i =0 ; i < vertexArr.length; i++){
            AbstractVertex v = vertexArr[i];

            String logstring = v.getAnnotation(ConstantVals.ann_log);
            String splitEventid = v.getAnnotation(AuditEventReader.EVENT_ID);


            JParser.State state = null;
            //l.debug("id={}, log={} ",i,logstring);
            //l.debug("State is: "+jParser.GetStateForLog(i));
            boolean isPartitioningUnit = (state=jParser.GetStateForLog(i))!=null?state.IsLikelyNewExecutionUnit():false;


            if(didJparserFail || isPartitioningUnit){
                l.debug("Going to split node now: "+logstring);
                if(splitLogKeyword==null || splitLogKeyword.isEmpty()){
                    splitLogKeyword = logstring.split("\\s+")[0];
                }

                // If splitpoint is at the beginning of the array no need to parition
                if(i==0){
                    continue;
                }

                AbstractVertex newNode = new Process();
                newNode.addAnnotations(procnode.getAnnotations());
                newNode.addAnnotation(ConstantVals.ann_name,procnode.getAnnotation(ConstantVals.ann_name));
                newNode.addAnnotation(ConstantVals.ann_compnum, String.valueOf(count++));
                g.putVertex(newNode);

                //create an edge form the original node to this one
                g.putEdge(new SimpleEdge(newNode,lastNewNode));


                // move existing edges till splitpoint to the new node
                boolean update = moveExistingEdges(splitEventid,newNode,processhash,g);
                lastNewNode = newNode;

            }
        }

    }


    private boolean splitRequired(String splitid, String processhash, Graph g) {
        boolean require = false;

        long splitEventID = Long.parseLong(splitid);

        // Update parent of child edges
        Set<AbstractEdge> childEdges = g.getChildren(processhash).edgeSet();
        for(AbstractEdge e : childEdges){
            String id = e.getAnnotation(OPMConstants.EDGE_EVENT_ID);
            if(id == null || id.isEmpty())
                continue;

            long idval = Long.parseLong(id);
            if(idval >= splitEventID){
                require = true;
            }
        }

        // Update child of parent edges
        Set<AbstractEdge> parentEdges = g.getParents(processhash).edgeSet();
        for(AbstractEdge e : parentEdges){
            String id = e.getAnnotation(OPMConstants.EDGE_EVENT_ID);
            if(id == null || id.isEmpty())
                continue;

            long idval = Long.parseLong(id);
            if(idval >= splitEventID){
                require = true;
            }
        }
        return require;
    }

    private void printEdges(AbstractVertex newNode, long splitEventid, boolean b) {
        System.out.println("printing data for "+newNode);
        Graph subgraph = g.getChildren(newNode.bigHashCode());

        for(AbstractEdge e : subgraph.edgeSet()){
            long val = Long.parseLong(e.getChildVertex().getAnnotation("eventid"));
            if(b) {
                if(val < splitEventid)
                    System.out.println("Wrong "+val);
            }
            else{
                if(val >= splitEventid)
                    System.out.println("Wrong "+val);
            }
        }

        Graph subgraph1 = g.getParents(newNode.bigHashCode());
        for(AbstractEdge e : subgraph1.edgeSet()){
            long val = Long.parseLong(e.getAnnotation(OPMConstants.EDGE_EVENT_ID));
            if(b) {
                if(val < splitEventid)
                    System.out.println("Wrong "+val);
            }
            else{
                if(val >= splitEventid)
                    System.out.println("Wrong "+val);
            }
        }
    }

    private boolean moveExistingEdges(String annotation, AbstractVertex newNode, String processhash, Graph g) {

        boolean changed = false;

        l.debug("Splitting at "+annotation);
        long splitEventID = Long.parseLong(annotation);

        // Update parent of child edges
        Set<AbstractEdge> childEdges = g.getChildren(processhash).edgeSet();
        for(AbstractEdge e : childEdges){
            String id = e.getAnnotation(OPMConstants.EDGE_EVENT_ID);
            if(id == null || id.isEmpty())
                continue;

            long idval = Long.parseLong(id);
            if(idval < splitEventID){
                l.debug("Moving edge "+id);
                g.updateParent(e,newNode);
                changed = true;
            }
        }

        // Update child of parent edges
        Set<AbstractEdge> parentEdges = g.getParents(processhash).edgeSet();
        for(AbstractEdge e : parentEdges){
            String id = e.getAnnotation(OPMConstants.EDGE_EVENT_ID);
            //System.out.println("Found edge "+id);
            if(id == null || id.isEmpty())
                continue;

            long idval = Long.parseLong(id);
            if(idval < splitEventID){
                l.debug("Moving edge "+id);
                g.updateChild(e,newNode);
                changed = true;
            }
        }
        return changed;

    }

    private AbstractVertex[] buildVertexArray(Set<AbstractVertex> vertices) {
        int i=0;
        AbstractVertex[] arr = new AbstractVertex[vertices.size()];
        for(AbstractVertex v : vertices)
            arr[i++] = v;
        return arr;
    }

    private void printArray(AbstractVertex[] vertexArr) {
        for(int i=0; i<vertexArr.length;i++)
            System.out.println(vertexArr[i].toString());
    }

    public String getLogKeyWord() {
        return splitLogKeyword;
    }
}

/*
*  private void splitNode(AbstractVertex procnode, String processhash, String logMsg) {

        int count = 1;
        AbstractVertex lastNewNode = procnode;

        // get children of the process (application logs are grafted as child nodes)
        Graph childSubgraph = g.getChildren(processhash);

        // The application logs are in the child subgraph
        Set<AbstractVertex> vertices = childSubgraph.vertexSet();

        // remove the process node itself
        vertices.remove(procnode);

        // remove nodes that are not application logs
        Iterator<AbstractVertex> itr = vertices.iterator();
        while(itr.hasNext()){
            AbstractVertex v = itr.next();
            if(!v.getAnnotation(ConstantVals.ann_type).equalsIgnoreCase(ConstantVals.ann_type_app))
                itr.remove();
        }


        AbstractVertex[] vertexArr = buildVertexArray(vertices);
        Arrays.sort(vertexArr, Comparator.comparing(a -> Long.valueOf(a.getAnnotation(AuditEventReader.EVENT_ID))));
        //printArray(vertexArr);


        for(int i =0 ; i < vertexArr.length; i++){
            AbstractVertex v = vertexArr[i];

            String logstring = v.getAnnotation(ConstantVals.ann_log);
            String splitEventid = v.getAnnotation(AuditEventReader.EVENT_ID);

            // if the log msg is contained in the applog node then split the original procnode
            if(logstring.toLowerCase().contains(logMsg.toLowerCase())){

                System.out.println("Going to split node now");


                // If splitpoint is at the end of the array handle that
                if(i==vertexArr.length-1){
                    if(!splitRequired(splitEventid,processhash,g))
                        continue;
                    System.out.println("Split true "+splitEventid);
                }

                AbstractVertex newNode = new Process();
                newNode.addAnnotations(procnode.getAnnotations());
                newNode.addAnnotation(ConstantVals.ann_name,procnode.getAnnotation(ConstantVals.ann_name));
                newNode.addAnnotation(ConstantVals.ann_compnum, String.valueOf(count++));
                g.putVertex(newNode);

                //create an edge form the original node to this one
                g.putEdge(new SimpleEdge(newNode,lastNewNode));


                // move existing edges till splitpoint to the new node
                boolean update = moveExistingEdges(splitEventid,newNode,processhash,g);
                lastNewNode = newNode;

            }
        }
    }
*/
