package parsers.jgraph;

import java.text.MessageFormat;
import java.util.Hashtable;

public class ULogNode {
    public Hashtable<String, Object> attributes;
    private final int id;

    public ULogNode(int _id) {
        id = _id;
        attributes = new Hashtable<String, Object>();
    }

    public int getId() {
        return id;
    }

    public Object getAttribute(String key) {
        // get attribute with the give key
        return attributes.get(key);
    }

    public void setAttribute(String key, Object val) {
        if (!attributes.containsKey(key))
            attributes.put(key, val);
    }

    public long getRVA() {
        if (attributes.containsKey("rva")) {
            return ((long) attributes.get("rva"));
        }
        return -1;
    }

    // for debugging
    public String toString() {
        if (attributes.containsKey("val"))
            return MessageFormat.format("< Node: {0} -- {1} > ({2})", id, attributes.get("val"),
                    attributes.get("last_instruction"));
        else
            return MessageFormat.format("< Node: {0} -- null > ({1})", id, attributes.get("last_instruction"));
    }

    // shortcuts to the node's attributes that are useful
    public boolean isStartNode() {
        if (attributes.containsKey("is_start")) {
            return ((boolean) attributes.get("is_start"));
        }
        return false;
    }

    public boolean isEndNode() {
        if (attributes.containsKey("is_end")) {
            return ((boolean) attributes.get("is_end"));
        }
        return false;
    }

    public String getStr() {
        return (String) attributes.get("val");
    }

    public boolean isPhonyNode() {
        if (attributes.containsKey("is_phony")) {
            return ((boolean) attributes.get("is_phony"));
        }
        return false;
    }

    public boolean isLikelyExec() {
        if (attributes.containsKey("is_exec")) {
            return ((boolean) attributes.get("is_exec"));
        }
        return false;
    }

    public boolean isFuncHead() {
        if (attributes.containsKey("is_func_head")) {
            return ((boolean) attributes.get("is_func_head"));
        }
        return false;
    }

    public boolean isFuncOut() {
        if (attributes.containsKey("is_func_out")) {
            return ((boolean) attributes.get("is_func_out"));
        }
        return false;
    }

    public boolean isLoop() {
        if (attributes.containsKey("is_loop")) {
            return (boolean) attributes.get("is_loop");
        }
        return false;
    }

    public boolean isRegex() {
        if (attributes.containsKey("is_regex")) {
            return ((boolean) attributes.get("is_regex"));
        }
        return false;
    }

    public boolean isSyscall() {
        if (attributes.containsKey("is_syscall")) {
            return ((boolean) attributes.get("is_syscall"));
        }
        return false;
    }

    public String getFunction() {
        if (attributes.containsKey("function")) {
            return ((String) attributes.get("function"));
        }
        return "";
    }

    public String getSyscallName() {
        if (attributes.containsKey("syscall_name")) {
            return ((String) attributes.get("syscall_name"));
        }
        return getStr();
    }

    public String getLastInstruction() {
        if (attributes.containsKey("last_instruction")) {
            return ((String) attributes.get("last_instruction"));
        }
        return "";
    }

    // overriding the equality operator
    @Override
    public boolean equals(Object o) {
        if (o == this)
            return true;

        if (!(o instanceof ULogNode))
            return false;

        ULogNode other = (ULogNode) o;
        return id == other.getId();
    }

}
