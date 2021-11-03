package parsers.jgraph;

import java.text.MessageFormat;

public class ULogLink {
    public ULogNode src;
    public ULogNode dst;
    private boolean is_shadow; //! mark the link as shadow link added at runtime.

    public ULogLink(ULogNode src, ULogNode dst) {
        this.src = src;
        this.dst = dst;
        this.is_shadow = false;
    }

    public boolean isShadow() {
        return is_shadow;
    }

    public void markAsShadow() {
        is_shadow = true;
    }

    public String toString() {
        return MessageFormat.format("{0} --> {1} [{2}]", src, dst, is_shadow);
    }
}
