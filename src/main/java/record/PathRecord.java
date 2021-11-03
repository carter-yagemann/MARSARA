package record;

public class PathRecord implements Comparable<PathRecord> {

    /**
     * Value of the name field in the audit log
     */
    private final String path;
    /**
     * Value of the item field in the audit log
     */
    private final int index;
    /**
     * Value of the nametype field in the audit log
     */
    private final String nametype;
    /**
     * Value of the mode field in the audit log
     */
    private final String mode;
    /**
     * Extracted from the mode variable by parsing it with base-8
     */
    private int pathType = 0;
    /**
     * Extracted from the mode variable
     */
    private String permissions = null;

    public PathRecord(int index, String path, String nametype, String mode) {
        this.index = index;
        this.path = path;
        this.nametype = nametype;
        this.mode = mode;
        this.pathType = parsePathType(mode);
        this.permissions = parsePermissions(mode);
    }

    /**
     * Parses the string mode into an integer with base 8
     *
     * @param mode base 8 representation of string
     * @return integer value of mode
     */
    public static int parsePathType(String mode) {
        try {
            return Integer.parseInt(mode, 8);
        } catch (Exception e) {
            return 0;
        }
    }

    /**
     * Returns the last 4 characters in the mode string.
     * If the length of the mode string is less than 4 than pads the
     * remaining zeroes at the beginning of the return value.
     * If the mode argument is null then null returned.
     *
     * @param mode mode string with last 4 characters as permissions
     * @return only the last 4 characters or null
     */
    public static String parsePermissions(String mode) {
        if (mode != null) {
            if (mode.length() >= 4) {
                return mode.substring(mode.length() - 4);
            } else {
                int difference = 4 - mode.length();
                for (int a = 0; a < difference; a++) {
                    mode = "0" + mode;
                }
                return mode;
            }
        }
        return null;
    }

    public String getPermissions() {
        return permissions;
    }

    public int getPathType() {
        return pathType;
    }

    public String getPath() {
        return path;
    }

    public String getNametype() {
        return nametype;
    }

    public int getIndex() {
        return index;
    }

    /**
     * Compares based on index. If the passed object is null then 1 returned always
     */
    @Override
    public int compareTo(PathRecord o) {
        if (o != null) {
            return this.index - o.index;
        }
        return 1;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + index;
        result = prime * result + ((mode == null) ? 0 : mode.hashCode());
        result = prime * result + ((nametype == null) ? 0 : nametype.hashCode());
        result = prime * result + ((path == null) ? 0 : path.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        PathRecord other = (PathRecord) obj;
        if (index != other.index)
            return false;
        if (mode == null) {
            if (other.mode != null)
                return false;
        } else if (!mode.equals(other.mode))
            return false;
        if (nametype == null) {
            if (other.nametype != null)
                return false;
        } else if (!nametype.equals(other.nametype))
            return false;
        if (path == null) {
            return other.path == null;
        } else return path.equals(other.path);
    }

    @Override
    public String toString() {
        return "PathRecord [path=" + path + ", index=" + index + ", nametype=" + nametype + ", mode=" + mode + "]";
    }
}