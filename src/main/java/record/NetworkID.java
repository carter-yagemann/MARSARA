package record;


public class NetworkID {

    private static final long serialVersionUID = -431788671179917399L;
    private final String localHost;
    private final String localPort;
    private final String remoteHost;
    private final String remotePort;
    private String protocol = "";

    public NetworkID(String localHost, String localPort,
                     String remoteHost, String remotePort, String protocol) {
        this.localHost = localHost;
        this.localPort = localPort;
        this.remoteHost = remoteHost;
        this.remotePort = remotePort;
        this.protocol = protocol;
    }

    public String getLocalHost() {
        return localHost;
    }

    public String getLocalPort() {
        return localPort;
    }

    public String getRemoteHost() {
        return remoteHost;
    }

    public String getRemotePort() {
        return remotePort;
    }

    public String getProtocol() {
        return protocol;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((remoteHost == null) ? 0 : remoteHost.hashCode());
        result = prime * result + ((remotePort == null) ? 0 : remotePort.hashCode());
        result = prime * result + ((protocol == null) ? 0 : protocol.hashCode());
        result = prime * result + ((localHost == null) ? 0 : localHost.hashCode());
        result = prime * result + ((localPort == null) ? 0 : localPort.hashCode());
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
        NetworkID other = (NetworkID) obj;
        if (remoteHost == null) {
            if (other.remoteHost != null)
                return false;
        } else if (!remoteHost.equals(other.remoteHost))
            return false;
        if (remotePort == null) {
            if (other.remotePort != null)
                return false;
        } else if (!remotePort.equals(other.remotePort))
            return false;
        if (protocol == null) {
            if (other.protocol != null)
                return false;
        } else if (!protocol.equals(other.protocol))
            return false;
        if (localHost == null) {
            if (other.localHost != null)
                return false;
        } else if (!localHost.equals(other.localHost))
            return false;
        if (localPort == null) {
            return other.localPort == null;
        } else return localPort.equals(other.localPort);
    }

    @Override
    public String toString() {
        return "NetworkID [localHost=" + localHost + ", localPort=" + localPort + ", remoteHost="
                + remoteHost + ", remotePort=" + remotePort + ", protocol=" + protocol + "]";
    }

}