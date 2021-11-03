package record;

public class AddressPort {
    public final String address, port;

    public AddressPort(String address, String port) {
        this.address = address;
        this.port = port;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((address == null) ? 0 : address.hashCode());
        result = prime * result + ((port == null) ? 0 : port.hashCode());
        return result;
    }

    @Override
    public String toString() {
        return "AddressPort{" +
                "address='" + address + '\'' +
                ", port='" + port + '\'' +
                '}';
    }
}