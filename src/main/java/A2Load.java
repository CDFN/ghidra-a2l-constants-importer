//Load A2L into data section of disassembled binary
//@author CDFN
//@category Processor.DATA
//@keybinding 
//@menupath 
//@toolbar 
//@runtime Java

import ghidra.app.script.GhidraScript;

import java.io.*;
import java.util.*;
import java.io.File;

class Asap2Parser {

    public static class Asap2Parameter {
        private final String name;
        private final long address;

        public Asap2Parameter(String name, long address) {
            this.name = name;
            this.address = address;
        }

        public String getName() {
            return name;
        }

        public long getAddress() {
            return address;
        }

        @Override
        public String toString() {
            return "Asap2Parameter{name='" + name + "', address=0x" +
                    Long.toHexString(address).toUpperCase() + "}";
        }
    }

    private final Map<Long, Asap2Parameter> addressToParam = new HashMap<>();

    public void parse(File file) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;

            while ((line = reader.readLine()) != null) {
                line = line.trim();

                if (line.startsWith("/begin CHARACTERISTIC")) {
                    List<String> buffer = new ArrayList<>();
                    buffer.add(line);

                    while ((line = reader.readLine()) != null) {
                        buffer.add(line.trim());
                        if (line.trim().startsWith("/end CHARACTERISTIC")) {
                            break;
                        }
                    }

                    parseCharacteristicBlock(buffer);
                }
            }
        }
    }

    private void parseCharacteristicBlock(List<String> lines) {
        if (lines.size() < 3) return;

        String name = null;

        for (int i = 1; i < lines.size(); i++) {
            String l = lines.get(i).trim();
            if (l.isEmpty()) continue;
            if (l.startsWith("\"")) continue;
            if (l.startsWith("//")) continue; //

            name = l;
            break;
        }

        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);

            if (line.equals("VALUE") && i + 1 < lines.size()) {
                String addressLine = lines.get(i + 1).trim();
                try {
                    long address = parseAddress(addressLine);
                    Asap2Parameter param = new Asap2Parameter(name, address);
                    addressToParam.put(address, param);
                } catch (NumberFormatException e) {
                    System.err.println("Incorrect address : " + addressLine);
                }
                break;
            }
        }
    }

    private long parseAddress(String s) {
        s = s.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) {
            return Long.parseUnsignedLong(s.substring(2), 16);
        } else {
            return Long.parseLong(s);
        }
    }

    public Asap2Parameter findByAddress(long address) {
        return addressToParam.get(address);
    }

    public Collection<Asap2Parameter> getAllParameters() {
        return addressToParam.values();
    }
}

public class A2Load extends GhidraScript {


    public void run() throws Exception {
        File a2lFile = askFile("Select A2L to load", "Load");
        Asap2Parser parser = new Asap2Parser();

        try {
            parser.parse(a2lFile);

            for (Asap2Parser.Asap2Parameter p : parser.getAllParameters()) {
                var address = getAddressFactory().getAddress(Long.toHexString(p.getAddress()));
                var data = getDataAt(address);

                if (data != null) {
                    String dataLabel = " (" + data.getLabel() + ")";
                    createLabel(address, p.getName(), true);
                    println("Added label: " + p.getName() + ": " + Long.toHexString(p.getAddress()) + dataLabel);

                }
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
