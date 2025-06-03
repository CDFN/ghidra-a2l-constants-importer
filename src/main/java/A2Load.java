// Load A2L into data section of disassembled binary
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



public class A2Load extends GhidraScript {
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
            String name = null;
            Long address = null;
            List<String> tokens = new ArrayList<>();

            for (String rawLine : lines) {
                String line = rawLine.trim();

                if (line.isEmpty() || line.startsWith("\"") || line.startsWith("//") || line.startsWith("/")) {
                    continue;
                }

                String[] parts = line.split("\\s+");
                for (String part : parts) {
                    tokens.add(part);
                }
            }

            if (!tokens.isEmpty()) {
                name = tokens.get(0);
            }

            for (String token : tokens) {
                try {
                    long parsedAddress = parseAddress(token);
                    address = parsedAddress;
                    break;
                } catch (Exception e) {

                }
            }

            if (name != null && address != null) {
                Asap2Parameter param = new Asap2Parameter(name, address);
                addressToParam.put(address, param);
            } else {
                println("Failed to parse CHARACTERISTIC block (name: " + name + ", address: " + address + ")");
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

    public void run() throws Exception {
        File a2lFile = askFile("Select A2L to load", "Load");
        Asap2Parser parser = new Asap2Parser();
        try {
            parser.parse(a2lFile);
            int labelCount = 0;

            for (Asap2Parser.Asap2Parameter p : parser.getAllParameters()) {
                try {
                    var addr = toAddr(p.getAddress());
                    if (currentProgram.getMemory().contains(addr)) {
                        createLabel(addr, p.getName(), true);
                        labelCount++;
                    } else {
                        println("Address not in memory map: " + p.getName() + " @ 0x" +
                                Long.toHexString(p.getAddress()).toUpperCase());
                    }
                } catch (Exception e) {
                    println("Failed to label: " + p.getName() + " @ 0x" +
                            Long.toHexString(p.getAddress()).toUpperCase() + " -> " + e.getMessage());
                }
            }

            println("Total labels added: " + labelCount);
        } catch (IOException e) {
            printerr("Error reading A2L file: " + e.getMessage());
        }
    }
}