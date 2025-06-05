// Load A2L into data section of disassembled binary
//@author CDFN
//@category Processor.DATA
//@keybinding
//@menupath
//@toolbar
//@runtime Java

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;

import java.io.*;
import java.util.*;

public class A2Load extends GhidraScript {
    class Asap2Parser {

        public static class Asap2Parameter {
            private final String name;
            private final long address;
            private final String description;

            public Asap2Parameter(String name, long address, String description) {
                this.name = name;
                this.address = address;
                this.description = description;
            }

            public String getName() {
                return name;
            }

            public long getAddress() {
                return address;
            }

            public String getDescription() {
                return description;
            }

            @Override
            public String toString() {
                return "Asap2Parameter{name='" + name + "', address=0x" +
                        Long.toHexString(address).toUpperCase() + ", description=\"" + description + "\"}";
            }
        }

        private final Map<Long, Asap2Parameter> addressToParam = new HashMap<>();

        public void parse(File file) throws IOException {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(new FileInputStream(file), "Cp1252"))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.startsWith("/begin CHARACTERISTIC")) {
                        List<String> block = new ArrayList<>();
                        block.add(line);
                        while ((line = reader.readLine()) != null) {
                            line = line.trim();
                            block.add(line);
                            if (line.startsWith("/end CHARACTERISTIC")) {
                                break;
                            }
                        }
                        parseCharacteristicBlock(block);
                    } else if (line.startsWith("/begin MEASUREMENT")) {
                        List<String> block = new ArrayList<>();
                        block.add(line);
                        while ((line = reader.readLine()) != null) {
                            line = line.trim();
                            block.add(line);
                            if (line.startsWith("/end MEASUREMENT")) {
                                break;
                            }
                        }
                        parseMeasurementBlock(block);
                    }
                }
            }
        }

        private void parseCharacteristicBlock(List<String> lines) {
            String name = null;
            String description = null;
            Long address = null;
            boolean foundName = false;

            for (String line : lines) {
                line = line.trim();

                if (line.startsWith("\"") && description == null) {
                    description = line.replace("\"", "").trim();
                    continue;
                }

                if (!foundName && !line.isEmpty() && !line.startsWith("/") && !line.startsWith("\"") && !line.startsWith("//")) {
                    name = line.split("\\s+")[0].trim();
                    foundName = true;
                    continue;
                }

                if (address == null && (line.startsWith("0x") || line.matches("^\\d+$"))) {
                    try {
                        address = parseAddress(line);
                    } catch (Exception ignored) {
                    }
                }
            }

            if (name != null && address != null) {
                Asap2Parameter param = new Asap2Parameter(name, address, description);
                addressToParam.put(address, param);
            } else {
                println("Failed to parse CHARACTERISTIC (name=" + name + ", address=" + address + ")");
            }
        }

        private void parseMeasurementBlock(List<String> lines) {
            String name = null;
            String description = null;
            Long address = null;
            boolean foundName = false;

            for (String line : lines) {
                line = line.trim();

                if (line.startsWith("\"") && description == null) {
                    description = line.replace("\"", "").trim();
                    continue;
                }

                if (!foundName && !line.isEmpty() && !line.startsWith("/") && !line.startsWith("\"") && !line.startsWith("//")) {
                    name = line.split("\\s+")[0].trim();
                    foundName = true;
                    continue;
                }

                if (line.startsWith("ECU_ADDRESS")) {
                    String[] parts = line.split("\\s+");
                    if (parts.length >= 2) {
                        try {
                            address = parseAddress(parts[1]);
                        } catch (Exception e) {
                            println("Invalid ECU_ADDRESS: " + parts[1]);
                        }
                    }
                }
            }

            if (name != null && address != null) {
                Asap2Parameter param = new Asap2Parameter(name, address, description);
                addressToParam.put(address, param);
            } else {
                println("Failed to parse MEASUREMENT (name=" + name + ", address=" + address + ")");
            }
        }

        private long parseAddress(String s) {
            s = s.trim();
            if (s.startsWith("0x") || s.startsWith("0X"))
                return Long.parseUnsignedLong(s.substring(2), 16);
            return Long.parseLong(s);
        }

        public Collection<Asap2Parameter> getAllParameters() {
            return addressToParam.values();
        }
    }

    @Override
    public void run() throws Exception {
        File a2lFile = askFile("Select A2L file to load", "Load");
        Asap2Parser parser = new Asap2Parser();
        try {
            parser.parse(a2lFile);
            int labelCount = 0;

            for (Asap2Parser.Asap2Parameter param : parser.getAllParameters()) {
                try {
                    Address address = toAddr(param.getAddress());

                    if (currentProgram.getMemory().contains(address)) {
                        createLabel(address, param.getName(), true);
                        if (param.getDescription() != null && !param.getDescription().isEmpty()) {
                            setEolCommentAtAddress(address, param.getDescription());
                        }
                        labelCount++;
                    } else {
                        println("Address not in memory: " + param.getName() + " @ 0x" +
                                Long.toHexString(param.getAddress()).toUpperCase());
                    }
                } catch (Exception e) {
                    println("Failed to label: " + param.getName() + " @ 0x" +
                            Long.toHexString(param.getAddress()).toUpperCase() + " -> " + e.getMessage());
                }
            }

            println("Total labels added: " + labelCount);

        } catch (IOException e) {
            printerr("Failed to read A2L file: " + e.getMessage());
        }
    }

    private void setEolCommentAtAddress(Address addr, String comment) {
        Listing listing = currentProgram.getListing();
        CodeUnit cu = listing.getCodeUnitAt(addr);
        if (cu != null) {
            cu.setComment(CodeUnit.EOL_COMMENT, comment);
        }
    }
}