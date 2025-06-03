# Ghidra A2L importer

This Ghidra script allows you to load labels from an A2L (ASAP2) file and automatically apply them to memory addresses in a disassembled binary. It is designed to help reverse engineers and automotive firmware analysts by mapping calibration parameters and data variables directly into Ghidra.

It was tested with BMW MEVD17.2.G A2L for TC1797 MCU. It was not tested with other architectures/MCUs/A2Ls. In case of any questions, please open issue.


## 📦 Features

- ✅ Parses CHARACTERISTIC blocks from A2L/ASAP2 files
- ✅ Automatically assigns labels in Ghidra at specified memory addresses
- ✅ Skips symbolic or unresolved addresses safely
- ✅ Logs label creation failures for missing memory or parse issues


## 🚀 Usage

1. Open your disassembled binary in Ghidra.
2. Copy the `A2Load.java` file into your Ghidra scripts directory (usually `~/ghidra_scripts`).
3. Go to `Window` → `Script Manager`.
4. In Ghidra, select the script and click `Run`.
5. Select your `.a2l` file when prompted.
6. After script finishes, you should have labels in your disassembled binary.
