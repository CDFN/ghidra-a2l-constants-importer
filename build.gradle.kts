plugins {
    id("java")
}

group = "org.example"
version = "1.0-SNAPSHOT"

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}

var ghidraInstallDir: String? = null

if (System.getenv().containsKey("GHIDRA_INSTALL_DIR")) {
    ghidraInstallDir = System.getenv()["GHIDRA_INSTALL_DIR"]
}

if (ghidraInstallDir != null) {
    apply {
        from(File(ghidraInstallDir!!).canonicalPath + "/support/buildExtension.gradle")
    }
}
tasks.test {
    useJUnitPlatform()
}