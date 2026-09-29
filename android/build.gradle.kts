buildscript {
    dependencies {
        constraints {
            // Build tooling only: the CycloneDX plugin (cyclonedx-core-java) pulls
            // jackson-databind onto this classpath. It is not in any :app configuration.
            classpath("com.fasterxml.jackson.core:jackson-databind:2.22.2") {
                because("CVE-2026-68497, CVE-2026-83557 and CVE-2026-19032 are fixed in 2.22.2")
            }
        }
    }
}
plugins {
    id("com.android.application") version "9.4.1" apply false
    id("org.jetbrains.kotlin.android") version "2.4.20" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.20" apply false
    id("com.google.devtools.ksp") version "2.3.12" apply false
    id("org.cyclonedx.bom") version "3.4.1" apply false
}
