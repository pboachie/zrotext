buildscript {
    dependencies {
        constraints {
            // Android build tooling only, never an application dependency.
            classpath("com.google.guava:guava:33.7.2-jre") {
                because("CVE-2026-102554 is fixed in 33.7.2")
            }
            // Build tooling only: the CycloneDX plugin (cyclonedx-core-java) pulls
            // jackson-databind onto this classpath. It is not in any :app configuration.
            classpath("com.fasterxml.jackson.core:jackson-databind:2.23.0") {
                because("CVE-2026-68497, CVE-2026-83557 and CVE-2026-19032 are fixed in 2.22.2")
            }
        }
    }
}
plugins {
    id("com.android.application") version "9.5.1" apply false
    id("org.jetbrains.kotlin.android") version "2.4.21" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.21" apply false
    id("com.google.devtools.ksp") version "2.3.13" apply false
    id("org.cyclonedx.bom") version "3.5.1" apply false
}
