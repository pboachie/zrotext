import com.google.devtools.ksp.gradle.KspAATask
import org.gradle.api.services.BuildService
import org.gradle.api.services.BuildServiceParameters

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

// BEGIN KSP execution gate (also exercised verbatim by the concurrency fixture).
// KSP 2.3.13 shares a CoreJarFileSystem cache between no-isolation workers.
// https://github.com/google/ksp/issues/3286
abstract class KspExecutionGate : BuildService<BuildServiceParameters.None>

val kspExecutionGate = gradle.sharedServices.registerIfAbsent(
    "zrotextKspExecutionGate", KspExecutionGate::class.java
) {
    maxParallelUsages.set(1)
}
allprojects {
    tasks.withType<KspAATask>().configureEach {
        usesService(kspExecutionGate)
    }
}
// END KSP execution gate.

val verifyKspSerialization = tasks.register<Exec>("verifyKspSerialization") {
    group = "verification"
    description = "Exercise the KSP execution gate with parallel Gradle workers and configuration cache"
    val python = if (System.getProperty("os.name").startsWith("Windows")) "python" else "python3"
    commandLine(python, layout.projectDirectory.file("tools/test_ksp_serialization.py").asFile,
        "--integration", "--gradle-home", requireNotNull(gradle.gradleHomeDir).absolutePath)
}
allprojects {
    tasks.withType<Test>().configureEach {
        dependsOn(verifyKspSerialization)
    }
}
