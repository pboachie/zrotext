import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.TaskAction
import org.cyclonedx.gradle.CyclonedxDirectTask
import org.cyclonedx.model.Component

abstract class WriteReleaseSourceCommit : DefaultTask() {
    @get:Input abstract val sourceCommit: Property<String>
    @get:OutputDirectory abstract val outputDir: DirectoryProperty

    @TaskAction fun write() {
        val commit = sourceCommit.get()
        require(Regex("[0-9a-f]{40}").matches(commit)) { "A full source commit SHA is required" }
        outputDir.get().file("zrotext-source-commit.txt").asFile.apply {
            parentFile.mkdirs()
            writeText("$commit\n", Charsets.US_ASCII)
        }
    }
}

val writeReleaseSourceCommit = tasks.register<WriteReleaseSourceCommit>("writeReleaseSourceCommit") {
    sourceCommit.set(providers.gradleProperty("zrotextSourceCommit"))
    outputDir.set(layout.buildDirectory.dir("generated/releaseSourceAssets"))
}

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.google.devtools.ksp")
    id("org.cyclonedx.bom")
}

tasks.named<CyclonedxDirectTask>("cyclonedxDirectBom") {
    // This inventory describes dependencies resolved for the shipped release APK.
    includeConfigs = listOf("releaseRuntimeClasspath")
    testConfigs = emptyList()
    includeBuildEnvironment = false
    projectType = Component.Type.APPLICATION
}

android {
    namespace = "org.zrotext.gateway"
    compileSdk = 37

    defaultConfig {
        applicationId = "org.zrotext.gateway"
        minSdk = 28
        targetSdk = 36
        versionCode = 7
        versionName = "0.1.6-m1-inbound-metadata"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
    }
}

androidComponents {
    onVariants(selector().withBuildType("release")) { variant ->
        variant.sources.assets?.addGeneratedSourceDirectory(
            writeReleaseSourceCommit, WriteReleaseSourceCommit::outputDir
        )
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencyLocking {
    lockAllConfigurations()
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2025.09.00"))
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("androidx.core:core-ktx:1.19.0")
    implementation("androidx.room:room-runtime:2.8.5")
    ksp("androidx.room:room-compiler:2.8.5")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.16.1")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    // Dormant draft-02 provider probe only; no Tink code enters the release runtime.
    androidTestImplementation("com.google.crypto.tink:tink:1.23.0")

    // These constraints affect local unit tests and AGP's lint tools. None of
    // these libraries is present in the app's release runtime classpath.
    constraints {
        testImplementation("org.bouncycastle:bcprov-jdk18on:1.86")
        add("androidLintTool", "org.bouncycastle:bcprov-jdk18on:1.86")
        add("androidLintTool", "org.bouncycastle:bcpkix-jdk18on:1.86")
        add("androidLintTool", "org.bouncycastle:bcutil-jdk18on:1.86")
        add("androidLintTool", "org.apache.commons:commons-lang3:3.18.0")
        add("androidLintTool", "org.apache.httpcomponents:httpclient:4.5.14")
    }
}
