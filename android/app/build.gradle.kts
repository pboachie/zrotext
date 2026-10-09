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

// Explicit, isolated debug packaging only. Never install it over the gateway.
val isolatedConversationProbe = providers.gradleProperty("isolatedConversationProbe").orNull == "true"
val isolatedPreparationProbe = providers.gradleProperty("isolatedPreparationProbe").orNull == "true"
require(!(isolatedConversationProbe && isolatedPreparationProbe)) { "Only one isolated probe may be selected" }
val conversationProbeFixtures = if (isolatedConversationProbe) tasks.register<Sync>("conversationProbeFixtures") {
    from("src/test/java") { include("**/ConversationSimulatorFixture.kt") }
    into(layout.buildDirectory.dir("generated/conversationProbeFixtures"))
} else null
val preparationProbeFixtures = if (isolatedPreparationProbe) tasks.register<Sync>("preparationProbeFixtures") {
    from("src/androidTest/java") { include("**/SealedPreparationDeviceSample.kt") }
    from("src/androidTest/java") { include("**/WolfHpkeKeystoreBridgeDeviceTest.kt") }
    from("src/sharedTest/java") { include("**/PreparationFixture.kt") }
    into(layout.buildDirectory.dir("generated/preparationProbeFixtures"))
} else null

val mmsSpikeAllowlist = providers.gradleProperty("zrotextMmsSpikeAllowlist").orNull.orEmpty()
require(Regex("[+0-9,]*").matches(mmsSpikeAllowlist)) {
    "zrotextMmsSpikeAllowlist must be comma-separated +E.164 numbers"
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
    // Same NDK the owner-custody native build and the CI images pin.
    ndkVersion = "28.2.13676358"

    defaultConfig {
        applicationId = "org.zrotext.gateway"
        minSdk = 28
        targetSdk = 36
        versionCode = 12
        versionName = "0.1.7-rc.2"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        if (isolatedConversationProbe) {
            applicationId = "org.zrotext.gateway.conversationprobe"
            testApplicationId = "org.zrotext.gateway.conversationprobe.test"
        }
        if (isolatedPreparationProbe) {
            applicationId = "org.zrotext.gateway.preparationprobe"
            testApplicationId = "org.zrotext.gateway.preparationprobe.test"
            testInstrumentationRunner = "org.zrotext.gateway.PreparationProbeRunner"
        }
    }

    // wolfSSL cryptocb-only HPKE receiver bridge (see src/main/cpp/CMakeLists.txt
    // and user_settings.h). Pure C, no STL, all four ABIs like the custody lib.
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
    buildTypes {
        release {
            // R8 removes unused code and resources from the release APK. The
            // libraries ship their own keep rules; proguard-rules.pro adds ours.
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
        debug {
            // MMS spike (#438) recipients, set only by whoever builds the debug APK:
            // -PzrotextMmsSpikeAllowlist=+E164[,+E164]. Empty (the default) refuses all.
            buildConfigField("String", "MMS_SPIKE_ALLOWLIST", "\"$mmsSpikeAllowlist\"")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    testOptions {
        // Render the real Material fields and semantics in JVM accessibility tests.
        unitTests.isIncludeAndroidResources = true
        // Robolectric 4.17 reads raw FileDescriptor internals through
        // jdk.internal.access, which JDK 17+ does not export to test code.
        // Only this package is opened; see robolectric.org/getting-started.
        unitTests.all {
            it.jvmArgs("--add-opens=java.base/jdk.internal.access=ALL-UNNAMED")
            // Preserve the actual native failure cause rather than only its source line.
            it.testLogging.exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
            // Keep native JNI registration isolated between mixed-SDK test classes.
            it.forkEvery = 1
            if (providers.gradleProperty("composedRootFixture").orNull == "true") {
                it.systemProperty("zrotext.composedRootRequired", "true")
                it.testLogging.showStandardStreams = true
            }
        }
    }
    // Package the locally built typed custodian in the ordinary gateway too.
    sourceSets.getByName("main").jniLibs.srcDir(layout.buildDirectory.dir("generated/ownerCustodyJniLibs").get().asFile)

    // The same signature corpus runs in CI's JVM suite and on an Android device.
    for (testSource in listOf("test", "androidTest")) {
        sourceSets.getByName(testSource) {
            java.srcDir("src/sharedTest/java")
            resources.srcDir("src/sharedTest/resources")
            resources.srcDir("../../protocol/v1/vectors")
            // Reuse the exact independent fixtures consumed by the Rust/TypeScript clients.
            resources.srcDir("../../sdk/typescript/test/vectors")
        }
    }
    if (isolatedConversationProbe) {
        sourceSets.getByName("main") {
            manifest.srcFile("src/conversationProbe/AndroidManifest.xml")
            java.srcDir("src/conversationProbe/java")
        }
        sourceSets.getByName("debug").manifest.srcFile("src/conversationProbe/DebugAndroidManifest.xml")
        sourceSets.getByName("androidTest") {
            manifest.srcFile("src/conversationProbeTest/AndroidManifest.xml")
            java.setSrcDirs(listOf("src/conversationProbeTest/java", layout.buildDirectory.dir("generated/conversationProbeFixtures")))
        }
    }
    if (isolatedPreparationProbe) {
        sourceSets.getByName("main").manifest.srcFile("src/preparationProbe/AndroidManifest.xml")
        // The probe APK must declare no components, so it skips the debug MMS spike manifest.
        sourceSets.getByName("debug").manifest.srcFile("src/preparationProbe/DebugAndroidManifest.xml")
        sourceSets.getByName("androidTest") {
            manifest.srcFile("src/preparationProbeTest/AndroidManifest.xml")
            java.setSrcDirs(listOf("src/preparationProbeTest/java", layout.buildDirectory.dir("generated/preparationProbeFixtures")))
        }
    }
}

if (isolatedPreparationProbe) tasks.matching { it.name == "preDebugAndroidTestBuild" }.configureEach {
    dependsOn(checkNotNull(preparationProbeFixtures))
}

if (isolatedConversationProbe) tasks.matching { it.name == "preDebugAndroidTestBuild" }.configureEach {
    dependsOn(checkNotNull(conversationProbeFixtures))
}

androidComponents {
    beforeVariants { if ((isolatedPreparationProbe || isolatedConversationProbe) && it.buildType != "debug") it.enable = false }
    onVariants(selector().withBuildType("release")) { variant ->
        variant.sources.assets?.addGeneratedSourceDirectory(
            writeReleaseSourceCommit, WriteReleaseSourceCommit::outputDir
        )
    }
}


// Build from reviewed source for every ordinary APK; never silently package an
// unavailable or old signer. This is build-host tooling, not an owner desktop step.
val buildAndroidOwnerCustodyNative = tasks.register<Exec>("buildAndroidOwnerCustodyNative") {
    val repoDir = rootProject.projectDir.parentFile
    workingDir(repoDir)
    inputs.files(fileTree(repoDir.resolve("crates/android-owner-custody")) { include("**/*.rs", "Cargo.toml") })
    inputs.files(fileTree(repoDir.resolve("crates/root-material")) { include("**/*.rs", "Cargo.toml") })
    inputs.files(repoDir.resolve("Cargo.toml"), repoDir.resolve("Cargo.lock"),
        repoDir.resolve("rust-toolchain.toml"), repoDir.resolve("scripts/build_android_owner_custody.py"))
    outputs.dir(layout.buildDirectory.dir("generated/ownerCustodyJniLibs"))
    // Cargo checks the actual pinned toolchain/NDK/linker inputs on every build.
    outputs.upToDateWhen { false }
    val python = providers.gradleProperty("ownerCustodyPython")
        .orElse(if (System.getProperty("os.name").startsWith("Windows")) "python" else "python3")
    val ndk = providers.gradleProperty("ownerCustodyNdk")
        // Hosted images may advertise an older preinstalled NDK in their environment.
        // Default to the reviewed SDK installation; explicit operator overrides stay explicit.
        .orElse(androidComponents.sdkComponents.sdkDirectory.map { it.asFile.resolve("ndk/28.2.13676358").absolutePath })
    // Resolve public build arguments during configuration: an execution closure
    // capturing the Kotlin script cannot be saved by the configuration cache.
    val command = mutableListOf(python.get(), "scripts/build_android_owner_custody.py", "--ndk", ndk.get(),
        "--output", layout.buildDirectory.dir("generated/ownerCustodyJniLibs").get().asFile.absolutePath)
    providers.gradleProperty("ownerCustodyTargetDir").orNull?.let { command.addAll(listOf("--target-dir", it)) }
    commandLine(command)
}
tasks.named("preBuild").configure { dependsOn(buildAndroidOwnerCustodyNative) }

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencyLocking {
    lockAllConfigurations()
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("com.squareup.okhttp3:okhttp:5.5.0")
    implementation("androidx.core:core-ktx:1.19.1")
    implementation("com.google.android.gms:play-services-code-scanner:16.1.0")
    constraints {
        implementation("androidx.fragment:fragment:1.8.9") {
            because("Scanner transitive Fragment must support the existing ActivityResult APIs")
        }
    }
    implementation("androidx.room:room-runtime:2.8.5")
    ksp("androidx.room:room-compiler:2.8.5")
    // Drives Compose frames reliably for navigation and permission-dialog regression tests.
    testDebugImplementation("androidx.compose.ui:ui-test-junit4")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.17")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    // Dormant draft-02 provider probe only; no Tink code enters the release runtime.
    androidTestImplementation("com.google.crypto.tink:tink:1.23.0")

    // These constraints affect local unit tests and AGP's lint tools. None of
    // these libraries is present in the app's release runtime classpath.
    constraints {
        testImplementation("org.bouncycastle:bcprov-jdk18on:1.86")
        add("androidLintTool", "org.bouncycastle:bcprov-jdk18on:1.86")
        add("androidLintTool", "org.bouncycastle:bcpkix-jdk18on:1.86")
        add("androidLintTool", "org.bouncycastle:bcutil-jdk18on:1.86")
        add("androidLintTool", "org.apache.commons:commons-lang3:3.20.0")
        add("androidLintTool", "org.apache.httpcomponents:httpclient:4.5.14")
    }
}
