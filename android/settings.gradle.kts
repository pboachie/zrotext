pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

// Keep the Android Gradle Plugin's own classpath on patched transitive versions.
// App/test/lint configurations are constrained separately in :app.
gradle.beforeProject(org.gradle.api.Action<org.gradle.api.Project> {
    buildscript.configurations.getByName("classpath").resolutionStrategy.force(
        "org.bouncycastle:bcprov-jdk18on:1.86",
        "org.bouncycastle:bcpkix-jdk18on:1.86",
        "org.bouncycastle:bcutil-jdk18on:1.86",
        "org.bitbucket.b_c:jose4j:0.9.6",
        "org.jdom:jdom2:2.0.6.1",
        "org.apache.commons:commons-lang3:3.18.0",
        "org.apache.httpcomponents:httpclient:4.5.14",
    )
})
rootProject.name = "ZROtext"
include(":app")
