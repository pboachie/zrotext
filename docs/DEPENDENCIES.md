# Dependencies and provenance

Build tools and libraries are pinned in the source tree. Check these files for the current versions:

| Component | Version source |
|---|---|
| Rust toolchain | [`rust-toolchain.toml`](../rust-toolchain.toml) |
| Rust packages | [`Cargo.lock`](../Cargo.lock) |
| Android plugins | [`android/build.gradle.kts`](../android/build.gradle.kts) |
| Android SDK levels and libraries | [`android/app/build.gradle.kts`](../android/app/build.gradle.kts) |
| Gradle distribution and checksum | [`android/gradle/wrapper/gradle-wrapper.properties`](../android/gradle/wrapper/gradle-wrapper.properties) |
| Gradle wrapper JAR | [`android/gradle/wrapper/gradle-wrapper.jar`](../android/gradle/wrapper/gradle-wrapper.jar) (checked against [Gradle's published checksum](https://gradle.org/release-checksums/)) |
| Android resolved dependencies | [`android/app/gradle.lockfile`](../android/app/gradle.lockfile) |
| Android artifact and metadata checksums | [`android/gradle/verification-metadata.xml`](../android/gradle/verification-metadata.xml) |
| Container base images | [`deploy/compose/Dockerfile`](../deploy/compose/Dockerfile) and [`deploy/compose/compose.yaml`](../deploy/compose/compose.yaml) |

CI actions are pinned to commit hashes. The [dependency graph workflow](../.github/workflows/android-dependency-graph.yml) submits the Gradle dependency graph from the main branch. GitHub's dependency graph and SBOM provide resolved package inventories; license and advisory checks should use those inventories and the lockfiles.

## Android verification and refresh

The Android CI job and unsigned release-candidate workflow run Gradle's [wrapper validation action](https://github.com/gradle/actions/blob/v6.3.0/docs/wrapper-validation.md) after checkout, before any Gradle invocation. It rejects a wrapper JAR with an unknown checksum. The distribution ZIP also has a pinned SHA-256 in `gradle-wrapper.properties`. Gradle verifies plugins, libraries, and their POM/module metadata using `verification-metadata.xml` in strict mode, so missing or changed artifact hashes fail the build. Version locks and checksum verification serve different purposes; update both when dependencies change.

For an Android plugin, library, or Dependabot update:

1. Review the proposed version and source repository. Update `android/app/gradle.lockfile` with Gradle's `--write-locks` if the resolved versions change.
2. With JDK 21 and Android SDK platform/build-tools 37.0 installed, run this from `android/` (use `gradlew.bat` on Windows):

   ```sh
   ./gradlew --write-verification-metadata sha256 help \
     :app:lintDebug :app:testDebugUnitTest :app:assembleDebug \
     :app:lintRelease :app:assembleRelease :app:cyclonedxDirectBom \
     :app:assembleAndroidTest \
     -PzrotextSourceCommit="$(git rev-parse HEAD)" --no-daemon
   ```

3. When Android Gradle Plugin or AAPT2 changes, run the metadata command on both Linux (the CI runner) and Windows: AAPT2 resolves a different JAR for each host. Review every new or changed coordinate and checksum in `gradle/verification-metadata.xml` against the intended dependency update. The generation command records the bytes currently served by repositories; it does not establish their authenticity. Investigate unexpected checksum changes for an unchanged version. Commit the reviewed metadata and lockfile with the dependency change.
4. Run the same task set without `--write-verification-metadata` and confirm strict verification passes. Do not set verification to `lenient` or `off` in CI or release jobs.

When upgrading Gradle itself, check the intended version's wrapper JAR and distribution ZIP SHA-256 at [Gradle's checksum list](https://gradle.org/release-checksums/). Run the `wrapper` task twice as [Gradle directs](https://docs.gradle.org/9.7.1/userguide/gradle_wrapper.html#sec:upgrading_wrapper) so the JAR and scripts are updated, passing the published binary ZIP checksum each time:

```sh
./gradlew :wrapper --gradle-version VERSION --distribution-type bin --gradle-distribution-sha256-sum ZIP_SHA256
./gradlew :wrapper --gradle-version VERSION --distribution-type bin --gradle-distribution-sha256-sum ZIP_SHA256
```

Confirm the checksum pinned in `gradle-wrapper.properties`, then compare the committed JAR against `https://services.gradle.org/distributions/gradle-VERSION-wrapper.jar.sha256` before running another build. In PowerShell, for example:

```powershell
$version = '9.7.1' # replace with the version in gradle-wrapper.properties
$expected = (Invoke-RestMethod "https://services.gradle.org/distributions/gradle-$version-wrapper.jar.sha256").Trim().ToLowerInvariant()
$actual = (Get-FileHash gradle/wrapper/gradle-wrapper.jar -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw 'Gradle wrapper JAR checksum mismatch' }
```

Review changes to the pinned `gradle/actions/wrapper-validation` commit against an official `gradle/actions` release. The wrapper action itself is a separate guard because the wrapper JAR runs before Gradle can enforce artifact or distribution checksums.

Application source is licensed under [AGPL-3.0-only](../LICENSE). Third-party tools and libraries retain their own licenses; generated wrapper files and downloaded distributions are not relicensed as application code.
