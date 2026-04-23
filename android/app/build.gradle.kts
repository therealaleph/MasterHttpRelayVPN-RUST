import org.gradle.api.tasks.Exec

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.therealaleph.mhrv"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.therealaleph.mhrv"
        minSdk = 24 // Android 7.0 — covers 99%+ of live devices.
        targetSdk = 34
        versionCode = 115
        versionName = "1.1.5"

        // Ship all four mainstream Android ABIs:
        //   - arm64-v8a      — 95%+ of real-world Android phones since 2019
        //   - armeabi-v7a    — older/cheaper devices still on 32-bit ARM
        //   - x86_64         — Android emulator on Intel Macs + Chromebooks
        //   - x86            — legacy 32-bit Intel emulator; cheap to include
        // Per-ABI .so files push the APK up to ~50 MB, but users expect one
        // APK that Just Works rather than "pick the right ABI" which nobody
        // does correctly. Google Play would auto-split; we ship universal.
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
        }
    }

    signingConfigs {
        create("release") {
            // Committed keystore — fixed signature across machines and
            // across CI runs. Using the auto-generated debug keystore
            // (as v1.0.0 / v1.0.1 did) makes every release APK fail to
            // install over the previous one with
            // INSTALL_FAILED_UPDATE_INCOMPATIBLE, because Android treats
            // a signature change as "different app": the user has to
            // uninstall first. That's awful UX.
            //
            // The password is in plaintext because this is an
            // open-source project without Play Store identity. A
            // forked/rebuilt APK signed with a different key is
            // fundamentally a different install path anyway — the
            // protection model here is "trust the source tree you
            // pulled from," not "trust that we hold a key you can't
            // see." If you're forking, generate your own key, commit
            // it, and ship.
            storeFile = file("release.jks")
            storePassword = "mhrv-rs-release"
            keyAlias = "mhrv-rs"
            keyPassword = "mhrv-rs-release"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    // libmhrv_rs.so is produced by `cargo ndk` in the repo root and dropped
    // under app/src/main/jniLibs/<abi>/. The cargoBuild task below runs
    // that before each assembleDebug / assembleRelease.
    sourceSets["main"].jniLibs.srcDirs("src/main/jniLibs")

    packaging {
        resources.excludes += setOf(
            "META-INF/AL2.0",
            "META-INF/LGPL2.1",
        )
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.06.00")
    implementation(composeBom)
    androidTestImplementation(composeBom)

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.2")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.2")
    // AppCompatDelegate.setApplicationLocales is the only thing we need
    // out of AppCompat — lets us flip the whole app locale at runtime
    // from MhrvApp.onCreate without touching every composable.
    implementation("androidx.appcompat:appcompat:1.7.0")

    // Compose UI.
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")

    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}

// --------------------------------------------------------------------------
// Cross-compile the Rust crate to arm64 Android and drop the .so into the
// place Android's packager looks. We hand the work off to `cargo ndk` which
// wraps the right CC / AR / linker env vars for us.
//
// This ties to the `assemble*` task so every debug/release build triggers
// a `cargo ndk` — no manual step. In CI we'd cache the target/ dir to
// avoid full rebuilds.
// --------------------------------------------------------------------------
val rustCrateDir = rootProject.projectDir.parentFile
val jniLibsDir = file("src/main/jniLibs")

// After cargo-ndk dumps artifacts into each jniLibs/<abi>/ dir, the
// tun2proxy cdylib lands as `libtun2proxy-<hash>.so` (rustc's deps/ naming
// convention, because tun2proxy is a transitive dep not a root crate).
// Android's System.loadLibrary expects a stable name, and the hash changes
// between builds, so we normalize it to `libtun2proxy.so` in every ABI dir.
// Also deletes any stale hash-suffixed copies from previous builds.
fun normalizeTun2proxySo() {
    val jniLibsRoot = file("src/main/jniLibs")
    if (!jniLibsRoot.isDirectory) return
    jniLibsRoot.listFiles()?.filter { it.isDirectory }?.forEach { abiDir ->
        val hashed = abiDir.listFiles { f -> f.name.matches(Regex("libtun2proxy-[0-9a-f]+\\.so")) }
            ?: emptyArray()
        val newest = hashed.maxByOrNull { it.lastModified() }
        if (newest != null) {
            val target = abiDir.resolve("libtun2proxy.so")
            if (target.exists()) target.delete()
            newest.copyTo(target, overwrite = true)
        }
        hashed.forEach { it.delete() }
    }
}

// All ABIs we ship. Keep in sync with `android.defaultConfig.ndk.abiFilters`
// above; if these drift, the APK either includes .so files with no matching
// ABI entry (dead weight) or advertises ABIs with no .so (runtime
// UnsatisfiedLinkError on devices that pick that split).
val androidAbis = listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")

tasks.register<Exec>("cargoBuildDebug") {
    group = "build"
    // Intentionally ALWAYS uses --release. The Rust debug build is 80+MB
    // of unoptimized object code vs 3MB with release; the 20x APK bloat is
    // never worth it just for a Rust stack trace you wouldn't see in
    // logcat anyway. If you need Rust debug symbols, temporarily drop
    // `--release` below and accept the APK size.
    description = "Cross-compile mhrv_rs for all ABIs (release — same as cargoBuildRelease)"
    workingDir = rustCrateDir
    commandLine(buildList<String> {
        add("cargo"); add("ndk")
        androidAbis.forEach { add("-t"); add(it) }
        add("-o"); add(jniLibsDir.absolutePath)
        add("build"); add("--release")
    })
    doLast { normalizeTun2proxySo() }
}

tasks.register<Exec>("cargoBuildRelease") {
    group = "build"
    description = "Cross-compile mhrv_rs for all ABIs (release)"
    workingDir = rustCrateDir
    commandLine(buildList<String> {
        add("cargo"); add("ndk")
        androidAbis.forEach { add("-t"); add(it) }
        add("-o"); add(jniLibsDir.absolutePath)
        add("build"); add("--release")
    })
    doLast { normalizeTun2proxySo() }
}

// Hook the right cargo task in front of each Android build variant.
tasks.configureEach {
    when (name) {
        "mergeDebugJniLibFolders" -> dependsOn("cargoBuildDebug")
        "mergeReleaseJniLibFolders" -> dependsOn("cargoBuildRelease")
    }
}
