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
        versionCode = 1
        versionName = "0.1.0"

        // Only arm64 for now — we can add armeabi-v7a in a second pass
        // if field reports need it. Android emulators on Apple Silicon
        // only run arm64 natively, so keeping things aarch64-only makes
        // the dev loop fast.
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
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

// After cargo-ndk dumps artifacts into jniLibs/arm64-v8a/, the tun2proxy
// cdylib lands as `libtun2proxy-<hash>.so` (rustc's deps/ naming convention,
// because tun2proxy is a transitive dep not a root crate). Android's
// System.loadLibrary expects a stable name, and the hash changes between
// builds, so we normalize it to `libtun2proxy.so` here. Also deletes any
// stale hash-suffixed copies from previous builds.
fun normalizeTun2proxySo() {
    val abiDir = file("src/main/jniLibs/arm64-v8a")
    if (!abiDir.isDirectory) return
    val hashed = abiDir.listFiles { f -> f.name.matches(Regex("libtun2proxy-[0-9a-f]+\\.so")) }
        ?: emptyArray()
    // Keep only the newest (release build) and rename it.
    val newest = hashed.maxByOrNull { it.lastModified() }
    if (newest != null) {
        val target = abiDir.resolve("libtun2proxy.so")
        if (target.exists()) target.delete()
        newest.copyTo(target, overwrite = true)
    }
    hashed.forEach { it.delete() }
}

tasks.register<Exec>("cargoBuildDebug") {
    group = "build"
    // Intentionally ALWAYS uses --release. The Rust debug build is 80+MB
    // of unoptimized object code vs 3MB with release; the 20x APK bloat is
    // never worth it just for a Rust stack trace you wouldn't see in
    // logcat anyway. If you need Rust debug symbols, temporarily drop
    // `--release` below and accept the APK size.
    description = "Cross-compile mhrv_rs for arm64-v8a (release — same as cargoBuildRelease)"
    workingDir = rustCrateDir
    commandLine(
        "cargo", "ndk",
        "-t", "arm64-v8a",
        "-o", jniLibsDir.absolutePath,
        "build", "--release",
    )
    doLast { normalizeTun2proxySo() }
}

tasks.register<Exec>("cargoBuildRelease") {
    group = "build"
    description = "Cross-compile mhrv_rs for arm64-v8a (release)"
    workingDir = rustCrateDir
    commandLine(
        "cargo", "ndk",
        "-t", "arm64-v8a",
        "-o", jniLibsDir.absolutePath,
        "build", "--release",
    )
    doLast { normalizeTun2proxySo() }
}

// Hook the right cargo task in front of each Android build variant.
tasks.configureEach {
    when (name) {
        "mergeDebugJniLibFolders" -> dependsOn("cargoBuildDebug")
        "mergeReleaseJniLibFolders" -> dependsOn("cargoBuildRelease")
    }
}
