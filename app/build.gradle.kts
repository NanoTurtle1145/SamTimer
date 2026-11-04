plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// ─────────────────────────────────────────────────────────────────────────
// Exploit payload build: app/src/main/cpp/timer.c → jniLibs/arm64-v8a/libtimer.so
//
// The CVE-2026-98260 binary ships inside the APK and is executed straight
// from nativeLibraryDir (useLegacyPackaging keeps it uncompressed).  Building
// it from Gradle keeps the payload in lockstep with the app: a plain
// `./gradlew assembleDebug` always produces a fresh binary.  The flags are
// exactly the ones the exploit was verified with; keep them in sync with any
// manual build.
// ─────────────────────────────────────────────────────────────────────────

fun ndkHome(): String? {
    val env = System.getenv("ANDROID_NDK_HOME")
    if (!env.isNullOrBlank()) return env
    val lp = rootProject.file("local.properties")
    val lines = if (lp.exists()) lp.readLines() else emptyList<String>()
    val ndkDirProp = lines.firstOrNull { it.startsWith("ndk.dir=") }
        ?.substringAfter("=")?.trim()
    if (!ndkDirProp.isNullOrBlank()) return ndkDirProp
    val sdkDirProp = lines.firstOrNull { it.startsWith("sdk.dir=") }
        ?.substringAfter("=")?.trim()
    val sdkDir = if (!sdkDirProp.isNullOrBlank()) sdkDirProp
        else System.getenv("ANDROID_SDK_ROOT")
    if (sdkDir != null) {
        val best = file("$sdkDir/ndk").listFiles()
            ?.filter { it.isDirectory }
            ?.maxByOrNull { it.name }
        if (best != null) return best.absolutePath
    }
    val home = System.getProperty("user.home")
    return listOf(
        "$home/android-ndk-r27c",
        "$home/Android/Sdk/ndk/27.2.12479018"
    ).firstOrNull { file(it).exists() }
}

val buildPayload by tasks.registering(Exec::class) {
    group = "build"
    description = "Builds the timer exploit payload into jniLibs (arm64)"
    val src = file("src/main/cpp/timer.c")
    val out = file("src/main/jniLibs/arm64-v8a/libtimer.so")
    inputs.file(src)
    outputs.file(out)
    doFirst {
        val ndk = ndkHome()
            ?: throw GradleException(
                "NDK not found — set ANDROID_NDK_HOME or ndk.dir in local.properties"
            )
        val windows = System.getProperty("os.name").startsWith("Windows")
        val host = if (windows) "windows-x86_64" else "linux-x86_64"
        val cc = "$ndk/toolchains/llvm/prebuilt/$host/bin/aarch64-linux-android34-clang" +
            if (windows) ".cmd" else ""
        if (!file(cc).exists()) throw GradleException("clang not found: $cc")
        out.parentFile.mkdirs()
        logger.lifecycle("payload: $src -> $out")
        val args = listOf(
            "-O2", "-std=gnu11", "-static",
            "-ffunction-sections", "-fdata-sections",
            src.absolutePath, "-o", out.absolutePath
        )
        if (windows)
            commandLine(listOf("cmd", "/c", cc) + args)
        else
            commandLine(listOf(cc) + args)
    }
}

android {
    namespace = "com.roottimer.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.roottimer.app"
        minSdk = 31
        targetSdk = 34
        versionCode = 3
        versionName = "1.2"
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
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        aidl = true
        compose = true
    }
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }
}

dependencies {
    val shizukuVersion = "13.1.5"
    implementation("dev.rikka.shizuku:api:$shizukuVersion")
    implementation("dev.rikka.shizuku:provider:$shizukuVersion")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.work:work-runtime-ktx:2.9.1")

    val composeBom = platform("androidx.compose:compose-bom:2024.10.01")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.activity:activity-compose:1.9.3")
    debugImplementation("androidx.compose.ui:ui-tooling")
}

// The payload must exist before anything packages jniLibs.
tasks.named("preBuild") { dependsOn(buildPayload) }

// clean deletes build outputs; the generated payload lives in jniLibs,
// so add it to the clean set (libksud.so is a hand-placed prebuilt and
// is left alone).
tasks.named<Delete>("clean") {
    delete(file("src/main/jniLibs/arm64-v8a/libtimer.so"))
}
