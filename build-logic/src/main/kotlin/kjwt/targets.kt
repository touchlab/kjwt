package kjwt

import com.android.build.api.dsl.KotlinMultiplatformAndroidLibraryTarget
import org.gradle.api.Action
import org.gradle.kotlin.dsl.assign
import org.gradle.kotlin.dsl.invoke
import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension

fun KotlinMultiplatformExtension.allTargets(
    supportsWasmWasi: Boolean = true,
) {
    jvmTarget()
    webTargets()
    nativeTargets()
    if (supportsWasmWasi) wasmWasiTarget()
}

fun KotlinMultiplatformExtension.androidJvmTarget(
    configure: Action<KotlinMultiplatformAndroidLibraryTarget>,
) {
    extensions.configure<KotlinMultiplatformAndroidLibraryTarget>("android") {
        configure(this)

        compileSdk = 36
        minSdk = 23

        withDeviceTestBuilder { sourceSetTreeName = "test" }.configure {
            instrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        }
    }
}

fun KotlinMultiplatformExtension.appleTargets() {
    macosTargets()
    iosTargets()
    watchosTargets()
    tvosTargets()
}

fun KotlinMultiplatformExtension.macosTargets() {
    macosX64()
    macosArm64()
}

fun KotlinMultiplatformExtension.iosTargets() {
    iosArm64()
    iosX64()
    iosSimulatorArm64()
}

fun KotlinMultiplatformExtension.watchosTargets() {
    watchosX64()
    watchosArm64()
    watchosSimulatorArm64()
    watchosDeviceArm64()
}

fun KotlinMultiplatformExtension.tvosTargets() {
    tvosX64()
    tvosArm64()
    tvosSimulatorArm64()
}

fun KotlinMultiplatformExtension.desktopTargets() {
    linuxX64()
    linuxArm64()

    mingwX64()

    macosX64()
    macosArm64()
}

fun KotlinMultiplatformExtension.nativeTargets() {
    appleTargets()
    desktopTargets()

    androidNativeX64()
    androidNativeX86()
    androidNativeArm64()
    androidNativeArm32()
}

fun KotlinMultiplatformExtension.jsTarget(
    supportsBrowser: Boolean = true,
) {
    js {
        nodejs()
        if (supportsBrowser) browser()
        binaries.executable()
    }
}

@OptIn(ExperimentalWasmDsl::class)
fun KotlinMultiplatformExtension.wasmJsTarget(
    supportsBrowser: Boolean = true,
) {
    wasmJs {
        nodejs()
        if (supportsBrowser) browser()
        binaries.executable()
    }
}

@OptIn(ExperimentalWasmDsl::class)
fun KotlinMultiplatformExtension.wasmWasiTarget() {
    wasmWasi {
        nodejs()
    }
}

fun KotlinMultiplatformExtension.webTargets(
    supportsBrowser: Boolean = true,
) {
    jsTarget(supportsBrowser = supportsBrowser)
    wasmJsTarget(supportsBrowser = supportsBrowser)
}

fun KotlinMultiplatformExtension.jvmTarget() {
    jvm {
        compilerOptions {
            jvmTarget = JvmTarget.JVM_1_8
        }
    }
}
