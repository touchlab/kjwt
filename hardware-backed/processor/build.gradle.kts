import kjwt.androidJvmTarget
import kjwt.configureKotlinTestDependencies
import kjwt.iosTargets

plugins {
    id("kjwt.multiplatform-library")
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.android.library)
}

description = "Hardware backed cryptography for KJWT"

kotlin {
    iosTargets()
    androidJvmTarget {
        namespace = "co.touchlab.kjwt.hardware"

        packaging.resources.excludes.addAll(
            listOf(
                "META-INF/AL2.0",
                "META-INF/LGPL2.1",
            )
        )
    }

    configureKotlinTestDependencies()
    applyDefaultHierarchyTemplate()

    sourceSets {
        commonMain.dependencies {
            api(projects.kjwtCore)
        }

        getByName("androidDeviceTest").dependencies {
            implementation(libs.androidx.test.runner)
        }
    }
}
