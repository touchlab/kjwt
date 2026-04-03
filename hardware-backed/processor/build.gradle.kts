import kjwt.androidJvmTarget
import kjwt.configureCryptographyProviderForTests

plugins {
    id("kjwt.multiplatform-library")
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.android.library)
}

description = "Hardware backed cryptography for KJWT"

kotlin {
    configureCryptographyProviderForTests()

    androidJvmTarget {
        namespace = "co.touchlab.kjwt.hardware"
    }

    sourceSets {
        commonMain.dependencies {
            api(projects.kjwtCore)
        }

        getByName("androidDeviceTest").dependencies {
            implementation(kotlin("test"))

            implementation(libs.kotlinx.coroutines.test)
            implementation(libs.androidx.test.runner)

            implementation(projects.kjwtCryptographyKotlinProcessor)
            implementation(projects.kjwtCryptographyKotlinProcessorExt)
        }
    }
}
