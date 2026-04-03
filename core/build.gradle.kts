import kjwt.allTargets
import kjwt.configureCryptographyProviderForTests
import kjwt.configureTests

plugins {
    id("kjwt.multiplatform-library")
    alias(libs.plugins.kotlin.serialization)
}

description = "Kotlin Multiplaftorm JWT"

kotlin {
    allTargets()
    configureTests()
    configureCryptographyProviderForTests()

    sourceSets {
        commonMain.dependencies {
            api(libs.kotlinx.serialization.json)
            implementation(libs.kotlinx.coroutines.core)
        }

        commonTest.dependencies {
            // This does not cause circular dependencies as only test modules depends on the other modules
            // I'll revamp the tests another time, ensuring only "core" logic remains in this module
            implementation(projects.kjwtCryptographyKotlinProcessor)
            implementation(projects.kjwtCryptographyKotlinProcessorExt)
        }
    }
}
