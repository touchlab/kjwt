import kjwt.allTargets
import kjwt.configureTests

plugins {
    id("kjwt.multiplatform-library")
    alias(libs.plugins.kotlin.serialization)
}

description = "Cryptography-kotlin extensions for KJWT"

kotlin {
    allTargets()
    configureTests()
    sourceSets {
        commonMain.dependencies {
            api(projects.kjwtCore)
            api(libs.cryptography.core)
        }
    }
}
