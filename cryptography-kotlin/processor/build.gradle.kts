import kjwt.configureCryptographyProviderForTests

plugins {
    id("kjwt.multiplatform-library")
    alias(libs.plugins.kotlin.serialization)
}

description = "Cryptography-kotlin extensions for KJWT"

kotlin {
    sourceSets {
        commonMain.dependencies {
            api(projects.kjwtCore)
            api(libs.cryptography.core)
        }
    }
}
