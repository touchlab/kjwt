plugins {
    id("kjwt.multiplatform-library")
    alias(libs.plugins.kotlin.serialization)
}

description = "Cryptography-kotlin processor for KJWT"

kotlin {
    sourceSets {
        commonMain.dependencies {
            api(projects.kjwtCore)
            api(projects.kjwtCryptographyKotlinProcessor)

            api(libs.cryptography.core)
            api(libs.cryptography.bigint)
            api(libs.kotlinx.serialization.json)

            implementation(libs.kotlinx.coroutines.core)
            implementation(libs.cryptography.serialization.asn1)
            implementation(libs.cryptography.serialization.asn1.modules)
        }
    }
}
