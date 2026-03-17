plugins {
    id("kjwt.multiplatform-library")
    alias(libs.plugins.kotlin.serialization)
}

description = "Kotlin Multiplaftorm JWT"

kotlin {
    sourceSets {
        commonMain.dependencies {
            implementation(libs.kotlinx.coroutines.core)
            implementation(libs.kotlinx.serialization.json)
            implementation(libs.cryptography.core)
            implementation(libs.cryptography.bigint)
            implementation(libs.cryptography.serialization.asn1)
            implementation(libs.cryptography.serialization.asn1.modules)
        }
    }
}
