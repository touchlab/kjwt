plugins {
    id("kjwt.multiplatform-library")
    alias(libs.plugins.kotlin.serialization)
}

description = "Kotlin Multiplaftorm JWT"

kotlin {
    sourceSets {
        commonMain.dependencies {
            api(libs.cryptography.core)
            api(libs.cryptography.bigint)
            api(libs.kotlinx.serialization.json)

            implementation(libs.kotlinx.coroutines.core)
            implementation(libs.cryptography.serialization.asn1)
            implementation(libs.cryptography.serialization.asn1.modules)
        }
    }
}
