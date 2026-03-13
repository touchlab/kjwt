plugins {
    `kotlin-dsl`
}

dependencies {
    implementation(libs.kotlin.gradle.plugin)
    implementation(libs.ksp.plugin)
    implementation(libs.kotest.plugin)
}