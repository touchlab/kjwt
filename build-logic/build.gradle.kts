plugins {
    `kotlin-dsl`
}

dependencies {
    implementation(libs.kotlin.gradle.plugin)
    implementation(libs.android.library.plugin)
    implementation(libs.ksp.plugin)
    implementation(libs.kotest.plugin)
    implementation(libs.detekt.plugin)
    implementation(libs.dokka.plugin)
    implementation(libs.dokka.plugin.versioning)
    implementation(libs.mavenPublish.plugin)
}
