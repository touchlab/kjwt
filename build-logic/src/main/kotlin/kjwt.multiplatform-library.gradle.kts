import kjwt.configureTests

plugins {
    kotlin("multiplatform")
    id("com.google.devtools.ksp")
    id("io.kotest")
    id("kjwt.linting")
    id("kjwt.dokka")
    id("kjwt.publish")
    `maven-publish`
}

kotlin {
    explicitApi()

    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
    }

    sourceSets {
        all {
            languageSettings {
                optIn("co.touchlab.kjwt.annotations.InternalKJWTApi")
                optIn("co.touchlab.kjwt.annotations.ExperimentalKJWTApi")
                optIn("kotlin.time.ExperimentalTime")
            }
        }
    }
}