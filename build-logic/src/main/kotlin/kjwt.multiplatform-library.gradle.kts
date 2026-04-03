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
        languageVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_2)
        apiVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_2)
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
