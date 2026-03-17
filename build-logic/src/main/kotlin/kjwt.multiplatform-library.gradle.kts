import kjwt.allTargets
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
    allTargets()
    configureTests()
    explicitApi()
}
