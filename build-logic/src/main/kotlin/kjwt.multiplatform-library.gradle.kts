import helpers.allTargets
import helpers.configureTests

plugins {
    kotlin("multiplatform")
    id("com.google.devtools.ksp")
    id("io.kotest")
    `maven-publish`
}

kotlin {
    allTargets()
    configureTests()
}
