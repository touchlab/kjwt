import helpers.allTargets
import helpers.configureTests

plugins {
    kotlin("multiplatform")
    id("com.google.devtools.ksp")
    id("io.kotest")
    id("kjwt.linting")
    `maven-publish`
}

kotlin {
    allTargets()
    configureTests()
}
