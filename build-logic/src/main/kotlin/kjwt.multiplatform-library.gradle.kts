import helpers.allTargets
import helpers.configureTests

plugins {
    kotlin("multiplatform")
    `maven-publish`
}

kotlin {
    allTargets()
    configureTests()
}
