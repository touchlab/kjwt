rootProject.name = "kotlin-jwt"
enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

pluginManagement {
    includeBuild("build-logic")
    repositories {
        google {
            mavenContent {
                includeGroupAndSubgroups("androidx")
                includeGroupAndSubgroups("com.android")
                includeGroupAndSubgroups("com.google")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google {
            mavenContent {
                includeGroupAndSubgroups("androidx")
                includeGroupAndSubgroups("com.android")
                includeGroupAndSubgroups("com.google")
            }
        }
        mavenCentral()
    }
}

include(":kjwt-core")
project(":kjwt-core").projectDir = file("core")

include(":kjwt-cryptography-kotlin-processor")
project(":kjwt-cryptography-kotlin-processor").projectDir = file("cryptography-kotlin/processor")

include(":kjwt-cryptography-kotlin-processor-ext")
project(":kjwt-cryptography-kotlin-processor-ext").projectDir = file("cryptography-kotlin/ext")

include(":kjwt-hardware-backed-processor")
project(":kjwt-hardware-backed-processor").projectDir = file("hardware-backed/processor")
