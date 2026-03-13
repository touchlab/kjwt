package helpers

import org.gradle.api.artifacts.VersionCatalogsExtension
import org.gradle.api.tasks.testing.Test
import org.gradle.kotlin.dsl.getByType
import org.gradle.kotlin.dsl.named
import org.gradle.kotlin.dsl.withType
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.targets.js.ir.KotlinJsIrTarget

fun KotlinMultiplatformExtension.configureTests() {
    configureKotlinTestDependencies()
    configureJSTests()
}

private fun KotlinMultiplatformExtension.configureKotlinTestDependencies() {
    val libs = project.extensions.getByType<VersionCatalogsExtension>().named("libs")

    sourceSets.commonTest.dependencies {
        implementation(kotlin("test"))
        implementation(libs.findLibrary("kotest-engine").get())
    }

    sourceSets.jvmTest.dependencies {
        implementation(libs.findLibrary("kotest-runner-junit5").get())
        implementation(libs.findLibrary("cryptography-provider-optimal").get())
        implementation(libs.findLibrary("cryptography-provider-optimal").get())
    }

    sourceSets.nativeTest.dependencies {
        implementation(libs.findLibrary("cryptography-provider-optimal").get())
    }

    sourceSets.webTest.dependencies {
        implementation(libs.findLibrary("cryptography-provider-web").get())
    }

    project.tasks.named<Test>("jvmTest") {
        useJUnitPlatform()
        filter {
            isFailOnNoMatchingTests = false
        }
    }
}

private fun KotlinMultiplatformExtension.configureJSTests() {
    targets.withType<KotlinJsIrTarget>().configureEach {
        whenBrowserConfigured {
            testTask {
                useKarma {
                    useConfigDirectory(project.rootProject.rootDir.resolve("karma.config.d"))
                    useChromeHeadless()
                }
            }
        }
    }
}