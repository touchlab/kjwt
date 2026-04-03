package kjwt

import org.gradle.api.artifacts.VersionCatalogsExtension
import org.gradle.api.tasks.testing.Test
import org.gradle.kotlin.dsl.getByType
import org.gradle.kotlin.dsl.named
import org.gradle.kotlin.dsl.withType
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.plugin.KotlinPlatformType
import org.jetbrains.kotlin.gradle.targets.js.ir.KotlinJsIrTarget

fun KotlinMultiplatformExtension.configureTests() {
    configureKotlinTestDependencies()
    configureJSTests()
}

fun KotlinMultiplatformExtension.configureCryptographyProviderForTests() {
    val libs = project.extensions.getByType<VersionCatalogsExtension>().named("libs")

    sourceSets.findByName("jvmTest")?.dependencies {
        implementation(libs.findLibrary("cryptography-provider-bc").get())
    }

    sourceSets.findByName("androidDeviceTest")?.dependencies {
        implementation(libs.findLibrary("cryptography-provider-bc").get())
    }

    sourceSets.nativeTest.dependencies {
        implementation(libs.findLibrary("cryptography-provider-optimal").get())
    }

    sourceSets.webTest.dependencies {
        implementation(libs.findLibrary("cryptography-provider-web").get())
    }
}

private fun KotlinMultiplatformExtension.configureKotlinTestDependencies() {
    val libs = project.extensions.getByType<VersionCatalogsExtension>().named("libs")

    sourceSets.commonTest.dependencies {
        implementation(kotlin("test"))
        implementation(libs.findLibrary("kotest-engine").get())
    }

    sourceSets.jvmTest.dependencies {
        implementation(libs.findLibrary("kotest-runner-junit5").get())
    }

    if (project.tasks.any { it.name == "jvmTest" }) {
        project.tasks.named<Test>("jvmTest") {
            useJUnitPlatform()
            filter {
                isFailOnNoMatchingTests = false
            }
        }
    }
}

private fun KotlinMultiplatformExtension.configureJSTests() {
    targets.withType<KotlinJsIrTarget>().configureEach {
        if (platformType == KotlinPlatformType.wasm) {
            whenNodejsConfigured {
                testTask {
                    enabled = false
                }
            }
        }

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
