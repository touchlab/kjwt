package helpers

import org.gradle.kotlin.dsl.withType
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.plugin.KotlinPlatformType
import org.jetbrains.kotlin.gradle.targets.js.ir.KotlinJsIrTarget

fun KotlinMultiplatformExtension.configureTests() {
    configureKotlinTestDependencies()
    configureJSTests()
}

private fun KotlinMultiplatformExtension.configureKotlinTestDependencies() {
    sourceSets.configureEach {
        when (name) {
            "commonTest" -> "test"
            "jvmTest"    -> "test-junit"
            else         -> null
        }?.let { testDependency ->
            dependencies {
                implementation(kotlin(testDependency))
            }
        }
    }
}

private fun KotlinMultiplatformExtension.configureJSTests() {
    targets.withType<KotlinJsIrTarget>().configureEach {
        // Wasm tests are not behaving as expected
        // TODO: Revisit Wasm Tests
        if (platformType == KotlinPlatformType.wasm) {
            whenBrowserConfigured {
                testTask {
                    enabled = false
                }
            }

            whenNodejsConfigured {
                testTask {
                    enabled = false
                }
            }

            return@configureEach
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