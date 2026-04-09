plugins {
    alias(libs.plugins.kotlin.multiplatform)
}

kotlin {
    listOf(
        iosArm64(),
        iosSimulatorArm64()
    ).forEach { iosTarget ->
        iosTarget.binaries.framework {
            baseName = "Shared"
            isStatic = false
            export("co.touchlab:kjwt-hardware-backed-processor:0.1.0")
            export("co.touchlab:kjwt-core:0.1.0")
        }
    }
    
    sourceSets {
        commonMain.dependencies {
            api("co.touchlab:kjwt-hardware-backed-processor:0.1.0")
            api("co.touchlab:kjwt-core:0.1.0")
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
    }
}
