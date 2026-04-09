import io.gitlab.arturbosch.detekt.Detekt
import io.gitlab.arturbosch.detekt.report.ReportMergeTask

plugins {
    id("io.gitlab.arturbosch.detekt")
}

detekt {
    autoCorrect = System.getenv("CI") == null
    config.from(files(rootProject.file("config/detekt/detekt.yml")))
    buildUponDefaultConfig = true
    basePath = rootProject.projectDir.absolutePath
}

dependencies {
    val libs = project.extensions.getByType<VersionCatalogsExtension>().named("libs")
    detektPlugins(libs.findLibrary("detekt-formatting").get())
}

tasks.withType<Detekt>().configureEach {
    if (name.contains("android", true)) {
        enabled = false
        return@configureEach
    }

    exclude { it.file.path.contains("generated/") }

    reports {
        xml.required.set(true)
        html.required.set(false)
        txt.required.set(false)
        md.required.set(false)
        sarif.required.set(true)
    }
}

val detektAll by tasks.registering {
    group = "verification"
    description = "Runs over whole code base without the starting overhead for each module."

    dependsOn(
        tasks
            .withType<Detekt>()
            .filterNot { it.name.contains("android", true) }
    )
}

val mergedDetektReport by tasks.registering(ReportMergeTask::class) {
    group = "verification"
    description = "Merges all detekt SARIF reports into one"

    output.set(project.layout.buildDirectory.file("reports/detekt/merged-report.sarif"))
    input.from(tasks.withType<Detekt>().map { it.sarifReportFile })

    dependsOn(detektAll)
}

val mergedDetektXmlReport by tasks.registering(ReportMergeTask::class) {
    group = "verification"
    description = "Merges all detekt XML reports into one"

    output.set(project.layout.buildDirectory.file("reports/detekt/merged-report.xml"))
    input.from(tasks.withType<Detekt>().map { it.xmlReportFile })

    dependsOn(detektAll)
}

subprojects {
    mergedDetektReport {
        input.from(
            input.from +
                tasks.withType<ReportMergeTask>()
                    .asSequence()
                    .filter { it.name.equals("mergedDetektReport", true) }
                    .map { it.output }
        )
    }
    mergedDetektXmlReport {
        input.from(
            input.from +
                tasks.withType<ReportMergeTask>()
                    .asSequence()
                    .filter { it.name.equals("mergedDetektXmlReport", true) }
                    .map { it.output }
        )
    }
}
