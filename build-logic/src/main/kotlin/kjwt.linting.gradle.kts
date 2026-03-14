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
    exclude { it.file.path.contains("generated/") }

    reports {
        xml.required.set(false)
        html.required.set(false)
        txt.required.set(false)
        md.required.set(false)
        sarif.required.set(true)
    }
}

val mergedDetektReport by tasks.registering(ReportMergeTask::class) {
    group = "verification"
    description = "Runs over whole code base and merge all reports into one"

    output.set(project.layout.buildDirectory.file("reports/detekt/merged-report.sarif"))
    input.from(tasks.withType<Detekt>().map { it.sarifReportFile })

    dependsOn(tasks.withType<Detekt>())
}

subprojects {
    mergedDetektReport {
        input.from(input.from + tasks.withType<ReportMergeTask>().map { it.output })
    }
}