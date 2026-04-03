package kjwt

import org.gradle.api.Project
import org.gradle.api.artifacts.VersionCatalog
import org.gradle.api.artifacts.VersionCatalogsExtension
import org.gradle.api.artifacts.dsl.DependencyHandler
import org.gradle.kotlin.dsl.getByType

object Projects {
    const val GROUP = "co.touchlab"
    const val VERSION = "0.1.0"

    private enum class Type { Library, Misc }

    private val allProjects = mapOf(
        ":kjwt-core" to Type.Library,
        ":kjwt-cryptography-kotlin-processor" to Type.Library,
        ":kjwt-cryptography-kotlin-processor-ext" to Type.Library,
    )

    val allLibraries: Set<String> = allProjects.filter { it.value == Type.Library }.keys
}

val Project.versionCatalog: VersionCatalog
    get() = extensions.getByType<VersionCatalogsExtension>().named("libs")

val Project.isRootProject: Boolean
    get() = path == ":"

fun Project.rootProjectDependencies(handler: DependencyHandler.(VersionCatalog) -> Unit) {
    if (!isRootProject) return
    dependencies.handler(versionCatalog)
}
