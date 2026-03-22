import kjwt.Projects

plugins {
    kotlin("multiplatform")
    id("com.vanniktech.maven.publish")
}

group = Projects.GROUP
version = Projects.VERSION.let {
    if (project.hasProperty("SNAPSHOT")) {
        "$it-SNAPSHOT"
    } else {
        it
    }
}

mavenPublishing {
    configureBasedOnAppliedPlugins()
    publishToMavenCentral()

    if (project.findProperty("RELEASE_SIGNING_ENABLED") != "false") {
        signAllPublications()
    }

    pom {
        name.set("KJWT")
        description.set(
            provider {
                checkNotNull(project.description) {
                    "Project description isn't set for project: ${project.path}"
                }
            }
        )
        inceptionYear.set("2026")
        url.set("https://github.com/touchlab/kjwt")

        scm {
            url.set("https://github.com/touchlab/kjwt")
            connection.set("scm:git:git://github.com/touchlab/kjwt.git")
            developerConnection.set("scm:git:git://github.com/touchlab/kjwt.git")
        }

        licenses {
            license {
                name.set("The Apache Software License, Version 2.0")
                url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                distribution.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                distribution.set("repo")
            }
        }

        developers {
            developer {
                id.set("faogustavo")
                name.set("Gustavo Fao Valvassori")
                url.set("https://github.com/faogustavo/")
                organization.set("Touchlab")
                organizationUrl.set("https://touchlab.co/")
            }
        }
    }
}
