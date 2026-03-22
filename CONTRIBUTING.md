# Contributing to a Touchlab Project

## License

By contributing you agree for your contribution to be licensed under the same license as the project which can be found
in the LICENSE file.
If no LICENSE file is present, all intellectual property rights for the project and contributions to the project are
reserved by Touchlab.

## Opening an issue

Issues can be useful for reporting bugs and requesting features.
If you simply have a question about the project or how to use it, please instead reach out in
the [Kotlinlang touchlab-tools channel](https://kotlinlang.slack.com/archives/CTJB58X7X)

### Reporting a Bug

When reporting a problem with the project please provide as much detail as possible including:

- The version of the project used as well as other relevant versions (eg: Kotlin, Android, iOS)
- What behavior was expected
- Steps to reproduce

#### Sample Project

Sharing a simple sample project which reproduces the issue is **immensely** helpful.
Issues are often caused by project specific configurations and uses which are not practical for us to derive from a bug
report.
A reproducing project is often the first thing we ask for on difficult bugs and going through the process will help you
make a more informed bug report.

### Requesting an Enhancement

We get a lot of great feedback from the community about how they use our projects and what can make them better.
If you'd like to suggest an improvement that is not fixing a defect, please label it as an Enhancement.
Share as much info as you can about your use case and how you would expect the enhancement might work.
Please understand that even great ideas might not fit in with our vision for the project and, even if we don't implement
them, we greatly appreciate your input

## Development Setup

### IDE Plugins

The following IntelliJ / Android Studio plugins are recommended:

- **[Detekt](https://plugins.jetbrains.com/plugin/10761-detekt)** — highlights static analysis issues in real time as
  you write code
- **[Ktlint](https://plugins.jetbrains.com/plugin/15057-ktlint)** — provides real-time code formatting feedback (the
  project enforces ktlint-compatible rules via detekt-formatting)
- **[Kotest](https://plugins.jetbrains.com/plugin/14080-kotest)** — required to run individual tests from the IDE, since
  tests are written in Kotest `FunSpec` style

### Code Quality

Before submitting a PR, run:

```bash
./gradlew detektAll
```

This runs static analysis across the entire codebase and will report any violations.
The CI pipeline also runs detekt automatically on pull requests and posts inline review comments.

The detekt configuration lives in `config/detekt/detekt.yml`. Zero violations are allowed (`maxIssues: 0`).

### Writing Tests

Tests live in `lib/src/commonTest/kotlin/` and run on all platforms.
They use [Kotest](https://kotest.io/) `FunSpec` style:

```kotlin
class MyFeatureTest : FunSpec({
    context("feature description") {
        test("specific behaviour") {
            // assertions
        }
    }
})
```

Install the Kotest IntelliJ plugin to run and debug individual tests from the IDE.

## Submitting a PR

We appreciate community members who are excited for our projects and willing to help improve them!

### Before Submitting a PR

If you are considering making a significant change, **please get in contact with us** before commiting a significant
amount of time and effort.
Even well thought out and constructed PRs sometimes do not fit into the current goals of the project and we would hate
for anyone to feel their time is wasted.
To discuss changes you can first [submit an issue](#opening-an-issue) documenting the bug or enhancement. Alternatively
you can reach out in the [Kotlinlang touchlab-tools channel](https://kotlinlang.slack.com/archives/CTJB58X7X)

### When Submitting a PR

Please be sure to check that no tests are broken and relevant tests have been added.
Include documentation updates for any changes to behavior or usage.
Be as detailed as possible in your PR comments about what has changed and how to test it.

## Other Ways To Help

- Test and comment on other's contributions
    - Review PR's
    - Confirm issues and provide reproducers
- Star the repository
- Share the project with other developers

## Releasing

Releases are published to Maven Central via the GitHub Actions workflow defined in
`.github/workflows/deployment.yml`.

### Version

The version is defined in `build-logic/src/main/kotlin/kjwt/Projects.kt`:

```kotlin
object Projects {
    const val VERSION = "0.1.0"
}
```

`main` always holds the version of the **next planned release**. After a release is published,
a follow-up PR is opened on `main` bumping the version to the next one.

### Snapshots

Every push to `main` automatically publishes a snapshot build to Maven Central.
Snapshot artifacts have `-SNAPSHOT` appended to the version.

### Final Releases

To publish a final (non-snapshot) release:

1. Ensure `Projects.VERSION` on `main` is set to the version you want to release
2. Manually trigger the **"Publish to Maven Central"** workflow from the GitHub Actions UI,
   selecting `main` as the target branch
3. After the release is published, open a PR on `main` bumping `Projects.VERSION` to the next version

Workflow dispatch triggers set `SNAPSHOT=false`, producing a final versioned artifact.

### Hotfix Releases

> [!IMPORTANT]
> Hotfix releases are handled by Touchlab developers. Community contributors should only submit PRs targeting `main`. If
> your change is urgent and needs to be included in a hotfix release, please reach out in
> the [Kotlinlang touchlab-tools channel](https://kotlinlang.slack.com/archives/CTJB58X7X) and add this information in
> the pull request description.

A hotfix is a patch that needs to ship on a previous release without including unreleased changes from `main`.

1. **Fix on `main` first** — open a PR with the bug fix targeting `main` and get it merged.
   This ensures the fix is never lost from the main line.

2. **Create a hotfix branch from the release tag**:
   ```bash
   git checkout -b hotfix/v0.1.1 v0.1.0
   ```
   Use the tag of the version that needs the patch as the base.

3. **Cherry-pick the fix** from `main`:
   ```bash
   git cherry-pick <commit-sha>
   ```

4. **Bump the version** in `build-logic/src/main/kotlin/kjwt/Projects.kt` to the hotfix version
   (e.g., `0.1.0` → `0.1.1`) and commit the change.

5. **Publish a snapshot and smoke test** — before triggering the final release, it is recommended
   to publish a snapshot from the hotfix branch and validate it in a real project.
   Trigger the **"Publish to Maven Central"** workflow with the **Snapshot** checkbox ticked,
   selecting your hotfix branch as the target. Test the resulting `-SNAPSHOT` artifact,
   then proceed to the next step only when satisfied.

6. **Trigger the release** by manually running the **"Publish to Maven Central"** workflow
   from the GitHub Actions UI, selecting your hotfix branch as the target and leaving the
   **Snapshot** checkbox unticked.
   This publishes the artifact and creates the `v0.1.1` git tag automatically.

7. **Delete the hotfix branch** — the git tag is the permanent reference for the release.
