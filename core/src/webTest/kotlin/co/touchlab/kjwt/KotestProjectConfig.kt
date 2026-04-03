package co.touchlab.kjwt

import io.kotest.core.config.AbstractProjectConfig
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

class KotestProjectConfig : AbstractProjectConfig() {
    override val retries: Int = 3
    override val timeout: Duration = 10.minutes
}
