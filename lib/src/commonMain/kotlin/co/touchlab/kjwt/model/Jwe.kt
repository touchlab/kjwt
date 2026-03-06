package co.touchlab.kjwt.model

data class Jwe<P>(
    val header: JweHeader,
    val payload: P,
)