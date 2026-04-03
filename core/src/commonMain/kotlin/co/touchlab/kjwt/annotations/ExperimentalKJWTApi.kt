package co.touchlab.kjwt.annotations

/**
 * APIs annotated as experimental KJWT API are subject to change at any time, with no binary nor
 * source compatibility guarantees. Behavior might change at any time.
 *
 * Using any API annotated as experimental in client code should be done with caution, and you will
 * have to take care of breakages in your code when usages are impacted by a change in a KJWT
 * update.
 */
@Target(
    allowedTargets = [
        AnnotationTarget.CLASS,
        AnnotationTarget.CONSTRUCTOR,
        AnnotationTarget.FIELD,
        AnnotationTarget.FUNCTION,
        AnnotationTarget.PROPERTY,
        AnnotationTarget.PROPERTY_GETTER,
        AnnotationTarget.PROPERTY_SETTER,
        AnnotationTarget.TYPEALIAS,
        AnnotationTarget.VALUE_PARAMETER,
    ],
)
@RequiresOptIn(
    level = RequiresOptIn.Level.WARNING,
    message = "This API is an experimental API and is likely to change before becoming stable",
)
public annotation class ExperimentalKJWTApi
