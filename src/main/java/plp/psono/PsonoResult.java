package plp.psono;

/**
 * Wraps the result of a Psono operation.
 * On success, {@link #getValue()} holds the result.
 * On failure, {@link #getMessage()} holds a user-readable error description.
 */
public class PsonoResult<T> {

    private final T      value;
    private final boolean success;
    private final String  message;

    private PsonoResult(T value, String message, boolean success) {
        this.value   = value;
        this.message = message;
        this.success = success;
    }

    // ── Factories ─────────────────────────────────────────────────────────────

    public static <T> PsonoResult<T> ok(T value) {
        return new PsonoResult<>(value, null, true);
    }

    public static <T> PsonoResult<T> fail(String message) {
        return new PsonoResult<>(null, message, false);
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    /** True if the operation succeeded. */
    public boolean isOk()      { return success; }

    /** True if the operation failed. */
    public boolean isFailed()  { return !success; }

    /**
     * The result value, or {@code null} if the operation failed.
     */
    public T getValue()        { return value; }

    /**
     * Human-readable error description on failure, or {@code null} on success.
     */
    public String getMessage() { return message; }

    @Override
    public String toString() {
        return success ? "PsonoResult{ok=" + value + "}" : "PsonoResult{fail=" + message + "}";
    }
}
