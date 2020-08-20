interface ICoverageOptions {
    /**
     * User data to be passed to `StalkerNativeTransformCallback`.
     */
    data?: NativePointerValue;
    /**
     * Which events, if any, should be generated and periodically delivered to
     * `onReceive()` and/or `onCallSummary()`.
     */
    events?: {
        /**
         * Whether to generate an event whenever a basic block is executed.
         *
         * Useful to record a coarse execution trace.
         */
        block?: boolean;
        /**
         * Whether to generate events for CALL/BLR instructions.
         */
        call?: boolean;
        /**
         * Whether to generate events for all instructions.
         *
         * Not recommended as it's potentially a lot of data.
         */
        exec?: boolean;
        /**
         * Whether to generate events for RET instructions.
         */
        ret?: boolean;
    };
    /**
     * Callback that transforms each basic block compiled whenever Stalker
     * wants to recompile a basic block of the code that's about to be executed
     * by the stalked thread.
     */
    transform?: StalkerTransformCallback;
    /**
     * Function to determine which modules should be included in the coverage information. This also causes omitted
     * modules to be excluded from Stalker using 'Stalker.exclude'.
     *
     * @param module The module information
     * @returns True if the module is to be included in the coverage output, false otherwise.
     */
    moduleFilter(module: Module): boolean;
    /**
     * Callback that periodically receives a summary of `call` events that
     * happened in each time window.
     *
     * You would typically implement this instead of `onReceive()` for
     * efficiency, i.e. when you only want to know which targets were called
     * and how many times, but don't care about the order that the calls
     * happened in.
     *
     * @param summary Key-value mapping of call target to number of calls, in
     *                the current time window.
     */
    onCallSummary?(summary: StalkerCallSummary): void;
    /**
     * Callback which periodically receives raw DynamoRio DRCOV format coverage data. This data can be written directly
     * to file (or otherwise sent elsewhere for egress) and then loaded directly into IDA lighthouse or Ghidra
     * Dragondance.
     *
     * @param coverageData The raw coverage data
     */
    onCoverage(coverageData: ArrayBuffer): void;
    /**
     * Callback that periodically receives batches of events.
     *
     * @param events Binary blob comprised of one or more `Gum.Event` structs.
     *               See `gumevent.h` for details about the format.
     *               Use `Stalker.parse()` to examine the data.
     */
    onReceive?(events: ArrayBuffer): void;
}

export { ICoverageOptions as CoverageOptions };
