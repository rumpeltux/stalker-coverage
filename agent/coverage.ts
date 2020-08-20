import { CoverageOptions } from "./options";
import { convertString, padStart, write16le, write32le } from "./util";

type Emitter = (coverageData: ArrayBuffer) => void;

/**
 * Class used to collect coverage information in DynamoRio DRCOV format suitable to be imported into IDA lighthouse or
 * Ghidra Dragondance.
 */
class Coverage {
    /**
     * Flushes out any buffered events. Useful when you don't want to wait until the next `queueDrainInterval` tick.
     * Calls the underlying Stalker
     * session.
     */
    public static flush(): void {
        Stalker.flush();
    }

    /**
     * Starts collecting coverage information for the given thread. Provides a super-set of the functionality of
     * Stalker.follow so that other information can be collected at the same time if required.
     *
     * @param threadId Thread ID to start following the execution of, or the
     *                 current thread if omitted.
     * @param options Options to customize the instrumentation. Note that the value of 'compile' is implicitly set to
     *                true as this is required to collect coverage information. Note that although this parameter is
     *                optional to remain consistent (and retain parameter order) with Stalker, unless options are
     *                provided, no coverage information will be collected.
     */
    public static follow(threadId?: ThreadId, options?: CoverageOptions): void {
        const stalkerOptions: StalkerOptions = {};

        if (options !== undefined) {
            stalkerOptions.data = options.data;

            stalkerOptions.events = options.events === undefined ? {} : options?.events;
            stalkerOptions.events.compile = true;

            const defaultModuleFilter: ModuleMapFilter = (m: Module): boolean => true;
            const moduleFilter: ModuleMapFilter = options.moduleFilter ?? defaultModuleFilter;

            const includedModules: Module[] = new ModuleMap(moduleFilter).values();
            Process.enumerateModules()
                .forEach((m: Module): void => {
                if (!moduleFilter(m)) {
                    Stalker.exclude(m);
                }
            });
            stalkerOptions.onCallSummary = options.onCallSummary;

            const coverage: Coverage = new Coverage(
                (coverageData: ArrayBuffer): void => {
                    options.onCoverage(coverageData);
                },
                includedModules);

            stalkerOptions.onReceive = (events: ArrayBuffer): void => {
                const parsed: StalkerEventFull[] = Stalker.parse(events, {
                        annotate: true,
                        stringify: false,
                    }) as StalkerEventFull[];

                parsed.forEach((e: StalkerEventFull): void => {
                    const type: string = e[Coverage.COMPILE_EVENT_TYPE_INDEX] as string;
                    if (type.toString() === Coverage.COMPILE_EVENT_TYPE.toString()) {
                        const start: NativePointer = e[Coverage.COMPILE_EVENT_START_INDEX] as NativePointer;
                        const end: NativePointer = e[Coverage.COMPILE_EVENT_END_INDEX]  as NativePointer;
                        coverage.emitEvent(start, end);
                    }
                });

                if (options.onReceive !== undefined) {
                    options.onReceive(events);
                }
            };
            stalkerOptions.transform = options.transform;

            coverage.emitHeader();
        }

        Stalker.follow(threadId, stalkerOptions);
    }

    /**
     * Stops collecting coverage information for the given thread, as well as stopping Stalking the thread.
     *
     * @param threadId Thread ID to stop following the execution of, or the
     *                 current thread if omitted.
     */
    public static unfollow(threadId?: ThreadId): void {
        Stalker.unfollow();
    }

    /**
     * The fixed character width of the module base field output for each module in the coverage header.
     */
    private static readonly COLUMN_WIDTH_MODULE_BASE: number = 16;
    /**
     * The fixed character width of the module checksum field output for each module in the coverage header.
     */
    private static readonly COLUMN_WIDTH_MODULE_CHECKSUM: number = 16;
    /**
     * The fixed character width of the module end field output for each module in the coverage header.
     */
    private static readonly COLUMN_WIDTH_MODULE_END: number = 16;
    /**
     * The fixed character width of the module entry field output for each module in the coverage header.
     */
    private static readonly COLUMN_WIDTH_MODULE_ENTRY: number = 16;
    /**
     * The fixed character width of the module id field output for each module in the coverage header.
     */
    private static readonly COLUMN_WIDTH_MODULE_ID: number = 3;
    /**
     * The fixed character width of the module timestamp field output for each module in the coverage header.
     */
    private static readonly COLUMN_WIDTH_MODULE_TIMESTAMP: number = 8;

    /**
     * The array index of the compile event end field in the StalkerCompileEventFull
     */
    private static readonly COMPILE_EVENT_END_INDEX: number = 2;
    /**
     * The array index of the compile event start field in the StalkerCompileEventFull
     */
    private static readonly COMPILE_EVENT_START_INDEX: number = 1;
    /**
     * The value of the type field in the StalkerCompileEventFull
     */
    private static readonly COMPILE_EVENT_TYPE: string = "compile";
    /**
     * The array index of the compile event type field in the StalkerCompileEventFull
     */
    private static readonly COMPILE_EVENT_TYPE_INDEX: number = 0;

    /**
     * The byte offset of the module id field within the DRCOV event structure
     */
    private static readonly EVENT_MODULE_OFFSET: number = 6;
    /**
     * The byte offset of the size field within the DRCOV event structure
     */
    private static readonly EVENT_SIZE_OFFSET: number = 4;
    /**
     * The byte offset of the start field within the DRCOV event structure
     */
    private static readonly EVENT_START_OFFSET: number = 0;
    /**
     * The total size in bytes of the DRCOV event structure
     */
    private static readonly EVENT_TOTAL_SIZE: number = 8;

    /**
     * The function passed in the 'onCoverage' property in the options used to receive coverage information
     */
    private readonly emit: Emitter;
    /**
     * An array of the modules to include within the coverage information
     */
    private readonly modules: Module[];

    private constructor(emit: Emitter, modules: Module[]) {
        this.emit = emit;
        this.modules = modules;
    }

    /**
     * Function used to emit a coverage event, when called with parameters parsed from StalkerCompileEventFull in the
     * 'onRecevied' function of stalker.
     *
     * @param start The address of the start of the compiled block.
     * @param end The address of the end of the compile block.
     */
    private emitEvent(start: NativePointer, end: NativePointer): void {
        let i: number;
        for (i = 0; i < this.modules.length; i += 1) {
            const base: NativePointer = this.modules[i].base;
            const size: number = this.modules[i].size;
            const limit: NativePointer = base.add(size);

            if (start.compare(base) < 0) {
                continue;
            }

            if (end.compare(limit) > 0) {
                continue;
            }

            const offset: number = start.sub(base)
                .toInt32();

            const length: number = end.sub(start)
                .toInt32();

            /*
             * struct _GumStalkerCoverageEntry {
             *     guint32 start;
             *     guint16 size;
             *     guint16 mod_id;
             * };
             */
            const memory: NativePointer = Memory.alloc(Coverage.EVENT_TOTAL_SIZE);
            write32le(memory.add(Coverage.EVENT_START_OFFSET), offset);
            write16le(memory.add(Coverage.EVENT_SIZE_OFFSET), length);
            write16le(memory.add(Coverage.EVENT_MODULE_OFFSET), i);

            const buf: ArrayBuffer = ArrayBuffer.wrap(memory, Coverage.EVENT_TOTAL_SIZE);
            this.emit(buf);
            break;
        }
    }

    /**
     * Function to emit the header information at the start of the DRCOV coverage information format. Note that the
     * format includes a number of events in the header. This is obviously not ideally suited to streaming data, so we
     * instead write the value of -1. This does not impair the operation of dragondance (which ignores the field), but
     * changes may be required for IDA lighthouse to accept this modification.
     */
    private emitHeader(): void {
        this.emit(convertString("DRCOV VERSION: 2\n"));
        this.emit(convertString("DRCOV FLAVOR: frida\n"));
        this.emit(convertString(
            `Module Table: version 2, count ${this.modules.length}\n`));

        this.emit(convertString(
            "Columns: id, base, end, entry, checksum, timestamp, path\n"));

        this.modules.forEach((m: Module, idx: number): void => {
            this.emitModule(idx, m);
        });

        this.emit(convertString("BB Table: -1 bbs\n"));
    }

    /**
     * Function to emit information about a given module into the header information of the DRCOV coverage information
     * format.
     *
     * @param idx The index of the module
     * @param module The module information
     */
    private emitModule(idx: number, module: Module): void {
        const moduleId: string = padStart(idx.toString(), Coverage.COLUMN_WIDTH_MODULE_ID, " ");

        let base: string = module.base
            .toString(16);
        base = padStart(base, Coverage.COLUMN_WIDTH_MODULE_BASE, "0");

        let end: string = module.base
            .add(module.size)
            .toString(16);
        end = padStart(end, Coverage.COLUMN_WIDTH_MODULE_END, "0");

        const entry: string = "0".repeat(Coverage.COLUMN_WIDTH_MODULE_ENTRY);
        const checksum: string = "0".repeat(Coverage.COLUMN_WIDTH_MODULE_CHECKSUM);
        const timeStamp: string = "0".repeat(Coverage.COLUMN_WIDTH_MODULE_TIMESTAMP);
        const path: string = module.path;
        const elements: string[] = [moduleId, base, end, entry, checksum, timeStamp, path];
        const line: string = elements.join(", ");
        this.emit(convertString(line));
        this.emit(convertString("\n"));
    }
}

export { Coverage };
