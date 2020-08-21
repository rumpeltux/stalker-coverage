import { CoverageOptions } from "./options";
import { CoverageSession } from "./session";
import { convertString, padStart, write16le, write32le } from "./util";

type Emitter = (coverageData: ArrayBuffer) => void;
type ThreadFilter = (thread: ThreadDetails) => boolean;

/**
 * Class used to collect coverage information in DynamoRio DRCOV format suitable to be imported into IDA lighthouse or
 * Ghidra Dragondance.
 */
class Coverage implements CoverageSession {
    /**
     * Module filter which selects all modules
     * @param module The module to filter
     */
    public static AllModules(module: Module): boolean {
        return true;
    }

    /**
     * Thread filter which selects all thread
     * @param threadDetails The thread to filter
     */
    public static AllThreads(threadDetails: ThreadDetails): boolean {
        return true;
    }

    /**
     * Thread filter which selects only the current thread
     * @param threadDetails The thread to filter
     */
    public static CurrentThread(threadDetails: ThreadDetails): boolean {
        return threadDetails.id === Process.getCurrentThreadId();
    }

    /**
     * Starts collecting coverage information for the given thread.
     *
     * @param options Options to customize the instrumentation.
     */
    public static follow(options: CoverageOptions): CoverageSession {
        const moduleFilter: ModuleMapFilter = (m: Module): boolean => options.moduleFilter(m);
        const threadFilter: ThreadFilter = (t: ThreadDetails): boolean => options.threadFilter(t);

        const coverage: Coverage = new Coverage(
            (coverageData: ArrayBuffer): void => {
                options.onCoverage(coverageData);
            },
            moduleFilter,
            threadFilter);

        return coverage;
    }

    /**
     * Module filter which selects only the main module
     * @param module The module to filter
     */
    public static MainModule(module: Module): boolean {
        return Process.enumerateModules()[0].path === module.path;
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

    /**
     * An array of the thread to include within the coverage information
     */
    private readonly threads: ThreadDetails[];

    private constructor(emit: Emitter, moduleFilter: ModuleMapFilter, threadFilter: ThreadFilter) {
        this.emit = emit;
        const map: ModuleMap = new ModuleMap((m: Module): boolean => {
                if (moduleFilter(m)) {
                    return true;
                }

                Stalker.exclude(m);

                return false;

            });
        this.modules = map.values();
        this.threads = Process.enumerateThreads()
            .filter(threadFilter);

        const stalkerOptions: StalkerOptions = {
            events: {
                compile: true,
            },
            onReceive: (events: ArrayBuffer): void => {
                const parsed: StalkerEventFull[] = Stalker.parse(events, {
                        annotate: true,
                        stringify: false,
                    }) as StalkerEventFull[];

                parsed.forEach((e: StalkerEventFull): void => {
                    const type: string = e[Coverage.COMPILE_EVENT_TYPE_INDEX] as string;
                    if (type.toString() === Coverage.COMPILE_EVENT_TYPE.toString()) {
                        const start: NativePointer = e[Coverage.COMPILE_EVENT_START_INDEX] as NativePointer;
                        const end: NativePointer = e[Coverage.COMPILE_EVENT_END_INDEX]  as NativePointer;
                        this.emitEvent(start, end);
                    }
                });
            },
        };
        this.emitHeader();
        this.threads.forEach((t: ThreadDetails): void => {
            Stalker.follow(t.id, stalkerOptions);
        });
    }

    /**
     * Stop the collection of coverage data
     */
    public stop(): void {
        this.threads.forEach((t: ThreadDetails): void => {
            Stalker.unfollow(t.id);
        });
        Stalker.flush();
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
