import { CoverageOptions } from "./options";
import { CoverageSession } from "./session";

type CoverageEmitter = (coverageData: ArrayBuffer) => void;
type CoverageThreadFilter = (thread: ThreadDetails) => boolean;

/**
 * Class used to collect coverage information in DynamoRio DRCOV format suitable to be imported into IDA lighthouse or
 * Ghidra Dragondance.
 */
class Coverage implements CoverageSession {
    /**
     * Module filter which selects all modules
     * @param module The module to filter
     */
    public static allModules(module: Module): boolean {
        return true;
    }

    /**
     * Thread filter which selects all thread
     * @param threadDetails The thread to filter
     */
    public static allThreads(threadDetails: ThreadDetails): boolean {
        return true;
    }

    /**
     * Thread filter which selects only the current thread
     * @param threadDetails The thread to filter
     */
    public static currentThread(threadDetails: ThreadDetails): boolean {
        return threadDetails.id === Process.getCurrentThreadId();
    }

    /**
     * Module filter which selects only the main module
     * @param module The module to filter
     */
    public static mainModule(module: Module): boolean {
        return Process.enumerateModules()[0].path === module.path;
    }

    /**
     * Starts collecting coverage information for the given thread.
     *
     * @param options Options to customize the instrumentation.
     */
    public static start(options: CoverageOptions): CoverageSession {
        const moduleFilter = (m: Module) => options.moduleFilter(m);
        const threadFilter = (t: ThreadDetails) => options.threadFilter(t);

        const coverage = new Coverage(
            (coverageData) => {
                options.onCoverage(coverageData);
            },
            moduleFilter,
            threadFilter);

        return coverage;
    }

    /**
     * Number of bits in a byte
     */
    private static readonly BITS_PER_BYTE = 8;
    /**
     * Mask to select the value of a single byte
     */
    private static readonly BYTE_MASK = 0xFF;
    /**
     * Number of bytes in an unsigned 16 bit number
     */
    private static readonly BYTES_PER_U16 = 2;
    /**
     * Number of bytes in an unsigned 32 bit number
     */
    private static readonly BYTES_PER_U32 = 4;

    /**
     * The fixed character width of the module base field output for each module in the coverage header.
     */
    private static readonly COLUMN_WIDTH_MODULE_BASE = 16;
    /**
     * The fixed character width of the module checksum field output for each module in the coverage header.
     */
    private static readonly COLUMN_WIDTH_MODULE_CHECKSUM = 16;
    /**
     * The fixed character width of the module end field output for each module in the coverage header.
     */
    private static readonly COLUMN_WIDTH_MODULE_END = 16;
    /**
     * The fixed character width of the module entry field output for each module in the coverage header.
     */
    private static readonly COLUMN_WIDTH_MODULE_ENTRY = 16;
    /**
     * The fixed character width of the module id field output for each module in the coverage header.
     */
    private static readonly COLUMN_WIDTH_MODULE_ID = 3;
    /**
     * The fixed character width of the module timestamp field output for each module in the coverage header.
     */
    private static readonly COLUMN_WIDTH_MODULE_TIMESTAMP = 8;

    /**
     * The array index of the compile event end field in the StalkerCompileEventFull
     */
    private static readonly COMPILE_EVENT_END_INDEX = 2;
    /**
     * The array index of the compile event start field in the StalkerCompileEventFull
     */
    private static readonly COMPILE_EVENT_START_INDEX = 1;
    /**
     * The value of the type field in the StalkerCompileEventFull
     */
    private static readonly COMPILE_EVENT_TYPE = "compile";
    /**
     * The array index of the compile event type field in the StalkerCompileEventFull
     */
    private static readonly COMPILE_EVENT_TYPE_INDEX = 0;

    /**
     * The byte offset of the module id field within the DRCOV event structure
     */
    private static readonly EVENT_MODULE_OFFSET = 6;
    /**
     * The byte offset of the size field within the DRCOV event structure
     */
    private static readonly EVENT_SIZE_OFFSET = 4;
    /**
     * The byte offset of the start field within the DRCOV event structure
     */
    private static readonly EVENT_START_OFFSET = 0;
    /**
     * The total size in bytes of the DRCOV event structure
     */
    private static readonly EVENT_TOTAL_SIZE = 8;

    /**
     * Function to convert an ANSI string into an ArrayBuffer
     *
     * @param data The string to convert
     * @returns An array buffer containing the raw string data
     */
    private static convertString(data: string): ArrayBuffer {
        const buf = new ArrayBuffer(data.length);
        const view = new Uint8Array(buf);
        for (let i = 0; i < data.length; i += 1) {
            view[i] = data.charCodeAt(i);
        }

        return buf;
    }

    /**
     * Function to left pad a string with a repeating pattern. If the pattern is not a multiple of the padding required
     * to make the output the correct length, then the last copy of the padding before the original string will be
     * truncated.
     * @param data The input string to be padded
     * @param length The required length of the output
     * @param pad The value which should be prepended to the string until it is the requested length
     * @returns The padded input string, padding to the requested length
     */
    private static padStart(data: string, length: number, pad: string): string {
        const paddingLength = length - data.length;
        const partialPadLength = paddingLength % pad.length;
        const fullPads = paddingLength - partialPadLength / pad.length;
        const result = pad.repeat(fullPads) + pad.substring(0, partialPadLength)
            + data;

        return result;
    }

    /**
     * Function to write a 16-bit value in little-endian format to a given address. Note that DRCOV format data is
     * always in little endian, regardless the endian-ness of the target application.
     *
     * @param address The address at which to write the value
     * @param value The value to be written
     */
    private static write16le(address: NativePointer, value: number): void {
        let i: number;
        for (i = 0; i < Coverage.BYTES_PER_U16; i += 1) {
            // tslint:disable-next-line:no-bitwise
            const byteValue: number = (value >> (Coverage.BITS_PER_BYTE * i)) & Coverage.BYTE_MASK;
            address.add(i)
                .writeU8(byteValue);
        }
    }

    /**
     * Function to write a 32-bit value in little-endian format to a given address. Note that DRCOV format data is
     * always in little endian, regardless the endian-ness of the target application.
     *
     * @param address The address at which to write the value
     * @param value The value to be written
     */
    private static write32le(address: NativePointer, value: number): void {
        let i: number;
        for (i = 0; i < Coverage.BYTES_PER_U32; i += 1) {
            // tslint:disable-next-line:no-bitwise
            const byteValue: number = (value >> (Coverage.BITS_PER_BYTE * i)) & Coverage.BYTE_MASK;
            address.add(i)
                .writeU8(byteValue);
        }
    }

    /**
     * The function passed in the 'onCoverage' property in the options used to receive coverage information
     */
    private readonly emit: CoverageEmitter;

    /**
     * Map to hold collected coverage data for the purposes of de-duplication
     */
    private readonly events: Map<NativePointer, NativePointer> = new Map<NativePointer, NativePointer>();

    /**
     * An array of the modules to include within the coverage information
     */
    private readonly modules: Module[];

    /**
     * An array of the thread to include within the coverage information
     */
    private readonly threads: ThreadDetails[];

    private constructor(emit: CoverageEmitter, moduleFilter: ModuleMapFilter, threadFilter: CoverageThreadFilter) {
        this.emit = emit;
        const map = new ModuleMap((m) => {
                if (moduleFilter(m)) {
                    return true;
                }

                Stalker.exclude(m);

                return false;

            });
        this.modules = map.values();
        this.threads = Process.enumerateThreads()
            .filter(threadFilter);

        const stalkerOptions = {
            events: {
                compile: true,
            },
            onReceive: (events: ArrayBuffer) => {
                const parsed = Stalker.parse(events, {
                        annotate: true,
                        stringify: false,
                    }) as StalkerEventFull[];

                parsed.forEach((e) => {
                    const type: string = e[Coverage.COMPILE_EVENT_TYPE_INDEX] as string;
                    if (type.toString() === Coverage.COMPILE_EVENT_TYPE.toString()) {
                        const start = e[Coverage.COMPILE_EVENT_START_INDEX] as NativePointer;
                        const end = e[Coverage.COMPILE_EVENT_END_INDEX]  as NativePointer;
                        this.events.set(start, end);
                    }
                });
            },
        };
        this.threads.forEach((t) => {
            Stalker.follow(t.id, stalkerOptions);
        });
    }

    /**
     * Stop the collection of coverage data
     */
    public stop(): void {
        this.threads.forEach((t) => {
            Stalker.unfollow(t.id);
        });
        Stalker.flush();
        this.emitHeader();

        const eventList = Array.from(this.events.entries());
        for (const [start, end] of eventList) {
            this.emitEvent(start, end);
        }
    }

    /**
     * Function used to emit a coverage event, when called with parameters parsed from StalkerCompileEventFull in the
     * 'onRecevied' function of stalker.
     *
     * @param start The address of the start of the compiled block.
     * @param end The address of the end of the compile block.
     */
    private emitEvent(start: NativePointer, end: NativePointer): void {
        for (let i = 0; i < this.modules.length; i += 1) {
            const base = this.modules[i].base;
            const size = this.modules[i].size;
            const limit = base.add(size);

            if (start.compare(base) < 0) {
                continue;
            }

            if (end.compare(limit) > 0) {
                continue;
            }

            const offset = start.sub(base)
                .toInt32();

            const length = end.sub(start)
                .toInt32();

            /*
             * struct _GumStalkerCoverageEntry {
             *     guint32 start;
             *     guint16 size;
             *     guint16 mod_id;
             * };
             */
            const memory = Memory.alloc(Coverage.EVENT_TOTAL_SIZE);
            Coverage.write32le(memory.add(Coverage.EVENT_START_OFFSET), offset);
            Coverage.write16le(memory.add(Coverage.EVENT_SIZE_OFFSET), length);
            Coverage.write16le(memory.add(Coverage.EVENT_MODULE_OFFSET), i);

            const buf = ArrayBuffer.wrap(memory, Coverage.EVENT_TOTAL_SIZE);
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
        this.emit(Coverage.convertString("DRCOV VERSION: 2\n"));
        this.emit(Coverage.convertString("DRCOV FLAVOR: frida\n"));
        this.emit(Coverage.convertString(
            `Module Table: version 2, count ${this.modules.length}\n`));

        this.emit(Coverage.convertString(
            "Columns: id, base, end, entry, checksum, timestamp, path\n"));

        this.modules.forEach((m: Module, idx: number): void => {
            this.emitModule(idx, m);
        });

        this.emit(Coverage.convertString("BB Table: -1 bbs\n"));
    }

    /**
     * Function to emit information about a given module into the header information of the DRCOV coverage information
     * format.
     *
     * @param idx The index of the module
     * @param module The module information
     */
    private emitModule(idx: number, module: Module): void {
        const moduleId = Coverage.padStart(idx.toString(), Coverage.COLUMN_WIDTH_MODULE_ID, " ");

        let base = module.base
            .toString(16);
        base = Coverage.padStart(base, Coverage.COLUMN_WIDTH_MODULE_BASE, "0");

        let end = module.base
            .add(module.size)
            .toString(16);
        end = Coverage.padStart(end, Coverage.COLUMN_WIDTH_MODULE_END, "0");

        const entry = "0".repeat(Coverage.COLUMN_WIDTH_MODULE_ENTRY);
        const checksum = "0".repeat(Coverage.COLUMN_WIDTH_MODULE_CHECKSUM);
        const timeStamp = "0".repeat(Coverage.COLUMN_WIDTH_MODULE_TIMESTAMP);
        const path = module.path;
        const elements = [moduleId, base, end, entry, checksum, timeStamp, path];
        const line = elements.join(", ");
        this.emit(Coverage.convertString(line));
        this.emit(Coverage.convertString("\n"));
    }
}

export { Coverage, CoverageOptions, CoverageSession, CoverageEmitter, CoverageThreadFilter };
