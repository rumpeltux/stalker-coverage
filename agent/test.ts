import { Coverage } from "./coverage";
import { CoverageOptions } from "./options";

/*
 * This sample replaces the 'main' function of the target application with one which starts collecting coverage
 * information, before calling the original 'main' function. Once the original 'main' function returns, coverage
 * collection is stopped. This coverage information is written into a file which can then be directly loaded into IDA
 * lighthouse or Ghidra Dragondance.
 */

/*
 * The address of the symbol 'main' which is to be used as the start and finish point to collect coverage information.
 */
const mainAddress: NativePointer = DebugSymbol.fromName("main").address;

/**
 * The main module for the program for which we will collect coverage information (we will not collect coverage
 * information for any library dependencies).
 */
const mainModule: Module = Process.enumerateModules()[0];

/*
 * A NativeFunction type for the 'main' function which will be used to call the original function.
 */
const mainFunctionPointer: NativeFunction = new NativeFunction(
    mainAddress,
    "int",
    ["int", "pointer"],
    { traps : "all"});

/*
 * A function to be used to replace the 'main' function. This function will start collecting coverage information before
 * calling the original 'main' function. Once this function returns, the coverage collection will be stopped and
 * flushed. Note that we cannot use Interceptor.attach here, since this interferes with Stalker (which is used to
 * provide the coverage data).
 */
const mainReplacement: NativeCallback = new NativeCallback(
    (argc: number, argv: NativePointer): number => {
        /* The following warning is a false-positive from TSLint */
        // tslint:disable-next-line: no-inferrable-types
        const coverageFileName: string = `${mainModule.path}.dat`;
        const coverageFile: File = new File(coverageFileName, "wb+");

        Coverage.follow(Process.id, {
            moduleFilter: (module: Module): boolean => module.path === mainModule.path,
            onCoverage: (coverageData: ArrayBuffer): void => {
                /* The following warning is a false-positive from TSLint */
                // tslint:disable-next-line: no-unsafe-any
                coverageFile.write(coverageData);
                // tslint:disable-next-line: no-unsafe-any
                coverageFile.flush();
            }});

        const ret: number = mainFunctionPointer(argc, argv) as number;

        Coverage.unfollow();
        Coverage.flush();
        // tslint:disable-next-line: no-unsafe-any
        coverageFile.close();

        return ret;
    },
    "int",
    ["int", "pointer"]);

/*
 * Replace the 'main' function with our replacement function defined above.
 */
Interceptor.replace(mainAddress, mainReplacement);
