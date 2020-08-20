// tslint:disable-next-line: typedef
const BITS_PER_BYTE = 8;
// tslint:disable-next-line: typedef
const BYTES_PER_U16 = 2;
// tslint:disable-next-line: typedef
const BYTES_PER_U32 = 4;
// tslint:disable-next-line: typedef
const BYTE_MASK = 0xFF;

/**
 * Function to convert an ANSI string into an ArrayBuffer
 *
 * @param data The string to convert
 * @returns An array buffer containing the raw string data
 */
const convertString: (data: string) => ArrayBuffer =
    (data: string): ArrayBuffer => {
        const buf: ArrayBuffer = new ArrayBuffer(data.length);
        const view: Uint8Array = new Uint8Array(buf);
        let i: number;
        for (i = 0; i < data.length; i += 1) {
            view[i] = data.charCodeAt(i);
        }

        return buf;
    };

/**
 * Function to left pad a string with a repeating pattern. If the pattern is not a multiple of the padding required to
 * make the output the correct length, then the last copy of the padding before the original string will be truncated.
 * @param data The input string to be padded
 * @param length The required length of the output
 * @param pad The value which should be prepended to the string until it is the requested length
 * @returns The padded input string, padding to the requested length
 */
const padStart: (data: string, length: number, pad: string) => string =
    (data: string, length: number, pad: string): string => {
        const paddingLength: number = length - data.length;
        const partialPadLength: number = paddingLength % pad.length;
        const fullPads: number = paddingLength - partialPadLength / pad.length;
        const result: string = pad.repeat(fullPads) + pad.substring(0, partialPadLength)
            + data;

        return result;
    };

/**
 * Function to write a 16-bit value in little-endian format to a given address. Note that DRCOV format data is always in
 * little endian, regardless the endian-ness of the target application.
 *
 * @param address The address at which to write the value
 * @param value The value to be written
 */
const write16le: (address: NativePointer, value: number) => void =
    (address: NativePointer, value: number): void => {
        let i: number;
        for (i = 0; i < BYTES_PER_U16; i += 1) {
            // tslint:disable-next-line:no-bitwise
            const byteValue: number = (value >> (BITS_PER_BYTE * i)) & BYTE_MASK;
            address.add(i)
                .writeU8(byteValue);
        }
    };

/**
 * Function to write a 32-bit value in little-endian format to a given address. Note that DRCOV format data is always in
 * little endian, regardless the endian-ness of the target application.
 *
 * @param address The address at which to write the value
 * @param value The value to be written
 */
const write32le: (address: NativePointer, value: number) => void =
    (address: NativePointer, value: number): void => {
        let i: number;
        for (i = 0; i < BYTES_PER_U32; i += 1) {
            // tslint:disable-next-line:no-bitwise
            const byteValue: number = (value >> (BITS_PER_BYTE * i)) & BYTE_MASK;
            address.add(i)
                .writeU8(byteValue);
        }
    };

export { convertString, padStart, write16le, write32le };
