import { strToU8 } from 'fflate';

export const TAR_BLOCK = 512;

export interface TarInput {
  name: string;
  content?: string;
  typeFlag?: string;
  /** Overrides the real byte length so malformed headers can be exercised. */
  declaredSize?: number;
  corruptChecksum?: boolean;
}

/**
 * Builds a minimal ustar archive in memory.
 *
 * Test-only helper: it lets hostile archive inputs be produced without adding a tar
 * writing dependency, and without committing malicious binary fixtures to the repository.
 */
export function buildTar(inputs: TarInput[], { terminate = true } = {}): Uint8Array {
  const blocks: Uint8Array[] = [];
  for (const input of inputs) {
    const data = strToU8(input.content ?? '');
    const header = new Uint8Array(TAR_BLOCK);
    const write = (offset: number, value: string, length: number): void => {
      for (let index = 0; index < Math.min(value.length, length); index++) header[offset + index] = value.charCodeAt(index);
    };
    write(0, input.name.slice(0, 100), 100);
    write(100, '0000644\0', 8);
    write(108, '0000000\0', 8);
    write(116, '0000000\0', 8);
    write(124, `${(input.declaredSize ?? data.byteLength).toString(8).padStart(11, '0')}\0`, 12);
    write(136, '00000000000\0', 12);
    header[156] = (input.typeFlag ?? '0').charCodeAt(0);
    write(257, 'ustar\0', 6);
    write(263, '00', 2);
    for (let index = 148; index < 156; index++) header[index] = 0x20;
    let checksum = 0;
    for (const byte of header) checksum += byte;
    if (input.corruptChecksum) checksum += 1;
    write(148, `${checksum.toString(8).padStart(6, '0')}\0 `, 8);
    blocks.push(header);
    const padded = new Uint8Array(Math.ceil(data.byteLength / TAR_BLOCK) * TAR_BLOCK);
    padded.set(data);
    if (padded.byteLength) blocks.push(padded);
  }
  if (terminate) blocks.push(new Uint8Array(TAR_BLOCK * 2));
  const total = blocks.reduce((sum, block) => sum + block.byteLength, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  for (const block of blocks) { output.set(block, offset); offset += block.byteLength; }
  return output;
}
