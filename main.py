import lief
import capstone
from elftools.elf.elffile import ELFFile

AES_KEY_SIZE = 32
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = True


def build_rela_dyn_map(rela_dyn_section):
    rela_dyn_bytes = bytes(rela_dyn_section.content)
    address_map = {}
    for i in range(rela_dyn_section.size // 24):
        source_address = rela_dyn_bytes[i * 24: i * 24 + 8]
        dest_address = rela_dyn_bytes[i * 24 + 16: i * 24 + 24]
        address_map[int.from_bytes(source_address[::-1])] = int.from_bytes(dest_address[::-1])

    return address_map


def check_address_in_section(address, section):
    return section.virtual_address <= address < section.virtual_address + section.size


def main():
    # only support arm64-v8a dynamic link library
    lib_path = "libgodot_android.so"
    lib_binary = lief.parse(lib_path)
    text_section = lib_binary.get_section(".text")
    got_section = lib_binary.get_section(".got")
    data_section = lib_binary.get_section(".data")
    rela_dyn_section = lib_binary.get_section(".rela.dyn")

    rela_dyn_address_map = build_rela_dyn_map(rela_dyn_section)

    last_adrp_inst = None

    # disassemble
    for inst in md.disasm(bytes(text_section.content), text_section.virtual_address):
        # search ADRP + LDR pattern
        if inst.mnemonic == 'adrp':
            last_adrp_inst = inst

        if inst.mnemonic == 'ldr' and last_adrp_inst is not None:
            got_address = last_adrp_inst.operands[1].imm + inst.operands[1].mem.disp
            # check in .got section
            if check_address_in_section(got_address, got_section) and got_address in rela_dyn_address_map:
                data_address = rela_dyn_address_map[got_address]

                # check in .data section
                if check_address_in_section(data_address, data_section):
                    key = bytes(lib_binary.get_content_from_virtual_address(data_address, AES_KEY_SIZE))
                    # dump possible key
                    print(key.hex())

            last_adrp_inst = None


if __name__ == '__main__':
    main()
