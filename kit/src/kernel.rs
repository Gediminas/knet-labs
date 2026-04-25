use core::mem;

#[inline(always)]
pub unsafe fn read<T>(pos: usize, end: usize) -> Result<T, &'static str> {
    if pos + mem::size_of::<T>() > end {
        return Err("Offset out of buffer scope");
    }

    Ok(unsafe { read_unchecked::<T>(pos) })
}

#[inline(always)]
pub unsafe fn read_unchecked<T>(pos: usize) -> T {
    // SAFETY Context must have enough bytes to read `T`
    let ptr = pos as *const T;
    unsafe { ptr.read_unaligned() }
}
