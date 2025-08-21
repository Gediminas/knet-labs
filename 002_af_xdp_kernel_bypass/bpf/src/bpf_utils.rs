use core::mem;

#[allow(dead_code)]
#[inline(always)]
pub unsafe fn read<T>(offset: usize, end: usize) -> Result<T, &'static str> {
    if offset + mem::size_of::<T>() > end {
        return Err("Offset out of buffer scope");
    }

    let ptr = offset as *const T;
    let res = unsafe { ptr.read_unaligned() };
    Ok(res)
}

#[inline(always)]
pub unsafe fn read_unchecked<T>(pos: usize) -> T {
    let ptr = pos as *const T;
    unsafe { ptr.read_unaligned() }
}
