#![no_std]
use std::marker::PhantomData;
/// Pseudo-structure that provides the inner type definition
/// and cast functions for every pair of types used
/// in C2Rust's implementation of tied inline assembly operands.
/// For two tied operands of types `In` and `Out`, this
/// implementation provides the smallest type that can
/// hold both operands, along with the casts to convert
/// each operand to this type.
pub struct AsmCast<Out, In>(PhantomData<(Out, In)>);
/// This trait implements the cast functions for the type pair
pub trait AsmCastTrait<Out, In> {
    type Type;
    fn cast_in(_: &mut Out, x: In) -> Self::Type;
    fn cast_out(out: &mut Out, _: In, x: Self::Type);
}
impl<T, U> AsmCastTrait<*const T, *const U> for AsmCast<*const T, *const U> {
    type Type = usize;
    fn cast_in(_: &mut *const T, x: *const U) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut *const T, _: *const U, x: Self::Type) {
        *out = x as *const T;
    }
}
impl<T, U> AsmCastTrait<*const T, *mut U> for AsmCast<*const T, *mut U> {
    type Type = usize;
    fn cast_in(_: &mut *const T, x: *mut U) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut *const T, _: *mut U, x: Self::Type) {
        *out = x as *const T;
    }
}
impl<T, U> AsmCastTrait<*mut T, *const U> for AsmCast<*mut T, *const U> {
    type Type = usize;
    fn cast_in(_: &mut *mut T, x: *const U) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut *mut T, _: *const U, x: Self::Type) {
        *out = x as *mut T;
    }
}
impl<T, U> AsmCastTrait<*mut T, *mut U> for AsmCast<*mut T, *mut U> {
    type Type = usize;
    fn cast_in(_: &mut *mut T, x: *mut U) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut *mut T, _: *mut U, x: Self::Type) {
        *out = x as *mut T;
    }
}
impl AsmCastTrait<u8, u8> for AsmCast<u8, u8> {
    type Type = u8;
    fn cast_in(_: &mut u8, x: u8) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u8, _: u8, x: Self::Type) {
        *out = x as u8;
    }
}
impl AsmCastTrait<u8, i8> for AsmCast<u8, i8> {
    type Type = u8;
    fn cast_in(_: &mut u8, x: i8) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u8, _: i8, x: Self::Type) {
        *out = x as u8;
    }
}
impl AsmCastTrait<i8, u8> for AsmCast<i8, u8> {
    type Type = u8;
    fn cast_in(_: &mut i8, x: u8) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i8, _: u8, x: Self::Type) {
        *out = x as i8;
    }
}
impl AsmCastTrait<u16, u16> for AsmCast<u16, u16> {
    type Type = u16;
    fn cast_in(_: &mut u16, x: u16) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u16, _: u16, x: Self::Type) {
        *out = x as u16;
    }
}
impl AsmCastTrait<u16, u8> for AsmCast<u16, u8> {
    type Type = u16;
    fn cast_in(_: &mut u16, x: u8) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u16, _: u8, x: Self::Type) {
        *out = x as u16;
    }
}
impl AsmCastTrait<u8, u16> for AsmCast<u8, u16> {
    type Type = u16;
    fn cast_in(_: &mut u8, x: u16) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u8, _: u16, x: Self::Type) {
        *out = x as u8;
    }
}
impl AsmCastTrait<u16, i8> for AsmCast<u16, i8> {
    type Type = u16;
    fn cast_in(_: &mut u16, x: i8) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u16, _: i8, x: Self::Type) {
        *out = x as u16;
    }
}
impl AsmCastTrait<i8, u16> for AsmCast<i8, u16> {
    type Type = u16;
    fn cast_in(_: &mut i8, x: u16) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i8, _: u16, x: Self::Type) {
        *out = x as i8;
    }
}
impl AsmCastTrait<u16, i16> for AsmCast<u16, i16> {
    type Type = u16;
    fn cast_in(_: &mut u16, x: i16) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u16, _: i16, x: Self::Type) {
        *out = x as u16;
    }
}
impl AsmCastTrait<i16, u16> for AsmCast<i16, u16> {
    type Type = u16;
    fn cast_in(_: &mut i16, x: u16) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i16, _: u16, x: Self::Type) {
        *out = x as i16;
    }
}
impl AsmCastTrait<u32, u32> for AsmCast<u32, u32> {
    type Type = u32;
    fn cast_in(_: &mut u32, x: u32) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u32, _: u32, x: Self::Type) {
        *out = x as u32;
    }
}
impl AsmCastTrait<u32, u8> for AsmCast<u32, u8> {
    type Type = u32;
    fn cast_in(_: &mut u32, x: u8) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u32, _: u8, x: Self::Type) {
        *out = x as u32;
    }
}
impl AsmCastTrait<u8, u32> for AsmCast<u8, u32> {
    type Type = u32;
    fn cast_in(_: &mut u8, x: u32) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u8, _: u32, x: Self::Type) {
        *out = x as u8;
    }
}
impl AsmCastTrait<u32, u16> for AsmCast<u32, u16> {
    type Type = u32;
    fn cast_in(_: &mut u32, x: u16) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u32, _: u16, x: Self::Type) {
        *out = x as u32;
    }
}
impl AsmCastTrait<u16, u32> for AsmCast<u16, u32> {
    type Type = u32;
    fn cast_in(_: &mut u16, x: u32) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u16, _: u32, x: Self::Type) {
        *out = x as u16;
    }
}
impl AsmCastTrait<u32, i8> for AsmCast<u32, i8> {
    type Type = u32;
    fn cast_in(_: &mut u32, x: i8) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u32, _: i8, x: Self::Type) {
        *out = x as u32;
    }
}
impl AsmCastTrait<i8, u32> for AsmCast<i8, u32> {
    type Type = u32;
    fn cast_in(_: &mut i8, x: u32) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i8, _: u32, x: Self::Type) {
        *out = x as i8;
    }
}
impl AsmCastTrait<u32, i16> for AsmCast<u32, i16> {
    type Type = u32;
    fn cast_in(_: &mut u32, x: i16) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u32, _: i16, x: Self::Type) {
        *out = x as u32;
    }
}
impl AsmCastTrait<i16, u32> for AsmCast<i16, u32> {
    type Type = u32;
    fn cast_in(_: &mut i16, x: u32) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i16, _: u32, x: Self::Type) {
        *out = x as i16;
    }
}
impl AsmCastTrait<u32, i32> for AsmCast<u32, i32> {
    type Type = u32;
    fn cast_in(_: &mut u32, x: i32) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u32, _: i32, x: Self::Type) {
        *out = x as u32;
    }
}
impl AsmCastTrait<i32, u32> for AsmCast<i32, u32> {
    type Type = u32;
    fn cast_in(_: &mut i32, x: u32) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i32, _: u32, x: Self::Type) {
        *out = x as i32;
    }
}
impl AsmCastTrait<u64, u64> for AsmCast<u64, u64> {
    type Type = u64;
    fn cast_in(_: &mut u64, x: u64) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u64, _: u64, x: Self::Type) {
        *out = x as u64;
    }
}
impl AsmCastTrait<u64, u8> for AsmCast<u64, u8> {
    type Type = u64;
    fn cast_in(_: &mut u64, x: u8) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u64, _: u8, x: Self::Type) {
        *out = x as u64;
    }
}
impl AsmCastTrait<u8, u64> for AsmCast<u8, u64> {
    type Type = u64;
    fn cast_in(_: &mut u8, x: u64) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u8, _: u64, x: Self::Type) {
        *out = x as u8;
    }
}
impl AsmCastTrait<u64, u16> for AsmCast<u64, u16> {
    type Type = u64;
    fn cast_in(_: &mut u64, x: u16) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u64, _: u16, x: Self::Type) {
        *out = x as u64;
    }
}
impl AsmCastTrait<u16, u64> for AsmCast<u16, u64> {
    type Type = u64;
    fn cast_in(_: &mut u16, x: u64) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u16, _: u64, x: Self::Type) {
        *out = x as u16;
    }
}
impl AsmCastTrait<u64, u32> for AsmCast<u64, u32> {
    type Type = u64;
    fn cast_in(_: &mut u64, x: u32) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u64, _: u32, x: Self::Type) {
        *out = x as u64;
    }
}
impl AsmCastTrait<u32, u64> for AsmCast<u32, u64> {
    type Type = u64;
    fn cast_in(_: &mut u32, x: u64) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u32, _: u64, x: Self::Type) {
        *out = x as u32;
    }
}
impl AsmCastTrait<u64, i8> for AsmCast<u64, i8> {
    type Type = u64;
    fn cast_in(_: &mut u64, x: i8) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u64, _: i8, x: Self::Type) {
        *out = x as u64;
    }
}
impl AsmCastTrait<i8, u64> for AsmCast<i8, u64> {
    type Type = u64;
    fn cast_in(_: &mut i8, x: u64) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i8, _: u64, x: Self::Type) {
        *out = x as i8;
    }
}
impl AsmCastTrait<u64, i16> for AsmCast<u64, i16> {
    type Type = u64;
    fn cast_in(_: &mut u64, x: i16) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u64, _: i16, x: Self::Type) {
        *out = x as u64;
    }
}
impl AsmCastTrait<i16, u64> for AsmCast<i16, u64> {
    type Type = u64;
    fn cast_in(_: &mut i16, x: u64) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i16, _: u64, x: Self::Type) {
        *out = x as i16;
    }
}
impl AsmCastTrait<u64, i32> for AsmCast<u64, i32> {
    type Type = u64;
    fn cast_in(_: &mut u64, x: i32) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u64, _: i32, x: Self::Type) {
        *out = x as u64;
    }
}
impl AsmCastTrait<i32, u64> for AsmCast<i32, u64> {
    type Type = u64;
    fn cast_in(_: &mut i32, x: u64) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i32, _: u64, x: Self::Type) {
        *out = x as i32;
    }
}
impl AsmCastTrait<u64, i64> for AsmCast<u64, i64> {
    type Type = u64;
    fn cast_in(_: &mut u64, x: i64) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u64, _: i64, x: Self::Type) {
        *out = x as u64;
    }
}
impl AsmCastTrait<i64, u64> for AsmCast<i64, u64> {
    type Type = u64;
    fn cast_in(_: &mut i64, x: u64) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i64, _: u64, x: Self::Type) {
        *out = x as i64;
    }
}
impl AsmCastTrait<u64, usize> for AsmCast<u64, usize> {
    type Type = u64;
    fn cast_in(_: &mut u64, x: usize) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u64, _: usize, x: Self::Type) {
        *out = x as u64;
    }
}
impl AsmCastTrait<usize, u64> for AsmCast<usize, u64> {
    type Type = u64;
    fn cast_in(_: &mut usize, x: u64) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut usize, _: u64, x: Self::Type) {
        *out = x as usize;
    }
}
impl AsmCastTrait<u64, isize> for AsmCast<u64, isize> {
    type Type = u64;
    fn cast_in(_: &mut u64, x: isize) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u64, _: isize, x: Self::Type) {
        *out = x as u64;
    }
}
impl AsmCastTrait<isize, u64> for AsmCast<isize, u64> {
    type Type = u64;
    fn cast_in(_: &mut isize, x: u64) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut isize, _: u64, x: Self::Type) {
        *out = x as isize;
    }
}
impl AsmCastTrait<i8, i8> for AsmCast<i8, i8> {
    type Type = i8;
    fn cast_in(_: &mut i8, x: i8) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i8, _: i8, x: Self::Type) {
        *out = x as i8;
    }
}
impl AsmCastTrait<i16, i16> for AsmCast<i16, i16> {
    type Type = i16;
    fn cast_in(_: &mut i16, x: i16) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i16, _: i16, x: Self::Type) {
        *out = x as i16;
    }
}
impl AsmCastTrait<i16, u8> for AsmCast<i16, u8> {
    type Type = i16;
    fn cast_in(_: &mut i16, x: u8) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i16, _: u8, x: Self::Type) {
        *out = x as i16;
    }
}
impl AsmCastTrait<u8, i16> for AsmCast<u8, i16> {
    type Type = i16;
    fn cast_in(_: &mut u8, x: i16) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u8, _: i16, x: Self::Type) {
        *out = x as u8;
    }
}
impl AsmCastTrait<i16, i8> for AsmCast<i16, i8> {
    type Type = i16;
    fn cast_in(_: &mut i16, x: i8) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i16, _: i8, x: Self::Type) {
        *out = x as i16;
    }
}
impl AsmCastTrait<i8, i16> for AsmCast<i8, i16> {
    type Type = i16;
    fn cast_in(_: &mut i8, x: i16) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i8, _: i16, x: Self::Type) {
        *out = x as i8;
    }
}
impl AsmCastTrait<i32, i32> for AsmCast<i32, i32> {
    type Type = i32;
    fn cast_in(_: &mut i32, x: i32) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i32, _: i32, x: Self::Type) {
        *out = x as i32;
    }
}
impl AsmCastTrait<i32, u8> for AsmCast<i32, u8> {
    type Type = i32;
    fn cast_in(_: &mut i32, x: u8) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i32, _: u8, x: Self::Type) {
        *out = x as i32;
    }
}
impl AsmCastTrait<u8, i32> for AsmCast<u8, i32> {
    type Type = i32;
    fn cast_in(_: &mut u8, x: i32) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u8, _: i32, x: Self::Type) {
        *out = x as u8;
    }
}
impl AsmCastTrait<i32, u16> for AsmCast<i32, u16> {
    type Type = i32;
    fn cast_in(_: &mut i32, x: u16) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i32, _: u16, x: Self::Type) {
        *out = x as i32;
    }
}
impl AsmCastTrait<u16, i32> for AsmCast<u16, i32> {
    type Type = i32;
    fn cast_in(_: &mut u16, x: i32) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u16, _: i32, x: Self::Type) {
        *out = x as u16;
    }
}
impl AsmCastTrait<i32, i8> for AsmCast<i32, i8> {
    type Type = i32;
    fn cast_in(_: &mut i32, x: i8) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i32, _: i8, x: Self::Type) {
        *out = x as i32;
    }
}
impl AsmCastTrait<i8, i32> for AsmCast<i8, i32> {
    type Type = i32;
    fn cast_in(_: &mut i8, x: i32) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i8, _: i32, x: Self::Type) {
        *out = x as i8;
    }
}
impl AsmCastTrait<i32, i16> for AsmCast<i32, i16> {
    type Type = i32;
    fn cast_in(_: &mut i32, x: i16) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i32, _: i16, x: Self::Type) {
        *out = x as i32;
    }
}
impl AsmCastTrait<i16, i32> for AsmCast<i16, i32> {
    type Type = i32;
    fn cast_in(_: &mut i16, x: i32) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i16, _: i32, x: Self::Type) {
        *out = x as i16;
    }
}
impl AsmCastTrait<i64, i64> for AsmCast<i64, i64> {
    type Type = i64;
    fn cast_in(_: &mut i64, x: i64) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i64, _: i64, x: Self::Type) {
        *out = x as i64;
    }
}
impl AsmCastTrait<i64, u8> for AsmCast<i64, u8> {
    type Type = i64;
    fn cast_in(_: &mut i64, x: u8) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i64, _: u8, x: Self::Type) {
        *out = x as i64;
    }
}
impl AsmCastTrait<u8, i64> for AsmCast<u8, i64> {
    type Type = i64;
    fn cast_in(_: &mut u8, x: i64) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u8, _: i64, x: Self::Type) {
        *out = x as u8;
    }
}
impl AsmCastTrait<i64, u16> for AsmCast<i64, u16> {
    type Type = i64;
    fn cast_in(_: &mut i64, x: u16) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i64, _: u16, x: Self::Type) {
        *out = x as i64;
    }
}
impl AsmCastTrait<u16, i64> for AsmCast<u16, i64> {
    type Type = i64;
    fn cast_in(_: &mut u16, x: i64) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u16, _: i64, x: Self::Type) {
        *out = x as u16;
    }
}
impl AsmCastTrait<i64, u32> for AsmCast<i64, u32> {
    type Type = i64;
    fn cast_in(_: &mut i64, x: u32) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i64, _: u32, x: Self::Type) {
        *out = x as i64;
    }
}
impl AsmCastTrait<u32, i64> for AsmCast<u32, i64> {
    type Type = i64;
    fn cast_in(_: &mut u32, x: i64) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u32, _: i64, x: Self::Type) {
        *out = x as u32;
    }
}
impl AsmCastTrait<i64, i8> for AsmCast<i64, i8> {
    type Type = i64;
    fn cast_in(_: &mut i64, x: i8) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i64, _: i8, x: Self::Type) {
        *out = x as i64;
    }
}
impl AsmCastTrait<i8, i64> for AsmCast<i8, i64> {
    type Type = i64;
    fn cast_in(_: &mut i8, x: i64) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i8, _: i64, x: Self::Type) {
        *out = x as i8;
    }
}
impl AsmCastTrait<i64, i16> for AsmCast<i64, i16> {
    type Type = i64;
    fn cast_in(_: &mut i64, x: i16) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i64, _: i16, x: Self::Type) {
        *out = x as i64;
    }
}
impl AsmCastTrait<i16, i64> for AsmCast<i16, i64> {
    type Type = i64;
    fn cast_in(_: &mut i16, x: i64) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i16, _: i64, x: Self::Type) {
        *out = x as i16;
    }
}
impl AsmCastTrait<i64, i32> for AsmCast<i64, i32> {
    type Type = i64;
    fn cast_in(_: &mut i64, x: i32) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i64, _: i32, x: Self::Type) {
        *out = x as i64;
    }
}
impl AsmCastTrait<i32, i64> for AsmCast<i32, i64> {
    type Type = i64;
    fn cast_in(_: &mut i32, x: i64) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i32, _: i64, x: Self::Type) {
        *out = x as i32;
    }
}
impl AsmCastTrait<i64, usize> for AsmCast<i64, usize> {
    type Type = i64;
    fn cast_in(_: &mut i64, x: usize) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i64, _: usize, x: Self::Type) {
        *out = x as i64;
    }
}
impl AsmCastTrait<usize, i64> for AsmCast<usize, i64> {
    type Type = i64;
    fn cast_in(_: &mut usize, x: i64) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut usize, _: i64, x: Self::Type) {
        *out = x as usize;
    }
}
impl AsmCastTrait<i64, isize> for AsmCast<i64, isize> {
    type Type = i64;
    fn cast_in(_: &mut i64, x: isize) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i64, _: isize, x: Self::Type) {
        *out = x as i64;
    }
}
impl AsmCastTrait<isize, i64> for AsmCast<isize, i64> {
    type Type = i64;
    fn cast_in(_: &mut isize, x: i64) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut isize, _: i64, x: Self::Type) {
        *out = x as isize;
    }
}
impl AsmCastTrait<usize, usize> for AsmCast<usize, usize> {
    type Type = usize;
    fn cast_in(_: &mut usize, x: usize) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut usize, _: usize, x: Self::Type) {
        *out = x as usize;
    }
}
impl AsmCastTrait<usize, u8> for AsmCast<usize, u8> {
    type Type = usize;
    fn cast_in(_: &mut usize, x: u8) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut usize, _: u8, x: Self::Type) {
        *out = x as usize;
    }
}
impl AsmCastTrait<u8, usize> for AsmCast<u8, usize> {
    type Type = usize;
    fn cast_in(_: &mut u8, x: usize) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u8, _: usize, x: Self::Type) {
        *out = x as u8;
    }
}
impl AsmCastTrait<usize, u16> for AsmCast<usize, u16> {
    type Type = usize;
    fn cast_in(_: &mut usize, x: u16) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut usize, _: u16, x: Self::Type) {
        *out = x as usize;
    }
}
impl AsmCastTrait<u16, usize> for AsmCast<u16, usize> {
    type Type = usize;
    fn cast_in(_: &mut u16, x: usize) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u16, _: usize, x: Self::Type) {
        *out = x as u16;
    }
}
impl AsmCastTrait<usize, i8> for AsmCast<usize, i8> {
    type Type = usize;
    fn cast_in(_: &mut usize, x: i8) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut usize, _: i8, x: Self::Type) {
        *out = x as usize;
    }
}
impl AsmCastTrait<i8, usize> for AsmCast<i8, usize> {
    type Type = usize;
    fn cast_in(_: &mut i8, x: usize) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i8, _: usize, x: Self::Type) {
        *out = x as i8;
    }
}
impl AsmCastTrait<usize, i16> for AsmCast<usize, i16> {
    type Type = usize;
    fn cast_in(_: &mut usize, x: i16) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut usize, _: i16, x: Self::Type) {
        *out = x as usize;
    }
}
impl AsmCastTrait<i16, usize> for AsmCast<i16, usize> {
    type Type = usize;
    fn cast_in(_: &mut i16, x: usize) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i16, _: usize, x: Self::Type) {
        *out = x as i16;
    }
}
impl AsmCastTrait<usize, isize> for AsmCast<usize, isize> {
    type Type = usize;
    fn cast_in(_: &mut usize, x: isize) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut usize, _: isize, x: Self::Type) {
        *out = x as usize;
    }
}
impl AsmCastTrait<isize, usize> for AsmCast<isize, usize> {
    type Type = usize;
    fn cast_in(_: &mut isize, x: usize) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut isize, _: usize, x: Self::Type) {
        *out = x as isize;
    }
}
impl AsmCastTrait<isize, isize> for AsmCast<isize, isize> {
    type Type = isize;
    fn cast_in(_: &mut isize, x: isize) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut isize, _: isize, x: Self::Type) {
        *out = x as isize;
    }
}
impl AsmCastTrait<isize, u8> for AsmCast<isize, u8> {
    type Type = isize;
    fn cast_in(_: &mut isize, x: u8) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut isize, _: u8, x: Self::Type) {
        *out = x as isize;
    }
}
impl AsmCastTrait<u8, isize> for AsmCast<u8, isize> {
    type Type = isize;
    fn cast_in(_: &mut u8, x: isize) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u8, _: isize, x: Self::Type) {
        *out = x as u8;
    }
}
impl AsmCastTrait<isize, u16> for AsmCast<isize, u16> {
    type Type = isize;
    fn cast_in(_: &mut isize, x: u16) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut isize, _: u16, x: Self::Type) {
        *out = x as isize;
    }
}
impl AsmCastTrait<u16, isize> for AsmCast<u16, isize> {
    type Type = isize;
    fn cast_in(_: &mut u16, x: isize) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u16, _: isize, x: Self::Type) {
        *out = x as u16;
    }
}
impl AsmCastTrait<isize, i8> for AsmCast<isize, i8> {
    type Type = isize;
    fn cast_in(_: &mut isize, x: i8) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut isize, _: i8, x: Self::Type) {
        *out = x as isize;
    }
}
impl AsmCastTrait<i8, isize> for AsmCast<i8, isize> {
    type Type = isize;
    fn cast_in(_: &mut i8, x: isize) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i8, _: isize, x: Self::Type) {
        *out = x as i8;
    }
}
impl AsmCastTrait<isize, i16> for AsmCast<isize, i16> {
    type Type = isize;
    fn cast_in(_: &mut isize, x: i16) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut isize, _: i16, x: Self::Type) {
        *out = x as isize;
    }
}
impl AsmCastTrait<i16, isize> for AsmCast<i16, isize> {
    type Type = isize;
    fn cast_in(_: &mut i16, x: isize) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i16, _: isize, x: Self::Type) {
        *out = x as i16;
    }
}
impl<T> AsmCastTrait<u8, *const T> for AsmCast<u8, *const T> {
    type Type = usize;
    fn cast_in(_: &mut u8, x: *const T) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u8, _: *const T, x: Self::Type) {
        *out = x as u8;
    }
}
impl<T> AsmCastTrait<*const T, u8> for AsmCast<*const T, u8> {
    type Type = usize;
    fn cast_in(_: &mut *const T, x: u8) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut *const T, _: u8, x: Self::Type) {
        *out = x as *const T;
    }
}
impl<T> AsmCastTrait<u8, *mut T> for AsmCast<u8, *mut T> {
    type Type = usize;
    fn cast_in(_: &mut u8, x: *mut T) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u8, _: *mut T, x: Self::Type) {
        *out = x as u8;
    }
}
impl<T> AsmCastTrait<*mut T, u8> for AsmCast<*mut T, u8> {
    type Type = usize;
    fn cast_in(_: &mut *mut T, x: u8) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut *mut T, _: u8, x: Self::Type) {
        *out = x as *mut T;
    }
}
impl<T> AsmCastTrait<u16, *const T> for AsmCast<u16, *const T> {
    type Type = usize;
    fn cast_in(_: &mut u16, x: *const T) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u16, _: *const T, x: Self::Type) {
        *out = x as u16;
    }
}
impl<T> AsmCastTrait<*const T, u16> for AsmCast<*const T, u16> {
    type Type = usize;
    fn cast_in(_: &mut *const T, x: u16) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut *const T, _: u16, x: Self::Type) {
        *out = x as *const T;
    }
}
impl<T> AsmCastTrait<u16, *mut T> for AsmCast<u16, *mut T> {
    type Type = usize;
    fn cast_in(_: &mut u16, x: *mut T) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u16, _: *mut T, x: Self::Type) {
        *out = x as u16;
    }
}
impl<T> AsmCastTrait<*mut T, u16> for AsmCast<*mut T, u16> {
    type Type = usize;
    fn cast_in(_: &mut *mut T, x: u16) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut *mut T, _: u16, x: Self::Type) {
        *out = x as *mut T;
    }
}
impl<T> AsmCastTrait<i8, *const T> for AsmCast<i8, *const T> {
    type Type = usize;
    fn cast_in(_: &mut i8, x: *const T) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i8, _: *const T, x: Self::Type) {
        *out = x as i8;
    }
}
impl<T> AsmCastTrait<*const T, i8> for AsmCast<*const T, i8> {
    type Type = usize;
    fn cast_in(_: &mut *const T, x: i8) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut *const T, _: i8, x: Self::Type) {
        *out = x as *const T;
    }
}
impl<T> AsmCastTrait<i8, *mut T> for AsmCast<i8, *mut T> {
    type Type = usize;
    fn cast_in(_: &mut i8, x: *mut T) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i8, _: *mut T, x: Self::Type) {
        *out = x as i8;
    }
}
impl<T> AsmCastTrait<*mut T, i8> for AsmCast<*mut T, i8> {
    type Type = usize;
    fn cast_in(_: &mut *mut T, x: i8) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut *mut T, _: i8, x: Self::Type) {
        *out = x as *mut T;
    }
}
impl<T> AsmCastTrait<i16, *const T> for AsmCast<i16, *const T> {
    type Type = usize;
    fn cast_in(_: &mut i16, x: *const T) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i16, _: *const T, x: Self::Type) {
        *out = x as i16;
    }
}
impl<T> AsmCastTrait<*const T, i16> for AsmCast<*const T, i16> {
    type Type = usize;
    fn cast_in(_: &mut *const T, x: i16) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut *const T, _: i16, x: Self::Type) {
        *out = x as *const T;
    }
}
impl<T> AsmCastTrait<i16, *mut T> for AsmCast<i16, *mut T> {
    type Type = usize;
    fn cast_in(_: &mut i16, x: *mut T) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i16, _: *mut T, x: Self::Type) {
        *out = x as i16;
    }
}
impl<T> AsmCastTrait<*mut T, i16> for AsmCast<*mut T, i16> {
    type Type = usize;
    fn cast_in(_: &mut *mut T, x: i16) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut *mut T, _: i16, x: Self::Type) {
        *out = x as *mut T;
    }
}
impl<T> AsmCastTrait<usize, *const T> for AsmCast<usize, *const T> {
    type Type = usize;
    fn cast_in(_: &mut usize, x: *const T) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut usize, _: *const T, x: Self::Type) {
        *out = x as usize;
    }
}
impl<T> AsmCastTrait<*const T, usize> for AsmCast<*const T, usize> {
    type Type = usize;
    fn cast_in(_: &mut *const T, x: usize) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut *const T, _: usize, x: Self::Type) {
        *out = x as *const T;
    }
}
impl<T> AsmCastTrait<usize, *mut T> for AsmCast<usize, *mut T> {
    type Type = usize;
    fn cast_in(_: &mut usize, x: *mut T) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut usize, _: *mut T, x: Self::Type) {
        *out = x as usize;
    }
}
impl<T> AsmCastTrait<*mut T, usize> for AsmCast<*mut T, usize> {
    type Type = usize;
    fn cast_in(_: &mut *mut T, x: usize) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut *mut T, _: usize, x: Self::Type) {
        *out = x as *mut T;
    }
}
impl<T> AsmCastTrait<isize, *const T> for AsmCast<isize, *const T> {
    type Type = usize;
    fn cast_in(_: &mut isize, x: *const T) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut isize, _: *const T, x: Self::Type) {
        *out = x as isize;
    }
}
impl<T> AsmCastTrait<*const T, isize> for AsmCast<*const T, isize> {
    type Type = usize;
    fn cast_in(_: &mut *const T, x: isize) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut *const T, _: isize, x: Self::Type) {
        *out = x as *const T;
    }
}
impl<T> AsmCastTrait<isize, *mut T> for AsmCast<isize, *mut T> {
    type Type = usize;
    fn cast_in(_: &mut isize, x: *mut T) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut isize, _: *mut T, x: Self::Type) {
        *out = x as isize;
    }
}
impl<T> AsmCastTrait<*mut T, isize> for AsmCast<*mut T, isize> {
    type Type = usize;
    fn cast_in(_: &mut *mut T, x: isize) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut *mut T, _: isize, x: Self::Type) {
        *out = x as *mut T;
    }
}
impl<T> AsmCastTrait<u64, *const T> for AsmCast<u64, *const T> {
    type Type = u64;
    fn cast_in(_: &mut u64, x: *const T) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u64, _: *const T, x: Self::Type) {
        *out = x as u64;
    }
}
impl<T> AsmCastTrait<*const T, u64> for AsmCast<*const T, u64> {
    type Type = u64;
    fn cast_in(_: &mut *const T, x: u64) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut *const T, _: u64, x: Self::Type) {
        *out = x as *const T;
    }
}
impl<T> AsmCastTrait<u64, *mut T> for AsmCast<u64, *mut T> {
    type Type = u64;
    fn cast_in(_: &mut u64, x: *mut T) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u64, _: *mut T, x: Self::Type) {
        *out = x as u64;
    }
}
impl<T> AsmCastTrait<*mut T, u64> for AsmCast<*mut T, u64> {
    type Type = u64;
    fn cast_in(_: &mut *mut T, x: u64) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut *mut T, _: u64, x: Self::Type) {
        *out = x as *mut T;
    }
}
impl<T> AsmCastTrait<i64, *const T> for AsmCast<i64, *const T> {
    type Type = i64;
    fn cast_in(_: &mut i64, x: *const T) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i64, _: *const T, x: Self::Type) {
        *out = x as i64;
    }
}
impl<T> AsmCastTrait<*const T, i64> for AsmCast<*const T, i64> {
    type Type = i64;
    fn cast_in(_: &mut *const T, x: i64) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut *const T, _: i64, x: Self::Type) {
        *out = x as *const T;
    }
}
impl<T> AsmCastTrait<i64, *mut T> for AsmCast<i64, *mut T> {
    type Type = i64;
    fn cast_in(_: &mut i64, x: *mut T) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i64, _: *mut T, x: Self::Type) {
        *out = x as i64;
    }
}
impl<T> AsmCastTrait<*mut T, i64> for AsmCast<*mut T, i64> {
    type Type = i64;
    fn cast_in(_: &mut *mut T, x: i64) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut *mut T, _: i64, x: Self::Type) {
        *out = x as *mut T;
    }
}
impl AsmCastTrait<usize, u32> for AsmCast<usize, u32> {
    type Type = u64;
    fn cast_in(_: &mut usize, x: u32) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut usize, _: u32, x: Self::Type) {
        *out = x as usize;
    }
}
impl AsmCastTrait<u32, usize> for AsmCast<u32, usize> {
    type Type = u64;
    fn cast_in(_: &mut u32, x: usize) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u32, _: usize, x: Self::Type) {
        *out = x as u32;
    }
}
impl AsmCastTrait<usize, i32> for AsmCast<usize, i32> {
    type Type = u64;
    fn cast_in(_: &mut usize, x: i32) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut usize, _: i32, x: Self::Type) {
        *out = x as usize;
    }
}
impl AsmCastTrait<i32, usize> for AsmCast<i32, usize> {
    type Type = u64;
    fn cast_in(_: &mut i32, x: usize) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i32, _: usize, x: Self::Type) {
        *out = x as i32;
    }
}
impl AsmCastTrait<isize, u32> for AsmCast<isize, u32> {
    type Type = u64;
    fn cast_in(_: &mut isize, x: u32) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut isize, _: u32, x: Self::Type) {
        *out = x as isize;
    }
}
impl AsmCastTrait<u32, isize> for AsmCast<u32, isize> {
    type Type = u64;
    fn cast_in(_: &mut u32, x: isize) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u32, _: isize, x: Self::Type) {
        *out = x as u32;
    }
}
impl AsmCastTrait<isize, i32> for AsmCast<isize, i32> {
    type Type = u64;
    fn cast_in(_: &mut isize, x: i32) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut isize, _: i32, x: Self::Type) {
        *out = x as isize;
    }
}
impl AsmCastTrait<i32, isize> for AsmCast<i32, isize> {
    type Type = u64;
    fn cast_in(_: &mut i32, x: isize) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i32, _: isize, x: Self::Type) {
        *out = x as i32;
    }
}
impl<T> AsmCastTrait<u32, *const T> for AsmCast<u32, *const T> {
    type Type = u64;
    fn cast_in(_: &mut u32, x: *const T) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u32, _: *const T, x: Self::Type) {
        *out = x as u32;
    }
}
impl<T> AsmCastTrait<*const T, u32> for AsmCast<*const T, u32> {
    type Type = u64;
    fn cast_in(_: &mut *const T, x: u32) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut *const T, _: u32, x: Self::Type) {
        *out = x as *const T;
    }
}
impl<T> AsmCastTrait<u32, *mut T> for AsmCast<u32, *mut T> {
    type Type = u64;
    fn cast_in(_: &mut u32, x: *mut T) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut u32, _: *mut T, x: Self::Type) {
        *out = x as u32;
    }
}
impl<T> AsmCastTrait<*mut T, u32> for AsmCast<*mut T, u32> {
    type Type = u64;
    fn cast_in(_: &mut *mut T, x: u32) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut *mut T, _: u32, x: Self::Type) {
        *out = x as *mut T;
    }
}
impl<T> AsmCastTrait<i32, *const T> for AsmCast<i32, *const T> {
    type Type = u64;
    fn cast_in(_: &mut i32, x: *const T) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i32, _: *const T, x: Self::Type) {
        *out = x as i32;
    }
}
impl<T> AsmCastTrait<*const T, i32> for AsmCast<*const T, i32> {
    type Type = u64;
    fn cast_in(_: &mut *const T, x: i32) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut *const T, _: i32, x: Self::Type) {
        *out = x as *const T;
    }
}
impl<T> AsmCastTrait<i32, *mut T> for AsmCast<i32, *mut T> {
    type Type = u64;
    fn cast_in(_: &mut i32, x: *mut T) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut i32, _: *mut T, x: Self::Type) {
        *out = x as i32;
    }
}
impl<T> AsmCastTrait<*mut T, i32> for AsmCast<*mut T, i32> {
    type Type = u64;
    fn cast_in(_: &mut *mut T, x: i32) -> Self::Type {
        x as Self::Type
    }
    fn cast_out(out: &mut *mut T, _: i32, x: Self::Type) {
        *out = x as *mut T;
    }
}
