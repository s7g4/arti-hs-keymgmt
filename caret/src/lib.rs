//! # Crikey! Another Rust Enum Tool?
//!
//! This module declares macros for use in making int-like enums,
//! enum-like ints, and other types for use in the arti tor
//! implementation.

#![deny(missing_docs)]
#![deny(clippy::await_holding_lock)]
#![warn(clippy::clone_on_ref_ptr)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]

/// A macro to implement string and int conversions for c-like enums.
///
/// The `caret_enum!` macro lets you describe
/// "c-like" enumerations (ones with no data, only discriminators). It then
/// then automatically builds functions to convert those enums to
/// and from integer types, and to and from strings.
///
/// To use it, write something like:
///
/// ```
/// use caret::caret_enum;
///
/// caret_enum! {
///     #[derive(Debug)]
///     pub enum Fruit as u16 {
///         Peach = 1,
///         Pear,
///         Plum,
///    }
/// }
/// ```
///
/// When you define an enum using `caret_enum!`, it automatically gains
/// conversion methods:
///
/// ```
/// # use caret::caret_enum;
/// # caret_enum! { #[derive(Debug)]
/// #    pub enum Fruit as u16 {
/// #    Peach = 1, Pear, Plum
/// # } }
/// assert_eq!(Fruit::Peach.to_int(), 1);
/// assert_eq!(Fruit::Pear.to_str(), "Pear");
/// assert_eq!(Fruit::from_int(1), Some(Fruit::Peach));
/// assert_eq!(Fruit::from_string("Plum"), Some(Fruit::Plum));
/// ```
///
/// The `caret_enum!` macro will also implement several traits for you:
///
/// ```
/// # use caret::caret_enum;
/// # caret_enum! { #[derive(Debug)]
/// #    pub enum Fruit as u16 {
/// #    Peach = 1, Pear, Plum
/// # } }
/// // impl From<Fruit> for u16
/// let val: u16 = Fruit::Peach.into();
/// assert_eq!(val, 1u16);
///
/// // impl From<Fruit> for &str
/// let val: &str = Fruit::Plum.into();
/// assert_eq!(val, "Plum");
///
/// // impl Display for Fruit
/// assert_eq!(format!("I need a recipe for a {} pie", Fruit::Peach),
///            "I need a recipe for a Peach pie");
///
/// // impl TryFrom<u16> for Fruit
/// use std::convert::TryInto;
/// let fruit: Fruit = 3u16.try_into().unwrap();
/// assert_eq!(fruit, Fruit::Plum);
///
/// // impl FromStr for Fruit
/// let fruit: Fruit = "Pear".parse().unwrap();
/// assert_eq!(fruit, Fruit::Pear);
/// ```
///
/// Finally, the enumeration will have derived implementations for Eq,
/// PartialEq, Copy, and Clone, as you'd expect from a fancy alias for
/// u16.
///
/// If you specify some other integer type instead of `u16`, that type
/// will be used as a representation instead.
///
/// You can specify specific values for the enumerated elements:
///
/// ```
/// # use caret::*;
/// caret_enum!{
///     #[derive(Debug)]
///     pub enum Fruit as u8 {
///         Peach = 1,
///         Pear = 5,
///         Plum = 9,
///     }
/// }
///
/// assert_eq!(Fruit::from_int(5), Some(Fruit::Pear));
/// ```
///
/// ## Advanced features
///
/// You can also override the string representation for enumerated elements:
/// ```
/// # use caret::*;
/// caret_enum!{
///     #[derive(Debug)]
///     pub enum Fruit as u8 {
///        Peach ("donut"),
///        Pear ("anjou"),
///        Plum ("mirabelle") = 9,
///     }
/// }
///
/// let fruit: Fruit = "mirabelle".parse().unwrap();
/// assert_eq!(fruit, Fruit::Plum);
/// ```
/// ## Ackowledgments
///
/// This crate combines ideas from several other crates that
/// build C-like enums together with appropriate conversion functions to
/// convert to and from associated integers and associated constants.
/// It's inspired by features from enum_repr, num_enum, primitive_enum,
/// enum_primitive, enum_from_str, enum_str, enum-utils-from-str, and
/// numeric-enum-macro.  I'm not sure it will be useful to anybody but
/// me.
#[macro_export]
macro_rules! caret_enum {
    {
       $(#[$meta:meta])*
       $v:vis enum $name:ident as $numtype:ident {
           $(
               $(#[$item_meta:meta])*
               $id:ident $( ( $as_str:literal ) )? $( = $num:literal )?
           ),*
           $( , )?
      }
    } => {
        #[repr( $numtype )]
        #[derive(PartialEq,Eq,Copy,Clone)]
        $(#[$meta])*
        $v enum $name {
            $( $( #[$item_meta] )* $id $( = $num )? , )*
        }

        impl $name {
            /// Convert an instance of this enumeration to an integer.
            ///
            /// (implemented by caret_enum!)
            pub fn to_int(self) -> $numtype {
                match self {
                    $( $name::$id => $name::$id as $numtype , )*
                }
            }
            /// Convert an instance of this enumeration object to a string.
            ///
            /// (implemented by caret_enum!)
            pub fn to_str(self) -> &'static str {
                match self {
                    $( $name::$id => $crate::caret_enum!(@impl string_for $id $($as_str)?) , )*
                }
            }
            /// Convert an integer to an instance of this enumeration.
            ///
            /// If the provided integer does not represent an instance
            /// of this enumeration, return None.
            pub fn from_int(val: $numtype) -> Option<Self> {
                #![allow(non_upper_case_globals)]
                $( const $id : $numtype = $name::$id as $numtype; )*
                match val {
                    $( $id => Some($name::$id) , )*
                    _ => None
                }
            }
            /// Convert a string to an instance of this enumeration.
            ///
            /// If the provided string does not represent an instance
            /// of this enumeration, return None.
            fn from_string(val: &str) -> Option<Self> {
                match val {
                    $( $crate::caret_enum!(@impl string_for $id $($as_str)?) => Some($name::$id) , )*
                    _ => None
                }
            }
        }

        impl std::convert::From<$name> for $numtype {
            fn from(val: $name) -> $numtype {
                val.to_int()
            }
        }
        impl std::convert::From<$name> for &'static str {
            fn from(val: $name) -> &'static str {
                val.to_str()
            }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.to_str())
            }
        }
        impl std::convert::TryFrom<$numtype> for $name {
            type Error = $crate::Error;
            fn try_from(val: $numtype) -> std::result::Result<Self, Self::Error> {
                $name::from_int(val).ok_or($crate::Error::InvalidInteger)
            }
        }
        impl std::str::FromStr for $name {
            type Err = $crate::Error;
            fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
                $name::from_string(s).ok_or($crate::Error::InvalidString)
            }
        }
    };

    // Internal helpers
    [ @impl string_for $id:ident $str:literal ] => ( $str );
    [ @impl string_for $id:ident ] => ( stringify!($id) );
}

/// An error produced from type derived from type.  These errors can
/// only occur when trying to convert to a type made with caret_enum!
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Tried to convert to an enumeration type from an integer that
    /// didn't represent a member of that enumeration.
    InvalidInteger,
    /// Tried to convert to an enumeration type from a string that
    /// didn't represent a member of that enumeration.
    InvalidString,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidInteger => write!(f, "Integer was not member of this enumeration"),
            Error::InvalidString => write!(f, "String was not member of this enumeration"),
        }
    }
}

impl std::error::Error for Error {}

/// Declare an integer type with some named elements.
///
/// Unlike caret_enum!, this macro declares a struct that wraps an integer
/// type, and allows any integer type as a value.  Some values of this type
/// have names, and others do not, but they are all allowed.
///
/// This macro is suitable for protocol implementations that accept
/// any integer on the wire, and have definitions for some of those
/// integers.  For example, Tor cell commands are 8 bit integers, but
/// not every u8 is a currently recognized Tor command.
///
/// # Examples
/// ```
/// use caret::caret_int;
/// caret_int! {
///     pub struct FruitID(u8) {
///         AVOCADO = 7,
///         PERSIMMON = 8,
///         LONGAN = 99
///     }
/// }
///
/// // Known fruits work the way we would expect...
/// let a_num: u8 = FruitID::AVOCADO.into();
/// assert_eq!(a_num, 7);
/// let a_fruit: FruitID = 8.into();
/// assert_eq!(a_fruit, FruitID::PERSIMMON);
/// assert_eq!(format!("I'd like a {}", FruitID::PERSIMMON),
///            "I'd like a PERSIMMON");
///
/// // And we can construct unknown fruits, if we encounter any.
/// let weird_fruit: FruitID = 202.into();
/// assert_eq!(format!("I'd like a {}", weird_fruit),
///            "I'd like a 202");
/// ```
#[macro_export]
macro_rules! caret_int {
    {
       $(#[$meta:meta])*
       $v:vis struct $name:ident ( $numtype:ty ) {
           $(
               $(#[$item_meta:meta])*
               $id:ident = $num:literal
           ),*
           $(,)?
      }
    } => {
        #[derive(PartialEq,Eq,Copy,Clone)]
        $(#[$meta])*
        $v struct $name($numtype);

        impl From<$name> for $numtype {
            fn from(val: $name) -> $numtype { val.0 }
        }
        impl From<$numtype> for $name {
            fn from(num: $numtype) -> $name { $name(num) }
        }
        impl $name {
            $(
                $( #[$item_meta] )*
                pub const $id: $name = $name($num) ; )*
            fn to_str(self) -> Option<&'static str> {
                match self {
                    $( $name::$id => Some(stringify!($id)), )*
                    _ => None,
                }
            }
            /// Return true if this value is one that we recognize.
            $v fn is_recognized(self) -> bool {
                matches!(self,
                         $( $name::$id )|*)
            }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self.to_str() {
                    Some(s) => write!(f, "{}", s),
                    None => write!(f, "{}", self.0),
                }
            }
        }
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}({})", stringify!($name), self)
            }
        }
    };

}
