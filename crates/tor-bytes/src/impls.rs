//! Implementations of Writeable and Readable for several items that
//! we use in Tor.
//!
//! These don't need to be in a separate module, but for convenience
//! this is where I'm putting them.

use super::*;
use generic_array::GenericArray;

// ----------------------------------------------------------------------

/// Vec<u8> is the main type that implements Writer.
impl Writer for Vec<u8> {
    fn write_all(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
    fn write_u8(&mut self, byte: u8) {
        // specialize for performance
        self.push(byte);
    }
    fn write_zeros(&mut self, n: usize) {
        // specialize for performance
        let new_len = self.len() + n;
        self.resize(new_len, 0);
    }
}

impl Writer for bytes::BytesMut {
    fn write_all(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

// ----------------------------------------------------------------------

impl<'a> Writeable for [u8] {
    fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
        b.write_all(self)
    }
}

impl Writeable for Vec<u8> {
    fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
        b.write_all(&self[..])
    }
}

/* There is no specialization in Rust yet, or we would make an implementation
   for this.

impl<N> Readable for GenericArray<u8, N>
where
    N: generic_array::ArrayLength<u8>,
{
    fn take_from(b: &mut Reader) -> Result<Self> {
        // safety -- "take" returns the requested bytes or error.
        Ok(Self::from_slice(b.take(N::to_usize())?).clone())
    }
}

impl<N> Writeable for GenericArray<u8, N>
where
    N: generic_array::ArrayLength<u8>,
{
    fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
        b.write_all(self.as_slice())
    }
}
*/

/// The GenericArray type is defined to work around a limitation in Rust's
/// typesystem.
impl<T, N> Readable for GenericArray<T, N>
where
    T: Readable + Clone,
    N: generic_array::ArrayLength<T>,
{
    fn take_from(b: &mut Reader<'_>) -> Result<Self> {
        let mut v: Vec<T> = Vec::new();
        for _ in 0..N::to_usize() {
            v.push(T::take_from(b)?);
        }
        // XXXX I wish I didn't have to clone this.
        Ok(Self::from_slice(v.as_slice()).clone())
    }
}

impl<T, N> Writeable for GenericArray<T, N>
where
    T: Writeable,
    N: generic_array::ArrayLength<T>,
{
    fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
        for item in self {
            item.write_onto(b)
        }
    }
}

// Implementations for reading and writing the unsigned types.
macro_rules! impl_u {
    ( $t:ty, $wrfn:ident, $rdfn:ident ) => {
        impl Writeable for $t {
            fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
                b.$wrfn(*self)
            }
        }
        impl Readable for $t {
            fn take_from(b: &mut Reader<'_>) -> Result<Self> {
                b.$rdfn()
            }
        }
    };
}

impl_u!(u8, write_u8, take_u8);
impl_u!(u16, write_u16, take_u16);
impl_u!(u32, write_u32, take_u32);
impl_u!(u64, write_u64, take_u64);
impl_u!(u128, write_u128, take_u128);

// ----------------------------------------------------------------------

/// Implement Readable and Writeable for IPv4 and IPv6 addresses.
///
/// These are encoded as a sequence of octets, not as strings.
mod net_impls {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    impl Writeable for Ipv4Addr {
        fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
            b.write_all(&self.octets()[..])
        }
    }

    impl Readable for Ipv4Addr {
        fn take_from(r: &mut Reader<'_>) -> Result<Self> {
            Ok(r.take_u32()?.into())
        }
    }

    impl Writeable for Ipv6Addr {
        fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
            b.write_all(&self.octets()[..])
        }
    }
    impl Readable for Ipv6Addr {
        fn take_from(r: &mut Reader<'_>) -> Result<Self> {
            Ok(r.take_u128()?.into())
        }
    }
}

/// Implement Readable and Writeable for Ed25519 types.
mod ed25519_impls {
    use super::*;
    use signature::Signature;
    use tor_llcrypto::pk::ed25519;

    impl Writeable for ed25519::PublicKey {
        fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
            b.write_all(self.as_bytes())
        }
    }
    impl Readable for ed25519::PublicKey {
        fn take_from(b: &mut Reader<'_>) -> Result<Self> {
            let bytes = b.take(32)?;
            Self::from_bytes(array_ref![bytes, 0, 32])
                .map_err(|_| Error::BadMessage("Couldn't decode Ed25519 public key"))
        }
    }

    impl Writeable for ed25519::Ed25519Identity {
        fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
            b.write_all(self.as_bytes())
        }
    }
    impl Readable for ed25519::Ed25519Identity {
        fn take_from(b: &mut Reader<'_>) -> Result<Self> {
            let bytes = b.take(32)?;
            Ok(Self::new(*array_ref![bytes, 0, 32]))
        }
    }
    impl Writeable for ed25519::Signature {
        fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
            b.write_all(&self.to_bytes()[..])
        }
    }
    impl Readable for ed25519::Signature {
        fn take_from(b: &mut Reader<'_>) -> Result<Self> {
            let bytes = b.take(64)?;
            Self::from_bytes(array_ref![bytes, 0, 64])
                .map_err(|_| Error::BadMessage("Couldn't decode Ed25519 signature."))
        }
    }
}

/// Implement Readable and Writeable for Curve25519 types.
mod curve25519_impls {
    use super::*;
    use tor_llcrypto::pk::curve25519::{PublicKey, SharedSecret};

    impl Writeable for PublicKey {
        fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
            b.write_all(self.as_bytes())
        }
    }
    impl Readable for PublicKey {
        fn take_from(b: &mut Reader<'_>) -> Result<Self> {
            let bytes = b.take(32)?;
            Ok((*array_ref![bytes, 0, 32]).into())
        }
    }
    impl Writeable for SharedSecret {
        fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
            b.write_all(self.as_bytes())
        }
    }
}

/// Implement readable and writeable for the the RsaIdentity type.
mod rsa_impls {
    use super::*;
    use tor_llcrypto::pk::rsa::*;

    impl Writeable for RsaIdentity {
        fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
            b.write_all(self.as_bytes())
        }
    }
    impl Readable for RsaIdentity {
        fn take_from(b: &mut Reader<'_>) -> Result<Self> {
            let m = b.take(RSA_ID_LEN)?;
            Ok(RsaIdentity::from_bytes(m).expect("take gave wrong length"))
        }
    }
}

/// Implement readable and writeable for the crypto_mac::Output type.
mod mac_impls {
    use super::*;
    use crypto_mac::{Mac, Output};
    impl<M: Mac> WriteableOnce for Output<M> {
        fn write_into<B: Writer + ?Sized>(self, b: &mut B) {
            let code = self.into_bytes();
            b.write(&code[..])
        }
    }
    impl<M: Mac> Readable for Output<M> {
        fn take_from(b: &mut Reader<'_>) -> Result<Self> {
            let array = GenericArray::take_from(b)?;
            Ok(Output::new(array))
        }
    }
}

/// Implement readable and writeable for common sizes of u8 arrays.
mod u8_array_impls {
    use super::*;
    macro_rules! impl_array {
        ($n:literal) => {
            impl Writeable for [u8; $n] {
                fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
                    b.write_all(&self[..])
                }
            }
            impl Readable for [u8; $n] {
                fn take_from(r: &mut Reader<'_>) -> Result<Self> {
                    let bytes = r.take($n)?;
                    Ok(array_ref!(bytes, 0, $n).clone())
                }
            }
        };
    }
    // These are the lengths we know we need right now.
    impl_array! {16}
    impl_array! {20}
    impl_array! {32}
}

#[cfg(test)]
mod tests {
    use crate::{Reader, Writer};
    use hex_literal::hex;
    macro_rules! check_encode {
        ($e:expr, $e2:expr) => {
            let mut w = Vec::new();
            w.write(&$e);
            assert_eq!(&w[..], &$e2[..]);
        };
    }
    macro_rules! check_decode {
        ($t:ty, $e:expr, $e2:expr) => {
            let mut r = Reader::from_slice(&$e[..]);
            let obj: $t = r.extract().unwrap();
            assert_eq!(obj, $e2);
            assert!(r.should_be_exhausted().is_ok());
        };
    }
    macro_rules! check_roundtrip {
        ($t:ty, $e:expr, $e2:expr) => {
            check_encode!($e, $e2);
            check_decode!($t, $e2, $e);
        };
    }
    macro_rules! check_bad {
        ($t:ty, $e:expr) => {
            let mut r = Reader::from_slice(&$e[..]);
            let len_orig = r.remaining();
            let res: Result<$t, _> = r.extract();
            assert!(res.is_err());
            assert_eq!(r.remaining(), len_orig);
        };
    }
    #[test]
    fn vec_u8() {
        let v: Vec<u8> = vec![1, 2, 3, 4];
        check_encode!(v, b"\x01\x02\x03\x04");
    }

    #[test]
    fn genarray() {
        use generic_array as ga;
        let a: ga::GenericArray<u16, ga::typenum::U7> = [4, 5, 6, 7, 8, 9, 10].into();
        check_roundtrip!(ga::GenericArray<u16, ga::typenum::U7>,
                         a,
                         [0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 0, 9, 0, 10]);
    }

    #[test]
    fn roundtrip_u64() {
        check_roundtrip!(u64, 0x4040111u64, [0, 0, 0, 0, 4, 4, 1, 17]);
    }

    #[test]
    fn u8_array() {
        check_roundtrip!(
            [u8; 16],
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        );
    }

    #[test]
    fn ipv4addr() {
        use std::net::Ipv4Addr;
        check_roundtrip!(Ipv4Addr, Ipv4Addr::new(192, 168, 0, 1), [192, 168, 0, 1]);
    }

    #[test]
    fn ipv6addr() {
        use std::net::Ipv6Addr;
        check_roundtrip!(
            Ipv6Addr,
            Ipv6Addr::new(65535, 77, 1, 1, 1, 0, 0, 0),
            [255, 255, 0, 77, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn ed25519() {
        use signature::Signature;
        use tor_llcrypto::pk::ed25519;
        let b = &hex!(
            "68a6cee11d2883661f5876f7aac748992cd140f
             cfc36923aa957d04b5f8967ff"
        );
        check_roundtrip!(
            ed25519::PublicKey,
            ed25519::PublicKey::from_bytes(b).unwrap(),
            b
        );
        let b = &hex!(
            "68a6cee11d2883661f5876f7aac748992cd140f
             cfc36923aa957d04b5f8967"
        ); // too short
        check_bad!(ed25519::PublicKey, b);
        let b = &hex!(
            "68a6cee11d2883661f5876f7aac748992cd140f
             cfc36923aa957d04b5f896700"
        ); // not a valid compressed Y
        check_bad!(ed25519::PublicKey, b);

        let sig = &hex!(
            "b8842c083a56076fc27c8af21211f9fe57d1c32d9d
             c804f76a8fa858b9ab43622b9e8335993c422eab15
             6ebb5a047033f35256333a47a508b02699314d22550e"
        );
        check_roundtrip!(
            ed25519::Signature,
            ed25519::Signature::from_bytes(sig).unwrap(),
            sig
        );
        let sig = &hex!(
            "b8842c083a56076fc27c8af21211f9fe57d1c32d9d
             c804f76a8fa858b9ab43622b9e8335993c422eab15
             6ebb5a047033f35256333a47a508b02699314d2255ff"
        );
        check_bad!(ed25519::Signature, sig);
    }

    #[test]
    fn curve25519() {
        use tor_llcrypto::pk::curve25519;
        let b = &hex!("5f6df7a2fe3bcf1c9323e9755250efd79b9db4ed8f3fd21c7515398b6662a365");
        let pk: curve25519::PublicKey = (*b).into();
        check_roundtrip!(curve25519::PublicKey, pk, b);
    }

    #[test]
    fn rsa_id() {
        use tor_llcrypto::pk::rsa::RsaIdentity;
        let b = &hex!("9432D4CEA2621ED09F5A8088BE0E31E0D271435C");
        check_roundtrip!(RsaIdentity, RsaIdentity::from_bytes(b).unwrap(), b);
    }
}
