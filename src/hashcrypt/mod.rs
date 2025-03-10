//! Hashcrypt
use core::marker::PhantomData;

use embassy_hal_internal::{into_ref, Peripheral, PeripheralRef};
use hasher::Hasher;

use crate::clocks::enable_and_reset;
use crate::peripherals::{DMA0_CH30, HASHCRYPT};
use crate::{dma, pac};

/// Hasher module
pub mod hasher;

trait Sealed {}

/// Asynchronous or blocking mode
#[allow(private_bounds)]
pub trait Mode: Sealed {}

/// Blocking mode
pub struct Blocking {}
impl Sealed for Blocking {}
impl Mode for Blocking {}

/// Asynchronous mode
pub struct Async {}
impl Sealed for Async {}
impl Mode for Async {}

/// Trait for compatible DMA channels
#[allow(private_bounds)]
pub trait HashcryptDma: Sealed + dma::Instance {}
impl Sealed for DMA0_CH30 {}
impl HashcryptDma for DMA0_CH30 {}

/// Hashcrypt driver
pub struct Hashcrypt<'d, M: Mode> {
    hashcrypt: pac::Hashcrypt,
    dma_ch: Option<dma::channel::Channel<'d>>,
    _peripheral: PeripheralRef<'d, HASHCRYPT>,
    _mode: PhantomData<M>,
}

/// Hashcrypt mode
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
enum Algorithm {
    /// SHA256
    //SHA256,
    //AES
    AES,
}

impl From<Algorithm> for u8 {
    fn from(value: Algorithm) -> Self {
        match value {
            //Algorithm::SHA256 => 0x2,
            Algorithm::AES => 0x4,
        }
    }
}

impl<'d, M: Mode> Hashcrypt<'d, M> {
    /// Instantiate new Hashcrypt peripheral
    fn new_inner(peripheral: impl Peripheral<P = HASHCRYPT> + 'd, dma_ch: Option<dma::channel::Channel<'d>>) -> Self {
        enable_and_reset::<HASHCRYPT>();

        into_ref!(peripheral);

        Self {
            _peripheral: peripheral,
            _mode: PhantomData,
            dma_ch,
            hashcrypt: unsafe { pac::Hashcrypt::steal() },
        }
    }

    // Safety: unsafe for writing algorithm type to register
    fn start_aes(&mut self, _algorithm: Algorithm, decrypt: bool, _dma: bool) {
        //self.hashcrypt.ctrl().write(|w| w.mode().aes());

        /*
        self.hashcrypt.ctrl().write(|w| {
            unsafe { w.mode().bits(algorithm.into()) };
            if dma {
                w.dma_i().set_bit();
                w.dma_o().set_bit();
            }
            w
        });
        */

        if decrypt == false {
            self.hashcrypt.cryptcfg().modify(|_, w| {
                w.aesmode()
                    .ecb()
                    .aesdecrypt()
                    .encrypt()
                    .aessecret()
                    .normal_way()
                    .aeskeysz()
                    .bits_128()
            });
        } else {
            info!("decrypt");
            self.hashcrypt.cryptcfg().modify(|_, w| {
                w.aesmode()
                    .ecb()
                    .aesdecrypt()
                    .decrypt()
                    .aessecret()
                    .normal_way()
                    .aeskeysz()
                    .bits_128()
            });
        }

        self.hashcrypt
            .ctrl()
            .modify(|_, w| w.new_hash().start().mode().disabled());
        //self.hashcrypt.ctrl().modify(|_, w| w.new_hash().start().mode().aes());
        //info!("Read mode {:?}", self.hashcrypt.ctrl().read().mode().is_aes());

        self.hashcrypt.ctrl().modify(|_, w| {
            w.new_hash().start().mode().aes();
            /*
            if dma {
                w.dma_i().set_bit();
                w.dma_o().set_bit();
            }
            */
            w
        });
    }
}

impl<'d> Hashcrypt<'d, Blocking> {
    /// Create a new instance
    pub fn new_blocking(peripheral: impl Peripheral<P = HASHCRYPT> + 'd) -> Self {
        Self::new_inner(peripheral, None)
    }

    /// Start a new SHA256 hash
    pub fn new_sha256<'a>(&'a mut self) -> Hasher<'d, 'a, Blocking> {
        //self.start_algorithm(Algorithm::SHA256, false);
        Hasher::new_blocking(self)
    }

    /// AES encrypt
    pub fn new_aesencrypt<'a>(&'a mut self) -> Hasher<'d, 'a, Blocking> {
        self.start_aes(Algorithm::AES, false, false);
        Hasher::new_blocking(self)
    }

    /// AES decrypt
    pub fn new_aesdecrypt<'a>(&'a mut self) -> Hasher<'d, 'a, Blocking> {
        self.start_aes(Algorithm::AES, true, false);
        Hasher::new_blocking(self)
    }
}

impl<'d> Hashcrypt<'d, Async> {
    /// Create a new instance
    pub fn new_async(
        peripheral: impl Peripheral<P = HASHCRYPT> + 'd,
        dma_ch: impl Peripheral<P = impl HashcryptDma> + 'd,
    ) -> Self {
        Self::new_inner(peripheral, Some(dma::Dma::reserve_channel(dma_ch)))
    }

    /// AES encrypt
    pub fn new_aesencrypt<'a>(&'a mut self) -> Hasher<'d, 'a, Async> {
        self.start_aes(Algorithm::AES, false, true);
        Hasher::new_async(self)
    }

    /// AES decrypt
    pub fn new_aesdecrypt<'a>(&'a mut self) -> Hasher<'d, 'a, Async> {
        self.start_aes(Algorithm::AES, true, true);
        Hasher::new_async(self)
    }

    /// Start a new SHA256 hash
    pub fn new_sha256<'a>(&'a mut self) -> Hasher<'d, 'a, Async> {
        //self.start_algorithm(Algorithm::SHA256, true);
        Hasher::new_async(self)
    }
}
