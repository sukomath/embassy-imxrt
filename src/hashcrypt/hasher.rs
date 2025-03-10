use core::future::poll_fn;
use core::iter::zip;
use core::marker::PhantomData;
use core::task::Poll;

use embassy_futures::select::select;

use super::{Async, Blocking, Hashcrypt, Mode};
use crate::dma;
use crate::dma::transfer::{Transfer, Width};

/// Block length
pub const BLOCK_LEN: usize = 16;
/// Hash length
pub const HASH_LEN: usize = 32;
const END_BYTE: u8 = 0x80;

// 9 from the end byte and the 64-bit length
const LAST_BLOCK_MAX_DATA: usize = BLOCK_LEN - 9;

/// A hasher
pub struct Hasher<'d, 'a, M: Mode> {
    hashcrypt: &'a mut Hashcrypt<'d, M>,
    _mode: PhantomData<M>,
    written: usize,
}

impl<'d, 'a, M: Mode> Hasher<'d, 'a, M> {
    pub(super) fn new_inner(hashcrypt: &'a mut Hashcrypt<'d, M>) -> Self {
        Self {
            hashcrypt,
            _mode: PhantomData,
            written: 0,
        }
    }

    fn init_final_data(&self, data: &[u8], buffer: &mut [u8; BLOCK_LEN]) {
        buffer[..data.len()].copy_from_slice(data);
        buffer[data.len()] = END_BYTE;
    }

    fn init_final_block(&self, data: &[u8], buffer: &mut [u8; BLOCK_LEN]) {
        self.init_final_data(data, buffer);
        self.init_final_len(buffer);
    }

    fn init_final_len(&self, buffer: &mut [u8; BLOCK_LEN]) {
        buffer[BLOCK_LEN - 8..BLOCK_LEN].copy_from_slice(&(8 * self.written as u64).to_be_bytes());
    }

    fn wait_for_digest(&self) {
        /*
        if self.hashcrypt.hashcrypt.status().read().error().is_error() {
            info!("Error set");
        } else {
            info!("Error clear");
        }
        */

        while self.hashcrypt.hashcrypt.status().read().digest().is_not_ready() {}
    }

    /*
    fn wait_for_waiting(&self) {
        while self.hashcrypt.hashcrypt.status().read().waiting().is_waiting() {
            info!("Waiting");
        }

        info!("Done waiting");
    }
    */

    fn wait_for_needkey(&self) {
        while self.hashcrypt.hashcrypt.status().read().needkey().is_need() {}
    }

    /*
    fn check_for_needkey(&self) {
        if self.hashcrypt.hashcrypt.status().read().needkey().is_need() {
            info!("Need key set");
        } else {
            info!("Need key clear");
        }

        if self.hashcrypt.hashcrypt.status().read().neediv().is_need() {
            info!("Need div set");
        } else {
            info!("Need div clear");
        }

        if self.hashcrypt.hashcrypt.status().read().error().is_error() {
            info!("Error set");
        } else {
            info!("Error clear");
        }
    }
    */

    fn check_for_digest(&self) {
        self.hashcrypt.hashcrypt.ctrl().modify(|_, w| w.new_hash().start());
        self.hashcrypt
            .hashcrypt
            .ctrl()
            .modify(|_, w| w.new_hash().start().mode().aes());

        if self.hashcrypt.hashcrypt.status().read().digest().is_not_ready() {
            // info!("Digest not ready");
        } else {
            // info!("Digest ready");
        }
        if self.hashcrypt.hashcrypt.status().read().waiting().is_waiting() {
            //info!("Waiting set");
        } else {
            //info!("Waiting clear");
        }
    }

    fn read_hash(&mut self, hash: &mut [u8; HASH_LEN]) {
        for (reg, chunk) in zip(self.hashcrypt.hashcrypt.digest0_iter(), hash.chunks_mut(4)) {
            // Values in digest registers are little-endian, swap to BE to convert to a stream of bytes
            chunk.copy_from_slice(&reg.read().bits().to_be_bytes());
        }
    }

    fn read_encrypteddata(&mut self, encrypteddata: &mut [u8]) {
        for (reg, chunk) in zip(self.hashcrypt.hashcrypt.digest0_iter(), encrypteddata.rchunks_mut(4)) {
            // Values in digest registers are little-endian, swap to BE to convert to a stream of bytes
            chunk.copy_from_slice(&reg.read().bits().to_be_bytes());
        }

        //let addr = self.hashcrypt.hashcrypt.digest0(0).as_ptr() as *mut u32;
        //info!("Digest 0 {:02X}", unsafe { *addr });

        //let addr = self.hashcrypt.hashcrypt.digest0(3).as_ptr() as *mut u32;
        //info!("Digest 3 {:02X}", unsafe { *addr });
    }
}

impl<'d, 'a> Hasher<'d, 'a, Blocking> {
    /// Create a new hasher instance
    pub fn new_blocking(hashcrypt: &'a mut Hashcrypt<'d, Blocking>) -> Self {
        Self::new_inner(hashcrypt)
    }

    fn transfer_block(&mut self, data: &[u8; BLOCK_LEN]) {
        for word in data.chunks(4) {
            //let word = [0x61, 0x61, 0x61, 0x61];
            //info!("transfer block {:02X}", word);

            self.hashcrypt
                .hashcrypt
                .indata()
                .write(|w| unsafe { w.data().bits(u32::from_le_bytes([word[0], word[1], word[2], word[3]])) });
        }
        self.wait_for_digest();
    }

    /*
    fn write_block(&mut self, data: &[u8; BLOCK_LEN]) {
        for word in data.chunks(4) {
            self.hashcrypt
                .hashcrypt
                .indata()
                .write(|w| unsafe { w.data().bits(u32::from_le_bytes([word[0], word[1], word[2], word[3]])) });
        }
        self.wait_for_digest();
    }
    */

    fn write_key(&mut self, data: &[u8]) {
        //self.check_for_needkey();
        for word in data.chunks(4) {
            //info!("key{:02X}", word);
            self.hashcrypt
                .hashcrypt
                .indata()
                .write(|w| unsafe { w.data().bits(u32::from_le_bytes([word[0], word[1], word[2], word[3]])) });
        }
        self.wait_for_needkey();

        //self.check_for_needkey();
    }

    /// Submit one or more blocks of data to the hasher, data must be a multiple of the block length
    pub fn submit_blocks(&mut self, data: &[u8]) {
        if data.is_empty() || data.len() % BLOCK_LEN != 0 {
            panic!("Invalid data length");
        }

        self.check_for_digest();
        for block in data.chunks(BLOCK_LEN) {
            self.transfer_block(block.try_into().unwrap());
        }
        self.written += data.len();
        self.check_for_digest();
    }

    /// Submits the final data for hashing
    pub fn finalize(mut self, data: &[u8], hash: &mut [u8; HASH_LEN]) {
        let mut buffer = [0u8; BLOCK_LEN];

        self.written += data.len();
        if data.len() <= LAST_BLOCK_MAX_DATA {
            // Only have one final block
            self.init_final_block(data, &mut buffer);
            self.transfer_block(&buffer);
        } else {
            //End byte and padding won't fit in this block, submit this block and an extra one
            self.init_final_data(data, &mut buffer);
            self.transfer_block(&buffer);

            buffer.fill(0);
            self.init_final_len(&mut buffer);
            self.transfer_block(&buffer);
        }

        self.read_hash(hash);
    }

    /// Submits the final data for hashing
    pub fn finalizeencrypt(mut self, data: &[u8], encrypteddata: &mut [u8; 32]) {
        //let _buffer = [0u8; BLOCK_LEN];

        self.written += data.len();

        /*
        if data.len() <= LAST_BLOCK_MAX_DATA {
            // Only have one final block
            self.init_final_block(data, &mut buffer);
            self.transfer_block(&buffer);
        } else {
            //End byte and padding won't fit in this block, submit this block and an extra one
            self.init_final_data(data, &mut buffer);
            self.transfer_block(&buffer);

            buffer.fill(0);
            self.init_final_len(&mut buffer);
            self.transfer_block(&buffer);
        }
        */
        //info!("Buffer{}", buffer[0]);

        self.read_encrypteddata(encrypteddata);

        //self.check_status();
    }

    /// Computes the hash of the given data
    pub fn hash(mut self, data: &[u8], hash: &mut [u8; HASH_LEN]) {
        let full_blocks = data.len() / BLOCK_LEN;

        if full_blocks > 0 {
            self.submit_blocks(&data[0..full_blocks * BLOCK_LEN]);
        }
        self.finalize(&data[full_blocks * BLOCK_LEN..], hash);
    }

    /// Computes the hash of the given data
    pub fn encrypt(mut self, data: &[u8], encrypteddata: &mut [u8; 32]) {
        let aeskey = [
            //0x77, 0x0A, 0x8A, 0x65, 0xDA, 0x15, 0x6D, 0x24, 0xEE, 0x2A, 0x09, 0x32, 0x77, 0x53, 0x01, 0x42,
            //0x61, 0x65, 0x73, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x4b, 0x65, 0x79,
            0x59, 0x45, 0x4c, 0x4c, 0x4f, 0x57, 0x20, 0x53, 0x55, 0x42, 0x4d, 0x41, 0x52, 0x49, 0x4e, 0x45,
        ];
        self.write_key(&aeskey);

        //info!("Data len {}", data.len());

        let full_blocks = data.len() / BLOCK_LEN;

        //info!("Full blocks{}", full_blocks);
        if full_blocks > 0 {
            self.submit_blocks(&data[0..full_blocks * BLOCK_LEN]);
        }
        self.finalizeencrypt(&data[full_blocks * BLOCK_LEN..], encrypteddata);
    }
}

impl<'d, 'a> Hasher<'d, 'a, Async> {
    /// Create a new hasher instance
    pub fn new_async(hashcrypt: &'a mut Hashcrypt<'d, Async>) -> Self {
        Self::new_inner(hashcrypt)
    }

    /// Computes the hash of the given data
    pub async fn encrypt(mut self, data: &[u8], aeskey: &[u8], encrypteddata: &mut [u8; 32]) {
        info!("Key {:02X}", aeskey);

        let full_blocks_key = aeskey.len() / BLOCK_LEN;

        if full_blocks_key > 0 {
            self.submit_blocks_key(&aeskey[0..full_blocks_key * BLOCK_LEN]).await;
        }

        let full_blocks = data.len() / BLOCK_LEN;

        info!("Full blocks {:?}", full_blocks);

        self.hashcrypt
            .hashcrypt
            .ctrl()
            .modify(|_, w| w.dma_i().set_bit().dma_o().set_bit());

        //if full_blocks > 0 {
        let mut block_num = 0;
        let mut buf = [0u8; 16];
        for block in data.chunks(BLOCK_LEN) {
            self.submit_blocks(&block, &mut buf).await;
            info!("Encrypted buffer {:02X}", buf);
            encrypteddata[block_num * BLOCK_LEN..(block_num + 1) * BLOCK_LEN].copy_from_slice(&buf);
            info!("Encrypted data after copy {:02X}", encrypteddata);
            block_num += 1;
            //}
        }
        //self.finalizeencrypt(&data[0..full_blocks * BLOCK_LEN], encrypteddata)
        //  .await;
    }

    /// Submits the final data for hashing
    pub async fn finalizeencrypt(mut self, data: &[u8], hash: &mut [u8; 32]) {
        self.read_encrypteddata(hash);
    }

    async fn transfer(&mut self, data: &[u8]) {
        if data.is_empty() || data.len() % BLOCK_LEN != 0 {
            panic!("Invalid data length");
        }

        let options = dma::transfer::TransferOptions {
            width: Width::Bit32,
            ..Default::default()
        };

        info!("Transfer data {:02X}", data);

        let transfer = Transfer::new_write(
            self.hashcrypt.dma_ch.as_ref().unwrap(),
            data,
            self.hashcrypt.hashcrypt.indata().as_ptr() as *mut u8,
            options,
        );

        select(
            transfer,
            poll_fn(|_| {
                // Check if transfer is already complete
                if self.hashcrypt.hashcrypt.status().read().waiting().is_waiting() {
                    return Poll::Ready(());
                }
                Poll::Pending
            }),
        )
        .await;
        // Wait for the digest to finish, this takes <100 clock cycles so it's not worth doing async
        self.wait_for_digest();
    }

    async fn transfer_key(&mut self, data: &[u8]) {
        for word in data.chunks(4) {
            self.hashcrypt
                .hashcrypt
                .indata()
                .write(|w| unsafe { w.data().bits(u32::from_le_bytes([word[0], word[1], word[2], word[3]])) });
        }

        self.wait_for_needkey();
    }

    /// Submit one or more blocks of data to the hasher, data must be a multiple of the block length
    pub async fn submit_blocks(&mut self, data: &[u8], hash: &mut [u8; 16]) {
        self.transfer(data).await;
        self.written += data.len();
        self.read_encrypteddata(hash);
    }

    /// Submit one or more blocks of data to the hasher, data must be a multiple of the block length
    pub async fn submit_blocks_key(&mut self, data: &[u8]) {
        self.transfer_key(data).await;
        self.written += data.len();
    }

    /// Submits the final data for hashing
    pub async fn finalize(mut self, data: &[u8], hash: &mut [u8; HASH_LEN]) {
        let mut buffer = [0u8; BLOCK_LEN];

        self.written += data.len();
        if data.len() <= LAST_BLOCK_MAX_DATA {
            // Only have one final block
            self.init_final_block(data, &mut buffer);
            self.transfer(&buffer).await;
        } else {
            //End byte and padding won't fit in this block, submit this block and an extra one
            self.init_final_data(data, &mut buffer);
            self.transfer(&buffer).await;

            buffer.fill(0);
            self.init_final_len(&mut buffer);
            self.transfer(&buffer).await;
        }

        self.read_hash(hash);
    }

    /// Computes the hash of the given data
    pub async fn hash(mut self, data: &[u8], hash: &mut [u8; HASH_LEN]) {
        let full_blocks = data.len() / BLOCK_LEN;

        if full_blocks > 0 {
            //self.submit_blocks(&data[0..full_blocks * BLOCK_LEN]).await;
        }
        self.finalize(&data[full_blocks * BLOCK_LEN..], hash).await;
    }
}
