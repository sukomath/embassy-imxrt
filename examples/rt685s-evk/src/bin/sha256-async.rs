#![no_std]
#![no_main]

use defmt::*;
use embassy_executor::Spawner;
use embassy_imxrt::hashcrypt::{hasher, Async as hashAsync, Hashcrypt};
use embassy_imxrt::uart::{Async, Uart};
use embassy_imxrt::{bind_interrupts, peripherals, uart};
use embassy_time::Timer;
use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    FLEXCOMM4 => uart::InterruptHandler<peripherals::FLEXCOMM4>;
});

const BUFLEN: usize = 32;

#[embassy_executor::task]
async fn usart4_task(mut uart: Uart<'static, Async>, mut hashcrypt: Hashcrypt<'static, hashAsync>) {
    info!("RX Task");

    loop {
        let mut rx_buf = [0; BUFLEN + 1];
        uart.read(&mut rx_buf).await.unwrap();

        info!("Rx buf {:02X}", rx_buf);
        Timer::after_millis(10).await;

        let key = b"dcbadcbadcbadcbf";

        let mut inputdata = [0u8; BUFLEN];
        let mut aeskey = [0u8; 16];
        let mut i = 0;

        for byte in key.iter().rev() {
            aeskey[i] = *byte;
            i += 1;
        }
        i = 0;
        for byte in rx_buf[1..].iter().rev() {
            inputdata[i] = *byte;
            i += 1;
        }
        info!("inputdata{:02X}", inputdata);
        if rx_buf[0] == b'e' {
            let mut encrypteddata = [0u8; BUFLEN];
            //let bytes = b"hello12345";

            hashcrypt
                .new_aesencrypt()
                .encrypt(&inputdata, &aeskey, &mut encrypteddata)
                .await;
            info!("Encrypted data {:02X}", encrypteddata);

            let mut i = 0;
            for byte in encrypteddata.iter().rev() {
                inputdata[i] = *byte;
                i += 1;
            }

            /*
            let mut buf = [0u8; 33];
            buf[..32].clone_from_slice(&encrypteddata);
            buf[32] = 0x0a;
            */
            info!("Sending buffer {:02X}", encrypteddata);
            uart.write(&encrypteddata).await.unwrap();
        } else if rx_buf[0] == b'd' {
            let mut decrypteddata = [0u8; BUFLEN];
            let mut decdata = [0u8; BUFLEN];
            /*
            let mut i = 0;
            for byte in inputdata.iter().rev() {
                decdata[i] = *byte;
                i += 1;
            }
            */

            hashcrypt
                .new_aesdecrypt()
                .encrypt(&inputdata, &aeskey, &mut decrypteddata)
                .await;

            let s = core::str::from_utf8(&decrypteddata).unwrap();
            info!("Decrypted data {:02X}", decrypteddata);
            info!("Decrypted data {}", s);
            /*
            let mut buf = [0u8; 33];
            buf[..32].clone_from_slice(&decrypteddata);
            buf[32] = 0x0a;
            */
            info!("Sending buffer {:02X}", decrypteddata);
            uart.write(&decrypteddata).await.unwrap();
        }
    }
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_imxrt::init(Default::default());
    let mut _hash = [0u8; hasher::HASH_LEN];

    info!("Initializing Hashcrypt");
    let hashcrypt = Hashcrypt::new_async(p.HASHCRYPT, p.DMA0_CH30);

    let usart4 = Uart::new_with_rtscts(
        p.FLEXCOMM4,
        p.PIO0_29,
        p.PIO0_30,
        p.PIO1_0,
        p.PIO0_31,
        Irqs,
        p.DMA0_CH9,
        p.DMA0_CH8,
        Default::default(),
    )
    .unwrap();
    spawner.must_spawn(usart4_task(usart4, hashcrypt));

    /*
    let mut encrypteddata = [0u8; 16];
    let mut decrypteddata = [0u8; 16];

    let bytes = b"hello12345";

    let key = b"dcbadcbadcbadcbf";

    let mut inputdata = [0u8; 16];
    let mut aeskey = [0u8; 16];
    let mut i = 0;

    for byte in key.iter().rev() {
        aeskey[i] = *byte;
        i += 1;
    }
    i = 0;
    for byte in bytes.iter().rev() {
        inputdata[i] = *byte;
        i += 1;
    }
    info!("inputdata{:02X}", inputdata);
    hashcrypt
        .new_aesencrypt()
        .encrypt(&inputdata, &aeskey, &mut encrypteddata)
        .await;
    info!("Encrypted data {:02X}", encrypteddata);

    let mut i = 0;
    for byte in encrypteddata.iter().rev() {
        inputdata[i] = *byte;
        i += 1;
    }

    hashcrypt
        .new_aesdecrypt()
        .encrypt(&inputdata, &aeskey, &mut decrypteddata)
        .await;

    let s = core::str::from_utf8(&decrypteddata).unwrap();

    info!("Decrypted data {}", s);
    */

    /*
    info!("Starting hashes");
    // Data that fits into a single block
    info!("Single hash block");
    hashcrypt.new_sha256().hash(b"abc", &mut hash).await;
    defmt::assert_eq!(
        &hash,
        &[
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03,
            0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
        ]
    );

    // Data that fits into two blocks
    info!("Two hash blocks");
    hashcrypt
        .new_sha256()
        .hash(
            b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()",
            &mut hash,
        )
        .await;
    defmt::assert_eq!(
        &hash,
        &[
            0xc6, 0x53, 0xd6, 0xb8, 0x3a, 0x21, 0x1a, 0x73, 0xe4, 0xf2, 0x50, 0x1b, 0xdf, 0x30, 0x53, 0x28, 0xaa, 0x8e,
            0x6f, 0x8f, 0xca, 0x46, 0x16, 0xf7, 0x19, 0x3f, 0xd4, 0xda, 0x5a, 0xca, 0xcc, 0x2e
        ]
    );

    // Data that is exactly one block
    info!("One block exactly");
    hashcrypt
        .new_sha256()
        .hash(
            b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@",
            &mut hash,
        )
        .await;
    defmt::assert_eq!(
        &hash,
        &[
            0x85, 0x7c, 0xce, 0x23, 0xb6, 0xba, 0x40, 0xd9, 0xa8, 0x33, 0x0d, 0x93, 0x97, 0x98, 0x1d, 0xa5, 0x8f, 0x5a,
            0x8f, 0x41, 0x34, 0x44, 0xc7, 0xa4, 0x1c, 0x42, 0x01, 0xa1, 0x47, 0x76, 0x51, 0xef
        ]
    );

    // Data where the final block needs to be split over two blocks
    info!("Split final block");
    hashcrypt.new_sha256().hash(
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ12345678",
        &mut hash,
    ).await;
    defmt::assert_eq!(
        &hash,
        &[
            0x1a, 0xdc, 0x94, 0xa1, 0xa4, 0x10, 0x77, 0x4a, 0x59, 0xf8, 0x60, 0xe3, 0x09, 0xf1, 0x1d, 0x62, 0x1d, 0xae,
            0x44, 0x95, 0x1d, 0xcd, 0xfc, 0xd0, 0x89, 0x90, 0xef, 0xe2, 0xb2, 0x4d, 0xac, 0x79
        ]
    );
    trace!("Hashes complete");
    */
}
