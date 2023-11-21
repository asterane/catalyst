// Catalyst, a program for selecting an option

// Copyright 2023 Matthew Rothlisberger

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// SPDX-License-Identifier: Apache-2.0

// <>

// src/main.rs

// <>

fn main() {
    //! Select randomly from a list of potential options according to a
    //! weight included along with each list item

    let weights_txt = match std::fs::read_to_string(match std::env::args().nth(1) {
        Some(s) => s,
        None => err_fail(ErrMode::WeightsNoPath),
    }) {
        Ok(s) => s,
        Err(_) => err_fail(ErrMode::WeightsNoOpen),
    };

    // weights are stored as fractions of u16::MAX
    let mut items: Vec<(String, u16)> = Vec::new();
    let mut chars = weights_txt.bytes();
    loop {
        let mut cacc = Vec::new();

        match chars.next() {
            Some(b'\n') => continue,
            Some(b'-') => match chars.next() {
                Some(b'-') => {
                    while chars.next() != Some(b'\n') {}
                    continue;
                }
                _ => err_fail(ErrMode::FileBadCmmnt),
            },
            Some(b) => cacc.push(b),
            None => (),
        }

        for c in chars.by_ref() {
            if c == b'0' || c == b'\n' {
                break;
            }
            cacc.push(c);
        }

        if cacc.is_empty() {
            break;
        }

        if (cacc.pop().unwrap() != b' ') || (chars.next().unwrap_or(0) != b'.') {
            err_fail(ErrMode::FileBadEntry)
        }

        let mut dacc = 0;
        let mut pv = 1;
        for c in chars.by_ref() {
            if !c.is_ascii_digit() {
                break;
            }
            dacc += (((c - b'0') as u64 * u16::MAX as u64) / (10_u64.pow(pv))) as u16;
            pv += 1;
        }

        items.push((String::from_utf8(cacc).unwrap(), dacc));
    }

    {
        let total_sum = items.iter().map(|it| it.1 as u64).sum::<u64>();
        if !(total_sum >= u16::MAX as u64 - items.len() as u64) || !(total_sum <= u16::MAX as u64) {
            err_fail(ErrMode::IncorrectSum)
        }
    }

    // miniscule chance of no selection, so repeat
    loop {
        let selector = get_rnd_sel();

        if cfg!(feature = "dbg") {
            println!("(dbg) {:?}", items);
            println!("(dbg) {}", selector);
        }

        let mut sacc = 0;
        for (s, w) in &items {
            let start = sacc;
            sacc += w;

            if selector >= start && selector < sacc {
                println!("{}", s);
                return;
            }
        }
    }
}

/// Get 16 random bits from the kernel
fn get_rnd_sel() -> u16 {
    let mut buf = [0u8; 2];

    unsafe {
        let getrandom = 318u64;
        let rand_buf = &mut buf as *mut u8;
        let rand_len = 2u64;
        let rand_flags = 0u64;

        let rand_out: u64;

        std::arch::asm!("syscall",
                        in("rax") getrandom,
                        in("rdi") rand_buf,
                        in("rsi") rand_len,
                        in("rdx") rand_flags,
                        lateout("rax") rand_out,
                        out("rcx") _,
                        out("r11") _,
        );

        assert_eq!(rand_out, rand_len);

        std::mem::transmute::<[u8; 2], u16>(buf)
    }
}

#[repr(i32)]
enum ErrMode {
    WeightsNoPath = 10,
    WeightsNoOpen = 11,
    FileBadEntry = 20,
    FileBadCmmnt = 21,
    IncorrectSum = 30,
}

/// Prints error message and terminates process
fn err_fail(code: ErrMode) -> ! {
    eprint!("Failed: ");

    use ErrMode::*;
    match code {
        WeightsNoPath => eprintln!("Missing path to weights file"),
        WeightsNoOpen => eprintln!("Weights file not found"),
        FileBadEntry => eprintln!("Improper weights file format (entry)"),
        FileBadCmmnt => eprintln!("Improper weights file format (comment)"),
        IncorrectSum => eprintln!("Weights do not sum to 1"),
    }

    std::process::exit(code as _)
}
