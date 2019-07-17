# XChaCha20 - Extended Nonce Version of ChaCha20

XChaCha20 is a stream cipher based on ChaCha20. XChaCha20 uses a 256-bit
key and a 192-bit nonce. According to an [IETF draft:](https://tools.ietf.org/html/draft-arciszewski-xchacha-02), "The eXtended-nonce ChaCha cipher construction (XChaCha) allows for
ChaCha-based ciphersuites to accept a 192-bit nonce with similar guarantees
to the original construction, except with a much lower probability of
nonce misuse occurring. This enables XChaCha constructions to be stateless,
while retaining the same security assumptions as ChaCha."
Also, XChaCha20 does not use any look up tables and is immune to
timing attacks. This library is based on Daniel J. Bernstein's reference
implementation of the ChaCha stream cipher.

I decided to make this small C library for XChaCha20 because I could not
find one. Unlike some other libraries, it only allows using XChaCha20 with
a 256-bit key and a 192-bit nonce. No other key sizes or nonce sizes are
allowed. A large benefit of using XChaCha20 over the regular ChaCha20 is that
the larger nonce (192 bits v.s. 64 bits) allows the use of random nonces and
is more resistant to nonce misuse.

**More Information**

[IETF XChaCha20 Draft](https://tools.ietf.org/html/draft-arciszewski-xchacha-03)

[Bernstein's ChaCha Web page](http://cr.yp.to/chacha.html)

[Libsodium Documentation](https://libsodium.gitbook.io/doc/advanced/stream_ciphers/xchacha20)

[Crypto++ Documentation](https://www.cryptopp.com/wiki/XChaCha20)

[Wikipedia](https://en.wikipedia.org/wiki/Salsa20)

**WARNING**

I am not a cryptographer so use this library at your own risk.  


**Getting Started**

Import the library into your project

```C
    #include "xchacha20.h"
```

Create a XChaCha context

```C
    XChaCha_ctx ctx;
```

Set up the 256-bit encryption key and the 192-bit nonce to be used.

```C
    xchacha_keysetup(&ctx, key, nonce);
```

Optionally, set the counter to a different starting value other than zero.

```C
    xchacha_set_counter(&ctx, 0x1);
```

Then use xchacha_encrypt_bytes or xchacha_encrypt_blocks to encrypt data

```C
    xchacha_encrypt_bytes(&ctx, plaintext, ciphertext, sizeof(plaintext));
```


**Test Vectors**

In the src folder is a program named test.c It calculates and compares
XChaCha20 test vectors obtained from two different sources. The test vectors
were borrowed from the IETF draft regarding XChaCha20 and an example from
Crypto++ wikipedia. It will compare the output of this XChaCha20 library with
known good test vectors to ensure this library is working correctly.

To make the test program simply run make

    make

Then run the test program

    ./test

The program will produce the following output if successful:

    Cryptographic tests passed

If this library failed to generate the correct ciphertexts, then something
is wrong with the library and you will see this output:

    Cryptographic tests failed!


**To Do**

- [x] Add a program to calculate and compare test vectors
- [ ] Find and add more test vectors for XChaCha20


**Contributing**

Pull requests, new feature suggestions, and bug reports/issues are
welcome.


**Versioning**

This project uses semantic versioning 2.0. Version numbers follow the
MAJOR.MINOR.PATCH format.


**License**

This project is licensed under the 3-Clause BSD License also known as the
*"New BSD License"* or the *"Modified BSD License"*. A copy of the license
can be found in the LICENSE file. A copy can also be found at the
[Open Source Institute](https://opensource.org/licenses/BSD-3-Clause)
