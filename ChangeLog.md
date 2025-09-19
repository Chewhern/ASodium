# Versions
0.4.0 version \
-> stable version but >= .Net Framework 4.7.2 does not really supports it

0.5.0 version\
-> due to the error in 0.4.0 version, SetEnvironmentHelper put in the nuget package\
-> this has a problem as it is in the exact same location as the SodiumInit

0.5.1 version\
-> due to the problem in 0.5.0 version, SetEnvironmentHelper has a separate class now\
-> XChaChaPoly1305 in libsodium's secretbox was added\
-> minor adjustments to the ASodium binding on SecretBox and RNG. 

0.5.2 version\
-> Removed unnecessary code\
-> Added some helper\
-> Added some usability\
-> Added Salsa20Poly1305,ChaCha20Poly1305 and ChaCha20IETFPoly1305 in SodiumSecretBox

0.5.3 version\
-> Removed unnecessary code\
-> MAC in Salsa20Poly1305,ChaCha20Poly1305 and ChaCha20IETFPoly1305 in SodiumSecretBox no longer uses **System.Linq** \
and it uses **sodium_memcmp** to do the comparison with the MAC attached in the message.\
-> **SodiumSecureMemory.SecureClearBytes()** replaces all the sensitive key clearing function in ASodium as the code is shorter while doing its job.\
-> State clearing in several cryptographic functions were removed as it's uncertain they're sensitive or will cause troubles to the library(libsodium).

0.5.4 version\
-> Removed unnecessary code\
-> Added support for Salsa20 12 rounds and 8 rounds operations within the wrapper library.\
-> Added support for PRF which sources from libsodium library.\
-> Slight rework on **RevampedKeyPair** object.\
-> All sorts of detached box has been removed and uses only **DetachedBox** object\
-> Wiki is now available\
-> **Dropped support for .Net Framework**\
-> minor bug fixes on StreamCipherSalsa20

0.5.5 version\
-> Changed some exception message\
-> Added Experimental Domain Separation Stream Cipher\
-> Dropped support for .NetCoreApp\
-> From this version and onwards, there'll be no more DLL verifications

0.5.6 version\
-> Expose SealedBox XChaCha20Poly1305 native API\
-> Expose Public Key Box XChaCha20Poly1305 native API\
-> Expose Seeded KeyPair generation in Public Key Box and Public Key Auth\
-> Remove Experimental Domain Separation in ASodium\
-> If people would like to have domain separation, kindly head to my simplesofthsm for details.

0.5.7 version\
-> Added **Aegis-128L** native API\
-> Added **Aegis-256L** native API

0.5.8 version\
-> Removed hardware checkers on AES256GCM and AES256GCMPC\
-> Switched to **.Net 6** and now extends support to **.Net Standard 2.0**

0.5.9 version\
-> For details kindly refer to https://github.com/Chewhern/ASodium/blob/main/Source/SodiumSecureMemory.cs \
-> and https://github.com/Chewhern/ASodium/blob/main/Source/SodiumSecureMemoryLibrary.cs

0.6.0 version\
-> **sodium_memcmp** and **sodium_compare** have changed the input data types from **IntPtr** to **Byte[]**.\
-> Sodium_Memory_Compare have added some errors checker regarding ByteArray1 and ByteArray2.\
-> Sodium_Memory_Compare and Sodium_Compare have reduced 1 input parameter respectively.\
-> SodiumSecretBoxChaCha20Poly1305, SodiumSecretBoxChaCha20IETFPoly1305, SodiumSecretBoxSalsa20Poly1305 have some minor changes to the code.

0.6.1 version\
-> String operations within SodiumSecureMemory have been slightly reworked. For details, kindly refer [here](https://github.com/Chewhern/ASodium/blob/main/Source/SodiumSecureMemory.cs).

0.6.2 version\
-> Added support for .NET 8.0\
-> Added **HKDF-SHA512** and **HKDF-SHA256**.

0.6.4 version\
-> **SecretStream** fixed rekeying issues.\
-> All functions have additional **IntPtr** as the header.\
-> All exising **IntPtr** header methods reworked. Now it doesn't use **Marshal.Copy()**, it directly interact with libsodium with **IntPtr**.\
-> **IntPtr** issues/bugs that exist in **0.6.3** version were greatly reduced.\
-> All **IntPtr** created with **sodium_malloc**, this means they have **sodium_mlock** by default.

## Note(For 0.6.4 and above) - Memory Lock and Swap Partitions
Swap partition generally is required when involving with small RAM amount (Eg, 512 MB with 1 GB swap partition particularly on Linux operating system. Windows and MacOS might not be affected by this by default as they have bigger RAM. ). However, this's not a good idea for cryptographic security as the private key or data may be leaked as the operating system will write and read data from swap partitions.

From what I have tested and developed so far, in C#, calling **sodium_mlock** directly on **Byte[]** generally will cause the system to go into runtime error. I don't exactly know what caused this but with the use of **IntPtr**, this issue occurs less or didn't occur at all.

And so if cryptography security is the main concern, strict **IntPtr** that comes from **sodium_malloc** that has **sodium_mlock** within will be encouraged. However this won't be able to extend to functions or cryptographic functions outside of **libsodium**. In the case of **BouncyCastle**, they accept **Byte[]** but not lower level stuffs like **pointer**. (This might also be one of the missing puzzle in enabling or developing **Software emulated hardware security module**)

However, if your main concern is application runtime issue, then swap partitions can be enabled. 

If a cross cryptography libraries environment was expected, then if your machine is Linux and happen to have at least 2GB of RAM, kindly make sure the machine only host and have cryptographic related applications on it. This's to make space for both disabling swap partition and using **sodium_mlock** while swap partition was enabled. 

## Note(.Net Framework)
If you are developing for .Net Framework 4.8 or 4.7.2, you are required to put the dll(libsodium) into the application folder else it won't work

In later version of this binding/wrapper, it won't support .Net Framework anymore as Microsoft and the author of libsodium cryptography library no longer supports
it.

## Note(.Net 5/ASP.Net Core)
If you are developing for .Net 5 or ASP.Net Core 5, you don't need to put the dll(libsodium) into the application folder.

## Note(UWP/WPF)
If you are developing for UWP/WPF, I won't be providing support for UWP/WPF as it's not standardized and easy to use as opposed to .Net 5 or .Net Framework.

## Note(Xamarin)
In current stage, there's no support to be added to Xamarin but in future there'll be. If you are a .Net developer and you like this wrapper feel free to add support
to this library so that it can support Xamarin.

## Others
One of the sodium helper API "sodium_increment()" is not yet tested as it requires certain system architecture to work. It can have bugs or not working. \
Otherwise all the stuffs pretty much tested and work fine.
