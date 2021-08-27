Note:\
But this binding requires developer to put the libsodium.dll library into the exact same directory that the current application work on.\

AES256GCM is not yet tested as my machine does not support it, it can have bugs or not working at all.\

One of the sodium helper API "sodium_increment()" is not yet tested as it requires certain system architecture to work. It can have bugs or not working. \
Otherwise all the stuffs pretty much tested and work fine.

0.4.0 version \
-> stable version but >= .Net Framework 4.7.2 does not really supports it

0.5.0 version\
-> due to the error in 0.4.0 version, SetEnvironmentHelper put in the nuget package\
-> this has a problem as it is in the exact same location as the SodiumInit\

0.5.1 version\
-> due to the problem in 0.5.0 version, SetEnvironmentHelper has a separate class now\
-> XChaChaPoly1305 in libsodium's secretbox was added\
-> minor adjustments to the ASodium binding on SecretBox and RNG. 

0.5.2 version(Incoming updates)\
-> Removed unnecessary code\
-> Added some helper\
-> Added some usability
