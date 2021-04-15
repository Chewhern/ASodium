0.4.0 version \
-> stable version but >= .Net Framework 4.7.2 does not really supports it

0.5.0 version\
-> due to the error in 0.4.0 version, SetEnvironmentHelper put in the nuget package\
-> this has a problem as it is in the exact same location as the SodiumInit\

0.6.0 version\
-> due to the problem in 0.5.0 version, SetEnvironmentHelper has a separate class now
-> XChaChaPoly1305 in libsodium's secretbox was added
-> minor adjustments to the ASodium binding on SecretBox and RNG. 
