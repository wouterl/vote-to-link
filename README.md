Prototype code of Vote-to-Link system
=====================================

This repository contains the prototype implementation of the vote to link system described in the paper titled 'Vote to Link: recovering from misbehaving anonymous users' written by Wouter Lueks, Maarten H. Everts and Jaap-Henk Hoepman.

The vote-to-link system aims to mitigate the damage done by misbehaving anonymous users. Typically it takes time before misbehavior is detected and the user is subsequently blocked (for example using blacklistable anonymous credentials, or BLAC). In the mean time the user is free to continue to misbehave. Since the users are anonymous, it is impossible which actions belong to the same misbehaving user.

Vote-to-link helps the system to recover from this type of misbehavior by letting moderators vote on user's actions if they decide that that action is malicious. After enough moderators have voted on the action, the system can use these votes to link all the actions by the same user within a limited time window, making it much find all instances of abuse.

The prototype code included in this repository implements both the regular vote-to-link scheme, as well as the moderator-anonymous vote to link scheme. The code implements almost all cryptography described in the paper (the distributed key generation is omitted). However, the implementation is surely not immediately deployable. In particular, all communication parts required by the protocol have been omitted.

Dependencies
------------

The prototype requires the following dependencies:

 * RELIC (see below for how to compile this library)
 * GMP (required by RELIC)
 * The Sodium cryptographic library
 * OpenSSL

If you are using a debian-based system, you can install the latter three libraries using `apt`:

```
apt-get install libgmp-dev libsodium-dev libssl-dev
```

Setting up RELIC for Vote-to-Link
---------------------------------

Some of the [RELIC](https://github.com/relic-toolkit/relic) options are configured at compile time. Hence, you'll have to recompile relic to ensure that the correct version of the library is available for use with Vote-to-Revoke.  In particular, you have to build and install the RELIC with the `x64-pbc-128` preset and make sure that `gcc` can find the library and include files.

For completeness, here are the detailed instructions to install RELIC to `$HOME/local/` and to setup the environment variables. First clone RELIC:

```
git clone https://github.com/relic-toolkit/relic
cd relic
```

then setup cmake, compile the library and install it (we use the x64-pbc preset so we can use fast pairing arithmetic):

```
preset/x64-pbc-128.sh -DCMAKE_INSTALL_PREFIX=$HOME/local/
make
make install
```

finally, add the location of the include files 

```
export CPATH=$CPATH:$HOME/local/include
export LIBRARY_PATH=$LIBRARY_PATH:$HOME/local/lib
```

Compiling and running Vote-to-Link
----------------------------------

Simply run `make` (after setting up RELIC) to compile the binaries.

Now you can run the following tests:

 * `bin/test-tdh`: to test the implementation of the TDH2' threshold encryption scheme
 * `bin/test-bbsplus`: to test the implementation of the BBS+ signature scheme and credential system.
 * `bin/test-vtr`: to test the basic vote-to-link scheme
 * `bin/test-shuffle`: to test the implementation of Groth's shuffle protocol
 * `bin/test-anonvtr`: to test the implementation of the moderator-anonymous vote-to-link scheme

Finally, you can reproduce the measurements from the paper using `bin/bench`.

License
-------

The code is licensed under the GPLv3 license.

Disclaimer
----------

This code should be considered alpha quality and prototype software. The code, including the cryptography might not be correct.
