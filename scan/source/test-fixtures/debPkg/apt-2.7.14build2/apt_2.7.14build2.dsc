-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Format: 3.0 (native)
Source: apt
Binary: apt, libapt-pkg6.0t64, apt-doc, libapt-pkg-dev, libapt-pkg-doc, apt-utils, apt-transport-https
Architecture: any all
Version: 2.7.14build2
Maintainer: APT Development Team <deity@lists.debian.org>
Uploaders: Michael Vogt <mvo@debian.org>, Julian Andres Klode <jak@debian.org>, David Kalnischkies <donkult@debian.org>
Standards-Version: 4.1.1
Vcs-Browser: https://salsa.debian.org/apt-team/apt
Vcs-Git: https://salsa.debian.org/apt-team/apt.git
Testsuite: autopkgtest
Testsuite-Triggers: @builddeps@, aptitude, db-util, dpkg, fakeroot, g++, gdb, gdb-minimal, gnupg, gnupg1, gnupg2, gpgv, gpgv1, gpgv2, libfile-fcntllock-perl, lsof, pkg-config, python3-apt, stunnel4, valgrind, wget
Build-Depends: dpkg-dev (>= 1.22.5) <!pkg.apt.ci>, cmake (>= 3.4), debhelper-compat (= 12), docbook-xml <!nodoc>, docbook-xsl <!nodoc>, dpkg-dev (>= 1.20.8), gettext (>= 0.12), googletest <!nocheck> | libgtest-dev <!nocheck>, libbz2-dev, libdb-dev, libgnutls28-dev (>= 3.4.6), libgcrypt20-dev, liblz4-dev (>= 0.0~r126), liblzma-dev, libseccomp-dev (>= 2.4.2) [amd64 arm64 armel armhf i386 mips mips64el mipsel ppc64el s390x hppa powerpc powerpcspe ppc64 x32], libsystemd-dev [linux-any], libudev-dev [linux-any], libxxhash-dev (>= 0.8), libzstd-dev (>= 1.0), ninja-build, pkg-config, po4a (>= 0.34-2) <!nodoc>, triehash, xsltproc <!nodoc>, zlib1g-dev
Build-Depends-Indep: doxygen <!nodoc !pkg.apt.nodoxygen>, graphviz <!nodoc !pkg.apt.nodoxygen>, w3m <!nodoc>
Package-List:
 apt deb admin required arch=any
 apt-doc deb doc optional arch=all profile=!nodoc
 apt-transport-https deb oldlibs optional arch=all
 apt-utils deb admin required arch=any
 libapt-pkg-dev deb libdevel optional arch=any
 libapt-pkg-doc deb doc optional arch=all profile=!nodoc
 libapt-pkg6.0t64 deb libs optional arch=any
Checksums-Sha1:
 2055fbcc9271c4ac03dc85df9a7c84080575efcd 2352948 apt_2.7.14build2.tar.xz
Checksums-Sha256:
 7d4d0f2eb95464d175ef6a09b2b8f7040f56a8de77fa3b73de52d80395428410 2352948 apt_2.7.14build2.tar.xz
Files:
 f300b89d957cdf70a38d21ebd20604f7 2352948 apt_2.7.14build2.tar.xz

-----BEGIN PGP SIGNATURE-----

iQJOBAEBCgA4FiEErEg/aN5yj0PyIC/KVo0w8yGyEz0FAmYJlwEaHHN0ZXZlLmxh
bmdhc2VrQHVidW50dS5jb20ACgkQVo0w8yGyEz3f6hAAj2/LNtwv2gj1LQP+DiG/
uASrWsI9nprEMXl+6r34iRQxe1VWxYt0BxX45RVFxEohNp91rA2LeEIabeYs3iHB
QTR58jppiHmWGiFV1AGobdx/gxdt/VJLVMKvWVmLL55Kbx4pKM6Ei/VaEDWcYWFZ
8u8Xv8TOrXEBZ1wXg0oCAel7+aJT08Wpz/RLkY1UTplshZ3xf+ucjTHfnXM4oNTg
NWW2qnTP5MnttUmAWmVaSmcp5NStfb6JRfOxHdyRiV/fA6HD8PmW8YpB9qnrhxqF
QBEVntE98OnetC1Wp8xSaDdcYg/zJlcZcVrPIl0VuS1H9KWu13Oq3t2DVdgX4RLB
5O6aiS7VtFNvx/pgJ1TxA19nFpJc2cM0jvFui7SFrlaWQn+N4h4I/oeEFJ1rNsgE
AvxAE7PkZfhpXOuyTAblFvdSxtFc8/a3iTOeuoHXWakUrbpOL+H1CfoFW8FLdaif
YegE9oSxYniSxBwPVybwVy1Gb5W+RkcytAW1Vvp2sLQTcNCtlOZsDtYB1C5C/rO3
1mXl1ufe1YLY1Jh+MLe3DOYItHkV1qt3EJnd9pZENsjeUJzQcaRosaYsdD6M5RaY
a26yMs8UxNoAWW/3xM6g5GIw/b+8VNzNDThaUspqZSqXTcukBdc3iEalNf1HIr0M
rwQ7+a3ALimNL9yjcIiHTbM=
=h41p
-----END PGP SIGNATURE-----
