-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Format: 3.0 (quilt)
Source: bash
Binary: bash, bash-static, bash-builtins, bash-doc
Architecture: any all
Version: 5.2.21-2ubuntu4
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Homepage: http://tiswww.case.edu/php/chet/bash/bashtop.html
Standards-Version: 4.6.2
Vcs-Browser: https://code.launchpad.net/~doko/+junk/pkg-bash-debian
Vcs-Bzr: http://bazaar.launchpad.net/~doko/+junk/pkg-bash-debian
Testsuite: autopkgtest
Build-Depends: autoconf, autotools-dev, bison, libncurses5-dev, texinfo, texi2html, debhelper (>= 11), gettext, sharutils, locales <!nocheck>, time <!nocheck>, xz-utils
Build-Depends-Indep: texlive-latex-base, ghostscript, texlive-fonts-recommended, man2html-base
Build-Conflicts: r-base-core
Package-List:
 bash deb shells required arch=any essential=yes
 bash-builtins deb utils optional arch=any
 bash-doc deb doc optional arch=all
 bash-static deb shells optional arch=any
Checksums-Sha1:
 ab3f7f3ee2ca2a79e00037aab518934ba9ae566b 5598816 bash_5.2.21.orig.tar.xz
 254e7371bca8e65770f8d78b0a666007c0477690 94124 bash_5.2.21-2ubuntu4.debian.tar.xz
Checksums-Sha256:
 ec21ab4efd6bd7a6e2802fbda622b81bfc43a8095d721234d4bf075797683014 5598816 bash_5.2.21.orig.tar.xz
 bdb10c18d167dda3b265cb3db75314d524edbf7794fed36f0fb0dcc32f5e6ac9 94124 bash_5.2.21-2ubuntu4.debian.tar.xz
Files:
 b5acac4803646b77088117c3df3e4f55 5598816 bash_5.2.21.orig.tar.xz
 05cfb097873aa6220c48577d5c8b37ed 94124 bash_5.2.21-2ubuntu4.debian.tar.xz
Original-Maintainer: Matthias Klose <doko@debian.org>

-----BEGIN PGP SIGNATURE-----

iQJOBAEBCgA4FiEErEg/aN5yj0PyIC/KVo0w8yGyEz0FAmYJIaIaHHN0ZXZlLmxh
bmdhc2VrQHVidW50dS5jb20ACgkQVo0w8yGyEz1JgA//ZbWR0wW2qeHUyV40+0hL
NTlRx+xbG/30OxfP9w53w3kWHcA3Fy0Gwd+V0EIu/W7Ehzbn9olNT1BEBQDD/StA
GWa84nv8c3OYT7ekm9tyIKURcuRngguv5J358W3OAmhG9p60u20qDCqZbA95r5km
3TBLbKDZMt25hyIJg3Hdo5+3k0Aegssu8uw8ajOFn5r5CLa+ZNG8+ihFQQ6UoG4Y
ilOkaCX11O9hon9a0bBAZ5pFWEt7bl9PPSeI1Q8jw77lWYVP8NYML6KkUMghEkGD
TDMPsAslaJhKBWCFDPhUIz12JGoYn2I2hzAXnCuZ4eavHesE0H8oo2HP2QDnvcd9
VoSoRtHaVkoEgUcm0cs6pUG+CjmgiarjmZJW6cg5aScQetVbHVJTlorgvYbjXROZ
VWb1WjSoy3kzaKgiHBb/+UIBsEfL0ypZMgrceWrToxR/B9w81kufW9+O+AMa9q6n
xOWPJA6RgrqeL+pKPtNvYQ88MstZREkE7MW6nEMdTAAPn8PkAOZhLvk0+RU/Rfh8
I+3q+xy64m1qHGA7h9HDds9Z5hbJ2QZJM5h5hRuJIwyW0X01Oi6hBkG00lx74ZSp
0xH3GsymqYddsChYRGkOGEhNjNqE4EvNWYTay0VIRZ+K38OJLR1XJb1lGTz2jSwm
Rc5lQURu6H1c+xPbq706ddc=
=bw1z
-----END PGP SIGNATURE-----
