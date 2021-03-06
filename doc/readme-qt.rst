Tughlaq-qt: Qt5 GUI for Tughlaq
===============================

Build instructions
===================

Building your own Tughlaq GUI requires Qt version 5.2 or newer.

Debian
-------

- Download the `Qt Creator 5` and install it.

Make sure that the required packages for Qt5 development of your
distribution are installed, for Debian and Ubuntu these are:

::

    apt-get install qt5-qmake libqt5-dev build-essential libboost-dev libboost-system-dev \
        libboost-filesystem-dev libboost-program-options-dev libboost-thread-dev \
        libssl-dev libdb4.8++-dev

then execute the following:

::

    cd src/leveldb
    make libleveldb.a libmemenv.a

    cd ../quazip
    qmake quazip.pro
    make

    cd ../..
    qmake tughlaq-qt.pro
    make

Alternatively, run Qt Creator and open the `tughlaq-qt.pro` file.

   You may need to install libGL in some Linux environments:

   sudo apt-get install libglu1-mesa-dev -y

An executable named `tughlaq-qt` will be built.


Windows
--------

Windows build instructions:

- Download the `Qt Creator 5` and install it.

- Download and extract the `dependencies archive`_  [#]_, or compile openssl, boost and dbcxx yourself.  Refer to build-msw.txt.

- Open the .pro file in QT creator and build as normal (ctrl-B)



Mac OS X
--------

- Download and install XCode from the app store.

- Now install compiler dependencies by running this in the terminal

::

	sudo xcode-select --install

- Download and install MacPorts for your version of macOS

- Execute the following commands in a terminal to get the dependencies:

::

	sudo port selfupdate
	sudo port install db48@+no_java openssl miniupnpc qt5 boost@1.59.0_3+no_single+no_static+python27 qrencode curl

- Create file .bash_profile in your user directory and add these two lines, save and close file

::
	export PATH="/opt/local/bin:/opt/local/sbin:$PATH"
	export PATH="/opt/local/libexec/qt5/bin:$PATH"
	
- Close terminal application and reopen

- Now build the qt wallet

::
	cd tughlaq
	qmake tughlaq-qt.pro
	make -f Makefile


Build configuration options
============================

UPNnP port forwarding
---------------------

To use UPnP for port forwarding behind a NAT router (recommended, as more connections overall allow for a faster and more stable tughlaq experience), pass the following argument to qmake:

::

    qmake "USE_UPNP=1"

(in **Qt Creator**, you can find the setting for additional qmake arguments under "Projects" -> "Build Settings" -> "Build Steps", then click "Details" next to **qmake**)

This requires miniupnpc for UPnP port mapping.  It can be downloaded from
http://miniupnp.tuxfamily.org/files/.  UPnP support is not compiled in by default.

Set USE_UPNP to a different value to control this:

+------------+--------------------------------------------------------------------------+
| USE_UPNP=- | no UPnP support, miniupnpc not required;                                 |
+------------+--------------------------------------------------------------------------+
| USE_UPNP=0 | (the default) built with UPnP, support turned off by default at runtime; |
+------------+--------------------------------------------------------------------------+
| USE_UPNP=1 | build with UPnP support turned on by default at runtime.                 |
+------------+--------------------------------------------------------------------------+

Notification support for recent (k)ubuntu versions
---------------------------------------------------

To see desktop notifications on (k)ubuntu versions starting from 10.04, enable usage of the
FreeDesktop notification interface through DBUS using the following qmake option:

::

    qmake "USE_DBUS=1"

Generation of QR codes
-----------------------

libqrencode may be used to generate QRCode images for payment requests. 
It can be downloaded from http://fukuchi.org/works/qrencode/index.html.en, or installed via your package manager. Pass the USE_QRCODE 
flag to qmake to control this:

+--------------+--------------------------------------------------------------------------+
| USE_QRCODE=0 | (the default) No QRCode support - libarcode not required                 |
+--------------+--------------------------------------------------------------------------+
| USE_QRCODE=1 | QRCode support enabled                                                   |
+--------------+--------------------------------------------------------------------------+


Berkely DB version warning
==========================

A warning for people using the *static binary* version of Tughlaq on a Linux/UNIX-ish system (tl;dr: **Berkely DB databases are not forward compatible**).

The static binary version of Tughlaq is linked against libdb4.8 (see also `this Debian issue`_).

Now the nasty thing is that databases from 5.X are not compatible with 4.X.

If the globally installed development package of Berkely DB installed on your system is 5.X, any source you
build yourself will be linked against that. The first time you run with a 5.X version the database will be upgraded,
and 4.X cannot open the new format. This means that you cannot go back to the old statically linked version without
significant hassle!

.. _`this Debian issue`: http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=621425

Ubuntu 11.10 warning
====================

Ubuntu 11.10 has a package called 'qt-at-spi' installed by default.  At the time of writing, having that package
installed causes tughlaq-qt to crash intermittently.  The issue has been reported as `launchpad bug 857790`_, but
isn't yet fixed.

Until the bug is fixed, you can remove the qt-at-spi package to work around the problem, though this will presumably
disable screen reader functionality for Qt apps:

::

    sudo apt-get remove qt-at-spi

.. _`launchpad bug 857790`: https://bugs.launchpad.net/ubuntu/+source/qt-at-spi/+bug/857790
