mean-torrent-client
===================

MeanTorrent is a simple BitTorrent client. It is a command line application for Linux. At the moment it only downloads files (hence mean) and only downloads single-file torrents. Single-file torrents download just one file rather than downloading multiple files. See the Work to do section below.

Compiling the code:
==================

1. Download the code on a Linux machine. 
2. Make sure libCurl is installed. If not, obtain it from <...>. 
3. In command line, go into `mean-torrent-client/src` and type `make client`. This will compile the client and create a folder named `bin` inside the `mean-torrent-client\src` folder.
4. Go into that `bin` folder where you will see the main executable named `mtc`. 

Downloading torrent:
====================

Once you have generated the executable `mtc` by compiling the code, you can download a single-file torrent. To do that follow these steps.

1. Download a single-file torrent file. An example would be the Office Libre torrent which can be found here.
2. Copy that torrent file into the `bin` folder where the `mtc` executable is. 
3. On command line, go into the `bin` folder and type this: `mtc path/to/torrent/file`. 

This will start downloading the file into a new folder whose name will correspond the name of torrent file. That file will have the extension ".saved".

You can also specify a second argument after `path/to/torrent/file`. This is the mode. There are two modes: `fresh` and `new`. 

*fresh* is when you want to resume downloading the file which wasn't fully downloaded the last time mtc was run, but this time you want mtc to retreive a fresh list of peers from the tracker. If you want to resume downloading without getting a fresh list of peers then just don't provide a mode argument.

*new* is when you have an incomplete download from last time but you want to completely delete any of previously downloaded pieces and start all over again. In new mode, as in fresh mode, mtc will get a fresh list of peers from the tracker.

For details of how it works, read Overview.txt in `docs` folder.

Work to do:
==========

1. Allow it to share files with other peers, i.e. honour the PIECE requests.
2. Allow it do handle multi-file downloads.
3. Implement distributed hash tables (DHT) protocol.

Credits:
========

This uses bencode.h and bencode.c files from Heapless Bencode library from here: https://github.com/willemt/heapless-bencode. This was greatly helpful.
