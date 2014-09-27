mean-torrent-client
===================

MeanTorrent is a simple BitTorrent client. It is a command line application for Linux. At the moment it only downloads files (hence "mean") and only downloads single-file torrents. By single-file torrents it is meant those torrents which download just one file rather than downloading multiple files. See the *Work to do* section below. For technical overview, see https://github.com/bytefire/mean-torrent-client/blob/master/docs/overview.txt.

Compiling the code
==================

1. Download the code on a Linux machine. 
2. Make sure libCurl is installed. If not, obtain it from . http://curl.haxx.se/download.html
3. In command line, go into `mean-torrent-client/src` and type `make`. This will compile the client and create a folder named `bin` inside the `mean-torrent-client/src` folder.
4. Go into that `bin` folder where you will see the main executable named `mtc`. 

**Logging:** Logs can be found in `bin/logs/` folder. Logging is quite extensive which hinders performance as it involves disk I/O as well as lock contention as separate threads try to write to the same log file without interleaving their log statements with other threads' log statements. Turning logging off completely should greatly improve performance.

Downloading torrent
===================

Once you have generated the executable `mtc` by compiling the code, you can download a single-file torrent. To do that follow these steps.

1. Download a single-file torrent file. An example would be the Office Libre torrent which can be found here.
2. Copy that torrent file into the `bin` folder where the `mtc` executable is. 
3. On command line, go into the `bin` folder and type this: `./mtc path/to/torrent/file`. 

This will start downloading the file into a new folder whose name will correspond the name of torrent file. That file will have the extension ".saved". If the whole file is not downloaded, as the resume file would indicate by not having all bits (except the extra bits in the last byte if the number of pieces is not an exact multiple of 8) being set, then run `mtc path/to/torrent/file fresh` as explained below. 

You can also specify a second argument after `path/to/torrent/file`. This is the mode. There are two modes: `fresh` and `new`. 

`fresh` is when you want to resume downloading the file which wasn't fully downloaded the last time mtc was run, but this time you want mtc to retreive a fresh list of peers from the tracker. If you want to resume downloading without getting a fresh list of peers then just don't provide a mode argument.

`new` is when you have an incomplete download from last time but you want to completely delete any of previously downloaded pieces and start all over again. In new mode, as in fresh mode, mtc will get a fresh list of peers from the tracker.

For details of how it works, read Overview.txt in `docs` folder.

Work to do
==========

1. Allow it to share files with other peers, i.e. honour the PIECE requests.
2. Allow it do handle multi-file downloads.
3. If the whole file isn't downloaded after going through all peers then download a new announce file and download again. This is a relatively simple change as most of the code for this is already in place and working. It only needs to be connected together and then tested. 
4. Implement distributed hash tables (DHT) protocol.

Credits
=======

This uses bencode.h and bencode.c files from Heapless Bencode library from here: https://github.com/willemt/heapless-bencode. This was greatly helpful.
