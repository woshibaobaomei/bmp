Interactive BGP Monitoring Protocol (BMP) Server
================================================

BGP speaking routers use the BGP Monitoring Protocol (BMP) to inform a monitoring
end-station about various events happening at the router. More information regarding 
BMP:

http://tools.ietf.org/html/draft-ietf-grow-bmp

The code here implements an interactive BGP Monitoring Protocol end-station - a
server process - that BGP speakers can connect to and exchange routing and topology 
information with.

An important goal of this BMP server project is to handle a very large scale of
BGP clients (with each BGP client having a very large scale of peers) so that an
entire network of BGP routers can be monitored from single end-point

[pic]



Build/Run
=========

Note: this software currently will build and run on Linux (2.6+)

To compile the code simply run the 'compile' script:

    $ source compile

This creates an executable named `bmp` and adds the current directory to `$PATH`
so that `bmp` can be invoked directly from the shell:

    $ bmp 

    Usage:

      * bmp -s <port> (server mode)
      * bmp <command> (control mode)

      [snip]

The `bmp` executable has a *dual role*: it can be used in the *server* mode (with 
the `-s` option) which will run the actual BMP server process, or it can be used 
in a *control* mode (or *query* mode) which can control and query running BMP 
servers (more on this later!) 

For example, a BMP server can be instantiated at port 1111 by issuing `bmp -s 1111`:

    $ bmp -s 1111
    [05:11:33.471] Listening on port 11111
    $

This will run a BMP sever listening on port 1111 on your machine. BGP routers 
can now connect to the machine on this port and start sending BMP messages. The 
BMP server runs in the background by default (unless the `-i` interactive option 
is specified) and emits timestamped messages on the console for events such as 
new BGP clients connecting to the server:
 
    $ bmp -s 1111
    [05:11:33.471] Listening on port 11111
    $
    $
    [05:12:02.211] BMP-1111-ADJCHANGE: Client 10.1.0.1:22011 UP
    [05:12:04.501] BMP-1111-ADJCHANGE: Client 100.11.0.3:22013 UP
    $
    $

 
Usage
=====

    $ bmp show summary
    
     

. 

    $ bmp show clients

    ID    Address:Port            Uptime    Peers  Messages     Data
     1   1.1.1.1:12234          00:03:11     2300     10023    2.2MB
     2   2.2.2.2:23423          01:23:11       22    102323   30.2MB
     3   1.1.1.1:12234          00:03:11      300     10023    2.2MB
     4   2.2.2.2:23423          01:23:11       72    102323   30.2MB
     5   1.1.1.1:12234          00:03:11      202     10023    2.2MB
     6   2.2.2.2:23423          01:23:11        0    102323    0.0MB
     7   1.1.1.1:12234          00:03:11     2300     10023    2.2MB
     8   2.2.2.2:23423          01:23:11        2    102323   30.2MB
     9   1.1.1.1:12234          00:03:11     2300     10023    2.2MB
    10   2.2.2.2:23423          01:23:11        2    102323   30.2MB

.

    $ bmp show client X

.

    $ bmp show client X messages

.

    $ bmp show client X peers

.

    $ bmp show client X peer Y

.

    $ bmp show client X peer Y messages

.

    $ bmp clear client X

.

    $ bmp debug client X

.

    $ bmp flush client X

.




