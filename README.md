Interactive BGP Monitoring Protocol (BMP) Server
================================================

BGP speaking routers use the BMP protocol to inform a monitoring end-station 
about various events happening at the router. More information regarding BMP:

http://tools.ietf.org/html/draft-ietf-grow-bmp

The code here implements an interactive BMP end-station that BGP speakers can
connect to and exchange routing and topology information with.


Build/Installation/Run
======================

Note: this software currently will only build and run on Linux (2.6+)

To compile the software simply run the 'compile' script:

    $ source compile

This creates an executable named 'bmp' which takes a port number as an option:

    $ ./bmp 1200
    BMP# [05:11:33.471] Listening on port 1200
    BMP#
  
Now the BMP sever is running on port 1200 on your machine. BGP routers can now 
connect to the machine on this port and start sending BMP messages. There is a
console prompt started for entering commands that can interact with the server.

    BMP# 

Significant events occurring on the server (new BGP client connection, etc) are
logged with a timestamp on the console as well.  

    BMP# [05:11:33.471] Listening on port 1200
    BMP#
    BMP# [05:12:02.211] BMP-ADJCHANGE: Client 1  10.1.0.1:22011  UP
    BMP# [05:12:02.521] BMP-ADJCHANGE: Client 2  1.1.1.1:22012  UP
    BMP# [05:12:04.501] BMP-ADJCHANGE: Client 3  100.11.0.3:22013  UP
    BMP# 


Usage
=====

    BMP# show summary
    
     

. 

    BMP# show clients

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

    show client X

.

    show client X messages

.

    show client X peers

.

    show client X peer Y

.

    show client X peer Y messages

.

    clear client X

.

    debug client X

.

    flush client X

.




