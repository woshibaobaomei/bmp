Interactive BGP Monitoring Protocol (BMP) Server
------------------------------------------------

BGP speaking routers use the BMP protocol to inform a monitoring end-station 
about various events happening at the router. More information regarding BMP:

http://tools.ietf.org/html/draft-ietf-grow-bmp

The code here implements an interactive BMP end-station that BGP speakers can
connect to and exchange routing and topology information with.


Build/Installation/Run
----------------------

Note: this software currently will only build and run on Linux (2.6+)

To compile the software simply run the 'compile' script:

    $ source compile

This creates an executable named 'bmp' which takes a port number as an option:

    $ ./bmp 1200
    BMP# [05:11:33.471] Listening on port 1200
    BMP#
  
Now the BMP sever is running on port 1200 on your machine. BGP routers can now 
connect to the machine on this port and start sending BMP messages.


Usage
----- 

    BMP# show bmp summary

. 

    BMP# show bmp clients

    ID    Address:Port            Uptime    Peers  Messages     Data
     0   1.1.1.1:12234          00:03:11     2300     10023    2.2MB
     1   2.2.2.2:23423          01:23:11       22    102323   30.2MB
     3   1.1.1.1:12234          00:03:11      300     10023    2.2MB
     4   2.2.2.2:23423          01:23:11       72    102323   30.2MB
     5   1.1.1.1:12234          00:03:11      202     10023    2.2MB
     6   2.2.2.2:23423          01:23:11        0    102323    0.0MB
     7   1.1.1.1:12234          00:03:11     2300     10023    2.2MB
     8   2.2.2.2:23423          01:23:11        2    102323   30.2MB
     9   1.1.1.1:12234          00:03:11     2300     10023    2.2MB
    10   2.2.2.2:23423          01:23:11        2    102323   30.2MB

.

    show bmp client X

.

    show bmp client X messages

.

    show bmp client X ....

.

    clear bmp client X

.

    debug bmp client X

.

    flush bmp client X

.




