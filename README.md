# PORTSCANNER

## ABOUT
A simple portscanner I developed as an exercise in using Berkeley sockets with C as well as getting to know protocols like IP, TCP and UDP better.

## BUILDING

    Open your terminal or shell and navigate to the directory containing portscanner.cpp.
    To build Portscanner, simply enter "g++ portscanner.cpp -o portscanner". This will
    create an executable file portscanner in the same directory. See below for running.

## USING

    Open your terminal or shell and navigate to the directory containing Portscanner.
    To run Portscanner, simply enter "sudo ./portscanner localhost vports1.txt <arg01> <arg02> <arg03>"
    The arguments are as follows:

        <arg01> = Host name - e.g. scanme.nmap.org
        <arg02> = Input file - e.g. vports1.txt
        <arg03> = Scan method - e.g. TCP

    Example run commands:

        - "sudo ./portscanner scanme.nmap.org vports1.txt TCP"
        - "sudo ./portscanner www.mbl.is vports1.txt UDP"
        - "sudo ./portscanner skel.ru.is vports1.txt SYN"

    The only available methods for <arg03> are:

        - "TCP"
        - "UDP"
        - "SYN"
        - "FIN"

    Portscanner reads a list of ports that are known to be vulnerable from the supplied file
    "vports1.txt". To try out other ports, simply put a comment block around the code inside
    function "fillVectorFromFileAndShuffle" and insert a line like this one:

        "ports.push_back(#);" 
        
    Where # is any positive integer from 1 - 65536. Make sure that the function still returns
    true and recompile before running. Note: You still have to provide the file as an argument.

    Root privileges are needed because the process is using more than one socket at a time.
    That is one for sending and a second one for receiving.

## DESIGN DECISIONS

    SYN/FIN scans do both make custom raw headers in order to scan. They do however use different
    methods to create these structures. SYN scan uses the built in library structs (ip and tcphdr)
    while the FIN scan uses custom made non-library structures (ip_header and tcp_header). This is
    due to the scans being implemented by two different persons that failed to communicate properly.
    Resulting from that, there are different functions too, which the other method does not make us of.
    On the bright side, they do both however function properly. (besides no answer being delivered)

## CODE
    
    The list of ports, read from vports1.txt, is shuffled and a delay of 0.5s to 1s is ensured
    in order to prevent detection from target host.

    The first thing that the program does is to determine which method is to be used to scan.
    After that it makes a function call to a dedicated function that performs scan with the
    desired method.

## KNOWN ISSUES

    ### SYN/FIN scan
    
        We successfully built our own custom TCP/IP headers which contained the required flags
        for these scans. The TCP header for the SYN scan contains a SYN flag and, similarly,
        the TCP header for the FIN scan contains a FIN flag. 
        According to Wireshark, the packets containing these headers are successfully sent to
        the target host. We however never got any answer at all, regardless of which hosts we
        tried to scan. Thus we were unable to code any further.
        For SYN scan we wanted to implement a package processing such that we check the received
        TCP header if it contains a SYN|ACK flag or a RST|ACK flag. If it would have contained the
        former we would determine that the port is open and send back a TCP header containing a RST
        flag to terminate the connection and continue scanning. If it would have contained the latter
        we would determine that the port is closed and continue scanning.
        Similarly for FIN scan, we wanted to implement a package processing such that we check the
        received TCP header if it contains RST|ACK or a no answer at all. If it would have contained
        a RST|ACK flag we would determined the port was closed and continue scanning. If there was
        no answer and a timeout we would have determined that the port was open and continue scanning.

        In the last minutes we discovered that the FIN code is not running as it should. The sendto
        function fails for unknown reasons. 

    ### UDP

        The UDP scan might not give correct results. There are two issues:

            1. The "expected output" is only received when scanning localhost. When examining
               Wireshark, closed ports yield an ICMP header saying that the port is unreachable
               while open ports yield no answer.

            2. There is some pointer arithmetic required in order to cast the received buffer
               contents to a struct udphdr. No matter what we tried and no matter how many TAs
               we asked about it, we were unable to get it correctly. Thus, we were unable to
               completely process the received packet. We were able to get the IP header and the
               ICMP header as well and establish that an ICMP packet was received with code 3
               (Port unreachable). But because that we were unable to read the information from
               the UDP packet (which was clearly visible in Wireshark), we were unable to determine
               that the destination port was the same as the port which is being scanned.

## EXAMPLE OUTPUT

    The following is an output from a TCP scan made on 45.33.32.156 (scanme.nmap.org):

        Scan status: about 0.00% done.
        Scan status: about 2.27% done.
        Scan status: about 4.55% done.
        Scan status: about 6.82% done.
        Scan status: about 9.09% done.
        Scan status: about 11.36% done.
        Scan status: about 13.64% done.
        Scan status: about 15.91% done.
        Scan status: about 18.18% done.
        Scan status: about 20.45% done.
        Scan status: about 22.73% done.
        Scan status: about 25.00% done.
        Scan status: about 27.27% done.
        Scan status: about 29.55% done.
        Scan status: about 31.82% done.
        Scan status: about 34.09% done.
        Scan status: about 36.36% done.
        Scan status: about 38.64% done.
        Scan status: about 40.91% done.
        Scan status: about 43.18% done.
        Scan status: about 45.45% done.
        Scan status: about 47.73% done.
        Scan status: about 50.00% done.
        Scan status: about 52.27% done.
        Scan status: about 54.55% done.
        Scan status: about 56.82% done.
        Scan status: about 59.09% done.
        Scan status: about 61.36% done.
        Scan status: about 63.64% done.
        Scan status: about 65.91% done.
        Scan status: about 68.18% done.
        Scan status: about 70.45% done.
        Scan status: about 72.73% done.
        Scan status: about 75.00% done.
        Scan status: about 77.27% done.
        Scan status: about 79.55% done.
        Scan status: about 81.82% done.
        Scan status: about 84.09% done.
        Scan status: about 86.36% done.
        Scan status: about 88.64% done.
        Scan status: about 90.91% done.
        Scan status: about 93.18% done.
        Scan status: about 95.45% done.
        Scan status: about 97.73% done.
        ---------------------------------
        Number of open ports: 1
        Number of closed ports: 87
        Open ports: 9929

## HELPFUL SOURCES

    The following sources proved to be helpful and we studied them in depth in order to better
    understand raw socket programming in C.

        http://www.cplusplus.com/forum/general/7109/
        https://en.wikipedia.org/wiki/Berkeley_sockets
        http://www.cs.binghamton.edu/~steflik/cs455/rawip.txt
        https://www.binarytides.com/programming-udp-sockets-c-linux/
        https://github.com/angrave/SystemProgramming/wiki/Networking%2C-Part-2%3A-Using-getaddrinfo

## IMPORTANT Note

    Regarding SYN scan. In the last minutes before turn-in, we managed to get a RST|ACK reply from a 
    target host. That is something that did not happen before, ever. That shows that our code is correct
    and the reason that we were unable to proceed and finish the code for that scan method is most likely
    some faults in the campus network.

## CREDITS

    Portscanner was designed and implemented by:

        - Snorri Arinbjarnar          - snorria16
        - Smári Freyr Guðmundsson     - smarig16
        - Þórir Ármann Valdimarsson   - thorirv15
