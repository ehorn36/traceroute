# #################################################################################################################### #
# Imports                                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
import os
from socket import *
import struct
import time
import select


# #################################################################################################################### #
# Class IcmpHelperLibrary                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
class IcmpHelperLibrary:
    # ################################################################################################################ #
    # Class IcmpPacket                                                                                                 #
    #                                                                                                                  #
    # References:                                                                                                      #
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                           #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    # ***** Eric Code *****
    _echo_reply_packet = None
    _echo_reply_rtt = None
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml

    _error_codes = \
        [
            ["Echo Reply"],
            [""],
            [""],
            ["Net Unreachable", "Host Unreachable",
             "Protocol Unreachable", "Port Unreachable", "Fragmentation Needed and Don't Fragment was Set",
             "Source Route Failed", "Destination Network Unknown", "Destination Host Unknown",
             "Source Host Isolated", "Communication with Destination Network is Administratively Prohibited",
             "Communication with Destination Host is Administratively Prohibited",
             "Destination Network Unreachable for Type of Service",
             "Destination Host Unreachable for Type of Service", "Communication Administratively Prohibited",
             "Host Precedence Violation", "Precedence cutoff in effect"
             ],
            ["Source Quench (Deprecated)"],
            ["Redirect Datagram for the Network (or subnet)", "Redirect Datagram for the Host",
             "Redirect Datagram for the Type of Service and Network",
             "Redirect Datagram for the Type of Service and Host"],
            ["Alternate Host Address (Deprecated)"],
            [""],
            ["Echo"],
            ["Normal router advertisement", "Does not route common traffic"],
            ["Router Selection"],
            ["Time to Live exceeded in Transit", "Fragment Reassembly Time Exceeded"],
            ["Pointer indicates the error", "Missing a Required Option", "Bad Length"],
            ["Timestamp"],
            ["Timestamp Reply"]
        ]

    class IcmpPacket:
        # ############################################################################################################ #
        # IcmpPacket Class Scope Variables                                                                             #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __icmpTarget = ""  # Remote Host
        __destinationIpAddress = ""  # Remote Host IP Address
        __header = b''  # Header after byte packing
        __data = b''  # Data after encoding
        __dataRaw = ""  # Raw string data before encoding
        __icmpType = 0  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0  # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0  # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0  # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 30
        __ttl = 255  # Time to live

        __DEBUG_IcmpPacket = False  # Allows for debug output

        # ***** Eric Code *****
        __echo_reply_host_ip = ""

        # ############################################################################################################ #
        # IcmpPacket Class Getters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        def get_destination_ip(self):
            return self.__destinationIpAddress

        # ***** Eric Code *****
        def get_echo_reply_host_ip(self):
            return self.__echo_reply_host_ip

        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff  # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff  # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)  # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum  # Rotate and add

            answer = ~checksum  # Invert bits
            answer = answer & 0xffff  # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                        self.getIcmpType(),  # 8 bits / 1 byte  / Format code B
                                        self.getIcmpCode(),  # 8 bits / 1 byte  / Format code B
                                        self.getPacketChecksum(),  # 16 bits / 2 bytes / Format code H
                                        self.getPacketIdentifier(),  # 16 bits / 2 bytes / Format code H
                                        self.getPacketSequenceNumber()  # 16 bits / 2 bytes / Format code H
                                        )

        def __encodeData(self):
            data_time = struct.pack("d", time.time())  # Used to track overall round trip time
            # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()  # packHeader() and encodeData() transfer data to their respective bit
            # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()  # Result will set new checksum value
            self.__packHeader()  # Header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            # Hint: Work through comparing each value and identify if this is a valid response.

            # ***** Eric Code *****
            outgoing_seq_num = self.getPacketSequenceNumber()
            outgoing_identifier = self.getPacketIdentifier()
            outgoing_data = self.getDataRaw()

            reply_seq_num = icmpReplyPacket.getIcmpSequenceNumber()
            reply_identifier = icmpReplyPacket.getIcmpIdentifier()
            reply_data = icmpReplyPacket.getIcmpData()

            # Update expected values within reply packet
            icmpReplyPacket.set_expected_seq_num(outgoing_seq_num)
            icmpReplyPacket.set_expected_identifier(outgoing_identifier)
            icmpReplyPacket.set_expected_data(outgoing_data)

            # Confirm the following items received are the same as what was sent
            # Sequence number
            print("icmpReplyPacket seq_num:", str(reply_seq_num)) if self.__DEBUG_IcmpPacket else 0
            print("OriginalPingData seq_num:", str(outgoing_seq_num)) if self.__DEBUG_IcmpPacket else 0
            if outgoing_seq_num == reply_seq_num:
                icmpReplyPacket.set_is_valid_seq_num(True)
            else:
                icmpReplyPacket.set_is_valid_seq_num(False)
            print("icmpReplyPacket seq_num is valid:", icmpReplyPacket.get_is_valid_seq_num()) \
                if self.__DEBUG_IcmpPacket else 0

            # Packet identifier
            print("icmpReplyPacket identifier:", str(reply_identifier)) if self.__DEBUG_IcmpPacket else 0
            print("OriginalPingData identifier:", str(outgoing_identifier)) if self.__DEBUG_IcmpPacket else 0
            if outgoing_identifier == reply_identifier:
                icmpReplyPacket.set_is_valid_identifier(True)
            else:
                icmpReplyPacket.set_is_valid_identifier(False)
            print("icmpReplyPacket identifier is valid:", icmpReplyPacket.get_is_valid_identifier()) \
                if self.__DEBUG_IcmpPacket else 0

            # Raw data
            print("icmpReplyPacket data:", reply_data) if self.__DEBUG_IcmpPacket else 0
            print("OriginalPingData data:", outgoing_data) if self.__DEBUG_IcmpPacket else 0
            if outgoing_data == reply_data:
                icmpReplyPacket.set_is_valid_data(True)
            else:
                icmpReplyPacket.set_is_valid_data(False)
            print("icmpReplyPacket data is valid:", icmpReplyPacket.get_is_valid_identifier()) \
                if self.__DEBUG_IcmpPacket else 0

            # Set the valid data variable in the IcmpPacket_EchoReply class based on
            # the outcome of the data comparison
            if (icmpReplyPacket.get_is_valid_seq_num() is True and
                    icmpReplyPacket.get_is_valid_identifier() is True and
                    icmpReplyPacket.get_is_valid_data() is True):
                icmpReplyPacket.setIsValidResponse(True)
            else:
                icmpReplyPacket.setIsValidResponse(False)
            print("icmpReplyPacket is valid:", icmpReplyPacket.isValidResponse()) if self.__DEBUG_IcmpPacket else 0

        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber, ttl):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setTtl(ttl)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def sendEchoRequest(self, is_tracer):
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            # print("Pinging (" + self.__icmpTarget + ") " + self.__destinationIpAddress)

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 30
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    print("  *        *        *        *        *    Request timed out.")
                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                self.__echo_reply_host_ip = addr[0]
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    print("  *        *        *        *        *    Request timed out (By no remaining time left).")

                else:

                    # ***** Eric Code *****
                    IcmpHelperLibrary._echo_reply_rtt = (timeReceived - pingStartTime) * 1000
                    IcmpHelperLibrary._echo_reply_packet = recvPacket
                    # *********************

                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]
                    type_code_msg = IcmpHelperLibrary._error_codes[icmpType][icmpCode]

                    if icmpType == 11:  # Time Exceeded
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d (%s)    %s" %
                              (
                                  self.getTtl(),
                                  (timeReceived - pingStartTime) * 1000,
                                  icmpType,
                                  icmpCode,
                                  type_code_msg,
                                  addr[0]
                              )
                              )

                    elif icmpType == 3:  # Destination Unreachable
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d (%s)    %s" %
                              (
                                  self.getTtl(),
                                  (timeReceived - pingStartTime) * 1000,
                                  icmpType,
                                  icmpCode,
                                  type_code_msg,
                                  addr[0]
                              )
                              )

                    elif icmpType == 0:  # Echo Reply
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        # if is_tracer is False:
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr)
                        return  # Echo reply is the end and therefore should return

                    else:
                        print("error")
            except timeout:
                print("  *        *        *        *        *    Request timed out (By Exception).")
            finally:
                mySocket.close()

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i + 1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __recvPacket = b''
        __isValidResponse = False

        # ***** Eric Code *****
        __valid_icmp_seq_num = False
        __valid_icmp_identifier = False
        __valid_icmp_data = False

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Constructors                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __init__(self, recvPacket):
            self.__recvPacket = recvPacket

            # ***** Eric Code *****
            self._expected_seqnum = None
            self._expected_identifier = None
            self._expected_data = ""
            self._rtt = 0

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)  # Used to track overall round trip time
            # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def isValidResponse(self):
            return self.__isValidResponse

        # ***** Eric Code *****
        def get_is_valid_seq_num(self):
            return self.__valid_icmp_seq_num

        def get_is_valid_identifier(self):
            return self.__valid_icmp_identifier

        def get_is_valid_data(self):
            return self.__valid_icmp_data

        def get_expected_seq_num(self):
            return self._expected_seqnum

        def get_expected_identifier(self):
            return self._expected_identifier

        def get_expected_data(self):
            return self._expected_data

        def get_rrt(self):
            return self._rtt

        # def get_source_ip(self):
        #     # IP address == 4 Byte string starting at Byte 12 of datagram
        #     self.__unpackByFormatAndPosition("4s", 12)
        #
        #     return data

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        # ***** Eric Code *****
        def set_is_valid_seq_num(self, booleanValue: bool):
            self.__valid_icmp_seq_num = booleanValue

        def set_is_valid_identifier(self, booleanValue: bool):
            self.__valid_icmp_identifier = booleanValue

        def set_is_valid_data(self, booleanValue: bool):
            self.__valid_icmp_data = booleanValue

        def set_expected_seq_num(self, seq_num):
            self._expected_seqnum = seq_num

        def set_expected_identifier(self, identifier):
            self._expected_identifier = identifier

        def set_expected_data(self, data):
            self._expected_data = data

        def set_rtt(self, rtt):
            self._rtt = rtt

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def printResultToConsole(self, ttl, timeReceived, addr):

            # This returns the size of the double (size 8) string format...aka bytes
            bytes = struct.calcsize("d")

            # Unpacks from the buffer (self.__recvPacket) according to the double (size 8) format starting at index 28
            # This corresponds to
            icmp_type = self.getIcmpType()                                          # Eric code
            icmp_code = self.getIcmpCode()                                          # Eric code
            type_code_msg = IcmpHelperLibrary._error_codes[icmp_type][icmp_code]    # Eric code
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]
            print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d (%s)    Identifier=%d    Sequence Number=%d    %s" %
                  (
                      ttl,
                      (timeReceived - timeSent) * 1000,
                      self.getIcmpType(),
                      self.getIcmpCode(),
                      type_code_msg,                                                # Eric code
                      self.getIcmpIdentifier(),
                      self.getIcmpSequenceNumber(),
                      addr[0]
                  )
                  )

            # ***** Eric Code *****
            #  Report any error information details.
            if self.get_is_valid_seq_num() is False:
                print("seq_num error:")
                print("Expected seq_num:", str(self.get_expected_seq_num()))
                print("Actual seq_num:", str(self.getIcmpSequenceNumber()))

            if self.get_is_valid_identifier() is False:
                print("identifier error:")
                print("Expected identifier:", str(self.get_expected_identifier()))
                print("Actual identifier:", str(self.getIcmpIdentifier()))

            if self.get_is_valid_data() is False:
                print("raw data error:")
                print("Expected raw data:", str(self.get_expected_data()))
                print("Actual raw data:", str(self.getIcmpData()))

            type_errors = [3, 4, 11, 12]
            if self.getIcmpType() in type_errors:
                print("Error: ", IcmpHelperLibrary._error_codes[icmp_type][icmp_code])
                # self.print_error_code()

    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False  # Allows for debug output

    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def __sendIcmpEchoRequest(self, host):
        """
        Initiates ping functionality. Prints information for each echo reply from the
        destination host. Sends 4 pings and provides a summary of min, max and avg rtt.
        """

        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        packets_sent = 4
        min_rtt = None
        max_rtt = None
        rtt_sum = 0
        packets_received = []
        ttl = 64

        for i in range(packets_sent):

            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            randomIdentifier = (os.getpid() & 0xffff)  # Get as 16-bit number - Limit based on ICMP header standards
            # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber, ttl)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)

            if i == 0:
                print("Pinging (" + icmpPacket.getIcmpTarget() + ") " + icmpPacket.get_destination_ip())
            icmpPacket.sendEchoRequest(False)  # Build IP

            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0

            # Access reply and update variables
            echo_reply = IcmpHelperLibrary.IcmpPacket_EchoReply(IcmpHelperLibrary._echo_reply_packet)

            # if echo_reply.isValidResponse() is True:
            packets_received.append(echo_reply)
            echo_reply.set_rtt(IcmpHelperLibrary._echo_reply_rtt)

        for echo_reply in packets_received:

            # Update min_rtt
            if min_rtt is None:
                min_rtt = echo_reply.get_rrt()
            else:
                if echo_reply.get_rrt() < min_rtt:
                    min_rtt = echo_reply.get_rrt()

            # Update max_rtt
            if max_rtt is None:
                max_rtt = echo_reply.get_rrt()
            else:
                if echo_reply.get_rrt() > max_rtt:
                    max_rtt = echo_reply.get_rrt()

            rtt_sum += echo_reply.get_rrt()

        # If no valid packets were returned.
        if min_rtt is None:
            min_rtt = 0
        if max_rtt is None:
            max_rtt = 0

        # Determine average and packet loss %
        avg_rtt = 0
        packet_loss_percent = 100
        if len(packets_received) != 0:
            avg_rtt = rtt_sum / len(packets_received)
            packet_loss_percent = ((packets_sent - len(packets_received)) / packets_sent) * 100

        # Print and format results
        print()
        print("%d packets transmitted, %d packets received, %.0f%% packet loss" %
              (packets_sent, len(packets_received), packet_loss_percent))
        print("--- %s ping statistics ---" % host)
        print("round-trip min/max/avg = %.0f/%.0f/%.0f ms" % (min_rtt, max_rtt, avg_rtt))

    def __sendIcmpTraceRoute(self, host):
        """
        Initiates traceroute functionality. Prints information for each echo reply, each
        1 hop further than the previous host. Stops at 30 hops, or once the
        destination hosts replies with type 0.
        """
        print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        max_hops = 30
        ttl = 1

        for i in range(max_hops):

            # Build packet
            trace_packet = IcmpHelperLibrary.IcmpPacket()

            randomIdentifier = (os.getpid() & 0xffff)  # Get as 16-bit number - Limit based on ICMP header standards
            # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            trace_packet.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber, ttl)  # Build ICMP for IP payload
            trace_packet.setIcmpTarget(host)
            if i == 0:
                print("Traceroute to (" + trace_packet.getIcmpTarget() + ") " + trace_packet.get_destination_ip())
            trace_packet.sendEchoRequest(True)  # Build IP

            # Debug
            trace_packet.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            trace_packet.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0

            # Access reply and update variables
            trace_reply = IcmpHelperLibrary.IcmpPacket_EchoReply(IcmpHelperLibrary._echo_reply_packet)
            reply_type = trace_reply.getIcmpType()

            # If echo request comes back destination host was reached
            if reply_type == 0:
                break

            ttl += 1

    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions                                                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def sendPing(self, targetHost):
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)


# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()
https://github.com/ehorn36/traceroute
    # ***** Ping *****
    # Choose one of the following by uncommenting out the line
    # icmpHelperPing.sendPing("209.233.126.254")
    # icmpHelperPing.sendPing("www.google.com")
    # icmpHelperPing.sendPing("gaia.cs.umass.edu")
    # icmpHelperPing.sendPing("62.115.138.190")

    # ***** Traceroute *****
    # icmpHelperPing.traceRoute("164.151.129.20")
    # icmpHelperPing.traceRoute("122.56.99.243")
    # icmpHelperPing.traceRoute("www.gla.ac.uk")
    icmpHelperPing.traceRoute("www.google.com")


if __name__ == "__main__":
    main()
