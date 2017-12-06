# -*- coding:utf-8 -*-

import os
import struct
# import socket
import multiprocessing
from multiprocessing import Queue


XDR_PATH = "bad/mobile-dpi_0302003714022000000004000235_796_1512015423_0_0.xdr"
try:
    XDR_FP = open(XDR_PATH, "rb")
except Exception, err:
    XDR_FP = None
    print err
    exit()

TLV_ID = {
    # GENER
    0: "XDR_DATA_LENGTH", 1: "XRD_SESSION_STATUS", 2: "XDR_APP_ID", 3: "XDR_TUPLE", 4: "XDR_STAT",
    5: "XDR_TIME", 6: "XDR_BUSI_STAT", 7: "XDR_TCP_INFO", 8: "XDR_RESPONSE", 9: "XDR_L7_TYPE",
    55: "XDR_VPN_TYPE", 56: "XDR_PROXY_TYPE", 57: "XDR_PROTO_TYPE", 58: "XDR_VPN_TUPLE",
    61: "XDR_GEN_SSNDIRECTION",
    # HTTP
    10: "XDR_HTTP_BASE_INFO", 11: "XDR_HTTP_HOST", 12: "XDR_HTTP_URL", 13: "XDR_HTTP_XONLINEHOST",
    14: "XDR_HTTP_USERAGENT", 15: "XDR_HTTP_CONTENT", 16: "XDR_HTTP_REFER", 17: "XDR_HTTP_COOKIE",
    18: "XDR_HTTP_LOCATION", 62: "XDR_SPECIAL_HTTP_FLAG",
    # SIP
    19: "XDR_SIP_BASE_INFO", 20: "XDR_SIP_CALLER_NUM", 21: "XDR_SIP_CALLED_NUM", 22: "XDR_SIP_CALLID_NUM",
    # RTSP
    23: "XDR_RTSP_BASE_INFO", 24: "XDR_RTSP_URL", 25: "XDR_RTSP_USERAGENT", 26: "XDR_RTSP_SERVERIP",
    # FTP
    27: "XDR_FTP_STATUS", 28: "XDR_FTP_USR_NM", 29: "XDR_FTP_CUR_DIR", 30: "XDR_FTP_TRANS_MODE",
    31: "XDR_FTP_TRANS_TYPE", 32: "XDR_FTP_FILE_NM",
    33: "XDR_FTP_FILE_SIZ", 34: "XDR_FTP_PSP_TM", 35: "XDR_FTP_TRANS_TM",
    # MAIL
    36: "XDR_MAIL_MSG_TYPE", 37: "XDR_MAIL_RSP_STATUS", 38: "XDR_MAIL_USR_NM",
    39: "XDR_MAIL_SND_INFO", 40: "XDR_MAIL_LEN", 41: "XDR_MAIL_DOMAIN", 42: "XDR_MAIL_RCV_ACCOUNT",
    43: "XDR_MAIL_HDR", 44: "XDR_MAIL_ACS_TYPE",
    # DNS
    45: "XDR_DNS_DOMAIN", 46: "XDR_DNS_IP_NUM", 47: "XDR_DNS_IPV4", 48: "XDR_DNS_IPV6",
    49: "XDR_DNS_RSP_CODE", 50: "XDR_DNS_REQ_CNT", 51: "XDR_DNS_RSP_RECORD", 52: "XDR_DNS_AUTH_CNTT_CNT",
    53: "XDR_DNS_EXTRA_RECORD_CNT", 54: "XDR_DNS_RSP_DELAY", 59: "XDR_DNS_PKT_VALID",
    # IM
    60: "XDR_IM_ACCOUNT",
    # New Type
    201: "HTTP_REQUESE_CONTENT", 202: "HTTP_RESPONSE_CONTENT", 203: "RESTORE_CONTENT",
    204: "SSL_SERVER_CERTIFICATE", 205: "SSL_CLIENT_CERTIFICATE", 206: "SSL_LINK_FAIL_REASON",
    # END
    63: "XDR_END"
}
TLVTYPE = {
    0: "XDR_TYPE_SHORT",
    1: "XDR_TYPE_INT16",
    2: "XDR_TYPE_INT32",
    3: "XDR_TYPE_INT64",
    4: "XDR_TYPE_STRING",
    5: "XDR_TYPE_STRUCT",
    6: "XDR_TYPE_END",

    "XDR_TYPE_SHORT": 0,
    "XDR_TYPE_INT16": 1,
    "XDR_TYPE_INT32": 2,
    "XDR_TYPE_INT64": 3,
    "XDR_TYPE_STRING": 4,
    "XDR_TYPE_STRUCT": 5,
    "XDR_TYPE_END": 6,
    "NULL": 99
}
TLVTYPE_BY_TLVID = {
    # GENER
    "XDR_DATA_LENGTH": "XDR_TYPE_SHORT", "XRD_SESSION_STATUS": "XDR_TYPE_SHORT",
    "XDR_APP_ID": "XDR_TYPE_SHORT", "XDR_TUPLE": "XDR_TYPE_STRUCT", "XDR_STAT": "XDR_TYPE_STRUCT",
    "XDR_TIME": "XDR_TYPE_STRUCT", "XDR_BUSI_STAT": "XDR_TYPE_STRUCT", "XDR_TCP_INFO": "XDR_TYPE_STRUCT",
    "XDR_RESPONSE": "XDR_TYPE_INT32", "XDR_L7_TYPE": "XDR_TYPE_INT32", "XDR_VPN_TYPE": "NULL",
    "XDR_PROXY_TYPE": "NULL", "XDR_PROTO_TYPE": "NULL", "XDR_VPN_TUPLE": "NULL",
    "XDR_GEN_SSNDIRECTION": "NULL",
    # HTTP
    "XDR_HTTP_BASE_INFO": "XDR_TYPE_STRUCT", "XDR_HTTP_HOST": "XDR_TYPE_SHORT", "XDR_HTTP_URL": "XDR_TYPE_SHORT",
    "XDR_HTTP_XONLINEHOST": "XDR_TYPE_SHORT", "XDR_HTTP_USERAGENT": "XDR_TYPE_SHORT",
    "XDR_HTTP_CONTENT": "XDR_TYPE_SHORT",
    "XDR_HTTP_REFER": "XDR_TYPE_SHORT", "XDR_HTTP_COOKIE": "XDR_TYPE_SHORT", "XDR_HTTP_LOCATION": "XDR_TYPE_SHORT",
    "XDR_SPECIAL_HTTP_FLAG": "NULL",
    # SIP
    "XDR_SIP_BASE_INFO": "XDR_TYPE_STRUCT", "XDR_SIP_CALLER_NUM": "XDR_TYPE_STRING",
    "XDR_SIP_CALLED_NUM": "XDR_TYPE_STRING", "XDR_SIP_CALLID_NUM": "XDR_TYPE_STRING",
    # RTSP
    "XDR_RTSP_BASE_INFO": "XDR_TYPE_STRUCT", "XDR_RTSP_URL": "XDR_TYPE_STRING",
    "XDR_RTSP_USERAGENT": "XDR_TYPE_STRING", "XDR_RTSP_SERVERIP": "XDR_TYPE_STRING",
    # FTP
    "XDR_FTP_STATUS": "XDR_TYPE_INT16", "XDR_FTP_USR_NM": "XDR_TYPE_STRING", "XDR_FTP_CUR_DIR": "XDR_TYPE_STRING",
    "XDR_FTP_TRANS_MODE": "XDR_TYPE_SHORT", "XDR_FTP_TRANS_TYPE": "XDR_TYPE_SHORT",
    "XDR_FTP_FILE_NM": "XDR_TYPE_STRING",
    "XDR_FTP_FILE_SIZ": "XDR_TYPE_INT32", "XDR_FTP_PSP_TM": "XDR_TYPE_INT64", "XDR_FTP_TRANS_TM": "XDR_TYPE_INT64",
    # MAIL
    "XDR_MAIL_MSG_TYPE": "XDR_TYPE_INT16", "XDR_MAIL_RSP_STATUS": "XDR_TYPE_INT16",
    "XDR_MAIL_USR_NM": "XDR_TYPE_STRING",
    "XDR_MAIL_SND_INFO": "XDR_TYPE_STRING", "XDR_MAIL_LEN": "XDR_TYPE_INT32", "XDR_MAIL_DOMAIN": "XDR_TYPE_STRING",
    "XDR_MAIL_RCV_ACCOUNT": "XDR_TYPE_STRING", "XDR_MAIL_HDR": "XDR_TYPE_STRING", "XDR_MAIL_ACS_TYPE": "XDR_TYPE_SHORT",
    # DNS
    "XDR_DNS_DOMAIN": "XDR_TYPE_STRING", "XDR_DNS_IP_NUM": "XDR_TYPE_SHORT", "XDR_DNS_IPV4": "XDR_TYPE_INT32",
    "XDR_DNS_IPV6": "XDR_TYPE_STRUCT", "XDR_DNS_RSP_CODE": "XDR_TYPE_SHORT", "XDR_DNS_REQ_CNT": "XDR_TYPE_SHORT",
    "XDR_DNS_RSP_RECORD": "XDR_TYPE_SHORT", "XDR_DNS_AUTH_CNTT_CNT": "XDR_TYPE_SHORT",
    "XDR_DNS_EXTRA_RECORD_CNT": "XDR_TYPE_SHORT",
    "XDR_DNS_RSP_DELAY": "XDR_TYPE_INT32", "XDR_DNS_PKT_VALID": "NULL",
    # IM
    "XDR_IM_ACCOUNT": "NULL",
    # New Type
    "HTTP_REQUESE_CONTENT": "NULL", "HTTP_RESPONSE_CONTENT": "NULL", "RESTORE_CONTENT": "NULL",
    "SSL_SERVER_CERTIFICATE": "XDR_TYPE_STRING", "SSL_CLIENT_CERTIFICATE": "XDR_TYPE_STRING",
    "SSL_LINK_FAIL_REASON": "XDR_TYPE_SHORT",
    # END
    "XDR_END": "NULL"
}


class Cream(multiprocessing.Process):

    version = "white"

    def __init__(self, xdrstatusq=None, styles="*", functiontype="print"):

        multiprocessing.Process.__init__(self)

        self.xdrstatusq = xdrstatusq
        self.styles = styles
        self.xdrfilefp = open(XDR_PATH, "rb")
        self.xdrmem = self.xdrfilefp.read()
        self.xdrstring = ""
        self.resultfilefp = None
        self.xdrnum = 0

        if functiontype == "file":
            self.resultfilefp = open("./result", "w")
            self.functiontype = self.functionfile
        else:
            self.functiontype = self.functionprint

        if styles is None:
            self.stylefun = self.functionnull
        elif styles == "*":
            self.stylefun = self.functionall
        else:
            self.stylefun = self.functionrange

    def functionbase(self, tlvstatus):
        if 100 == tlvstatus[0]:
            open("./creamcake.ok", "w")
        elif TLVTYPE[0] == TLVTYPE_BY_TLVID[TLV_ID[tlvstatus[0]]]:
            self.shortdata(tlvstatus)
        elif TLVTYPE[1] == TLVTYPE_BY_TLVID[TLV_ID[tlvstatus[0]]]:
            self.int16(tlvstatus)
        elif TLVTYPE[2] == TLVTYPE_BY_TLVID[TLV_ID[tlvstatus[0]]]:
            self.int32(tlvstatus)
        elif TLVTYPE[3] == TLVTYPE_BY_TLVID[TLV_ID[tlvstatus[0]]]:
            self.int64(tlvstatus)
        elif TLVTYPE[4] == TLVTYPE_BY_TLVID[TLV_ID[tlvstatus[0]]]:
            self.string(tlvstatus)
        elif TLVTYPE[5] == TLVTYPE_BY_TLVID[TLV_ID[tlvstatus[0]]]:
            self.struct(tlvstatus)
        else:
            self.xdrstring = "cannot read " + "tlvid " + tlvstatus[0] + " tlvlength " + tlvstatus[2] + " tlvstart ", tlvstatus[3] + "\n"

    def functionnull(self, tlvstatus):
        pass

    def functionall(self, tlvstatus):
        self.functionbase(tlvstatus)

    def functionrange(self, tlvstatus):
        if tlvstatus[0] in self.styles:
            self.functionbase(tlvstatus)

    def functionprint(self):
        print self.xdrstring
        self.xdrstring = ""

    def functionfile(self):
        self.resultfilefp = open("./result", "a")
        self.resultfilefp.write(self.xdrstring)
        self.xdrstring = ""

    def shortdata(self, tlvstatus):
        tlvmem = self.xdrmem[tlvstatus[3]:tlvstatus[3] + tlvstatus[2]]
        tlvidnull, shortdatamem = struct.unpack("2B", tlvmem[:2])
        if 0 == tlvstatus[0]:
            self.xdrnum += 1
            self.xdrstring = "header " + str(self.xdrnum)+ "\n"
        else:
            self.xdrstring = "tlv id is %d, value is %d" % (tlvstatus[0], shortdatamem) + "\n"

    def int16(self, tlvstatus):
        tlvmem = self.xdrmem[tlvstatus[3]:tlvstatus[3] + tlvstatus[2]]
        int16value, = struct.unpack("I", tlvmem[-4:])
        self.xdrstring = "tlv id is %d, value is %d" % (tlvstatus[0], int16value) + "\n"

    def int32(self, tlvstatus):
        tlvmem = self.xdrmem[tlvstatus[3]:tlvstatus[3] + tlvstatus[2]]
        int32value, = struct.unpack("I", tlvmem[-4:])
        self.xdrstring = "tlv id is %d, value is %d" % (tlvstatus[0], int32value) + "\n"

    def int64(self, tlvstatus):
        tlvmem = self.xdrmem[tlvstatus[3]:tlvstatus[3] + tlvstatus[2]]
        int64value, = struct.unpack("I", tlvmem[-8:])
        self.xdrstring = "tlv id is %d, value is %d" % (tlvstatus[0], int64value) + "\n"

    def string(self, tlvstatus):
        tlvmem = self.xdrmem[tlvstatus[3]:tlvstatus[3] + tlvstatus[2]]
        self.xdrstring = "tlv id is %d, value is %s" % (tlvstatus[0], tlvmem[4:]) + "\n"

    def struct(self, tlvstatus):
        # tlvmem = self.xdrmem[tlvstatus[3]:tlvstatus[3] + tlvstatus[2]]
        # self.xdrstring = "tlv id is %d, value is %d" % (tlvstatus[0], tlvmem[]) + "\n"
        pass

    def run(self):
        while True:
            xdrstatus = self.xdrstatusq.get()
            self.stylefun(xdrstatus)
            self.functiontype()


if __name__ == "__main__":
    xdrmem = XDR_FP.read()
    xdrmemlen = len(xdrmem)
    xdrnum = 0
    xdrflag = 0
    xdrstatusqueue = Queue(maxsize=0)
    xdrhandle = Cream(xdrstatusqueue, functiontype="file")
    xdrhandle.start()
    while True:
        if xdrflag == xdrmemlen:
            print "[Complete] xdrlength is %d, xdrnum is %d" % (xdrmemlen, xdrnum)
            xdrstatusqueue.put([100, "end", "process", "flag"])
            # exit()
            xdrstatusqueue.put([100, "end", "process", "flag"])
            while True:
                if os.access("./creamcake.ok", os.F_OK):
                    xdrhandle.terminate()
                    os.remove("./creamcake.ok")
                    exit()
        elif xdrflag > xdrmemlen:
            print "[**Error] xdrlength is :%d, but lengthsum is :%d, now xdrnum is %d" % (xdrmemlen, xdrflag, xdrnum)
            # exit()
            xdrstatusqueue.put([100, "end", "process", "flag"])
            while True:
                if os.access("./creamcake.ok", os.F_OK):
                    xdrhandle.terminate()
                    os.remove("./creamcake.ok")
                    exit()
        tlvid, shortdata, typeandlength = struct.unpack("2BH", xdrmem[xdrflag:xdrflag + 4])
        if typeandlength & 0x1 == 1:
            tlvid, shortdata, tlvtype, length = struct.unpack("2BHI", xdrmem[xdrflag:xdrflag + 8])
            if tlvid == 0:
                xdrstatusqueue.put([tlvid, tlvtype, 8, xdrflag])
                xdrnum += 1
                xdrflag = xdrflag + 8
                print "xdrnum is %d" % xdrnum
            else:
                xdrstatusqueue.put([tlvid, tlvtype, length, xdrflag])
                xdrflag = xdrflag + length
            if TLVTYPE[4] == TLVTYPE_BY_TLVID[TLV_ID[tlvid]] and length-8 < shortdata:
                print "ERROR(long) length=%d shortdata=%d" % (length, shortdata)
        else:
            tlvtype = typeandlength & 15
            length = typeandlength >> 4
            if tlvid == 0:
                xdrstatusqueue.put([tlvid, tlvtype, 4, xdrflag])
                xdrnum += 1
                xdrflag = xdrflag + 4
                print "xdrnum is %d" % xdrnum
            else:
                xdrstatusqueue.put([tlvid, tlvtype, length, xdrflag])
                xdrflag = xdrflag + length
            if TLVTYPE[4] == TLVTYPE_BY_TLVID[TLV_ID[tlvid]] and length-4 < shortdata:
                print "ERROR(short) length=%d shortdata=%d" % (length, shortdata)
        print "tlvid %3d | tlvlength %3d | nowlength %d" % (tlvid, length, xdrflag)


