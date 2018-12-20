import csv
import io
import pandas as pd
import InputLog

class SignatureDetector:
    EVENT_PRIV = "4672"
    EVENT_PROCESS = "4688"
    SYSTEM_DIR = "c:\windows";
    SYSTEM_DIR2 = "c:\program files";
    RESULT_NORMAL="normal"
    RESULT_PRIV = "Unexpected privilege is used"
    RESULT_CMD="Command on blackList is used"
    RESULT_MAL_CMD = "Abnormal command or tool is used"

    df=pd.DataFrame(data=None, index=None, columns=["datetime","eventid","accountname","clientaddr","servicename","processname","objectname"], dtype=None, copy=False)
    df_admin = pd.DataFrame(data=None, index=None, columns=[ "accountname"], dtype=None, copy=False)
    df_cmd = pd.DataFrame(data=None, index=None, columns=["processname"], dtype=None, copy=False)


    def __init__(self):
        print("constructor called")

    @staticmethod
    def signature_detect(datetime, eventid, accountname, clientaddr, servicename, processname, objectname,sharedname):
        """ Detect attack using signature based detection.
        :param datetime: Datetime of the event
        :param eventid: EventID
        :param accountname: Accountname
        :param clientaddr: Source IP address
        :param servicename: Service name
        :param processname: Process name(command name)
        :param objectname: Object name
        :return : True(1) if attack, False(0) if normal
        """

        inputLog = InputLog.InputLog(datetime, eventid, accountname, clientaddr, servicename, processname, objectname,sharedname)
        return SignatureDetector.signature_detect(inputLog)

    @staticmethod
    def signature_detect(inputLog):
        """ Detect attack using signature based detection.
        :param inputLog: InputLog object of the event
        :return : True(1) if attack, False(0) if normal
        """
        result=SignatureDetector.RESULT_NORMAL

        if (inputLog.get_eventid() == SignatureDetector.EVENT_PRIV):
            result =SignatureDetector.isNotAdmin(inputLog)

        elif (inputLog.get_eventid() == SignatureDetector.EVENT_PROCESS):
            result = SignatureDetector.isSuspiciousProcess(inputLog)

        series = pd.Series([inputLog.get_datetime(),inputLog.get_eventid(),inputLog.get_accountname(),inputLog.get_clientaddr(),
                      inputLog.get_servicename(),inputLog.get_processname(),inputLog.get_objectname(),inputLog.get_sharedname()], index=SignatureDetector.df.columns)
        SignatureDetector.df=SignatureDetector.df.append(series, ignore_index = True)

        return result

    @staticmethod
    def isNotAdmin(inputLog):
        logs = SignatureDetector.df_admin[(SignatureDetector.df_admin.accountname == inputLog.get_accountname())]
        if len(logs) == 0:
            return SignatureDetector.RESULT_PRIV
        else:
            return SignatureDetector.RESULT_NORMAL

    @staticmethod
    def isSuspiciousProcess(inputLog):
        if (inputLog.get_processname().find(SignatureDetector.SYSTEM_DIR)==-1 and inputLog.get_processname().find(SignatureDetector.SYSTEM_DIR2)==-1):
            return SignatureDetector.RESULT_MAL_CMD
        cmds=inputLog.get_processname().split("\\")
        cmd=cmds[len(cmds)-1]
        logs = SignatureDetector.df_cmd[SignatureDetector.df_cmd.processname.str.contains(cmd)]
        if len(logs)>0:
            return SignatureDetector.RESULT_CMD

        return SignatureDetector.RESULT_NORMAL


SignatureDetector.df = pd.read_csv("./logs.csv")

SignatureDetector.df_admin = pd.read_csv("./admin.csv")

SignatureDetector.df_cmd = pd.read_csv("./command.csv")


csv_file = io.open("./log.csv", mode="r", encoding="utf-8")
f = csv.DictReader(csv_file, delimiter=",", doublequote=True, lineterminator="\r\n", quotechar='"', skipinitialspace=True)
for row in f:
    datetime=row.get("datetime")
    eventid=row.get("eventid")
    accountname=row.get("accountname").lower()
    clientaddr=row.get("clientaddr")
    servicename=row.get("servicename").lower()
    processname=row.get("processname").lower()
    objectname=row.get("objectname").lower()
    sharedname = row.get("sharedname").lower()

    # To specify parameter as Object
    inputLog = InputLog.InputLog(datetime, eventid, accountname, clientaddr, servicename, processname, objectname,sharedname)
    print(SignatureDetector.signature_detect(inputLog))

