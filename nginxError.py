#!/usr/bin/env python
# coding: utf-8
# author: shishaohui
# 读取nginx-error日志,从中抽出IP,将其加到nginx的拦截配置文件里

#encoding:utf-8
import os
import sys
import re
from datetime import datetime

reload(sys)
sys.setdefaultencoding("utf-8")

def formatNowDatetime():
  return "[%s]" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3])

def getLineno():
  return str(sys.exc_traceback.tb_lineno)

def debugLog(msg):
  print formatNowDatetime() + " " + msg

def printException(e):
  debugLog("Exception, line=" + getLineno() + " " + str(e))

# 错误明细
# 699#0: *29 open() "/usr/local/nginx/html/aa.asp" failed (2: No such file or directory),
# 697#0: *8309 SSL renegotiation disabled while waiting for request,
# 698#0: *8304 SSL_do_handshake() failed (SSL: error:14094085:SSL routines:ssl3_read_bytes:ccs received early) while SSL handshaking,
# 698#0: *7786 upstream prematurely closed connection while reading response header from upstream,
def parseThreadInfo(data):
  if "failed" in data:
    reg = re.compile("(.*?)#(.*?)\*(.*?) (.*?)\(\)(.*?)failed(.*?)$")
    match = reg.match(data)
    if match != None:
      result = {}
      result["threadMethod"] = match.group(4)
      result["threadPath"] = match.group(5).replace("\"", "")
      result["threadReason"] = match.group(6).replace(",", "")
      return result
    else:
      return None
  else:
    return None

# 解析剩余部分
def parseOthers(data):
  result = {}
  try:
    # 处理request
    if "request" in data:
      reg = re.compile("(.*?)request(.*?)\"(.*?)\"")
      match = reg.match(data)
      requestInfo = match.group(3)
      requestAry = requestInfo.split(" ")
      result["requestMethod"] = requestAry[0]
      result["requestPath"] = requestAry[1]
      if len(requestAry) > 2:  # 有的不带协议
        result["requestProtocol"] = requestAry[2]
    # 处理host
    if "host" in data:
      reg = re.compile("(.*?)host(.*?)\"(.*?)\"")
      match = reg.match(data)
      result["host"] = match.group(3)
    # 处理referrer
    if "referrer" in data:
      reg = re.compile("(.*?)referrer(.*?)\"(.*?)\"")
      match = reg.match(data)
      result["referrer"] = match.group(3)
    # 处理upstream
    if "upstream" in data:
      reg = re.compile("(.*?)upstream(.*?)\"(.*?)\"")
      match = reg.match(data)
      result["upstream"] = match.group(3)
    # 处理server
    if "," in data:
      data = ""
      if "request" in data:
        data = data[0: data.index("request")]
      elif "upstream" in data:
        data = data[0: data.index("upstream")]

      data = data.replace(":", "").replace(",", "").replace(" ", "")
      result["server"] = data
    else:
      reg = re.compile(":(.*?)$")
      match = reg.match(data)
      result["server"] = match.group(1)
  except Exception, e:
    printException(e)
  return result

# 将每行数据解析
# 2023/05/16 13:02:08 [error] 699#0: *29 open() "/usr/local/nginx/html/aa.asp" failed (2: No such file or directory), client: 106.75.96.247, server: 1.2.3, request: "GET /favicon.ico HTTP/1.1", host: "1.2.3.4"
# 2023/07/17 06:29:12 [error] 698#0: *7786 upstream prematurely closed connection while reading response header from upstream, client: 1.1.1.1, server: 1.2c.com, request: "GET / HTTP/1.1", upstream: "http://127.0.0.1:20040/", host: "1.1.1.1:443"
def parseRow(data):
  result = {}
  try:
    reg = re.compile("(.*?)\[(.*)\](.*?)client:(.*?)server(.*?)$")
    match = reg.match(data)
    if match != None:
      # 请求的时间
      result["requestTime"] = match.group(1)
      # 日志等级
      result["level"] = match.group(2)
      # 线程信息
      info = parseThreadInfo(match.group(3))
      if info == None:
        return None
      else:
        result.update(info)
      # 客户端ip
      result["clientIp"] = match.group(4)
      # 其它信息
      info2 = parseOthers(match.group(5))
      if info2 != None and len(info2) > 0:
        result.update(info2)
  except Exception, e:
    printException(e)
  return result

# 检查row是否属于非法请求
def checkRow(row):
  try:
    if row == None:
      return False
    else:
      itms = row.items()
      if len(itms) < 1:
        return False
    # 线程原因 (2: No such file or directory)
    if row.has_key("threadReason"):
      if "No such file or directory" in row.get("threadReason"):
        return True
    # 明确知道自己的系统不存在该文件后缀的
    keys = [".php", ".git", ".txt", ".asp" ]
    for key in keys:
      if key in row.get("threadPath"):
        return True
  except Exception, e:
    printException(e)
    return False

# 分析日志
def analyLog(errorLogFile):
  result = []
  try:
    reader = open(errorLogFile, "rb")
    lines = reader.readlines()
    for line in lines:
      row = parseRow(line)
      flag = checkRow(row)
      if flag:
        ip = row.get("clientIp").replace(" ", "")
        ipa = ip.split(".")
        # 直接用ip四段,要处理的ip太多了
        # 所以这里取ip前三段 1.2.3.0/24 整个网段全部封掉
        ipv = ipa[0] + "." + ipa[1] + "." + ipa[2] + ".0/24"
        if ipv in result:
          pass
        else:
          result.append(ipv)
    reader.close()
  except Exception,e:
    printException(e)
  return result

# 将日志里的IP合并到黑名单里
def mergeeData(ips, blackFile):
  try:
    reader = open(blackFile, "r")
    lines = reader.readlines()
    blackIpList = []
    for line in lines:
      line = line.replace("deny", "").replace(";", "").replace("\n", "")
      if line != "":
        blackIpList.append(line)
    reader.close()
    reader = open(blackFile, "w")
    # 将原来的数据写入
    for old in blackIpList:
      reader.write("deny " + old + ";\n")
    # 遍历当次的IP,与黑名单里的IP进行比对
    for ip in ips:
      if ip in blackIpList :
        pass # 本次要处理的ip已经存在于黑名单里面
      else:
        reader.write("deny " + ip + ";\n")
    reader.close()
    debugLog("Merged complete")
  except Exception, e:
    printException(e)

if __name__ == "__main__":
  # nginx日志文件
  errorLogFile = "E:\\temp\\logs\\error.log"
  ips = analyLog(errorLogFile)
  # nginx拦截ip文件
  blackPath = "E:\\temp\\logs\\black.conf"
  mergeeData(ips, blackPath)
