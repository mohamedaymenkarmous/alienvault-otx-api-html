#!/usr/bin/python3
from __future__ import print_function
import json
from OTXv2 import OTXv2
import IndicatorTypes
from json2html import *
import imgkit
from datetime import datetime

class AlienVault_OTX:

  def init(self):
    config=None
    try:
      with open('config.json', 'r') as configFile:
        configContent = configFile.read()
        config=json.loads(configContent)
    except json.decoder.JSONDecodeError:
      print("Problem occured while parsing the config.json file")
      exit()
    if config==None:
      print("Problem occured while parsing the config.json file")
      exit()
    global OutputDir
    OutputDir = config['General']['OutputDir']
    global HTMLHeader
    HTMLHeader = config['General']['HTMLHeader']
    global TablesClass
    TablesClass = config['General']['TablesClass']
    global APIKeys
    APIKeys = config['AlienVault-OTX']['APIKeys']
    self.loadRecordsTmp()
    global APIKey
    APIKEY = APIKeys[APIKeyIndex]
    global APIKeysNumber
    APIKeysNumber = len(APIKeys)
    global DisabledAttr
    DisabledAttr = config['AlienVault-OTX']['DisabledAttr']
    global MaxResults
    MaxResults = config['AlienVault-OTX']['MaxResults']
    global AttrSubstitution
    AttrSubstitution = config['AlienVault-OTX']['AttrSubstitution']
    global Order
    Order = config['AlienVault-OTX']['Order']
    global Instance
    Instance = OTXv2(APIKEY)
    self.HTML=""
    self.IMG=""

  def preHandling(self):
    self.number={}
    self.history={}

  def loadRecordsTmp(self):
    global APIKeyIndex
    try:
      with open('.records.tmp', 'r') as recordsTmpFile:
        recordsTmpContent = recordsTmpFile.read()
        recordsTmp=json.loads(recordsTmpContent)
        APIKeyIndex=recordsTmp["APIKeyIndex"]
    except Exception:
      APIKeyIndex=0
      recordsTmp={"APIKeyIndex":APIKeyIndex}
      with open('.records.tmp', 'w') as recordsTmpFile:
        json.dump(recordsTmp, recordsTmpFile)

  def updateAPIKeyIndex(self):
    try:
      with open('.records.tmp', 'r') as recordsTmpFile:
        recordsTmpContent = recordsTmpFile.read()
        recordsTmp=json.loads(recordsTmpContent)
    except Exception:
      recordsTmp={"APIKeyIndex":APIKeyIndex}
    recordsTmp["APIKeyIndex"]=APIKeyIndex
    with open('.records.tmp', 'w') as recordsTmpFile:
      json.dump(recordsTmp, recordsTmpFile)

  def updateInstance(self):
    global APIKeyIndex
    APIKeyIndex=(APIKeyIndex+1)%APIKeysNumber
    self.updateAPIKeyIndex()
    global APIKEY
    APIKEY = APIKeys[APIKeyIndex]
    global Instance
    Instance = OTXv2(APIKEY)
    #print(APIKEY)

  def getIPReportAPI(self):
    result={}
    with open("input_ip.txt") as file:
      ips=file.read().strip()
      for ip in ips.split("\n"):
        response = Instance.get_indicator_details_full(IndicatorTypes.IPv4, ip)
        self.updateInstance()
        if 'error' not in response:
          result[ip]=response
        else:
          print(response)
    return result

  def formatGeolocation(self,ip_report_api,attr):
      result={"Location":ip_report_api[attr]["city"]+", "+ip_report_api[attr]["country_name"]+" <img src='https://otx.alienvault.com"+ip_report_api[attr]["flag_url"]+"'>","ASN/Owner":ip_report_api[attr]["asn"]}
      return result

  def formatArrayDateDomain(self,ip_report_api,attr):
      result=[]
      count=MaxResults[attr] if MaxResults[attr] else -1
      for elem in list(ip_report_api[attr][attr]):
        if count==0:
          break
        if elem['hostname']==elem['address']:
          continue
        obj={'Date resolved':"", 'Domain':""}
        obj['Date resolved']=elem['first']
        if elem['first']!=elem['last']:
          obj['Date resolved']=obj['Date resolved']+" - "+elem['last']
        obj['Domain']='<a href="https://otx.alienvault.com'+elem['indicator_link']+'">['+elem['record_type']+'] '+elem['hostname']+'</a>'
        result.append(obj)
        count=count-1
      return result

  def formatArrayDateActivitySource(self,ip_report_api,attr):
      result=[]
      max=MaxResults[attr] if MaxResults[attr] else -1
      count=max
      for elem in list(ip_report_api[attr][attr]['activities']):
        if count==0:
          break
        obj={'Scanned':"",'Activity':"",'Finding':"",'Source':""}
        obj['Scanned']=elem['first_date']
        if elem['first_date']!=elem['last_date']:
          obj['Scanned']=obj['Scanned']+" - "+elem['last_date']
        obj['Activity']=elem['name']
        obj['Finding']=elem['data_key']
        obj['Source']=elem['source']
        result.append(obj)
        count=count-1
      return result

  def formatArrayDateHashScore(self,ip_report_api,attr):
      result=[]
      max=MaxResults[attr] if MaxResults[attr] else -1
      count=max
      for elem in list(ip_report_api[attr]['data']):
        if count==0:
          break
        obj={'Scanned':"",'File Hash (SHA256)':"",'Detections':""}
        obj['Scanned']=datetime.utcfromtimestamp(elem['datetime_int']).strftime('%Y-%m-%d %H:%M:%S')
        obj['File Hash (SHA256)']='<a href="https://otx.alienvault.com/indicator/file/'+elem['hash']+'">'+elem['hash']+'</a>'
        for detection in list(elem['detections']):
          if elem['detections'][detection]:
            if obj['Detections']:
              obj['Detections']=obj['Detections']+", "
            obj['Detections']=obj['Detections']+'<span style="color:red">['+detection+'] '+elem['detections'][detection]+"</span>"
        result.append(obj)
        count=count-1
      return result

  def formatArrayDateURLStatus(self,ip_report_api,attr):
      result=[]
      max=MaxResults[attr] if MaxResults[attr] else -1
      count=max
      has_next=ip_report_api[attr]['has_next']
      page=0
      for elem in list(ip_report_api[attr][attr]):
        if count==0:
          break
        obj={'Scanned':"", 'URL':"",'HTTP Response':""}
        obj['Scanned']=elem['date']
        obj['URL']='<a href="'+elem['url']+'">'+elem['url']+'</a>'
        obj['HTTP Response']=str(elem['httpcode']) if 'httpcode' in elem and elem['httpcode']>0 else 'Connection Error'
        result.append(obj)
        count=count-1
      return result

  def formatArrayPulse(self,ip_report_api,attr):
      result=[]
      max=MaxResults[attr] if MaxResults[attr] else -1
      count=max
      for elem in list(ip_report_api[attr]["pulse_info"]["pulses"]):
        if count==0:
          break
        obj={'Created/Modified':"", 'Title':"",'Description':"",'Tags':"",'HTML_Template':""}
        obj['Created/Modified']=("[Created]" if elem['is_modified']==True else "[Modified]")+" "+elem['modified']
        obj['Title']="<a href='https://otx.alienvault.com/pulse/"+elem['id']+"'>"+elem['name']+"</a>"
        obj['Description']=elem['description']
        obj['Tags']=elem['tags']
        obj['References']=elem['references']
        obj['HTML_Template']="<div class='pulse'><h4>"+obj['Title']+"</h4><h5>"+obj['Created/Modified']+"</h5><p>"+obj['Description']+"</p>"
        if len(obj['References'])>0:
          obj['HTML_Template']=obj['HTML_Template']+"<p>References: "+", ".join(obj['References'])+"</p>"
        if len(obj['Tags'])>0:
           obj['HTML_Template']=obj['HTML_Template']+"<p>Tags: "+", ".join(obj['Tags'])+"</p>"
        obj['HTML_Template']=obj['HTML_Template']+"</div>"
        result.append(obj)
        count=count-1
      return result

  def getIPReportFiltered(self,ip_report_api):
      result={}
      for attr in list(ip_report_api):
        if(attr in DisabledAttr):
          None
        elif attr=='geo':
          newAttr=AttrSubstitution[attr] if attr in AttrSubstitution else attr
          result[newAttr]=self.formatGeolocation(ip_report_api,attr)
        elif attr=='passive_dns' and ip_report_api[attr] and ip_report_api[attr][attr]:
          newAttr=AttrSubstitution[attr] if attr in AttrSubstitution else attr
          self.history[newAttr]=ip_report_api[attr]['count']
          result[newAttr]=self.formatArrayDateDomain(ip_report_api,attr)
        elif attr=='reputation' and ip_report_api[attr] and ip_report_api[attr][attr] and ip_report_api[attr][attr]['activities']:
          newAttr=AttrSubstitution[attr] if attr in AttrSubstitution else attr
          self.history[newAttr]=len(ip_report_api[attr][attr]['activities'])
          result[newAttr]=self.formatArrayDateActivitySource(ip_report_api,attr)
        elif attr=='malware' and ip_report_api[attr] and ip_report_api[attr]['data']:
          newAttr=AttrSubstitution[attr] if attr in AttrSubstitution else attr
          self.history[newAttr]=ip_report_api[attr]['size']
          result[newAttr]=self.formatArrayDateHashScore(ip_report_api,attr)
        elif attr=='url_list' and ip_report_api[attr] and ip_report_api[attr][attr]:
          newAttr=AttrSubstitution[attr] if attr in AttrSubstitution else attr
          self.history[newAttr]=ip_report_api[attr]['full_size']
          result[newAttr]=self.formatArrayDateURLStatus(ip_report_api,attr)
        elif attr=='general' and ip_report_api[attr] and ip_report_api[attr]["pulse_info"] and ip_report_api[attr]["pulse_info"]["pulses"]:
          newAttr=AttrSubstitution[attr] if attr in AttrSubstitution else attr
          self.history[newAttr]=ip_report_api[attr]['pulse_info']['count']
          result[newAttr]=self.formatArrayPulse(ip_report_api,attr)
        else:
          result[attr]=ip_report_api[attr]
      return result

  def getOrdered(self,ip_report_filtered):
      result={}
      #We order the Order's elements in the begining of the result list
      for elem in Order:
        #If the substitued element index exists in the Order list, then it should be ordered
        if elem in AttrSubstitution and AttrSubstitution[elem] and AttrSubstitution[elem] in ip_report_filtered and ip_report_filtered[AttrSubstitution[elem]]:
          #Ordered elements should not duplicated
          if AttrSubstitution[elem] not in result:
            result[AttrSubstitution[elem]]=ip_report_filtered[AttrSubstitution[elem]]
        #If the index is not substitutable and if the index exists in the Order list, then it should be ordered
        elif elem in ip_report_filtered and ip_report_filtered[elem]:
          #Ordered elements should not duplicated
          if elem not in result:
            result[elem]=ip_report_filtered[elem]
      #Then, we add the non ordered elements since they are not blacklisted so of the Order list is missing some elements, they will be added in the end of the result list
      for attr in list(ip_report_filtered):
        #Ordered elements should not duplicated
        if attr not in result:
          result[attr]=ip_report_filtered[attr]
      return result

  def getHTML(self,ip_report_filtered,ip):
      html=""
      html=html+"<h3>IP Address: "+ip+"</h3>"
      for elem in list(ip_report_filtered):
        html=html+"<h4>"+elem+"</h4>"
        if elem in self.number and self.number[elem]:
          malicious=self.number[elem]["malicious"] if "malicious" in self.number[elem] else 0
          benign=self.number[elem]["benign"] if "benign" in self.number[elem] else 0
          html=html+"<h5>(<span style='color:red'>"+str(malicious)+" malicious</span> and <span style='color:green'>"+str(benign)+" benign</span>)</h5>"
        if elem in self.history and self.history[elem]:
          history=self.history[elem]
          html=html+"<h5>("+str(history)+" found)</h5>"
        if isinstance(ip_report_filtered[elem],list) and len(ip_report_filtered[elem])>0 and isinstance(ip_report_filtered[elem][0],dict) and 'HTML_Template' in ip_report_filtered[elem][0]:
          for html_elem in ip_report_filtered[elem]:
            html=html+html_elem['HTML_Template']
        else:
          html=html+json2html.convert(json = ip_report_filtered[elem], table_attributes='class="'+TablesClass+'"',escape=False)
      self.HTML=self.HTML+html
      html='<html><head>'+HTMLHeader+'</head><body>'+html
      html=html+'</body></html>'
      output=OutputDir+"/"
      imgkit.from_string(html, output+ip+'-AlienVault-OTX.jpg')
      with open(output+ip+'-AlienVault-OTX.html', 'w') as HTMLFile:
        HTMLFile.write(html)
      self.IMG=self.IMG+"<img src='"+ip+"-AlienVault-OTX.jpg'><br/>"

  def updateGeneralHTML(self):
    HTMLPrefix='<html><head>'+HTMLHeader+'</head><body>'
    self.HTML=HTMLPrefix+self.HTML+'</body></html>'
    self.IMG=HTMLPrefix+self.IMG+'</body></html>'
    output=OutputDir+"/"
    with open(output+'latest-HTML-AlienVault-OTX.html', 'w') as HTMLFile:
      HTMLFile.write(self.HTML)
    with open(output+'latest-IMG-AlienVault-OTX.html', 'w') as HTMLFile:
      HTMLFile.write(self.IMG)

def main():
  instance=AlienVault_OTX()
  instance.init()
  ips_report_api=instance.getIPReportAPI()
  results=[]
  for ip_report_api in list(ips_report_api):
    instance.preHandling()
    ip_report_filtered=instance.getIPReportFiltered(ips_report_api[ip_report_api])
    if len(Order)>0:
      ip_report_filtered=instance.getOrdered(ip_report_filtered)
    instance.getHTML(ip_report_filtered,ip_report_api)
  instance.updateGeneralHTML()

if __name__ == "__main__":
    main()
