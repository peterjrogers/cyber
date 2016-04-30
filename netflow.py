Enter file contents herefrom tools import Tools
import os
from geopy.distance import vincenty
import pprint
import pickle
import math

path = os.getcwd() + '\\'
db_file = path + 'netflow.db'

try: 
    import pygeoip
    cfile = path + 'GeoLiteCity.dat'
    geoip_city = pygeoip.GeoIP(cfile)
    cfile = path + 'GeoIPASNum.dat'
    geoip_asn = pygeoip.GeoIP(cfile)
except: pass


class Inetflow(Tools):
    def __init__(self, verbose=0):
        """
        Analyse netflow data and establish baselines according to the ASN# and county of origin, duration, size of flows
        
        netflow reports will load from \netflow\ folder
        
        a load file logging list will record each file opened
        
        new files will be opened according to file age
        
        Format of netflow load file will be csv with the following fields:
        RouterAddress,InterfaceIn,Protocol,SourceAddress,SourcePort,DestinationAddress,DestinationPort,TypeOfService,BytesInVolume,BytesInRatePerDuration,BytesInPercentOfTotalTraffic,FlowCount,FlowDuration,PacketsInVolume,PacketsInRatePerDuration,PacketsInPercentOfTotalTraffic
        
        Only specified interesting fileds will be loaded:
        Protocol
        SourceAddress
        SourcePort
        DestinationAddress
        DestinationPort
        BytesInVolume
        BytesInRatePerDuration
        FlowDuration
        PacketsInVolume
        PacketsInRatePerDuration
        
             
        format of dictionary will be based on the fact that this is an inbound flow report that is manually created so each flow will be to the same destination - i.e. 193.127.210.129
        
        ['destination_ip'] = {}
        [destination_ip]['Protocol'] = {}
        [destination_ip][Protocol]['src'] = {}
        [destination_ip][Protocol][src] = SourceAddress + '_' + SourcePort
        [destination_ip][Protocol][src]['DestinationPort'] = DestinationPort
        
        [destination_ip][Protocol][src]['TotalFlowCount'] = (1 if first entry but will increment for each flow seen for this src addrd and port to destination)
        [destination_ip][Protocol][src]['BytesInVolume'] = BytesInVolume + will increment for future matching flows
        [destination_ip][Protocol][src]['BytesInRatePerDuration'] = BytesInRatePerDuration + will increment for future matching flows
        
        Etc for remaining fields, they will increment for future matching flows
        
        
        GeoIP lookups will be perfromed to provide the following fields:
        AS Number
        AS Org Name
        Country Code
        Latitude
        Longitude
        
        
        flow [src] fields will be checked for the AS# and arrays will be built for BytesinVolume, FlowDuration, TotalFlowCount & PacketsInRatePerDuration for each AS#
        when records are parsed each flow will be first compared to the existing array data and checked for anomolys, then the data will be added.
        
        An AS# dict entry will be created for each AS#
        AS = {}
        AS[CIDR_Size] = num of possible hosts
        AS[src_ip] = []    each src ip will be added to the dict to give a count of unique IP's seen from each AS#
        
        Calculate the difference between Milton Keynes Latitude 52.0175    Longitude -.7896  and the source IP in miles
        
        Shenley = (52.0175, -0.7896)
        
        GeoIP city lookup - 'latitude' and 'longitude'
        
        Get an everage of the source distance in miles for each netflow sample and save to the dict at the end
        
        [destination_ip]['Protocol']['Avg_Distance'] = Avg_Distance
        
        Use BytesInVolume distrubution per ASN to determine how trustworthy the AS# is
        
        Use distance to AS# as another measure of trust
        
        Country reputation can be manually fixed per country - i.e. mark down China, Russia, Nork, USA
        
        Use whitelists for known good AS# & black lists for known bad AS#
        
        Use Avg_BytesPerFlow for the highest distrubution AS# to deterine the expected rates
        
        
        Tested with Python ver 2.7.2 on Win7
        (c) 2012 - 2016 Intelligent Planet Ltd
        
        """
        Tools.__init__(self)
        self.verbose = verbose
        self.path = 'C:\\temp\\' + 'netflow' + '\\'
        
        self.netflow_dict = {}
        self.netflow_dict['load_file_history'] = {}
        
        
        self.netflow_dict['ASN_Stats'] = {}
        self.netflow_dict['ASN_Stats']['Total_TotalFlowCount'] = 0
        self.netflow_dict['ASN_Stats']['Total_BytesInVolume'] = 0
        self.netflow_dict['ASN_Stats']['Avg_BytesPerFlow'] = 0
        self.netflow_dict['ASN_Stats']['Dist_TotalFlowCount'] = []
        self.netflow_dict['ASN_Stats']['Dist_BytesInVolume'] = []
        self.netflow_dict['ASN_Stats']['Dist_FlowCutOff'] = 0.
        self.netflow_dict['ASN_Stats']['Dist_BytesCutOff'] = 0.
        
        self.DistFlowCutOffFactor  = 0.0005
        self.DistBytesCutOffFactor = 0.000005
        
        self.field_map = {'Protocol':-1, 'SourceAddress':-1, 'SourcePort':-1, 'DestinationAddress':-1, 'DestinationPort':-1, 'BytesInVolume':-1, 'BytesInRatePerDuration':-1, 'FlowDuration':-1, 'PacketsInVolume':-1, 'PacketsInRatePerDuration':-1}
        
        self.home_city = (52.0175, -0.7896)
        
        self.SourceFilter = ''
        
        self.open_db()
        
        

        
    def get_next_file(self):
        """
        Get the oldest file that has not loaded before.
        """
        #list the files in the directory
        #print self.path
        files = os.listdir(self.path)
        #print files
        
        if len(files) == 1: out = files[0]
        
        #add files not previously loaded to a new list
        new_files = []
        keys = self.netflow_dict['load_file_history']
        #pprint.pprint(keys)
        for cfile in files:
            if cfile not in keys: new_files.append(cfile)
        
        #Find the oldest new_file
        age = []
        for cfile in new_files: 
            path_cfile = self.path + cfile
            age.append(os.path.getmtime(path_cfile))
        age.sort()
        max = age[-1]    #newest file age
        
        #sort the oldest file first
        for cfile in new_files:
            path_cfile = self.path + cfile
            if os.path.getmtime(path_cfile) <= max:
                out = cfile
                max = os.path.getmtime(path_cfile)
        
        #out is the oldest cfile not previously loaded so add it to the load history
        self.netflow_dict['load_file_history'][out] = {}
        #save the age now as we have the value
        self.netflow_dict['load_file_history'][out]['age'] = max
        #print 'out =', out
        return out
        
        
    def load(self):
        try: cfile = self.get_next_file()
        except: #exit load as no new file to parse
            #refresh the ASN trust metrics
            ignore = self.asn_metric()
            print 'All file stats'
            self.view_stats()
            return 'nothing to load'
        self.load_file = self.path + cfile
        print '##### loading ', self.load_file
        
        #initialise stats for the current load_file
        self.netflow_dict['load_file_history'][cfile]['Total_TotalFlowCount'] = 0
        self.netflow_dict['load_file_history'][cfile]['Total_BytesInVolume'] = 0
        self.netflow_dict['load_file_history'][cfile]['Avg_BytesPerFlow'] = 0
        self.netflow_dict['load_file_history'][cfile]['Avg_AsnMetric'] = 0
        
        #identify the first line with the data label
        init = 0
        
        file = open(self.load_file, 'rU')
        for row in file:
            if row:
                try:
                    raw = row.split(',')
                    #build the filed mapping from the first line of the csv data
                    if init ==0:
                        for item in raw:
                            for key in self.field_map:
                                if key == item: self.field_map[key] = raw.index(item)
                        init = 1
                        #print self.field_map
                        continue
                        
                    #read first line of data
                    #print raw
                    
                    #define the csv data from NetQoS
                    DestinationAddress = raw[self.field_map['DestinationAddress']]
                    Protocol = int(raw[self.field_map['Protocol']])
                    SourceAddress = raw[self.field_map['SourceAddress']]
                    SourcePort = int(raw[self.field_map['SourcePort']])
                    DestinationPort = int(raw[self.field_map['DestinationPort']])
                    BytesInVolume = int(raw[self.field_map['BytesInVolume']])
                    BytesInRatePerDuration = float(raw[self.field_map['BytesInRatePerDuration']])
                    BytesInRatePerDuration = round(BytesInRatePerDuration, 2)
                    FlowDuration = int(raw[self.field_map['FlowDuration']])
                    PacketsInRatePerDuration = float(raw[self.field_map['PacketsInRatePerDuration']])
                    
                    #test
                    #print DestinationAddress, Protocol, SourceAddress, SourcePort, DestinationPort, BytesInVolume, BytesInRatePerDuration, FlowDuration, PacketsInRatePerDuration
                    #print BytesInVolume, BytesInRatePerDuration, FlowDuration, PacketsInRatePerDuration
                    
                    #source filter to ignore any return packets - Inbound only
                    #if self.SourceFilter in SourceAddress: continue
                    
                    #swap around SourceAddress and DestinationAddress for outbound flow analysis
                    if self.SourceFilter in SourceAddress: SourceAddress = DestinationAddress
                    
                    #source filter to ignore any inbound packets - Outbound only
                    #if self.SourceFilter not in SourceAddress: continue
                    
                    #GeoIP lookups will be perfromed to provide the following fields:
                    #AS Number, AS Org Name, Country Code, Latitude, Longitude
                    
                    #city lookup
                    #print 'city lookup', SourceAddress
                    #city_res = geoip_city.record_by_addr(SourceAddress)
                    #print city_res
                    #CountryCode = city_res['country_code']
                    #Latitude = city_res['latitude']
                    #Longitude = city_res['longitude']
                    #print CountryCode, Latitude, Longitude
                    
                    #AS lookup
                    #print 'asn lookup', SourceAddress
                    asn_res = geoip_asn.asn_by_addr(SourceAddress)
                    #print asn_res
                    asn_raw = asn_res.split(' ')
                    AS_Number = asn_raw[0]
                    

                    #calculate distance from self.home_city to the SourceAddress in Miles
                    #SourceAddressCity = (Latitude, Longitude)
                    #SourceAddressDistance = int(vincenty(self.home_city, SourceAddressCity).miles)
                    #print 'distance', SourceAddressDistance
                    
                    #create a dict structre to hold the data for AS_Number comparison
                    #self.netflow_dict[AS_Number] = {}
                    #self.netflow_dict[AS_Number]['CountryCode'] = []    #add each unique country code to a list
                    #self.netflow_dict[AS_Number]['ASN_Org'] = ASN_Org
                    #self.netflow_dict[AS_Number]['SourceAddressDistance'] = []    #add each distance to a list
                    #self.netflow_dict[AS_Number]['BytesinVolume'] = []    #add each BytesinVolume to a list
                    #self.netflow_dict[AS_Number]['PacketsInRatePerDuration'] = []    #add each PacketsInRatePerDuration to a list
                    
                    #FlowDuration and TotalFlowCount are not being added as 15 min data will not give anything meaningfull
                    #data will be added to the lists and will form a baseline, once there is sufficient data statistical anylsis can 
                    #be perfomred to compare the base data to new flows.
                    
                    #check if the AS_Number dict exists, if not then create the entries for it
                    try: self.netflow_dict[AS_Number]
                    except: 
                        try:
                            start = len(AS_Number) + 1
                            ASN_Org = asn_res[start:]
                            print AS_Number, ASN_Org
                            
                            #city lookup
                            #print 'city lookup', SourceAddress
                            city_res = geoip_city.record_by_addr(SourceAddress)
                            #print city_res
                            CountryCode = city_res['country_code']
                            Latitude = city_res['latitude']
                            Longitude = city_res['longitude']
                            #print CountryCode, Latitude, Longitude
                        
                            #calculate distance from self.home_city to the SourceAddress in Miles
                            SourceAddressCity = (Latitude, Longitude)
                            SourceAddressDistance = int(vincenty(self.home_city, SourceAddressCity).miles)
                            #print 'distance', SourceAddressDistance
                        
                        except:
                            CountryCode = 'unknown'
                            SourceAddressCity = 'unknown'
                            SourceAddressDistance = 100
                        
                        self.netflow_dict[AS_Number] = {}
                        self.netflow_dict[AS_Number]['CountryCode'] = CountryCode
                        self.netflow_dict[AS_Number]['ASN_Org'] = ASN_Org
                        self.netflow_dict[AS_Number]['SourceAddressDistance'] = SourceAddressDistance
                        self.netflow_dict[AS_Number]['BytesInVolume'] = 0
                        self.netflow_dict[AS_Number]['PacketsInRatePerDuration'] = 0.0
                        self.netflow_dict[AS_Number]['TotalFlowCount'] = 0
                        self.netflow_dict[AS_Number]['Avg_BytesPerFlow'] = 0
                        self.netflow_dict[AS_Number]['Avg_PacketsInRatePerDuration'] = 0
                        self.netflow_dict[AS_Number]['DistanceMetric'] = DistanceMetric
                        
                    
                    try: self.netflow_dict[AS_Number]['TotalFlowCount'] += 1
                    except: pass
                    
                    try: self.netflow_dict[AS_Number]['BytesInVolume'] += BytesInVolume
                    except: pass
                    
                    try: self.netflow_dict[AS_Number]['Avg_BytesPerFlow'] = self.netflow_dict[AS_Number]['BytesInVolume'] / self.netflow_dict[AS_Number]['TotalFlowCount']
                    except: pass
                    
                    try: self.netflow_dict[AS_Number]['PacketsInRatePerDuration'] += round(PacketsInRatePerDuration, 4)
                    except: pass
                    
                    try: self.netflow_dict[AS_Number]['Avg_PacketsInRatePerDuration'] = self.netflow_dict[AS_Number]['PacketsInRatePerDuration'] / self.netflow_dict[AS_Number]['TotalFlowCount']
                    except: pass
                    
                    #update the Avg_AsnMetric for the file history
                    #self.netflow_dict['ASN_Metrics']['Trust'][ASN]
                    #
                    try: trust_res = self.netflow_dict['ASN_Metrics']['Trust'][AS_Number]
                    except: trust_res = self.metric_as(AS_Number, verbose=0)
                    try: self.netflow_dict['load_file_history'][cfile]['Avg_AsnMetric'] += int(trust_res)
                    except: pass
                    
                    #global and load_file ASN stats
                    
                    try: 
                        self.netflow_dict['ASN_Stats']['Total_TotalFlowCount'] += 1
                        self.netflow_dict['load_file_history'][cfile]['Total_TotalFlowCount'] += 1
                    except: pass
                    
                    try: 
                        self.netflow_dict['ASN_Stats']['Total_BytesInVolume'] += BytesInVolume
                        self.netflow_dict['load_file_history'][cfile]['Total_BytesInVolume'] += BytesInVolume
                    except: pass

               
                    #flows will be stored by the following format to provide a reasenable level of data compression:
                    #self.netflow_dict[DestinationAddress] = {}
                    #self.netflow_dict[DestinationAddress][protocol] = {}
                    #self.netflow_dict[DestinationAddress][protocol][DestinationPort] = {}
                    #self.netflow_dict[DestinationAddress][protocol][DestinationPort][SourceAddress] = {}
                    #self.netflow_dict[DestinationAddress][protocol][DestinationPort][SourceAddress][SourcePort] = {}
                    #self.netflow_dict[DestinationAddress][protocol][DestinationPort][SourceAddress][SourcePort]['TotalFlowCount'] = 1    #if the first otherwise will increment by +1
                    #self.netflow_dict[DestinationAddress][protocol][DestinationPort][SourceAddress][SourcePort]['BytesInVolume'] = BytesInVolume    #if the first otherwise will increment by sum
                    #self.netflow_dict[DestinationAddress][protocol][DestinationPort][SourceAddress][SourcePort]['FlowDuration'] = FlowDuration    #if the first otherwise will increment by sum
                    #self.netflow_dict[DestinationAddress][protocol][DestinationPort][SourceAddress][SourcePort]['PacketsInRatePerDuration'] = PacketsInRatePerDuration    #if the first otherwise will increment by sum
                    
                    #check if the destination dict exists, if not then create it
                    #try: self.netflow_dict[DestinationAddress]
                    #except: self.netflow_dict[DestinationAddress] = {}
                    
                    #check if the protocol dict exists, if not then create it
                    #try: self.netflow_dict[DestinationAddress][Protocol]
                    #except: self.netflow_dict[DestinationAddress][Protocol] = {}
                    
                    #check if the DestinationPort dict exists, if not then create it
                    #try: self.netflow_dict[DestinationAddress][Protocol][DestinationPort]
                    #except: self.netflow_dict[DestinationAddress][Protocol][DestinationPort] = {}
                    
                    #check if the SourceAddress dict exists, if not then create it
                    #try: self.netflow_dict[DestinationAddress][Protocol][DestinationPort][SourceAddress]
                    #except: self.netflow_dict[DestinationAddress][Protocol][DestinationPort][SourceAddress] = {}
                    
                    #check if the SourcePort dict exists, if not then create it
                    #try: self.netflow_dict[DestinationAddress][Protocol][DestinationPort][SourceAddress][SourcePort]
                    #except: self.netflow_dict[DestinationAddress][Protocol][DestinationPort][SourceAddress][SourcePort] = {}
                    
                    #check if the TotalFlowCount entry exists, if so increment the total by 1
                    #try: self.netflow_dict[DestinationAddress][Protocol][DestinationPort][SourceAddress][SourcePort]['TotalFlowCount'] += 1
                    #except: self.netflow_dict[DestinationAddress][Protocol][DestinationPort][SourceAddress][SourcePort]['TotalFlowCount'] = 1
                    
                    #check if the BytesInVolume entry exists, if so increment the total by sum
                    #try: self.netflow_dict[DestinationAddress][Protocol][DestinationPort][SourceAddress][SourcePort]['BytesInVolume'] += BytesInVolume
                    #except: self.netflow_dict[DestinationAddress][Protocol][DestinationPort][SourceAddress][SourcePort]['BytesInVolume'] = BytesInVolume
                    
                    #check if the FlowDuration entry exists, if so increment the total by sum
                    #try: self.netflow_dict[DestinationAddress][Protocol][DestinationPort][SourceAddress][SourcePort]['FlowDuration'] += FlowDuration
                    #except: self.netflow_dict[DestinationAddress][Protocol][DestinationPort][SourceAddress][SourcePort]['FlowDuration'] = FlowDuration
                    
                    #check if the PacketsInRatePerDuration entry exists, if so increment the total by sum
                    #try: self.netflow_dict[DestinationAddress][Protocol][DestinationPort][SourceAddress][SourcePort]['PacketsInRatePerDuration'] += PacketsInRatePerDuration
                    #except: self.netflow_dict[DestinationAddress][Protocol][DestinationPort][SourceAddress][SourcePort]['PacketsInRatePerDuration'] = PacketsInRatePerDuration
                    
                    #test the new stucture
                    #pprint.pprint(self.netflow_dict[DestinationAddress][Protocol][DestinationPort][SourceAddress][SourcePort])
                    
                           
                except: pass
        
        #end of file
        try: 
            self.netflow_dict['ASN_Stats']['Avg_BytesPerFlow'] = self.netflow_dict['ASN_Stats']['Total_BytesInVolume'] / self.netflow_dict['ASN_Stats']['Total_TotalFlowCount']
            
            
            self.netflow_dict['load_file_history'][cfile]['Avg_BytesPerFlow'] = self.netflow_dict['load_file_history'][cfile]['Total_BytesInVolume'] / self.netflow_dict['load_file_history'][cfile]['Total_TotalFlowCount']
            
        except: pass
        
        #get the distribution stats
        self.get_asn_dist()
        
        #get the standard deviation and avg for the loaded files
        res = self.flow_dist()
        self.netflow_dict['load_file_history']['StdDevBytesPerFlow'] = res[0][0]
        self.netflow_dict['load_file_history']['StdDevBytesPerFlowAvg'] = res[0][1]
        
        #display the Avg_AsnMetric
        print
        print 'Stats for: ', cfile
        pprint.pprint(self.netflow_dict['load_file_history'][cfile])
        print
        #print 'Avg_AsnMetric:', self.netflow_dict['load_file_history'][cfile]['Avg_AsnMetric']

        #self.view_db()
        self.save_db()
        self.load()
        
        
        
    def get_asn_dist(self):
        """
        get a distribution list of TotalFlowCount per ASN
        get a distribution of BytesInVolume per ASN
        """
        #TotalFlowCount
        #reset the list
        self.netflow_dict['ASN_Stats']['Dist_TotalFlowCount'] = []
        for ASN_key in self.netflow_dict:
            
            try: 
                if 'AS' in ASN_key:
                    res = self.netflow_dict[ASN_key]['TotalFlowCount']
                    self.netflow_dict['ASN_Stats']['Dist_TotalFlowCount'].append(res)
                    
            except: pass
        
        #sort the list for easier viewing
        self.netflow_dict['ASN_Stats']['Dist_TotalFlowCount'].sort()
        
        #find the flow value that is insignificant compared to Total_TotalFlowCount
        self.netflow_dict['ASN_Stats']['Dist_FlowCutOff'] = self.netflow_dict['ASN_Stats']['Total_TotalFlowCount'] * self.DistFlowCutOffFactor
        
        
        #BytesInVolume
        #reset the list
        self.netflow_dict['ASN_Stats']['Dist_BytesInVolume'] = []
        for ASN_key in self.netflow_dict:
            
            try: 
                if 'AS' in ASN_key:
                    res = self.netflow_dict[ASN_key]['BytesInVolume']
                    self.netflow_dict['ASN_Stats']['Dist_BytesInVolume'].append(res)
                    
            except: pass
        
        #sort the list for easier viewing
        self.netflow_dict['ASN_Stats']['Dist_BytesInVolume'].sort()
        
        #find the flow value that is insignificant compared to Total_TotalFlowCount
        self.netflow_dict['ASN_Stats']['Dist_BytesCutOff'] = self.netflow_dict['ASN_Stats']['Total_BytesInVolume'] * self.DistBytesCutOffFactor
        
    
    def flow_dist(self):
        """
        get the distribution of Avg_BytesPerFlow per load file
        """
        try:
            out = []
            keys = self.netflow_dict['load_file_history']
            for cfile in keys:
                try:
                    Avg_BytesPerFlow = self.netflow_dict['load_file_history'][cfile]['Avg_BytesPerFlow']
                    #print cfile, Avg_BytesPerFlow
                    out.append(Avg_BytesPerFlow)
                except: pass
            return self.std_dev(out), out
        except: pass
        
        
    def std_dev(self, clist):
        """
        1) Work out the Mean avg
        2) Then for each number: subtract the Mean and square the result
        3) Then work out the mean of those squared differences
        4) Retrun the square root
        """
        try:
            mean = 0
            count = 0
            for num in clist: 
                mean += num
                count +=1
            avg = mean / count
            #print 'average', avg
            
            sq_mean = 0
            for num in clist:
                sum = num - avg
                sq_mean += (sum * sum)
            sq_avg = sq_mean / count
            #print sq_avg
            return math.sqrt(sq_avg), avg
        except: pass
        
        
    def percentile(self, N, percent, key=lambda x:x):
        """
        Find the percentile of a list of values.
        http://code.activestate.com/recipes/511478-finding-the-percentile-of-the-values/
        @parameter N - is a list of values. Note N MUST BE already sorted.
        @parameter percent - a float value from 0.0 to 1.0.
        @parameter key - optional key function to compute value from each element of N.
        """
        if not N: return None
        k = (len(N)-1) * percent
        f = math.floor(k)
        c = math.ceil(k)
        if f == c: return key(N[int(k)])
        d0 = key(N[int(f)]) * (c-k)
        d1 = key(N[int(c)]) * (k-f)
        return d0+d1
            
    
    def save_db(self):
        """
        save self.netflow_dict to db_file
        """
        cfile = open(db_file, 'wb')
        pickle.dump(self.netflow_dict, cfile, -1)
        cfile.close()
        
        
    def open_db(self):
        """
        open self.netflow_dict from db_file
        """
        cfile = open(db_file, 'rb')
        self.netflow_dict = pickle.load(cfile)
        cfile.close()
        
        
    def view_db(self): 
        try: pprint.pprint(self.netflow_dict)
        except: pass
        
        
    def get_asn(self):
        """
        Get the AS# list
        """
        try:
            out = []
            keys = self.netflow_dict.keys()
            for key in keys:
                if 'ASN' in key: continue
                if 'AS' in key: out.append(key)
            return out   
        except: pass
        
        
    def asn_metric(self):
        """
        Calculate the Trust metric for each AS
        Store the result in dict key self.netflow_dict['ASN_Metrics']
        return a sorted list of metrics
        """
        try:
            out = []
            self.netflow_dict['ASN_Metrics'] = {}
            self.netflow_dict['ASN_Metrics']['Trust'] = {}
            keys = self.get_asn()
            for ASN in keys: 
                try: 
                    trust = int(self.metric_as(ASN, verbose=0))
                    if not trust: continue
                    self.netflow_dict['ASN_Metrics']['Trust'][ASN] = trust
                    out.append(trust)                        
                except: pass
                
            #pprint.pprint(self.netflow_dict['ASN_Metrics']['Trust'])
            out.sort()
            return out
            
        except: pass
        
        
        
        
    def run(self, cmd):
        """
        help: Execute a function or assign a variable within the local scope
        usage: netflow.[cmd]
        example: netflow.ls
        """
        self.res = ''
        try:
            if 'view(' in cmd: exec('self.view(self.' + cmd[5:] + ')')
            #check for assign statement
            if '=' in cmd: exec('self.' + cmd)
            #check if function
            if ')' in cmd: exec('self.' + cmd)
            #print variable
            else: exec('print self.' + cmd)
        except: pass
        
        
    def view_loadfile(self):
        try:
            keys = self.netflow_dict['load_file_history']
            pprint.pprint(keys)
        except: pass
        
        
    def view_stats(self): 
        try: 
            print 'Avg_BytesPerFlow:', '{:0,d}'.format(self.netflow_dict['ASN_Stats']['Avg_BytesPerFlow'])
            print 'Dist_FlowCutOff:', '{:0,.0f}'.format(self.netflow_dict['ASN_Stats']['Dist_FlowCutOff'])
            print 'Dist_BytesCutOff', '{:0,.0f}'.format(self.netflow_dict['ASN_Stats']['Dist_BytesCutOff'])
            print 'Total_BytesInVolume:', '{:0,d}'.format(self.netflow_dict['ASN_Stats']['Total_BytesInVolume'])
            print 'Total_TotalFlowCount:', '{:0,d}'.format(self.netflow_dict['ASN_Stats']['Total_TotalFlowCount'])
            LoadFileTotal = len(self.netflow_dict['load_file_history'].keys())
            LoadFileMins = LoadFileTotal * 15
            print 'Total_Netflow_Time: %d Mins in %d files' % (LoadFileMins, LoadFileTotal)
            sum = 1000000 * self.DistFlowCutOffFactor
            print 'DistFlowCutOffFactor: %f or %d in 1,000,000' % (self.DistFlowCutOffFactor, sum)
            
        except: pass
        
        
    def view_as(self, asn): 
        try: 
            asn = asn.upper()
            print 'trying ', asn
            pprint.pprint(self.netflow_dict[asn])
        except: pass
        
        
    def metric_as(self, asn, verbose=1):
        """
        Metric to define how trustworthy the AS is
        DistanceMetric = (SourceAddressDistance / 2500.)
        TotalByteMetric = difference between AS BytesPerFlow and ALL AS AVG BytesPerFlow
        FlowCountMetric = (Dist_FlowCutOff / TotalFlowCount) limited to a max of 10
        TrustMetric = ((FlowCountMetric) * TotalByteMetric) * DistanceMetric
        """
        try:
            asn = asn.upper()
            if verbose > 0:
                print
                print 'Calculating trust metric for', asn
            
            #Calculate the metric for distance
            SourceAddressDistance = self.netflow_dict[asn]['SourceAddressDistance']
            self.DistanceMetric = (SourceAddressDistance / 2500.)
            if self.DistanceMetric < 1: self.DistanceMetric = 1.
            if self.DistanceMetric > 2: self.DistanceMetric = 2.
            if verbose > 0: print 'DistanceMetric = ', '{:0,.2f}'.format(self.DistanceMetric)
            
            #Calculate the metric for BytesPerFlow
            Avg_BytesPerFlow = self.netflow_dict[asn]['Avg_BytesPerFlow']
            Dist_Avg_BytesPerFlow = self.netflow_dict['ASN_Stats']['Avg_BytesPerFlow']
            
            StdDev = self.netflow_dict['load_file_history']['StdDevBytesPerFlow']
            StdDevAvg = self.netflow_dict['load_file_history']['StdDevBytesPerFlowAvg']
            if verbose > 0: print 'StdDevAvg', '{:0,d}'.format(StdDevAvg), 'StdDev', '{:0,.0f}'.format(StdDev)
            
            #NegByteMetric = float(Dist_Avg_BytesPerFlow) - Avg_BytesPerFlow
            NegByteMetric = float(Avg_BytesPerFlow) - (StdDevAvg + (StdDev / 2))
            if NegByteMetric < 1: NegByteMetric = 1.
            #PosByteMetric = float(Avg_BytesPerFlow) - Dist_Avg_BytesPerFlow
            PosByteMetric = float(StdDevAvg - (StdDev / 2.)) - Avg_BytesPerFlow
            if PosByteMetric < 1: PosByteMetric = 1.
            #print Dist_Avg_BytesPerFlow, Avg_BytesPerFlow
            #print NegByteMetric, PosByteMetric
            
            self.TotalByteMetric = NegByteMetric + PosByteMetric
            if self.TotalByteMetric > 50000: self.TotalByteMetric = 50000
            if verbose > 0: print 'TotalByteMetric = ', '{:0,.0f}'.format(self.TotalByteMetric)
            
            #Calculate the metric for FlowCount
            TotalFlowCount = self.netflow_dict[asn]['TotalFlowCount']
            Dist_FlowCutOff = self.netflow_dict['ASN_Stats']['Dist_FlowCutOff']
            
            self.FlowCountMetric = (Dist_FlowCutOff / TotalFlowCount)
            if self.FlowCountMetric > 5: self.FlowCountMetric = 5.
            if verbose > 0: print 'FlowCountMetric = ', '{:0,.2f}'.format(self.FlowCountMetric)
            
            self.TrustScale = 1000
            self.TrustMetric = ((((self.FlowCountMetric) * self.TotalByteMetric) * self.DistanceMetric) / 500000) * self.TrustScale
            if verbose > 0: print 'TrustMetric = ', '{:0,.0f}'.format(self.TrustMetric), 'out of', self.TrustScale, '(lower is better)'
            return self.TrustMetric
            
        except: pass
    

    def load_blackhole(self):
        self.BlackTrustMetric = 0
        self.BlackCount = 0
        AS_List = []
        cfile = path + 'blackhole.txt'
        #print cfile
        file = open(cfile, 'rU')
        for row in file:
            if row:
                try:
                    ipAddr = row.split()[0]
                    #AS lookup
                    #print 'asn lookup', ipAddr
                    asn_res = geoip_asn.asn_by_addr(ipAddr)
                    #print asn_res
                    asn_raw = asn_res.split(' ')
                    AS_Number = asn_raw[0]
                    if AS_Number not in AS_List: AS_List.append(AS_Number)
                    else: continue
                    res = self.metric_as(AS_Number)
                    if res:
                        self.BlackCount += 1
                        self.BlackTrustMetric += res
                except: pass
                    
        print 'BlackCount =', self.BlackCount, 'BlackTrustMetric =', self.BlackTrustMetric, 'AvgBlackTrustMetric =', self.BlackTrustMetric / self.BlackCount
    
                    
