import dpkt, socket, pygeoip, optparse

gi = pygeoip.GeoIP('/opt/GeoLite/GeoLiteCity.dat')

def retGeoStr(ip):
    try:
        rec = gi.record_by_name(ip)
        country = rec['country_code3']
        city = rec['city']
        if city != '':
            geoLoc = city +', ' + country
        else:
            geoLoc = country
        return geoLoc
    except:
        return 'Unregistered'
      

    
def printPcap(pcap):
   for (ts, buf) in pcap:
       try:
           eth = dpkt.ethernet.Ethernet(buf)
           ip = eth.data
           src = socket.inet_ntoa(ip.src)
           dst = socket.inet_ntoa(ip.dst)
           print '[*] Src: ' + src + ' --> Dest: ' + dst
           print '[*] Src: ' + retGeoStr(src) + ' --> Dest: '+ retGeoStr(dst)
       except:
           pass
       
def main():
    parser = optparse.OptionParser('usage%prog -p <pcap file>')
    parser.add_option('-p', dest='pcapFile', type='string', help='specify pcap name')
    (options, args) = parser.parse_args()
    if options.pcapFile == None:
        print parser.usage
        exit(0)
    pcapFile = options.pcapFile
    f = open(pcapFile)
    pcap = dpkt.pcap.Reader(f)
    printPcap(pcap)

if __name__ == '__main__':
    main()
