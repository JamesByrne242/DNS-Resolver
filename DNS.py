import datetime
import time
import dns.message
import dns.rdatatype
import dns.query

#list of all root server IPs
rootServerList = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']

#creates query and recieves responses from target server
def simpleRequest(domainName, server):
    try:
        request = dns.message.make_query(domainName, dns.rdatatype.A)
        response = dns.query.udp(request, server, 1)
        return response
    except:
        print('Sorry, unable to fulfill your request.')

#Print format function
def printQnA(domainName, port, type, address, resolveTime, dateTime):
    resolveTime = str(resolveTime)
    dateTime = str(dateTime)
    print('\nQUESTION:\n' + domainName + ' IN A\n\nANSWER:\n' + domainName + ' ' + port + ' IN ' + type + ' ' +  address +
    '\n\nQuery Time: ' + resolveTime + 'ms ' + '\nWHEN: ' + dateTime)

""" If a CNAME is found in the answer section of query, findCNAME returns to the root server
and passes the CNAME as cnameSite in order to resolve completely """
def findCNAME(cnameSite, Ip):
    canswer = None
    while canswer == None:
        cres = simpleRequest(cnameSite, Ip)
        if cres.answer:
            canswer = cres
        else:
            if cres.additional:
                for i in range(len(cres.additional)):
                    caddRecord = str(cres.additional[i]).split()
                    if caddRecord[3] == 'A':
                        Ip = caddRecord[4]
    return canswer

""" Responsible for parsing and checking server responses in order to return the information
in the answer section in the form of an list of strings  """
def myDig(url):
    answer = None
    for root in rootServerList:
        ip = root
        while answer == None:
            try:   
                response = simpleRequest(url, ip)
            except:
                print('Error: could not connect to a root server.')
                exit(0)
            if response.answer:
                response = str(response.answer[0]).split()

                while (response[3] == 'CNAME'):
                    try:
                        cnameRes = findCNAME(response[4], root)
                        cStr = str(cnameRes.answer[0]).split()
                        response = cStr
                    except:
                        print('Error: CNAME request could not be resolved.')
                        exit(0)
                else:
                    answer = response
            else:
                if response.additional:
                    for i in range(len(response.additional)):
                        additionalRecord = str(response.additional[i]).split()
                        if additionalRecord[3] == 'A':
                            ip = additionalRecord[4]
                    
        return answer

""" main function that asks for domain name input, which is then passed into the myDig
function to resolve the query """
if __name__ == "__main__":

    print('Please enter a domain name:')
    domainName = input().lower().replace(" ", "")

    #get start time and start timer
    start = time.time()
    dateTime = datetime.datetime.now()

    try:
        answerRecord = myDig(domainName)
        port = answerRecord[1]
        type = answerRecord[3]
        address = answerRecord[4]
    except:
        print('Error: Query was not resolved try again.')
        exit(0)

    resolveTime = (time.time() - start)*1000
    printQnA(domainName, port, type, address, resolveTime, dateTime)
