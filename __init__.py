from __future__ import unicode_literals, absolute_import, print_function
import sys,os,bdblib
sys.path.insert(0, '/'.join(os.path.realpath(__file__).split('/')[:-1]))
from x509_util import stpCertDecoder,Clone


def task(env,input_file):
    '''
    Returns a single webpage link to access all the certificates in the 
    showtech file 
    
    Takes the input showtech file and opens it to read the file
    and convert it into a list based element and send it to 
    acion function of the stpCertDecoder class.  
    '''
    scd = stpCertDecoder()
    f = open(input_file).read()
    a = scd.action(input_file)
    
    '''
    The resultant javascript code is placed into a separate main.js file
    '''
        
    with open('main.js','w') as f:
        for i in range(len(a)):
            f.write(str(a[i]['text']))
    
    '''
    The javascript file is separately executed using the html code
    that is linked to it
    '''
    with open('main.js','r') as f:
        data = f.read()

    out=bdblib.TaskResult()
    myhtml='''<html><body style="background-color:	#FFFFF0;">
                <p style="text-align:center;"><b>*Click x509-Decode to view the X509 output of the certificate in text format.*</b></p>
                <p style="text-align:center;"><b>*Click asn1-Decode to view the asn1 decode of the certificate*</b></p>
                <p style="text-align:center;"><b>*To edit any certificate, Click on clone all certificates and use the first link to proceed.*</b></p>
                <p style="text-align:center;"><b>*Click below to clone all the certifiates present.*</b></p>
                <button type="button" style="margin:auto;display:block;height:40px; width:400px;font-size : 15px" onclick="window.open('https://scripts.cisco.com:443/ui/use/clonesaurabh?input_file='''+input_file+'''&autorun=true&log=true')"><b><font color="blue"> Clone all the certificates in this Chain</font></b></button>'''
    with open('main.js','r') as f:
        data=f.read()
        myhtml+=data
    myhtml+='</body></html>'
    open('tree.html','wb').write(myhtml)
    html = '<html><body>'
    html += '<a target="_blank" href="https://scripts.cisco.com/api/v1/files/tree.html">Open the Certificate Hierarchy.</a>'
    html += '</body></html>'
    out.append(bdblib.HTML(html))
    return out
    