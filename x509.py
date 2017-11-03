import re
from subprocess import PIPE, Popen
from OpenSSL.crypto import FILETYPE_PEM, FILETYPE_ASN1, load_certificate
from hierarchy import TreeNode, TrustRel
from binascii import unhexlify


class certObj:
    '''
    A certificate decoder module which decodes the input certificate into text, asn1 parse and pem formats
    and assigns the various field based variables constraints for the given input certificate along with the 
    trustpoint name.
    '''
    def __init__(self, source='stp', platform1='ASA', type1='', certificate_string='', certificate_type='', startline=-1, endline=-1, certificate_position=-1, trustpoint_name='', trustpoint_line=-1, cccl=-1):
        '''
        certObj constructor which assigns the various types of arguments in the certificate to the field that is 
        present in them.
        '''
        self.ret = 0
        self._certHexDER = certificate_string
        '''
        Checks whether the certificate is in hex code format and loads the certificate by unhexilfying the certificate 
        '''
        if certificate_type == 'hex':
            try:
                self.x509 = load_certificate(FILETYPE_ASN1, (unhexlify(certificate_string)))
            except:
                self.ret = -1
        elif certificate_type == 'pem':
            self.x509 = load_certificate(FILETYPE_PEM, certificate_string)
        elif certificate_type == 'der':
            self.x509 = load_certificate(FILETYPE_ASN1, certificate_string)

        self.authorityKeyIdentifier = None
        self.authorityInfoAccess = None
        self.basicConstraints = None
        self.certificatePolicies = None
        self.cert_chain_cmd_line = cccl
        self.end_line = endline
        self.errors = []
        self.ExtendedKeyUsage = ''
        self.expired = None
        self.issuer = ''
        self.isRoot = None
        self.isSelfSigned = None
        self.isKuCritical = None
        self.isEkuCritical = None
        self.key_size = -1
        self.KeyUsage = ''
        self.noRootInChain = None
        self.nameConstraints = None
        self.node = TreeNode(self)
        self.platform = platform1
        self.pos = [-1, certificate_position]
        self.short_name = ''
        self.short_issuer_name = ''
        self.start_line = startline
        self.serial_number = ''
        self.subject = ''
        self.subjectKeyIdentifier = None
        self.signature_algorithm = None
        self.source = source
        self.summary = ''
        self.type = type1
        self.trustpoint_line = trustpoint_line
        self.trustpoint_name = trustpoint_name
        self.trustRels = []
        self.use_by = ''
        self.use_by_lines = []
        self.valid_from = ''
        self.valid_till = ''
        
        '''
        Checking whether the hex code hexlify function returned any error or not.
        And decoding the given certificate string into x509 text and asn1 decoded form
        '''
        if self.ret >= 0:
            self.x509Decode, self.asn1Decode = self._openSslDecode(certificate_string, certificate_type)
            self._buildHelpers()
            self._buildSummary()

        else:
            return None

    def _openSslDecode(self, certificate_string, certificate_type):
        
        '''
        This module takes an input certificate string and certificate type and decodes 
        it into the particuar text and asn1 format
        '''

        if certificate_type == 'hex':
            '''
            xxd command is used to convert the hex code in the original
            binary coded format using the shell call functionality
            '''
            xxd_out = Popen(['xxd', '-r', '-p', '-c', '32'], stdin=PIPE, stdout=PIPE)
            out1 = xxd_out.communicate(certificate_string)[0]
            '''
            A subprocess file operation is used to convert the certificate into the text and
            the asn1 format
            '''
            openssl_x509_out = Popen(['openssl', 'x509', '-text', '-inform', 'DER'], stdin=PIPE, stdout=PIPE)
            openssl_asn1_out = Popen(['openssl', 'asn1parse', '-inform', 'DER'], stdin=PIPE, stdout=PIPE)
            xxd_out.stdout.close()
            '''
            Assigning the values into the return objects
            '''
            cert_x509_output = openssl_x509_out.communicate(out1)[0]
            cert_asn1_output = openssl_asn1_out.communicate(out1)[0]


        elif certificate_type == 'pem':
            '''
            A subprocess file operation is used to convert the certificate into the text and
            the asn1 format
            '''
            openssl_x509_out = Popen(['openssl', 'x509', '-text'], stdin=PIPE, stdout=PIPE)
            openssl_asn1_out = Popen(['openssl', 'asn1parse', 'inform', 'PEM'], stdin=PIPE, stdout=PIPE)
            '''
            Assigning the values into the return objects
            '''
            cert_x509_output = openssl_x509_out.communicate(certificate_string)[0]
            cert_asn1_output = openssl_asn1_out.communicate(certificate_string)[0]

        elif certificate_type == 'der':
            '''
            A subprocess file operation is used to convert the certificate into the text and
            the asn1 format
            '''
            openssl_x509_out = Popen(['openssl', 'x509', '-text', '-inform', 'DER'], stdin=PIPE, stdout=PIPE)
            openssl_asn1_out = Popen(['openssl', 'asn1parse', '-inform', 'DER'], stdin=PIPE, stdout=PIPE)
            '''
            Assigning the values into the return objects
            '''
            cert_x509_output = openssl_x509_out.communicate(certificate_string)[0]
            cert_asn1_output = openssl_asn1_out.communicate(certificate_string)[0]

        return cert_x509_output, cert_asn1_output

    def _buildHelpers(self):
        '''
        This module decodes the individual component of the cvertificate  
        '''
        month = ['START', 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', \
                 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

        '''
        Checking for the partiular serial number in the certificate
        '''
        try:
            l = self.x509.get_serial_number()
            '''
            To get the hex of the certificate serial number
            '''
            lh = '%x' % (l)
            '''
            Checking if the hex of the certificate serial number is 
            negative and making it into positive.
            '''
            if lh[0] == '-':
                lh = lh[1:]
                neg1 = '-'
                neg2 = ' (Negative)'
            else:
                neg1 = ''
                neg2 = ''
                
            '''
            assigning the hex converted and the value to the object's serial number
            '''
            if len(lh) <= 16:
                self.serial_number = '%d (%s0x%s)' % (l, neg1, lh)
            else:
                self.serial_number = '%s%s' % (neg2, ":".join([lh[x:x + 2] for x in range(0, len(lh), 2)]))
        except Exception as inst:
            self.errors.append('Error in retrieving serial number: ' + str(inst))

        '''
        Getting the issuer components of the certificate and assigning it to the object's issuer variable
        '''
        try:
            self.issuer = ", ".join(
                [str(y) for y in ["=".join(x) for x in self.x509.get_issuer().get_components()]])  # Haha :D
        except Exception as inst:
            self.errors.append('Error in retrieving issuer: ' + str(inst))
        
        '''
        Getting the validity of the certificate and assigning them to the 
        object's validity variables
        '''
        try:
            g = self.x509.get_notBefore()
            self.valid_from = month[int(g[4:6])] + ' ' + g[6:8] + ' ' + ":".join(
                [g[8:14][x:x + 2] for x in range(0, 6, 2)]) + ' ' + g[0:4] + ' GMT'
            g = self.x509.get_notAfter()
            self.valid_till = month[int(g[4:6])] + ' ' + g[6:8] + ' ' + ":".join(
                [g[8:14][x:x + 2] for x in range(0, 6, 2)]) + ' ' + g[0:4] + ' GMT'
        except Exception as inst:
            self.errors.append('Error in retrieving validity: ' + str(inst))

        '''
        Getting the subject components of the certificate and assigning them to the 
        object's subject variable by joining them
        '''
        try:
            self.subject = ", ".join(
                [str(y) for y in ["=".join(x) for x in self.x509.get_subject().get_components()]])
        except Exception as inst:
            self.errors.append('Error in retrieving subject: ' + str(inst))
            
        '''
        Getting the public key size of the certificate and assigning them to the 
        object's bits variable
        '''
        self.key_size = self.x509.get_pubkey().bits()
        
        '''
        Comparing the subject and issuer hash code and checking if the certificate 
        is self-signed certificate and assigning 'True' or 'False' in the object's isID variable, 
        along if the certificate is an Root or ID certificate.
        '''
        if self.x509.get_subject().hash() == self.x509.get_issuer().hash():
            self.isRoot = True
            if self.type == 'id':
                self.isSelfSigned = True
            else:
                self.isSelfSigned = False
        else:
            self.isRoot = False
        
        '''
        Getting the common name of the certificate and checking if it's length is
        not more than 40 and if it is then the string is sliced.
        '''
        if re.search(r'(unstructuredName|CN)=.*?(?=,|$)', self.subject):
            self.short_name = re.search(r'(unstructuredName|CN)=.*?(?=,|$)',
                                        self.subject).group(0)
            if len(self.short_name) >= 41:
                self.short_name = self.short_name[0:40] + '...'
        else:
            self.short_name = self.subject
        
        '''
        Checking the type of signature algorithm that is being used in the 
        certificate.
        '''

        if self.x509.get_signature_algorithm() == 'md5WithRSAEncryption':
            self.signature_algorithm = 'md5'
        elif self.x509.get_signature_algorithm() == 'sha1WithRSAEncryption':
            self.signature_algorithm = 'sha1'
        elif self.x509.get_signature_algorithm() == 'sha256WithRSAEncryption':
            self.signature_algorithm = 'sha256'
        
        '''
        Getting various extensions in the certificate and making them assigned to
        the certificate object's variable
        '''
        if self.x509.get_extension_count():
            for ext in xrange(0, self.x509.get_extension_count()):
                if self.x509.get_extension(ext).get_short_name() == 'keyUsage':

                    if self.x509.get_extension(ext).get_critical:
                        self.isKuCritical = True
                    else:
                        self.isKuCritical = False

                    self.KeyUsage = str(self.x509.get_extension(ext))

                elif self.x509.get_extension(ext).get_short_name() == 'extendedKeyUsage':

                    if self.x509.get_extension(ext).get_critical:
                        self.isEkuCritical = True
                    else:
                        self.isEkuCritical = False

                    self.ExtendedKeyUsage = str(self.x509.get_extension(ext))

                elif self.x509.get_extension(ext).get_short_name() == 'subjectKeyIdentifier':
                    self.subjectKeyIdentifier = str(self.x509.get_extension(ext))

                elif self.x509.get_extension(ext).get_short_name() == 'authorityKeyIdentifier':
                    self.authorityKeyIdentifier = re.sub(r'\n.*', '',
                                                         re.sub(r'keyid:', '', str(self.x509.get_extension(ext))))

                elif self.x509.get_extension(ext).get_short_name() == 'nameConstraints':
                    self.nameConstraints = str(self.x509.get_extension(ext))

                elif self.x509.get_extension(ext).get_short_name() == 'certificatePolicies':
                    self.certificatePolicies = str(self.x509.get_extension(ext))

                elif self.x509.get_extension(ext).get_short_name() == 'authorityInfoAccess':
                    self.authorityInfoAccess = str(self.x509.get_extension(ext))

    def _buildSummary(self):
        '''
        This module establishes the content that needs to be displayed in the 
        certificate and they are being asasigned to the various contents of the 
        file as whether it is ID, CA, Self-Signed etc.
        '''
        KeyUsage_summ = ''
        ExtendedKeyUsage_summ = ''

        if self.type == 'id':
            header = 'Type: Identity'
        else:
            header = 'Type: CA'

        if self.isSelfSigned:
            header += ' (Self-signed)<br/>'
        elif self.isRoot:
            header += ' (Root)<br/>'
        else:
            header += '<br/>'

        if self.isKuCritical == True:
            KeyUsage_summ = 'Key Usage (Type: Critical): ' + self.KeyUsage + '<br/>'
        elif self.isKuCritical == False:
            KeyUsage_summ = 'Key Usage (Type: Non Critical): ' + self.KeyUsage + '<br/>'

        if self.isEkuCritical == True:
            ExtendedKeyUsage_summ = 'Extended Key Usage (EKU) (Type: Critical): ' + self.ExtendedKeyUsage + '<br/>'
        elif self.isEkuCritical == False:
            ExtendedKeyUsage_summ = 'Extended Key Usage (EKU) (Type: Non Critical): ' + self.ExtendedKeyUsage + '<br/>'

        '''
        Creating a html based summary variable and they are being assigned to the summary variable
        which is to be returned
        '''
        summary = header \
                  + 'Serial Number: ' + self.serial_number + '<br/>' \
                  + 'Issuer: ' + self.short_issuer_name + '<br/>' \
                  + 'Subject: ' + self.short_name + '<br/>' \
                  + 'Valid from: ' + self.valid_from + '<br/>' \
                  + 'Valid till: ' + self.valid_till + '<br/>' \
                  + 'Key Size (bits): ' + str(self.key_size) + '<br/>' \
                  + KeyUsage_summ \
                  + ExtendedKeyUsage_summ
        self.summary = summary

    def buildTrustRelation(self):
        '''
        This module defines the trustr relation establishment for the individual certificate
        by calling the class TrustRel in Hierarchy
        '''
        if not self.node.hasChildren():
            TrustRel(self, 'rel_' + '_' + str(self.pos[0]) + '_' + str(self.pos[1]))

