import re
from x509 import certObj
from hierarchy import build_nodes
toggle_javascript='''
<script type="text/javascript">

function decode_show (input, tag_id)
{
    if (/x509-Decode/.test(input.innerHTML))
    {
        input.innerHTML = "<a><a><i><b>&nbsp &nbsp Hide-x509</b></i></a><br /><br />";
        var src = document.getElementById(tag_id).innerHTML
        var node = document.createElement("pre");
        var att=document.createAttribute("onclick");
        att.value="event.cancelBubble=true;if(event.stopPropagation) event.stopPropagation();return false;";
        node.setAttributeNode(att);
        var textnode = document.createTextNode(src);
        node.appendChild(textnode);
        input.appendChild(node);
    }
    else if (/asn1-Decode/.test(input.innerHTML))
    {
        input.innerHTML = "<a><i><b>&nbsp &nbsp Hide-asn1</b></i></a><br />";
        var src = document.getElementById(tag_id).innerHTML
        var node = document.createElement("pre");
        var att=document.createAttribute("onclick");
        att.value="event.cancelBubble=true;if(event.stopPropagation) event.stopPropagation();return false;";
        node.setAttributeNode(att);
        var textnode = document.createTextNode(src);
        node.appendChild(textnode);
        input.appendChild(node);
    }
    else if (/Hide-x509/.test(input.innerHTML))
    {
        input.innerHTML = "<a><i><b>&nbsp &nbsp x509-Decode</b></i></a>";
    }
    else if (/Hide-asn1/.test(input.innerHTML))
    {
        input.innerHTML = "<a><i><b>&nbsp &nbsp asn1-Decode</b></i></a>";
    }
}
</script>

'''

class showTechParser:
    def process_running_config(self, showtech, running_config):
        context_result = []
        length_of_config = len(running_config)
        
        trustpoint_list = []
        trustpoint_position = 0
        line = 0
        platform = ''
        found = False

        while line <= length_of_config - 1:

            if not platform:
                if (re.search('crypto ca trustpoint ', running_config[line])):
                    platform = 'ASA'
                if (re.search('crypto pki trustpoint ', running_config[line])):
                    platform = 'IOS'

                if re.search(r'crypto (ca|pki) trustpoint ', running_config[line]):
                    found, trustpoint_dictionary = self.find_cert_chain_cmd(platform, running_config, line,
                                                                            length_of_config)
                if found:
                    for cert in trustpoint_dictionary['cert_chain']:
                        cert.pos[0] = trustpoint_position
                    trustpoint_list.append(trustpoint_dictionary)
                    trustpoint_position += 1
            elif (re.search('console logs', running_config[line])):
                break
            line += 1

        line_num = 0

        for line in running_config:
            if re.search('trust-point', line) or re.search('ikev2 local-authentication certificate', line) or re.search(
                    'client ldc issuer', line) or re.search('trustpoint', line):
                if re.match(r'^\s*ssl trust-point ', line):
                    self.update_use_by(trustpoint_list, line.split()[2], 'SSL', line_num)
                elif re.match(r'^\s*ikev1 trust-point ', line):
                    self.update_use_by(trustpoint_list, line.split()[2], 'IKEv1', line_num)
                elif re.match(r'^\s*ikev2 local-authentication certificate ', line):
                    self.update_use_by(trustpoint_list, line.split()[3], 'IKEv2', line_num)
                elif re.match(r'^\s*trust-point ', line):
                    self.update_use_by(trustpoint_list, line.split()[1], 'IKEv1', line_num)
                elif re.match(r'^\s*record-entry (cucm-tftp|cucm|tftp) trustpoint ', line):
                    self.update_use_by(trustpoint_list, line.split()[3], 'Phone Proxy', line_num)
                elif re.match(r'^\s*(server|client) trust-point ', line):
                    self.update_use_by(trustpoint_list, line.split()[2], 'TLS Proxy', line_num)
                elif re.match(r'^\s*client ldc issuer ', line):
                    self.update_use_by(trustpoint_list, line.split()[3], 'TLS Proxy', line_num)
            line_num += 1



        for trustpoint in range(0, len(trustpoint_list)):
            for cert in range(0, len(trustpoint_list[trustpoint]['cert_chain'])):
                build_nodes(trustpoint_list, trustpoint_list[trustpoint]['cert_chain'][cert])

        for trustpoint in range(0, len(trustpoint_list)):
            for cert in range(0, len(trustpoint_list[trustpoint]['cert_chain'])):
                trustpoint_list[trustpoint]['cert_chain'][cert].buildTrustRelation()

        for trustpoint in range(0, len(trustpoint_list)):
            instances_to_report = self.highlight_and_show_decode(trustpoint_list[trustpoint], trustpoint)
            if instances_to_report is not None:
                context_result += instances_to_report
            for cert in range(0, len(trustpoint_list[trustpoint]['cert_chain'])):
                instances_to_report = self.check_bit_size(trustpoint_list[trustpoint]['cert_chain'][cert])
                if instances_to_report is not None:
                    context_result += instances_to_report

        return context_result

    def find_cert_chain_cmd(self, platform, running_config, line, length_of_config):
        trustpoint_name = running_config[line].split()[3]
        trustpoint_line = line
        found = False
        line += 1

        while line <= length_of_config - 1:
            if re.match(r'^\s*crypto (ca|pki) certificate chain ' + trustpoint_name + r'\s*$', running_config[line]):
                cert_chain_cmd_line = line
                found, cert_chain, num_of_ca, num_of_id = self.get_cert_chain(platform, running_config, line,
                                                                              length_of_config, trustpoint_name,
                                                                              trustpoint_line, cert_chain_cmd_line)
                break
            line += 1

        if found:
            trustpoint_dictionary = {'trustpoint_name': trustpoint_name, 'use_by': '', 'use_by_lines': [],
                                     'cert_chain': cert_chain, 'trustpoint_line': trustpoint_line,
                                     'cert_chain_cmd_line': cert_chain_cmd_line, 'num_of_ca': num_of_ca,
                                     'num_of_id': num_of_id}
            return (found, trustpoint_dictionary)
        else:
            return (found, 0)

    def get_cert_chain(self, platform, running_config, line, length_of_config, trustpoint_name, trustpoint_line,
                       cert_chain_cmd_line):
        cert_chain = []
        num_of_id = 0
        num_of_ca = 0
        cert_pos = 0
        line += 1


        while line <= length_of_config - 1:
            if re.match(r'^\s*certificate', running_config[line]):
                if 'certificate ca ' in running_config[line]:
                    start = line
                    found, cert_hex_stream, line = self.get_cert(running_config, line, length_of_config)
                    if found:
                        cert_obj = certObj('stp', platform, 'ca', cert_hex_stream, 'hex', start, line, cert_pos,
                                           trustpoint_name, trustpoint_line, cert_chain_cmd_line)
                        if cert_obj.ret >= 0:
                            cert_chain.append(cert_obj)
                            num_of_ca += 1
                            cert_pos += 1
                else:
                    start = line
                    found, cert_hex_stream, line = self.get_cert(running_config, line, length_of_config)
                    if found:
                        cert_obj = certObj('stp', platform, 'id', cert_hex_stream, 'hex', start, line, cert_pos,
                                           trustpoint_name, trustpoint_line, cert_chain_cmd_line)
                        if cert_obj.ret >= 0:
                            cert_chain.append(cert_obj)
                            num_of_id += 1
                            cert_pos += 1
            line += 1

        if len(cert_chain) >= 1:
            return (True, cert_chain, num_of_ca, num_of_id)
        else:
            return (False, 0, 0, 0)

    def get_cert(self, running_config, line, length_of_config):
        cert_hex_block = ''
        orig_line = line
        found = False
        line += 1

        while line <= length_of_config - 1:
            if re.match(r'^\s*[0-9a-fA-F]{2}', running_config[line], re.I):
                cert_hex_block += running_config[line]
            elif 'quit' in running_config[line]:
                cert_end_line = line
                if cert_hex_block:
                    found = True
                break
            line += 1

        if found:
            cert_hex_stream = "".join(cert_hex_block.split())
            if len(cert_hex_stream) % 2 == 1:
                found = False
                return (found, '', orig_line)
            return (found, cert_hex_stream, cert_end_line)
        else:
            return (found, '', orig_line)

    def update_use_by(self, trustpoint_list, tp_in_line, feature, line_num):
        if re.match(r'_internal_', tp_in_line):
            return
        for chain in trustpoint_list:
            if tp_in_line == chain['trustpoint_name']:
                if not chain['use_by']:
                    chain['use_by'] = feature
                    chain['use_by_lines'].append(line_num)
                elif not feature in chain['use_by']:
                    chain['use_by'] += ', ' + feature
                    chain['use_by_lines'].append(line_num)
                else:
                    chain['use_by_lines'].append(line_num)
                for cert in chain['cert_chain']:
                    cert.use_by = chain['use_by']
                    cert.use_by_lines.append(line_num)

    def highlight_and_show_decode(self, trustpoint_dictionary, trustpoint):
        instances_to_report = []
        rel_identifiers = []
        chain_summary_orig = ''
        for cert in range(0, len(trustpoint_dictionary['cert_chain'])):
            cert_summary_orig = ''
            for rel in trustpoint_dictionary['cert_chain'][cert].trustRels:
                cert_summary_orig += rel.trustRelation
                if not rel.identifier in rel_identifiers:
                    rel_identifiers.append(rel.identifier)
                    chain_summary_orig += rel.trustRelation + '<br />'
            cert_summary = cert_summary_orig.replace(str(trustpoint_dictionary['cert_chain'][cert].pos[0]) + '_' + str(
                trustpoint_dictionary['cert_chain'][cert].pos[1]) + '"',
                                                     str(trustpoint_dictionary['cert_chain'][cert].pos[0]) + '_' + str(
                                                         trustpoint_dictionary['cert_chain'][cert].pos[
                                                             1]) + '" style="color:purple;font-weight:bold"')
            cert_summary = '<br /><hr>Num of hierarchies that this certificate is involved in: ' + str(
                len(trustpoint_dictionary['cert_chain'][cert].trustRels)) \
                           + '<br /><br />Hierarchies (This certificate is shown in <span style="color:purple"><b>purple</b></span>. Hover over the names to see summary.):<br /><br />' \
                           + cert_summary
            t1 = '<span style="display:none" id="x509_decode_' + str(trustpoint) + '_' + str(cert) + '"><pre>' + \
                 trustpoint_dictionary['cert_chain'][cert].x509Decode.decode('utf-8') + '</pre></span>'
            t2 = '<span style="display:none" id="asn1_decode_' + str(trustpoint) + '_' + str(cert) + '"><pre>' + \
                 trustpoint_dictionary['cert_chain'][cert].asn1Decode.decode('utf-8') + '</pre></span>'
            t3 = '<span style="display:none" id="edit_cert"><pre>lalala</pre></span>'
            text_cert = t1 + t2 + t3 + cert_summary
            title_cert = 'Certificate Information:'
            instances_to_report.append({'start': trustpoint_dictionary['cert_chain'][cert].start_line,
                                        'end': trustpoint_dictionary['cert_chain'][cert].end_line,
                                        'severity': 'invisible', 'title': title_cert, 'text': text_cert})
        chain_summary = re.sub('id="cert_pos_' + str(trustpoint_dictionary['cert_chain'][cert].pos[0]) + '_', \
                               'style="color:purple;font-weight:bold" id="cert_pos_' + str(
                                   trustpoint_dictionary['cert_chain'][cert].pos[0]) + '_', \
                               chain_summary_orig)
        if trustpoint_dictionary['use_by']:
            prepend = '<br /><b>This Trustpoint is used by ' + trustpoint_dictionary[
                'use_by'] + ' feature(s).</b><br />'
        else:
            prepend = ''
        chain_summary = prepend + '<br /><hr>Num of certificates in this trustpoint: ' + str(
            trustpoint_dictionary['num_of_ca']) + ' CA and ' + str(trustpoint_dictionary['num_of_id']) + ' identity.' \
                        + '<br />Num of hierarchies that certificates of this trustpoint are involved in: ' + str(
            len(rel_identifiers)) \
                        + '<br /><br />Hierarchies (Certificates of this trustpoint shown in <span style="color:purple"><b>purple</b></span>. Hover over the names to see summary.):<br /><br />' \
                        + chain_summary
        title_tp = 'Trustpoint Information:'
        if trustpoint == 0:
            text_tp = toggle_javascript + chain_summary
        else:
            text_tp = chain_summary
        instances_to_report.append(
            {'start': trustpoint_dictionary['trustpoint_line'], 'end': trustpoint_dictionary['trustpoint_line'],
             'severity': 'invisible', 'title': title_tp, 'text': text_tp})
        title_chain = 'Certificate chain Information:'
        text_chain = chain_summary
        instances_to_report.append(
            {'start': trustpoint_dictionary['cert_chain_cmd_line'], 'end': trustpoint_dictionary['cert_chain_cmd_line'],
             'severity': 'invisible', 'title': title_chain, 'text': text_chain})
        return (instances_to_report)

    def check_bit_size(self, cert_obj):
        instances_to_report = []
        if cert_obj.type == 'id' and cert_obj.use_by and cert_obj.key_size < 8192:
            feature_lines = []
            for item in cert_obj.use_by_lines:
                feature_lines.append({'start': item, 'end': item})
            title = "The key size of Identity certificate for " + cert_obj.use_by + " feature(s), is less than 1024 bit, which is a deviation from security best practices."
            external_title = title
            display = "The key size of Identity certificate " + cert_obj.short_name + " in trustpoint " + cert_obj.trustpoint_name \
                      + " for " + cert_obj.use_by + " feature(s), is " + str(cert_obj.key_size) \
                      + ". The minimum size of certificate keys as per security best practices should be 1024 bit."
            display_ext = display
            instances_to_report.append(
                {'start': 0, 'end': 0, 'severity': 'notice', 'title': title, 'external_title': external_title, \
                 'text': display, 'external_text': display_ext, \
                 'multiple_line_values': [ \
                                             {'start': cert_obj.trustpoint_line, 'end': cert_obj.trustpoint_line}, \
                                             {'start': cert_obj.start_line, 'end': cert_obj.start_line} \
                                             ] + feature_lines \
                 })
        return instances_to_report
