
'''
A TreeNode class that contains the various function including the creation
of a node for the certificate in the tree with all the relations for
the Parent, Siblings, Child etc is also involved
'''
class TreeNode:  # Creates the Tree

    def __init__(self, data):  # To create a node with the certificate data present
        self.data = data
        self.children = []  # List assigned for the children nodes.
        self.parent = None  # Parent node is initialized to None

    def addChild(self, obj):  # To add children to the given node
        self.children.append(obj)  # adds the node as children of self node
        curr = len(self.children)  # Returns the number of children of the node
        self.children[curr - 1].parent = self  # Sets the current node(self) as the parent node for the node (obj)

    def addParent(self, obj):  # Sets the parent node of self as obj
        self.parent = obj  # adds obj as parent of self
        self.parent.children.append(self)  # Adding the self node to the parents children list

    def getChildren(self):  # returns the children of current node
        if self.hasChildren():
            return (self.children)

    def getParent(self):  # returns the parent of the current node
        if not self.isRoot():  # if not the current node is the root
            return self.parent

    def getData(self):  # returns data of the current node
        if self.data:
            return self.data

    def getLevel(self):  # returns the level of node from root, starting from 0
        level = 0
        x = self
        while not x.isRoot():
            level += 1
            x = x.parent  # transversing upwards in the tree
        return level

    def getRoot(self):  # returns the root node of the tree
        x = self
        while not x.isRoot():
            x = x.parent
        return x

    def isRoot(self):  # returns true or false for is node is root
        # Toplevel. Not the the term we use in PKI.
        if not self.parent:  # if no  parent is present
            return True
        else:
            return False

    def hasChildren(self):  # returns true or false for if node has children
        if self.children:  # if children present
            return True
        else:
            return False

    def noOfChildren(self):  # returns number of children
        return len(self.children)

    def noOfRels(self):  # returns number of relatives
        if self.hasChildren():
            return self.noOfChildren()
        else:
            return 1


class TrustRel:
    def __init__(self, cert_obj, identifier):
        '''
        A trust relation is established in it in order to work on them and it 
        is maintained in the way that is organised with the certificate object
        that is sent to this function.
        '''
        self.trustRelation = ''
        self.identifier = identifier
        isId = ''
        isId2 = ''
        if cert_obj.type == 'id':  #
            isId = ' (Identity)'
            if cert_obj.use_by:
                isId2 = '<br />(Trustpoint <b>' + cert_obj.trustpoint_name + '</b> used by <b>' + cert_obj.use_by + '</b>.)'
        trust_string = self._branchTowardsRoot(cert_obj, '')
        x = str(cert_obj.pos[0])
        y = str(cert_obj.pos[1])
        trust_string += '<span id="cert_pos_' + str(cert_obj.pos[0]) + '_' + str(cert_obj.pos[1]) \
                        + '" onmouseout="tooltip.hide()" onmouseover="tooltip.show(&quot;' + cert_obj.summary + '&quot;)">' \
                        + cert_obj.short_name + ' (TP: ' + cert_obj.trustpoint_name + ')' + isId + '</span>' \
                        + ' <span onclick="decode_show(this, &quot;x509_decode_' + x + '_' + y + '&quot;)" ><a><i><b><font color="blue"> &nbsp &nbsp x509-Decode</font></b></i></a></span>' \
                        + ' <span onclick="decode_show(this, &quot;asn1_decode_' + x + '_' + y + '&quot;)" ><a><i><b><font color="blue"> &nbsp &nbsp asn1-Decode</font></b></i></a></span>' + isId2 +'<br />'
        # trust_string = self._branchTowardsLeaves(cert_obj, trust_string)
        trust_string = self._replaceNbspWithIndent(trust_string)
        self.trustRelation = trust_string

    def _replaceNbspWithIndent(self, trust_string):
        trust_string = trust_string.replace('|__', '|__</span>')
        t = trust_string.split('&nbsp;&nbsp;')
        trust_string_new = t[0]
        i = 1
        c = 1
        while i <= len(t) - 1:
            if t[i]:
                trust_string_new += '<span style="padding-left: ' + str(c * 20) + 'px">' + t[i]
                c = 1
            else:
                c += 1
            i += 1
        return trust_string_new

    def _branchTowardsRoot(self, cert_obj, root_string):
        cert_obj.trustRels.append(self)
        if not cert_obj.node.isRoot():
            x = str(cert_obj.node.parent.getData().pos[0])
            y = str(cert_obj.node.parent.getData().pos[1])
            root_string = '<span id="cert_pos_' + str(cert_obj.node.parent.getData().pos[0]) + '_' + str(
                cert_obj.node.parent.getData().pos[1]) \
                            + '" onmouseout="tooltip.hide()" onmouseover="tooltip.show(&quot;' + cert_obj.node.parent.getData().summary + '&quot;)">' \
                            + cert_obj.node.parent.getData().short_name + ' (TP: ' + cert_obj.node.parent.getData().trustpoint_name + ')</span>' \
                            + ' <span onclick="decode_show(this, &quot;x509_decode_' + x + '_' + y + '&quot;)" ><a><i><b><font color="blue"> &nbsp &nbsp x509-Decode</font></b></i></a></span>' \
                            + ' <span onclick="decode_show(this, &quot;asn1_decode_' + x + '_' + y + '&quot;)" ><a><i><b><font color="blue"> &nbsp &nbsp asn1-Decode</font></b></i></a></span>' \
                            + '<br />' + '&nbsp;&nbsp;' * (cert_obj.node.parent.getLevel() + 1) + '|__' + root_string
            root_string = self._branchTowardsRoot(cert_obj.node.parent.getData(), root_string)
        else:
            if cert_obj.isSelfSigned == True:
                root_string = '(Self-Signed) ' + root_string
            elif cert_obj.isRoot == True:
                root_string = '(Root) ' + root_string
            else:
                if root_string:
                    root_string = "<br />&nbsp;&nbsp;".join(root_string.split('<br />'))
                root_string = '(Root) ??? (Root Certificate not in trust store)<br />&nbsp;&nbsp;|__' + root_string
                cert_obj.noRootInChain = True
                self._update_no_root_in_chain(cert_obj)
        return (root_string)

    def _update_no_root_in_chain(self, cert_obj):
        if cert_obj.node.hasChildren():
            for branch in xrange(0, cert_obj.node.noOfChildren()):
                cert_obj.node.children[branch].getData().noRootInChain = True
                self._update_no_root_in_chain(cert_obj.node.children[branch].getData())


def build_nodes(trustpoint_list, cert_obj):
    '''
    Creates a node for the input certificate and links the truspoint that is 
    defined in the certificate that is parsed.
    '''
    ignore_tp = -1
    for trustpoint in range(0, len(trustpoint_list)):
        if cert_obj.trustpoint_name == trustpoint_list[trustpoint]['trustpoint_name']:
            for cert in range(0, len(trustpoint_list[trustpoint]['cert_chain'])):
                if trustpoint == cert_obj.pos[0] and cert == cert_obj.pos[1]:
                    continue
                if cert_obj.issuer == trustpoint_list[trustpoint]['cert_chain'][cert].subject:
                    if True and not cert_obj.subject == trustpoint_list[trustpoint]['cert_chain'][cert].subject:
                        if not cert_obj.node.getParent():
                            if cert_obj.authorityKeyIdentifier and trustpoint_list[trustpoint]['cert_chain'][
                                cert].subjectKeyIdentifier:
                                if cert_obj.authorityKeyIdentifier == trustpoint_list[trustpoint]['cert_chain'][
                                    cert].subjectKeyIdentifier:
                                    cert_obj.node.addParent(trustpoint_list[trustpoint]['cert_chain'][cert].node)
                                    ignore_tp = trustpoint
                                    break
                            else:
                                cert_obj.node.addParent(trustpoint_list[trustpoint]['cert_chain'][cert].node)
                                ignore_tp = trustpoint
                                break
            break

    for trustpoint in range(0, len(trustpoint_list)):
        if trustpoint == ignore_tp:
            continue
        for cert in range(0, len(trustpoint_list[trustpoint]['cert_chain'])):
            # Dont compare with yourself.
            if trustpoint == cert_obj.pos[0] and cert == cert_obj.pos[1]:
                continue
            if cert_obj.issuer == trustpoint_list[trustpoint]['cert_chain'][cert].subject:
                if True and not cert_obj.subject == trustpoint_list[trustpoint]['cert_chain'][cert].subject:
                    if not cert_obj.node.getParent():
                        if cert_obj.authorityKeyIdentifier and trustpoint_list[trustpoint]['cert_chain'][
                            cert].subjectKeyIdentifier:
                            if cert_obj.authorityKeyIdentifier == trustpoint_list[trustpoint]['cert_chain'][
                                cert].subjectKeyIdentifier:
                                cert_obj.node.addParent(trustpoint_list[trustpoint]['cert_chain'][cert].node)
                                break
                        else:
                            cert_obj.node.addParent(trustpoint_list[trustpoint]['cert_chain'][cert].node)
                            break

