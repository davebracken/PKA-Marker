# py_ptmp.py
# Author: Dave Bracken

import socket
import logging

from ptmp_constants import *

logger = logging.getLogger()


class PDUSender():
    """Send PDUs to Packet Tracer. """

    def __init__(self, remote_host, remote_port):
        self.pt_socket = None
        self.host = remote_host
        self.port = remote_port
        self.connected_status = False
        self.connection_msg = None


    def connect(self):
        """Attempt to connect to Packet Tracer. Returns True if successful, False with error message otherwise."""
    
        self.pt_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.pt_socket.connect((self.host, self.port))
        except Exception as exception_msg:
            self.connection_msg = exception_msg
        else:
            self.connected_status = True
            self.connection_msg = None

    
    def disconnect(self):
        """Disconnect from Packet Tracer. Returns True if successful, False with error message otherwise."""
        
        try:
            self.pt_socket.close()
        except Exception as exception_msg:
            self.connection_msg = exception_msg
        else:
            self.connected_status = False
            self.connection_msg = None


    def is_connected(self): 
        """Returns current connection status, True if connected, False otherwise."""
    
        return self.connected_status


    def getblocking(self):
        """Get the blocking status of the socket. """
    
        return self.pt_socket.getblocking()


    def send(self, pdu):
        """Send the PDU to Packet Tracer. """
    
        logger.debug(f'Sending: {pdu=}')
        self.pt_socket.sendall(pdu)
        reply = self.pt_socket.recv(PTMP_MAX_BUFFER_SIZE)
        logger.debug(f'Received: {reply=}')
        return reply



class PacketTracerIPC():
    """Packet Tracer IPC class.  This is the base class for all Packet Tracer IPC classes. """

    message_id = 1
    pdu_sender = None

    def __init__(self):
        self.api_full_name = ''
        self.method_name = ''
        self.api_string = ''
        self.pdu_length = 0
        self.pdu = ''

        # ToDo Consider if the following be better implemented as a reply object.
        self.reply_length = None
        self.reply_type = None
        self.reply_message_id = None
        self.reply_value_type = None
        self.reply_value = None


    def get_message_id(self):
        """Return the current message ID incremented."""
        
        PacketTracerIPC.message_id += 1
        return self.message_id


    def process_reply(self, reply):
        """Process the reply from Packet Tracer. """

        logger.debug(f'Received {reply=}')
        reply = reply.decode().split('\x00')
        logger.debug(f'Received {reply=}')
        
        # ToDo.  Need to look further into the reply object and find out the meaning of the potential lengths
        # Shorter replies (seen when authenticacting to ExApp) look like acknowledgements of receiving the previous message and are Length, Message Type, Value.
        # An empty string is in the last element of the list due to using split.  This needs to be addressed.

        # ToDo Add code to support TreeNode reply type in the future
        
        if len(reply) > PTMP_REPLY_LENGTH:
            self.reply_length = reply[PTMP_REPLY_LENGTH_IDX]
            self.reply_type = reply[PTMP_REPLY_TYPE_IDX]
            self.reply_message_id  = reply[PTMP_REPLY_MESSAGE_ID_IDX]
            self.reply_value_type = reply[PTMP_REPLY_VALUE_TYPE_IDX]
            if self.reply_value_type.isdigit():
                self.reply_value_type = int(reply[PTMP_REPLY_VALUE_TYPE_IDX])

                if self.reply_value_type == PTMP_TYPE_VALUE_BOOL:
                    self.reply_value = True if reply[PTMP_REPLY_VALUE_IDX] == PTMP_CONFIRMATION else False
                elif self.reply_value_type == PTMP_TYPE_VALUE_INT:
                    self.reply_value = int(reply[PTMP_REPLY_VALUE_IDX])
                elif self.reply_value_type == PTMP_TYPE_VALUE_DOUBLE:
                    self.reply_value = float(reply[PTMP_REPLY_VALUE_IDX])
                else:
                    self.reply_value = reply[PTMP_REPLY_VALUE_IDX]
            elif self.reply_value_type == PTMP_TYPE_VALUE_TREENODE:
                    self.reply_value = reply[PTMP_REPLY_VALUE_IDX]
        else:
            self.reply_value = reply[len(reply)-1]
        logger.debug(f'{self.reply_value=} Type is {type(self.reply_value)}')

        return None 


    def set_method_name(self, method_name, msg_arg = None, arg_type = None):
        """Set the method name. """
        
        if msg_arg:
            # self.method_name = f'{method_name}.{arg_type}.{msg_arg}.'
            self.method_name = f'\x000\x00{method_name}\x00{arg_type}\x00{msg_arg}\x000\x00'
        else:
            self.method_name = f'\x000\x00{method_name}\x000\x00'
        return None 


    def update_api_name(self, name):
        """ Append the name to the API name. """

        self.api_name += f'{name}.'

        return None 


    def send_message(self):
        """ Send the message to Packet Tracer. """

        self.api_string = self.api_full_name
        logger.debug(f'{self.api_string=}')

        self.api_string = self.api_string.replace('.', '\x000\x00')
        self.api_string = '\x00' + self.api_string
        self.api_string = self.api_string + self.method_name

        ipc_message_id = self.get_message_id()

        # ToDo. Explain why initially 4.  Yucky magic number.
        # 5 is when the message id is a single digit.
        # 6 is when the message id becomes 2 digits etc.  Has been tested with an initial message_id value of 1000
        self.pdu_length = len(str(ipc_message_id)) + 4
        self.pdu_length += len(self.api_string.replace('\x000','.0').replace('\x00','0'))

        logger.debug(f'api_string: {self.api_string.encode()}')

        self.pdu = f'{self.pdu_length}\x00{PTMP_MESSAGE_TYPE_IPC_MESSAGE}\x00{ipc_message_id}{self.api_string}'.encode()

        reply = self.pdu_sender.send(self.pdu)
        self.process_reply(reply)
        return self.reply_value


class Simulation(PacketTracerIPC):
    """ Simulation class used to control the simulation time. """

    def __init__(self):
        super().__init__()
        self.cls_name = 'simulation'
        self.api_full_name = f'{self.cls_name}'


    def get_current_sim_time(self):
        """getCurrentSimTime in Cisco API. """

        self.set_method_name('getCurrentSimTime')
        self.send_message()
        return self.reply_value


class AppWindow(PacketTracerIPC):
    """ AppWindow class. Main use if file operations. """ 

    def __init__(self):
        super().__init__()
        self.cls_name = 'appWindow'
        self.api_full_name = f'{self.cls_name}'


    def file_new(self, confirmation):
        """ fileNew in Cisco API. """

        self.set_method_name('fileNew', confirmation, PTMP_TYPE_VALUE_BOOL)
        self.send_message()
        return self.reply_value


    def file_open(self, filename):
        """ fileOpen in Cisco API. """

        self.set_method_name('fileOpen', filename, PTMP_TYPE_VALUE_STRING)
        self.send_message()
        return self.reply_value


class GetRealtimeToolbar(AppWindow):
    """ Get the Realtime toolbar and fast forward. """

    def __init__(self):
        super().__init__()
        self.cls_name = 'getRealtimeToolbar'
        self.api_full_name = f'{self.api_full_name}.{self.cls_name}'


    def fast_forward_time(self):
        """fastForwardTime in Cisco API.  """

        self.set_method_name('fastForwardTime')
        self.send_message()
        return self.reply_value



class ActiveFile(AppWindow):
    """Access the active PKA file.  """

    def __init__(self):
        super().__init__()
        self.cls_name = 'getActiveFile'
        self.api_full_name = f'{self.api_full_name}.{self.cls_name}'


    def is_password_confirmed(self):
        """isPasswordConfirmed in Cisco API. """

        self.set_method_name('isPasswordConfirmed')
        self.send_message()
        return self.reply_value


    def get_challenge_key_as_base64(self):
        """getChallengeKeyAsBase64 in Cisco API. """

        self.set_method_name('getChallengeKeyAsBase64')
        self.send_message()
        return self.reply_value

 
    def confirm_password(self, password):
        """confirmPassword in Cisco API. """

        self.set_method_name('confirmPassword', password, PTMP_TYPE_VALUE_STRING)
        self.send_message()
        return self.reply_value


    def get_script_data_store(self, object_name):
        """getScriptDataStore in Cisco API. """

        self.set_method_name('getScriptDataStore', object_name, PTMP_TYPE_VALUE_STRING)
        self.send_message()
        return self.reply_value


    # Need to look into if this can be used instead of advancing the time.
    def set_time_elapsed(self, time_val):
        """setTimeElapsed in Cisco API. """

        self.set_method_name('setTimeElapsed', time_val, PTMP_TYPE_VALUE_INT)
        self.send_message()
        return self.reply_value


    def run_connectivity_tests(self):
        """runConnectivityTests in Cisco API. """

        self.set_method_name('runConnectivityTests')
        self.send_message()
        return self.reply_value


    def get_percentage_complete(self):
        """getPercentageComplete in Cisco API. """

        self.set_method_name('getPercentageComplete')
        self.send_message()
        return self.reply_value
    
    
    def get_assessment_items_count(self):
        """getAssessmentItemsCount in Cisco API. """

        self.set_method_name('getAssessmentItemsCount')
        self.send_message()
        return self.reply_value
    
    
    def get_correct_assessment_items_count(self):
        """getCorrectAssessmentItemsCount in Cisco API. """

        self.set_method_name('getCorrectAssessmentItemsCount')
        self.send_message()
        return self.reply_value

    
    def get_assessment_score_count(self):
        """getAssessmentScoreCount in Cisco API. """

        self.set_method_name('getAssessmentScoreCount')
        self.send_message()
        return self.reply_value

    
    def get_correct_assessment_score_count(self):
        """getCorrectAssessmentScoreCount in Cisco API. """

        self.set_method_name('getCorrectAssessmentScoreCount')
        self.send_message()
        return self.reply_value

    
    def get_connectivity_count(self):
        """getConnectivityCount in Cisco API. """

        self.set_method_name('getConnectivityCount')
        self.send_message()
        return self.reply_value

    
    def get_last_connectivity_test_correct_count(self):
        """getLastConnectivityTestCorrectCount in Cisco API. """

        self.set_method_name('getLastConnectivityTestCorrectCount')
        self.send_message()
        return self.reply_value

    
    def get_percentage_complete_score(self):
        """ getPercentageCompleteScore in Cisco API. """

        self.set_method_name('getPercentageCompleteScore')
        self.send_message()
        return self.reply_value


    # The following are not currently used.
    # def get_completed_feedback(self):
    #     """getCompletedFeedback in Cisco API."""

    #     self.set_method_name('getCompletedFeedback')
    #     self.send_message()
    #     return self.reply_value


    # def get_incomplete_feedback(self):
    #     """getIncompleteFeedback in Cisco API. """

    #     self.set_method_name('getIncompleteFeedback')
    #     self.send_message()
    #     return self.reply_value


    # # Need to look into using this.
    # def is_user_profile_locked(self):
    #     """isUserProfileLocked in Cisco API."""

    #     self.set_method_name('isUserProfileLocked')
    #     self.send_message()
    #     return self.reply_value


    # def get_dynamic_percentage_feedback_type(self):
    #     """getDynamicPercentageFeedbackType in Cisco API."""

    #     self.set_method_name('getDynamicPercentageFeedbackType')
    #     self.send_message()
    #     return self.reply_value


    # def get_dy_feedback_string(self):
    #     """getDyFeedbackString in Cisco API."""

    #     self.set_method_name('getDyFeedbackString')
    #     self.send_message()
    #     return self.reply_value


    # def get_comparator_tree(self):
    #     """getComparatorTree in Cisco API."""

    #     self.set_method_name('getComparatorTree')
    #     self.send_message()
    #     return self.reply_value



class UserProfile(ActiveFile):
    """ Access the user profile.  """

    def __init__(self):
       super().__init__()
       self.cls_name = 'getUserProfile'
       self.api_full_name = f'{self.api_full_name}.{self.cls_name}'


    def get_email(self):
       """getEmail in Cisco API. """

       self.set_method_name('getEmail')
       self.send_message()
       return self.reply_value


    def get_name(self):
       """getName in Cisco API. """

       self.set_method_name('getName')
       self.send_message()
       return self.reply_value


#  Not currently used. 
# class TreeNodeImpl(ActiveFile):
#     """Access the activity tree. """

#     def __init__(self):
#         super().__init__()
#         self.cls_name = 'getLastAssessedComparatorTree'
#         self.api_full_name = f'{self.api_full_name}.{self.cls_name}'


#     def getNodeId(self):
#         """getNodeId in Cisco API. """

#         self.set_method_name('getNodeId')
#         self.send_message()
#         return self.reply_value


#     def getNodeName(self):
#         """getNodeName in Cisco API. """

#         self.set_method_name('getNodeName')
#         self.send_message()
#         return self.reply_value


#     def getNodeValue(self):
#         """getNodeValue in Cisco API. """

#         self.set_method_name('getNodeValue')
#         self.send_message()
#         return self.reply_value


#     def getParentNode(self):
#         """getParentNode in Cisco API. """

#         self.set_method_name('getParentNode')
#         self.send_message()
#         return self.reply_value


#     def getChildCount(self):
#         """getChildCount in Cisco API. """

#         self.set_method_name('getChildCount')
#         self.send_message()
#         return self.reply_value


#     def getCheckType(self):
#         """getCheckType in Cisco API. """

#         self.set_method_name('getCheckType')
#         self.send_message()
#         return self.reply_value


#     def getChildNodeAt(self, child_idx):
#         """getChildNodeAt in Cisco API. """

#         self.set_method_name('getChildNodeAt', child_idx, PTMP_TYPE_VALUE_INT)
#         self.send_message()
#         return self.reply_value


#     def getChildNodeBy(self, node_id):
#         """getChildNodeBy in Cisco API. """

#         self.set_method_name('getChildNodeBy', node_id, PTMP_TYPE_VALUE_STRING)
#         self.send_message()
#         return self.reply_value


#     def getCheckOnlyTree(self):
#         """getCheckOnlyTree in Cisco API. """

#         self.set_method_name('getCheckOnlyTree')
#         self.send_message()
#         return self.reply_value


#     def getIncorrectFeedback(self):
#         """getIncorrectFeedback in Cisco API. """

#         self.set_method_name('getIncorrectFeedback')
#         self.send_message()
#         return self.reply_value


#     def getLeafCount(self):
#         """getLeafCount in Cisco API. """

#         self.set_method_name('getLeafCount')
#         self.send_message()
#         return self.reply_value


#     def getCheckLeafCount(self):
#         """getCheckLeafCount in Cisco API. """

#         self.set_method_name('getCheckLeafCount')
#         self.send_message()
#         return self.reply_value


#     def getTotalLeafPoints(self):
#         """getTotalLeafPoints in Cisco API. """

#         self.set_method_name('getTotalLeafPoints')
#         self.send_message()
#         return self.reply_value


#     def isVariableEnabled(self):
#         """isVariableEnabled in Cisco API. """

#         self.set_method_name('isVariableEnabled')
#         self.send_message()
#         return self.reply_value


#     def getVariableName(self):
#         """getVariableName in Cisco API. """

#         self.set_method_name('getVariableName')
#         self.send_message()
#         return self.reply_value


#     def getVariableToString(self):
#         """getVariableToString in Cisco API. """

#         self.set_method_name('getVariableToString')
#         self.send_message()
#         return self.reply_value


#     def getComparatorClass(self):
#         """getComparatorClass in Cisco API. """

#         self.set_method_name('getComparatorClass')
#         self.send_message()
#         return self.reply_value


#     def getLeafCountByComponent(self, component):
#         """getLeafCountByComponent in Cisco API. """

#         self.set_method_name('getLeafCountByComponent', component, PTMP_TYPE_VALUE_STRING)
#         self.send_message()
#         return self.reply_value


#     def getCheckLeafPointsByComponent(self, component):
#         """getCheckLeafPointsByComponent in Cisco API. """

#         self.set_method_name('getCheckLeafPointsByComponent', component, PTMP_TYPE_VALUE_STRING)
#         self.send_message()
#         return self.reply_value


#     def getTotalLeafPointsByComponent(self, component):
#         """getTotalLeafPointsByComponent in Cisco API. """

#         self.set_method_name('getTotalLeafPointsByComponent', component, PTMP_TYPE_VALUE_STRING)
#         self.send_message()
#         return self.reply_value


#     def getCheckLeafPoints(self):
#         """getCheckLeafPoints in Cisco API. """

#         self.set_method_name('getCheckLeafPoints')
#         self.send_message()
#         return self.reply_value


#     def getCompPointPair(self):
#         """getCompPointPair in Cisco API. """

#         self.set_method_name('getCompPointPair')
#         self.send_message()
#         return self.reply_value


#     def getChildNodeByFullId(self, id):
#         """getChildNodeByFullId in Cisco API. """

#         self.set_method_name('getChildNodeByFullId', id, PTMP_TYPE_VALUE_STRING)
#         self.send_message()
#         return self.reply_value



class ConnectionNegotiationPDU():
    """Class to build the connection negotiation PDU."""

    def __init__(self, identifier,  version, uuid, encoding, encryption, compression, authentication, current_time, keep_alive, reserved):
        self.ptmp_identifier = identifier
        self.ptmp_version = version
        self.app_uuid = uuid
        self.ptmp_encoding_text = encoding
        self.ptmp_no_encryption = encryption
        self.ptmp_no_compression = compression
        self.ptmp_authentication_md5 = authentication
        self.current_time = current_time
        self.ptmp_keep_alive = keep_alive
        self.ptmp_reserved = reserved
        self.negotiation_msg_value = ''
        self.pdu_length = 0
        self.pdu = None


    def build_pdu(self):
        """Build the PDU. """

        self.negotiation_msg_value = f'.{self.ptmp_identifier}.{self.ptmp_version}.{{{self.app_uuid}}}.{self.ptmp_encoding_text}.{self.ptmp_no_encryption}'
        self.negotiation_msg_value += f'.{self.ptmp_no_compression}.{self.ptmp_authentication_md5}.{self.current_time}.{self.ptmp_keep_alive}.{self.ptmp_reserved}.'
        self.pdu_length = len(self.negotiation_msg_value) + 1
        self.pdu = f'{self.pdu_length}.{PTMP_MESSAGE_TYPE_NEGOTIATION_REQUEST}{self.negotiation_msg_value}'.replace('.','\x00').encode()
        return None 


    def __str__(self):
        return f'Negotiation message: {self.negotiation_msg_value}\nMessage length: {self.pdu_length}\nPDU: {self.pdu}'


    def __eq__(self, other_pdu):

        logger.debug(f'{self.ptmp_identifier} : {other_pdu.ptmp_identifier}')
        logger.debug(f'{self.ptmp_version} : {other_pdu.ptmp_version}')
        logger.debug(f'{self.ptmp_encoding_text} : {other_pdu.ptmp_encoding_text}')
        logger.debug(f'{self.ptmp_no_encryption} : {other_pdu.ptmp_no_encryption}')
        logger.debug(f'{self.ptmp_no_compression} : {other_pdu.ptmp_no_compression}')
        logger.debug(f'{self.ptmp_authentication_md5} : {other_pdu.ptmp_authentication_md5}')
        logger.debug(f'{self.current_time} : {other_pdu.current_time}')
        logger.debug(f'{self.ptmp_keep_alive} : {other_pdu.ptmp_keep_alive}')

        return all([self.ptmp_identifier == other_pdu.ptmp_identifier,
                    self.ptmp_version == other_pdu.ptmp_version,
                    self.ptmp_encoding_text == other_pdu.ptmp_encoding_text,
                    self.ptmp_no_encryption == other_pdu.ptmp_no_encryption,
                    self.ptmp_no_compression == other_pdu.ptmp_no_compression,
                    self.ptmp_authentication_md5 == other_pdu.ptmp_authentication_md5,
                    self.ptmp_keep_alive == other_pdu.ptmp_keep_alive
                    ])

