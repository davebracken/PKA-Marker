#!/usr/bin/env python3

# Automagic PKA marker
# Dave Bracken
# Christchurch, New Zealand.
# 2022-2025


import argparse
import base64
import binascii
from collections import namedtuple
import csv
from datetime import datetime
import glob
import hashlib
import logging
from pathlib import Path
import sys
import uuid

from dotenv import dotenv_values

import pt_constants
import ptmp_constants
import py_ptmp

environment_config = {
        **dotenv_values('.env.secret'),
        **dotenv_values('.env.shared')
        }

AUTHENTICATION_REQUEST_ID = environment_config['AUTHENTICATION_REQUEST_ID']
DATA_STORE_OBJECT_LAB_ID = environment_config['DATA_STORE_OBJECT_LAB_ID']
EXAPP_PASSWORD = environment_config['EXAPP_PASSWORD']
GUEST_FILENAME = environment_config['GUEST_FILENAME']
GUEST_NAME = environment_config['GUEST_NAME']
LOG_FILE = environment_config['LOG_FILE']
PKA_LAB_PASSWORD = environment_config['PKA_LAB_PASSWORD']
PKA_BASE_DIR = environment_config['PKA_BASE_DIR']
PT_HOST = environment_config['PT_HOST']
PT_PORT = int(environment_config['PT_PORT']) 
SCORE_ROUNDING_DP = int(environment_config['SCORE_ROUNDING_DP'])
RESULTS_CSV_FILE = environment_config['RESULTS_CSV_FILE']
SIM_TIME_ADVANCEMENT = int(environment_config['SIM_TIME_ADVANCEMENT'])
USE_DEFAULT_RESULTS_FILE = environment_config['USE_DEFAULT_RESULTS_FILE'].lower() == 'true'
USE_GUEST_FILE = environment_config['USE_GUEST_FILE'].lower() == 'true'

LOGGING_SEPARATOR = '-' * 40
NAME_IDX = 0
REQD_MAJOR_VER, REQD_MINOR_VER = 3, 6
VERSION = '1.1.0'


class ArgumentValidationError(Exception):
    """Custom exception for argument validation errors."""
    pass


class PythonVersionError(Exception):
    """Custom exception for Python version errors."""
    pass

class WideRawHelpFormatter(argparse.RawDescriptionHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
    """ Custom help formatter to allow for wider help text. """

    def __init__(self, prog):
        super().__init__(prog, max_help_position=50, width=120)

                      
def get_current_time():
    """ Return current time as a string in the format YYYYMMDDHHMMSS """

    return datetime.now().strftime('%Y%m%d%H%M%S')


def test_pt_connection():
    """ Tests the connection to Packet Tracer.

    This creates a PDUSender object and attempts to connect to Packet Tracer using the specified host and port.
    
    Returns:
        bool: True if the connection and subsequent disconnection to Packet Tracer are successful, otherwise False.
    """

    test_sender = py_ptmp.PDUSender(PT_HOST, PT_PORT)

    test_sender.connect()
    if test_sender.is_connected():
        logger.debug(f'Sucessfully connected to Packet Tracer on {PT_HOST}:{PT_PORT}')
        is_pt_connection_successful = True
    else:   
        logger.debug(f'Error connecting to Packet Tracer on {PT_HOST}:{PT_PORT}')
        is_pt_connection_successful = False
        logger.debug(test_sender.connection_msg)

    if is_pt_connection_successful:
        test_sender.disconnect()
        if not test_sender.is_connected():
            # This should be the case at this point
            logger.debug(f'Sucessfully disconnected from Packet Tracer.')
            pt_disconnection_successful = True
        else:
            logger.debug(f'Error disconnecting from Packet Tracer.')
            pt_disconnection_successful = False
            logger.debug(test_sender.connection_msg)

        if pt_disconnection_successful:
            logger.debug(f'Packet Tracer connected and disconnected successfully.')
        else:
            logger.debug(f'Error disconnecting from Packet Tracer: {test_sender.connection_msg}')

    if is_pt_connection_successful and pt_disconnection_successful:
        return True
    else:
        return False


def open_pka_file(filename, aw):
    """ Open the PKA file using the AppWindow object.
    Returns the status of the file open operation. """

    logger.info(f'Processing: {filename}')
    file_status = aw.file_open(filename)

    logger.debug(f'Received: {file_status}')
    logger.debug(LOGGING_SEPARATOR)

    return file_status


def close_pka_file(aw):
    """ We are done. Close the PKA file without prompting. Return the status of the close operation. """

    # This will position us to iterate through a list of PKA files 

    closed_status = aw.file_new(ptmp_constants.PTMP_NO_CONFIRMATION)
    logger.debug(f'Received {closed_status=}')
    logger.debug(LOGGING_SEPARATOR)

    return closed_status


def negotiate_connection(pdu_sender):
    """ Negotiate the connection with Packet Tracer.  Returns True if the negotiation is successful, False otherwise. """

    # random uuid
    app_uuid = str(uuid.uuid4())
    current_time = get_current_time()

    # ptmp_constants.PTMP identifier: ptmp_constants.PTMP, ptmp_constants.PTMP ver 1, text encoding, no compression, MD5 has for authentication, no keep alive
    negotiation_pdu = py_ptmp.ConnectionNegotiationPDU(ptmp_constants.PTMP_IDENTIFIER, ptmp_constants.PTMP_VERSION, app_uuid, ptmp_constants.PTMP_ENCODING_TEXT, ptmp_constants.PTMP_NO_ENCRYPTION,
                                                ptmp_constants.PTMP_NO_COMPRESSION, ptmp_constants.PTMP_AUTHENTICATION_MD5, current_time, ptmp_constants.PTMP_KEEP_ALIVE, ptmp_constants.PTMP_RESERVED)

    # As a test, use ptmp_constants.PTMP_AUTHENTICATION_CLEAR_TEXT
    # negotiation_pdu = ConnectionNegotiationPDU(ptmp_constants.PTMP_IDENTIFIER, ptmp_constants.PTMP_VERSION, app_uuid, ptmp_constants.PTMP_ENCODING_TEXT, ptmp_constants.PTMP_NO_ENCRYPTION,
    #                                             ptmp_constants.PTMP_NO_COMPRESSION, ptmp_constants.PTMP_AUTHENTICATION_CLEAR_TEXT, current_time, ptmp_constants.PTMP_KEEP_ALIVE, ptmp_constants.PTMP_RESERVED)

    negotiation_pdu.build_pdu()
    logger.debug(f'{negotiation_pdu.pdu=}')
    # Send the negotiation request
    reply = pdu_sender.send(negotiation_pdu.pdu)
    logger.debug(f'Received: {reply=}')

    negotiation_reply = reply.decode().split('\x00')
    logger.debug(f'Received: {negotiation_reply=}')

    # Just for info
    remote_pt_version = negotiation_reply[-2][1::]
    logger.debug(f'PT version: {remote_pt_version}')

    # Build a ConnectionNegotiationPDU from the reply and compare the objects
    # The reply from PT is an array of strings hence the selective type conversion
    
    # reply_pdu = ConnectionNegotiationPDU(negotiation_reply[2], int(negotiation_reply[3]), negotiation_reply[4], int(negotiation_reply[5]), int(negotiation_reply[6]),
    #                                        int(negotiation_reply[7]), int(negotiation_reply[8]), negotiation_reply[9], int(negotiation_reply[10]), negotiation_reply[11])
    
    reply_pdu = py_ptmp.ConnectionNegotiationPDU(negotiation_reply[ptmp_constants.PTMP_IDENTIFIER_IDX], int(negotiation_reply[ptmp_constants.PTMP_VERSION_IDX]), negotiation_reply[ptmp_constants.APP_UUID_IDX], int(negotiation_reply[ptmp_constants.PTMP_ENCODING_TEXT_IDX]),
                                         int(negotiation_reply[ptmp_constants.PTMP_NO_ENCRYPTION_IDX]), int(negotiation_reply[ptmp_constants.PTMP_NO_COMPRESSION_IDX]), int(negotiation_reply[ptmp_constants.PTMP_AUTHENTICATION_MD5_IDX]),
                                         negotiation_reply[ptmp_constants.CURRENT_TIME_IDX], int(negotiation_reply[ptmp_constants.PTMP_KEEP_ALIVE_IDX]), negotiation_reply[ptmp_constants.PTMP_RESERVED_IDX])
    
    # Did the server agree with the client?
    negotiated_status = reply_pdu == negotiation_pdu
    logger.debug(f'{negotiated_status=}')

    return negotiated_status


def authenticate_as_exaxpp(pdu_sender):
    """ Authenticate as the ExApp (PT external application).  Returns True if the password is confirmed, False otherwise. """

    pdu_msg = f'!{ptmp_constants.PTMP_MESSAGE_TYPE_AUTHENTICATION_REQUEST}!{AUTHENTICATION_REQUEST_ID}!'
    msg_length = len(pdu_msg) - 1
    pdu = f'{msg_length}{pdu_msg}'.replace('!','\x00').encode()

    reply = pdu_sender.send(pdu)
    logger.debug(f'Received: {reply}')

    challenge_reply = reply.decode().split('\x00')
    logger.debug(f'{challenge_reply=}')

    challenge = challenge_reply[ptmp_constants.PTMP_EXAPP_CHALLENGE_IDX]
    logger.debug(f'{challenge=}')

    message = challenge + EXAPP_PASSWORD
    hashed_pwd = hashlib.md5(message.encode('utf-8')).hexdigest()
    logger.debug(f'{hashed_pwd=}')
    logger.debug(f'{hashed_pwd.upper()=}')

    challenge_reply_msg = f'!{ptmp_constants.PTMP_MESSAGE_TYPE_AUTHENTICATION_RESPONSE}!{AUTHENTICATION_REQUEST_ID}!{hashed_pwd.upper()}!{ptmp_constants.PTMP_TYPE_VALUE_VOID}!'
    challenge_reply_msg_length = len(challenge_reply_msg) - 1
    challenge_reply_pdu = f'{challenge_reply_msg_length}{challenge_reply_msg}'.replace('!','\x00').encode()
    logger.debug(challenge_reply_pdu.decode())

    logger.debug('Sending challenge reply')
    challenge_reply = pdu_sender.send(challenge_reply_pdu)
    reply = challenge_reply.decode().split('\x00')
    logger.debug(f'Received {reply=}')

    # assert int(reply[1]) == ptmp_constants.PTMP_MESSAGE_TYPE_AUTHENTICATION_STATUS
    # exapp_authenticated = True if reply[2] == 'true' else False
    # return exapp_authenticated

    return True if reply[ptmp_constants.EXAPP_AUTHENTICATION_STATUS_IDX] == ptmp_constants.PTMP_CONFIRMATION else False


def authenticate_to_pka(active_file):
    """ Authenticate to the PKA file.  Returns True if the password is confirmed, False otherwise. """

    # Get challenge
    challenge = active_file.get_challenge_key_as_base64()
    logger.debug(f'Received {challenge=}')

    # Use the challenge
    decoded_bytes = base64.b64decode(challenge)
    challenge_hex_str = decoded_bytes.hex()
    logger.debug(f'{challenge_hex_str=}')

    # Encode as bytes
    pka_lab_password_as_bytes = binascii.hexlify(PKA_LAB_PASSWORD.encode())
    # logger.debug(f'{pka_lab_password_as_bytes=}')

    # Convert from byte array into str
    pka_lab_password_hex_str = pka_lab_password_as_bytes.decode('ascii')
    logger.debug(f'{pka_lab_password_hex_str=}')

    # Make challenge reply
    challenge_reply = challenge_hex_str + pka_lab_password_hex_str
    challenge_reply_byte_array = bytes.fromhex(challenge_reply)
    md5_hash = hashlib.md5(challenge_reply_byte_array)
    hashtext = md5_hash.hexdigest()

    # PT wants it in upper case
    hashtext = hashtext.upper()
    logger.debug(f'{hashtext=}')

    # Send the encoded challenge reply
    password_confirmation = active_file.confirm_password(hashtext)
    logger.debug(f'Received: {password_confirmation=}')
    logger.debug(LOGGING_SEPARATOR)

    return password_confirmation


# Not currently in use.
# def get_activity_feedback():
#     """ Get the activity feedback from the lab PKA file.  Returns a tuple of the completed and incomplete feedback. """

#     msg = '#' * 100
#     logger.debug(msg)

#     activity_tree_node = TreeNodeImpl()

#     node_id = activity_tree_node.getNodeId()
#     logger.debug(f'{node_id=}')

#     node_name = activity_tree_node.getNodeName()
#     logger.debug(f'{node_name=}')

#     node_value = activity_tree_node.getNodeValue()
#     logger.debug(f'{node_value =}')

#     leaf_count = activity_tree_node.getCheckLeafCount()
#     logger.debug(f'{leaf_count=}')

#     parent_node = activity_tree_node.getParentNode()
#     logger.debug(f'{parent_node=}')

#     child_count = activity_tree_node.getChildCount()
#     logger.debug(f'{child_count=}')

#     check_type = activity_tree_node.getCheckType()
#     logger.debug(f'{check_type=}')

#     logger.debug(LOGGING_SEPARATOR)

#     for child in range(child_count):
#         child_node = activity_tree_node.getChildNodeAt(child)
#         logger.debug(f'{child=} {child_node=}')

#     logger.debug(LOGGING_SEPARATOR)
#     logger.debug(msg)

#     return None


def get_authentication_status(active_file):
    """ Get the current authentication status of the lab PKA file.  Returns True if the password is confirmed, False otherwise. """

    # Is the lab password confirmed? 
    password_confirmed = active_file.is_password_confirmed()
    logger.debug(f'Received: {password_confirmed=}')
    logger.debug(LOGGING_SEPARATOR)

    return password_confirmed


def get_personal_details():
    """ Get the student full name and email address from the lab PKA file.  Returns a tuple of the full name and email address. """

    # Build a UserProfile to get the student details from the lab PKA file
    up = py_ptmp.UserProfile()

    # Get student full name
    full_name = up.get_name().strip()
    logger.debug(f'{full_name=}')
    logger.debug(LOGGING_SEPARATOR)

    # Get student email address
    email_addr = up.get_email().strip()
    logger.debug(f'{email_addr=}')
    logger.debug(LOGGING_SEPARATOR)

    return full_name, email_addr


def get_lab_score(active_file):
    """ Get the lab (percentage complete score) score. """
    
    percentage_complete_score = active_file.get_percentage_complete_score()
    logger.debug(f'{percentage_complete_score=}')
    logger.debug(LOGGING_SEPARATOR)
    return percentage_complete_score


def run_connectivity_test(active_file): 
    """ Run the connectivity tests on the active file.  Returns the reply from the test. """

    connectivity_test_reply = active_file.run_connectivity_tests()
    logger.debug(f'{connectivity_test_reply=}')
    logger.debug(LOGGING_SEPARATOR)
    return connectivity_test_reply


def get_lab_score_metrics(active_file):
    """Get lab metrics from the active file.  Returns a tuple of the metrics."""
    
    percentage_complete = active_file.get_percentage_complete()
    logger.debug(f'{percentage_complete=}')
    logger.debug(LOGGING_SEPARATOR)

    # Get student lab score
    # percentage_complete_score = active_file.get_percentage_complete_score()
    # logger.debug(f'{percentage_complete_score=}')
    # logger.debug(LOGGING_SEPARATOR)

    assessment_items_count = active_file.get_assessment_items_count()
    logger.debug(f'{assessment_items_count=}')
    logger.debug(LOGGING_SEPARATOR)

    correct_assessment_items_count = active_file.get_correct_assessment_items_count()
    logger.debug(f'{correct_assessment_items_count=}')
    logger.debug(LOGGING_SEPARATOR)
    
    assessment_score_count = active_file.get_assessment_score_count()
    logger.debug(f'{assessment_score_count=}')
    logger.debug(LOGGING_SEPARATOR)

    correct_assessment_score_count = active_file.get_correct_assessment_score_count()
    logger.debug(f'{correct_assessment_score_count=}')
    logger.debug(LOGGING_SEPARATOR)

    connectivity_count = active_file.get_connectivity_count()
    logger.debug(f'{connectivity_count=}')
    logger.debug(LOGGING_SEPARATOR)

    last_connectivity_test_correct_count = active_file.get_last_connectivity_test_correct_count()
    logger.debug(f'{last_connectivity_test_correct_count=}')
    logger.debug(LOGGING_SEPARATOR)

    return (percentage_complete, assessment_items_count, correct_assessment_items_count, assessment_score_count, correct_assessment_score_count, connectivity_count, last_connectivity_test_correct_count)


def advance_simulation_timer():
    """ Advance the simulation timer by 30 PT seconds. """

    sim = py_ptmp.Simulation()
    real_time_toolbar = py_ptmp.GetRealtimeToolbar()

    sim_time = sim.get_current_sim_time()
    logger.debug(f'{sim_time=}') 
    real_time_toolbar.fast_forward_time()

    return None


def get_lab_activity(active_file):
    """ Get and return the lab activity score. """
    
    # Advance the time in the specified number of 30sec increments and ask for the runConnectivityTests to be run on each iteration.
    # Exploring if requesting runConnectivityTests on each iteration is essential for the lab score to be updated to the correct final score
    # or just advance the time and then run runConnectivityTests once at the end of the iterations.
        
    forward_sim_time_counter = 1
    lab_score = 0

    while (forward_sim_time_counter < SIM_TIME_ADVANCEMENT) and (lab_score != pt_constants.MAX_LAB_SCORE):

        lab_score = get_lab_score(active_file)
        logger.debug(f'{lab_score=}')
        logger.debug(LOGGING_SEPARATOR)
        logger.debug(f'Current lab score is {lab_score} in {forward_sim_time_counter} of {SIM_TIME_ADVANCEMENT} iterations.') 
        
        if lab_score == pt_constants.MAX_LAB_SCORE:
            logger.debug(f'Got maximum lab score in {forward_sim_time_counter} iteration(s).') 
        else:
            # Possibly not the highest score available so lets advance the simulation timer and run a connectivity test.
            advance_simulation_timer()
            
            connectivity_test_reply = run_connectivity_test(active_file)
            logger.debug(f'{connectivity_test_reply= }') 
        
        forward_sim_time_counter += 1
        
    logger.debug(LOGGING_SEPARATOR)

    # ToDo. Get more details about the lab scores.
    # Needs to be conditional and assigned to a tuple.
    # get_lab_score_metrics(active_file)

    return lab_score


def process_pka_file(pka_filename, data_store_id):
    """ Authenticate to PT and PKA file, get student details, lab score and lab ID.
    Returns a tuple of the student details, lab score and lab ID."""

    pka_processed_status = False
    pdu_sender = py_ptmp.PDUSender(PT_HOST, PT_PORT)
    pdu_sender.connect()

    if pdu_sender.is_connected():

        # Get blocking status just for info, not strictly needed
        blocking_status = pdu_sender.getblocking()
        logger.debug(f'Received {blocking_status=}')
        logger.debug(LOGGING_SEPARATOR)

        # Negotiate the connection to PT
        connection_negotiated = negotiate_connection(pdu_sender)
        logger.debug(f'{connection_negotiated=}')
        logger.debug(LOGGING_SEPARATOR)

        if connection_negotiated:

            exapp_authenticated = authenticate_as_exaxpp(pdu_sender)
            logger.debug(f'{exapp_authenticated=}')
            logger.debug(LOGGING_SEPARATOR)

            if exapp_authenticated:

                # pt_ipc = PacketTracerIPC()
                py_ptmp.PacketTracerIPC.pdu_sender = pdu_sender
                
                app_window = py_ptmp.AppWindow()
                
                # Open the PKA file
                file_open_status = open_pka_file(pka_filename, app_window)

                # file_open method returns 0 for success, 6 (UNABLE_TO_READ_FILE) for bad.pka
                if file_open_status == ptmp_constants.FILE_OPEN_OK:
                    # PKA file has been opened
                    af = py_ptmp.ActiveFile()
                    
                    # Just for testing.  Is the lab password confirmed?  It shouldn't be at this point.
                    password_confirmed_status = get_authentication_status(af)
                    logger.debug(f'{password_confirmed_status=}')

                    # Authenticate using the PKA password
                    pka_authentication_status = authenticate_to_pka(af)
                    logger.debug(f'{pka_authentication_status=}')
                    logger.debug(LOGGING_SEPARATOR)

                    if pka_authentication_status:
                        # PKA lab password is confirmed

                        if data_store_id:
                            # Get LabID from Datastore to ensure we are marking the correct PKA
                            lab_id = af.get_script_data_store(data_store_id)
                            logger.debug(f'{lab_id=}')
                            logger.debug(LOGGING_SEPARATOR)
                        else:
                            logger.debug('Lab ID not required.')

                        lab_score = get_lab_activity(af)

                        # Work in progress.  Not currently used.
                        # get_activity_feedback()

                        full_name, email_addr = get_personal_details()

                        # ToDo status is not used.
                        status = close_pka_file(app_window)

                        if data_store_id:
                            logger.info(f'Result: {full_name}, {email_addr}, {lab_score}, {round(float(lab_score),SCORE_ROUNDING_DP)}, {lab_id}')
                        else:   
                            logger.info(f'Result: {full_name}, {email_addr}, {lab_score}, {round(float(lab_score),SCORE_ROUNDING_DP)}')

                        pka_processed_status = True

                    else:
                        # PKA lab password was not confirmed
                        error_msg = 'Error authenticating with PKA lab password.'

                else:
                    # Can't open PKA file.                    
                    error_msg = f'Error opening {pka_filename}. Received file_open_status={file_open_status}, expected=0 (FILE_OPEN_OK)'

            else:
                # ExApp failed to authenticate
                error_msg = 'ExApp failed to authenticate.'

        else:
            # Could not negotiate the connection
            error_msg = f'Error negotiating the connection. negotiate_connection returned {connection_negotiated}'

        # Close the socket
        pdu_sender.disconnect()

    else:
        error_msg = f'Cannot connect to Packet Tracer on host:{pdu_sender.host} port:{pdu_sender.port}\nError message: {pdu_sender.connection_msg}.'

    if pka_processed_status:
        if data_store_id:
            LabDetails = namedtuple('LabResult', ['full_name', 'email_addr', 'lab_score', 'lab_id'])
            lab_details = LabDetails(full_name, email_addr, lab_score, lab_id)
        else:
            LabDetails = namedtuple('LabResult', ['full_name', 'email_addr', 'lab_score'])
            lab_details = LabDetails(full_name, email_addr, lab_score)  
        return True, lab_details
    else:
        return False, error_msg


def get_pka_files(pka_files_dir):
    """ Get the PKA files from the pka_files_dir.  Returns a list of PKA files. """

    pka_files = glob.glob(rf'{pka_files_dir}\*.{pt_constants.PKA_FILETYPE}')
    file_count = len(pka_files)
    file_msg = 'file' if file_count == 1 else 'files'
    logger.info(f'Found {file_count} PKA {file_msg} in {pka_files_dir}')

    return pka_files


def setup_logging(verbose, log_file):
    """ Set up logging to console and file. """

    logger.handlers.clear()  

    level = logging.DEBUG if verbose else logging.ERROR
    logger.setLevel(level)

    formatter = logging.Formatter('%(levelname)s - %(message)s')
    
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    if verbose:
        file_handler = logging.FileHandler(filename=f'{log_file}', mode='w')
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return None


def get_results(pka_files, data_store_id, score_rounding_dp):
    """ Generate the results for the PKA files.  Yields each row to be output. """

    for pka_file in pka_files:
        logger.debug(f'Processing {pka_file}')
        
        score_obtained, info = process_pka_file(pka_file, data_store_id)
        if score_obtained:
            row = [info.full_name, info.email_addr, info.lab_score, f'{round(float(info.lab_score), score_rounding_dp):.{score_rounding_dp}f}']

            if data_store_id:
                row.append(info.lab_id)

            row.append(pka_file)  
            
            yield row
        else:
            logger.error(info)
            logger.error('Result not output due to error encountered.')
    
    return None


def output_results(pka_files, data_store_id, results_csv_file, no_console, score_rounding_dp, guest_filename):
    """ Output the results to a CSV file or console. """	

    headers = ['student_full_name', 'student_email_addr', 'lab_score', 'rounded_lab_score']
    
    if data_store_id:
        headers.append('lab_id')

    # Display the appropriate headers on the console
    if not no_console:
        print(','.join(headers))
    
    # If output to a CSV is required, write the headers to the file
    if results_csv_file:
        logger.debug(f'Writing results to {results_csv_file}') 
        csv_file = open(results_csv_file, mode='w', newline='') 
        csv_writer = csv.writer(csv_file, delimiter=',')
        csv_writer.writerow(headers)

    if guest_filename:
        guest_file = open(guest_filename, mode='w', newline='') 

    # Get the result generator and output the results as required
    for result in get_results(pka_files, data_store_id, score_rounding_dp):

        guest_found = result[NAME_IDX] == GUEST_NAME 
        
        # Direct the results to the appropriate output
        if guest_found and guest_filename:
            guest_pka_filename = Path(result[-1]).name
            guest_file.write(f'{guest_pka_filename}\n')
        elif not guest_found and results_csv_file or guest_found and not guest_filename:
            csv_writer.writerow(result[:-1])
        
        if not no_console:
            print(','.join(str(item) for item in result[:-1]))
    
    if results_csv_file:
        csv_file.close()
    
    if guest_filename:
        guest_file.close()

    return None


def parse_args():
    """Parse command line arguments."""

    parser = argparse.ArgumentParser(
        description=f'Super Duper Automagic PKA marker.\nDave Bracken.\nVersion: {VERSION}\n',
        allow_abbrev=False,
        formatter_class=WideRawHelpFormatter,
        argument_default=argparse.SUPPRESS 
    )

    results_group = parser.add_mutually_exclusive_group(required=False)
    lab_id_group = parser.add_mutually_exclusive_group(required=False)
    pka_group = parser.add_mutually_exclusive_group(required=False)
    guest_group = parser.add_mutually_exclusive_group(required=False)

    lab_id_group.add_argument('--data-store-id', type=str, help='Data store ID to use for lab ID.')
    guest_group.add_argument('--guest-file', type=str, help='Guest filename.')
    parser.add_argument('--log-file', type=str, help='Path to the debug log file.  This enables the verbose option.')
    results_group.add_argument('--no-console', action='store_true', help='Disable console output.')
    results_group.add_argument('--no-csv', action='store_true', help='Send results to the console, not CSV.')
    guest_group.add_argument('--no-guest-file', action='store_true', help='Do not use the guest file.  Save Guest scores to results CSV file.')
    lab_id_group.add_argument('--no-lab-id', action='store_true', help='Do not include the Lab ID.')
    pka_group.add_argument('--pka-dir', type=str, help='Path to directory containing PKA files to process.')
    pka_group.add_argument('--pka-file', type=str, help='Path to a single PKA file to process.')
    parser.add_argument('--results-file', type=str, help='Results CSV filename.')
    parser.add_argument('--score-rounding-dp', type=int, help='Number of decimal places to round the lab score.')
    parser.add_argument('--test-connection', action='store_true', help='Test connection to Packet Tracer without marking PKAs.')
    parser.add_argument('--use-default-results-file', action='store_true', help='Use the PKA directory name as the name of the results CSV file.')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging.')
    parser.add_argument('--version', '-V', action='version', version=f'%(prog)s {VERSION}', help='Show program version.')

    return parser.parse_args()


def validate_args(args):
    """ Validate command line arguments and check for mutually exclusive conflict. """

    if hasattr(args, 'pka_file') and not Path(args.pka_file).is_file():
        raise ArgumentValidationError(f'PKA file {args.pka_file} does not exist.')

    if hasattr(args, 'pka_dir') and not Path(args.pka_dir).is_dir():
        raise ArgumentValidationError(f'PKA directory {args.pka_dir} does not exist.')

    if hasattr(args, 'results_file') and not Path(args.results_file).parent.is_dir():
        raise ArgumentValidationError(f'Output directory {Path(args.results_file).parent} does not exist.')
    
    # Check for mutually exclusive arguments that argparse does not support due to mixed types.
    if hasattr(args, 'results_file') and hasattr(args, 'no_csv'):
        raise ArgumentValidationError('Cannot specify both --results-file and --no-csv.')
    
    return None


def check_python_version():
    """ Validate the current Python version. """

    if sys.version_info < (REQD_MAJOR_VER, REQD_MINOR_VER):
        raise PythonVersionError(f'Python {REQD_MAJOR_VER}.{REQD_MINOR_VER} or above is required.')
    return None


def main():
    """Validate args, test connection to PT and if good process the PKA files."""

    check_python_version()

    args = parse_args()

    try:
        validate_args(args)
    except ArgumentValidationError as e:
        print(f'Argument error: {e}')
        sys.exit(1)

    if hasattr(args, 'log_file'):
        log_file = args.log_file
    else:
        log_file = LOG_FILE

    if hasattr(args, 'verbose') or hasattr(args, 'log_file'):
        verbose = True
    else:
        verbose = False

    setup_logging(verbose, log_file)

    # Test connection to Packet Tracer if requested.
    if hasattr(args, 'test_connection'):
        connection_status = test_pt_connection()
        if connection_status:
            print(f'Packet Tracer is available on {PT_HOST}:{PT_PORT}.')
        else:
            print(f'Packet Tracer is not available on {PT_HOST}:{PT_PORT}.')
        sys.exit(0)

    # Set the results CSV file name.
    results_csv_file = None

    if hasattr(args, 'results_file'):
        results_csv_file = args.results_file
    elif hasattr(args, 'no_csv'):
        # No CSV output requested
        results_csv_file = None  
    else:
        # Determine the base directory for the results file
        if hasattr(args, 'pka_file'):
            base_dir = Path(args.pka_file).parent
        elif hasattr(args, 'pka_dir'):
            base_dir = Path(args.pka_dir)
        else:
            base_dir = Path(PKA_BASE_DIR)

        if USE_DEFAULT_RESULTS_FILE or hasattr(args, 'use_default_results_file'):
            # Use the directory name as the CSV filename
            results_csv_file = str(base_dir / f'{base_dir.name}.csv')
        else:
            results_csv_file = str(base_dir / RESULTS_CSV_FILE)

    # Set the PKA files directory.
    if hasattr(args, 'pka_file'):
        pka_files_dir = args.pka_file
    elif hasattr(args, 'pka_dir'):
        pka_files_dir = args.pka_dir
    else:
        pka_files_dir = PKA_BASE_DIR
  
    # Set the data store ID if requested.
    if hasattr(args, 'no_lab_id'):
        data_store_id = None
    elif hasattr(args, 'data_store_id'):
        data_store_id = args.data_store_id 
    elif DATA_STORE_OBJECT_LAB_ID:
        data_store_id = DATA_STORE_OBJECT_LAB_ID
    else:
        data_store_id = None

    # Set the score rounding decimal places.
    if hasattr(args, 'score_rounding_dp'):
        score_rounding_dp = args.score_rounding_dp  
    else:
        score_rounding_dp = SCORE_ROUNDING_DP

    # Generate a path to the guest file if requested.
    if hasattr(args, 'guest_file'):
        preferred_guest_filename = args.guest_file
    else:
        preferred_guest_filename = GUEST_FILENAME

    if hasattr(args, 'no_guest_file') or not USE_GUEST_FILE:
        guest_filename = None
    elif hasattr(args, 'pka_file'):
        guest_filename = str(Path(args.pka_file).parent / preferred_guest_filename)
    elif hasattr(args, 'pka_dir') and not hasattr(args, 'no_csv'):
        guest_filename = str(Path(args.pka_dir) / preferred_guest_filename)
    else:
        guest_filename = str(Path(PKA_BASE_DIR) / preferred_guest_filename)
    logger.debug(f'{guest_filename=}')

    # Suppress console output if requested.
    if hasattr(args,'no_console'):
        no_console = True
    else:
        no_console = False

    connection_status = test_pt_connection()
    if connection_status:
        logger.debug('Packet Tracer is available.')

        # PT needs an absolute path for the PKA file.
        if not Path(pka_files_dir).is_absolute():
            # Convert to absolute path
            pka_files_dir = Path.cwd() / pka_files_dir

        # Get file or files to process.  
        if hasattr(args, 'pka_file'):
            pka_files = [pka_files_dir]
        else:
            pka_files = get_pka_files(pka_files_dir)

        file_count = len(pka_files)

        if file_count > 0:        
            output_results(pka_files, data_store_id, results_csv_file, no_console, score_rounding_dp, guest_filename)
        else: 
            logger.error(f'No PKA files found: {pka_files if hasattr(args,'pka_file') else pka_files_dir}')
    else:
        logger.error(f'Test connection could not sucessfully connect and disconnect from Packet Tracer.')

    return None


if __name__ == '__main__':
    logger = logging.getLogger()
    main()
 
