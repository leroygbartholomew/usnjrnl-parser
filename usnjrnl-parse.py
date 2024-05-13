# DESCRIPTION AND LEGAL INFORMATION
#
# USN JOURNAL PARSER (TEXT AND BINARY)
#
# This the UsnJrnl parser.  This will assign needed
# variables and call functions from the other modules to use in parsing an 
# exported UsnJrnl file into a SQLite database. It will parse a text file
# that has been generated using Windows' built in commands which export
# data in locatl time and will also parse a binary file containing 
# the journal records.  The binary file can be obtained via forensic
# software like FTK Imager or X-Ways Forensics and is best done by data
# carving or exporting then removing the journal entries from the 0x00
# at the beginning.  Sometimes there are gigs and gigs of 0x00 at the 
# beginning of the exported journal where as carving may get you a journal
# that is under 50 mb.  
# 
# USE:  The easiest way to use this is to place the file to be parsed
# in the same folder as this program and run it.  You'll be prompted
# to select various options and specify the input file.  You can import
# multiple files into different tables which will allow correlation 
# between the records.  One example is one journal from a backup and
# another from the current system which may allow one to show movement
# of files from a longer period of time.  Additionally, records can be
# added into the same table from multiple journals.  
#           
#
# Version 1.0
# Date  2024-01-04
# Copyright (C) 2024 - Aaron Dee Roberts
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You can view the GNU General Public License at <http://www.gnu.org/licenses/>
#

import sys
import os
import datetime
from datetime import datetime, timezone
import sqlite3
from sqlite3 import OperationalError
import traceback

# PREASSIGN SOME VARIABLES TO AVOID ERRORS
of_db = ""
of_tsv = ""
of_name = ""
t_name = ''
s_name = ''

#Assign the counter and flags
count = 0
list_lock = 0

# GETS AN INTEGER VALUE FROM A LIST OF BYTE VALUES
def get_bit_total(s_bytes):
# THIS TOTALS BITS FROM BYTES GIVING YOU THE DECODED TOTAL
# IF YOU NEED IT DECODED LITTLE ENDIAN, REVERSE THE BYTES BEFORE
# YOU SEND IT HERE.  THIS WILL TOTAL IT IN THE ORDER IT IS SENT.
# BYTES NEED TO BE SENT IN A LIST.

	try:
		# TOTAL THE NUMBER OF BITS FROM BYTES SUBMITTED
		i_bits = 0
		for x in s_bytes:
			i_bits +=8 # TOTAL FOR BITS FROM BYTES
		
		# DEFINE VALUE FOR EACH BIT
		d_values = {}
		c_bit = 1 # COUNTER
		v_bit = 1 # VARIABLE
		
		# GENERATE THE VALUES FOR EACH BIT
		while c_bit < i_bits + 1:
			
			t_bit = {c_bit:v_bit}
			d_values.update(t_bit)
			c_bit +=1
			v_bit = v_bit * 2
		

		# CONVERT THE BYTES INTO INDEXED BIT SETS
		bit_dic = {}
		c_bit = 1
		
		for x in s_bytes:
			bits = bin(int(x,16))[2:].zfill(8)
			t_bit = {c_bit:bits}
			bit_dic.update(t_bit)
			c_bit +=1

		
		# MAKE A LIST OF THE BITS WITH EACH BIT A SEPARATE ITEM
		l_bits = []

		for x in bit_dic.values():
			for y in x:
				l_bits.append(y)

		# REVERSE THE BITS TO LINE UP WITH THE VALUES
		l_bits.reverse() 
		
		# REFERENCE EACH BIT POSITION WITH THE CORRESPONDING KEY AND ADD THE VALUES
		c_bit = 1
		i_total = 0
		
		for x in l_bits:
			if x == '1': 
				i = d_values[c_bit]
				i_total = i_total + int(i)
			c_bit +=1
		
		# RETURN THE TOTAL
		
		x = None
		x = []
		for y in l_bits:
			x.append(y)
		
		x.reverse()
		
		z = None
		z = ''.join(x) # CONVERT TO A STRING
		
		x.reverse()
		
		y = None
		y = ''.join(x)
		
		return i_total, i_bits, 'good'
	
	except:
		print('ERROR...Make sure you have valid bytes and include the direction.\nAdd the "help" argument for help')
		print()
		return 0,0,'error'

# FOR MAKING BYTE ARRAY STRING OUT OF HEX STRING IF NEEDED.
def hex_format(hex_string): 
    sep_count = 0
    sh_str = ""
    sep_dic = []
    while sep_count < len(separator):
        sep_dic.append(hex_string[sep_count:sep_count + 2])  # Separate the separator bytes into a dictionary
        sep_count += 2  # to allow for additions needed for byte array

    for sep_loop in sep_dic:
        sh_str = sh_str + '\\x' + sep_loop
        # print(sh_str)
    return sh_str

# FOR GETTING THE LENGTH VALUE OF ON BYTE
def pb_string_len_decode(hexoffset):
    hexoffset_u = hexoffset.hex()
    hexoffset_u = bytearray.fromhex(hexoffset_u).hex() # HEX VALUE OF STRING SIZE
    hexoffset_val = int(hexoffset_u, 16) # INTEGER VALUE OF STRING SIZE
    return hexoffset_val

# FOR DECODING BASE 16 HEX TO DECIMAL
def hex_to_decimal(hexdata):
    h = hexdata.hex()
    d = int(h, base = 16)
    return d

# TO DISPLAY THE BASIC INSTRUCTIONS
def basic_instructions():
	title_1 = """
========================================================================
======== DESCRIPTION: USNJRNL TO SQLITE PARSER =========================
========================================================================
This program will parse a file generated from reading the UsnJrnl to a 
text file and parse it to a SQLite database for analysis.  You will need 
to specify a file to parse and the name of the table you want to create 
with the data.  For ease of finding the files it's best if you place the 
files to parse in the same folder as this script. 

From the main menu, you'll want to start by specifying a table name to 
parse the data into. Afterward, items will appear in order on the menu.

You can parse multiple files into the same or different tables this way.
Most of the time you'll want to parse separate files into separate 
tables.  However, it may be benificial to parse journals from the same
volumes but different times of the forensic image to be able to analyze
data over a longer time period.  


"""
	print(title_1)
	title_1 = ''
	input('Press [ENTER] to continue...')
	
# TO SET THE NAME OF THE OUTPUT AND/OR WORKING DATABASE
def set_database():
	title_1 = """
========================================================================
========= SPECIFY THE WORKING DATABASE FILE ============================
========================================================================
Provide the name of the SQLite databse file (without the extension)
you want to records to be imported into. Do NOT use SPACES!
Pressing ENTER will default to the file 'UsnJrnl_Output' in the same
folder as this script was run from.

"""
	print(title_1)
	# SET THE NAME OF THE OUTPUT SQLITE DATABASE FILE
	of_name = input('     INPUT WORKING DATABASE NAME : ')
	
	if of_name == "":
		of_db = 'UsnJrnl_Output.db'
		of_tsv = 'UsnJrnl_Output.tsv'
	else: 
		of_db = of_name + '.db'
		of_tsv = of_name + '.tsv'
	
	print()
	print(f'Working database set to {of_db}')
	print()
	input('Press [ENTER] to continue...')
	
	return of_db, of_tsv

# THE MAIN MENU WHERE THE USER SELECTS WHAT TO DO NEXT		
def main_menu(list_lock):
	
	ifn = ""
	ifn_l = ""
	t_name = ""
	t_name_l = ""
	enc = ""
	
	
	while list_lock == 1:
		
		# SET THESE SO THE SHOW ONLY IF VARIABLES HAVE A VALUE
		if ifn != "":
			ifn_l = f'\nPARSE FILE      Parse {ifn} into {t_name}'
		
		if t_name != '':
			t_name_l = f'\nSELECT FILE     Select the file to parse into {t_name}'

		
		s_menu = f"""
========================================================================
=============== WHAT WOULD YOU LIKE TO DO ==============================
========================================================================

EXPORT USN      Show how to export the UsnJrnl via the Windows command.
TABLE NAME      Specify the name of the table to import the data into{t_name_l}{ifn_l}
EXIT		Do nothing and exit this application

"""
		print(s_menu)
		s_input = input("     INPUT: ").lower()
		
		if s_input == "select file" :
			if t_name != '':
				ifn, enc, tzone, tzone_os = select_file()
			else:
				print("you need to have a table name specified first")
		
		if s_input == "table name":
			t_name = table_name()
			
		if s_input == 'parse file' :
			if ifn != "" and t_name != '':
				parse_file(ifn, t_name, enc, tzone, tzone_os)
			else:
				print('You don\'s seem to have a table name and input file specified')

		if s_input == 'exit':
			print('\n     Exiting')
			list_lock = 0
		
		if s_input == 'export usn':
			export_usn()

# TO GET THE NAME OF THE TABLE DATA IS TO BE EXPORTED TO	
def table_name():
	
	title_1 = """
========================================================================
============ PROVIDE THE TABLE NAME ====================================
========================================================================

Provide the name of the table the data will be put into.  If you want to
make sure your queries work correctly, there are a few rules to follow.

   DO NOT (NOT NOT NOT) start the name with a number.  If you NEED to 
       use a number, start with a letter.  IE: T123_MYTABLE

   DO NOT use dashes "-" in your names.  Underscords "_" are fine. 
 
   DO NOT use SPACES.

If NO name is specified, 'UsnJrnl' will be used  

"""
	print(title_1)
	print()
	t_name = input('    INPUT TABLE NAME: ')
	
	if t_name =='':
		t_name = 'UsnJrnl'
	
	
	print()
	print(f'Table name set to {t_name}')
	print()
	input('Press [ENTER] to continue...')

	return t_name

# TO SELECT THE INPUT FILE, BINARY OR TEXT, AND TIME OFFSET
def select_file():

	title_1 = """
========================================================================
================== FILE TO PARSE RECORDS FROM ==========================
========================================================================

Provide the location you wish to parse data from.  This would be the
file containing your exported journal data in text format.  

    Ex: C:\\Documents\\UsnJournal_export.txt
    
"""
	print(title_1)
	print()
	list_lock = 1
	if_check = False
	enc = ''
	
	while list_lock == 1:
		
		ifn = input('    SPECIFY YOUR INPUT FILE: ')
		
		if_check = os.path.exists(ifn)
		
		
		if if_check == False:
			if ifn == '':
				print()
				print('Please specify a valid file to continue or \"N\" for NONE')
				print()	
			
			if ifn != '':		
				if ifn == 'N' or ifn == 'n':
					ifn = ''
					list_lock = 0
					break
				else:
					print()
					print(f'{ifn} does not appear to exist.  Please input a valid file')
					print()
		
		if if_check == True:
			print()
			print(f'{ifn} has been selected to parse')
			print()
			list_lock = 0
		
	list_lock = 1
	
	while list_lock ==1:
		
		print(f'Is {ifn} to be processed as a text or binary file?\n')
		print('    B = Binary, T = Text\n')
		response = input('    INPUT: ').lower()
		
		if response == 'b' or response == 't':
			enc = response
			
			if response == 'b':
				e = 'binary file '
				# GET THE TIMEZONE INFORMATION
				# tzone, tzone_os = get_timezone_offset()
				# Binary Timezones all appear to be in LT, therefore skipping this part now.  
				tzone = 'LT'
				tzone_os = 0
			
			if response == 't':
				e = 'text file '
				tzone = 'LT'
				tzone_os = 0

			list_lock = 0
		else:
			print('\nPlease select B or T\n')
		
		print()
		print(f'File {ifn} will be processed as a {e}')
		print(f'using the timezone {tzone}.  If this is not')
		print('correct, use the SELECT FILE again.')
		print()
		
		input('Press [ENTER] to continue...')
		print()
	
	return ifn, enc, tzone, tzone_os

# INSTRUCTIONS ON EXPORTING THE USN JOURNAL VIA WINDOWS COMMAND
def export_usn():
	title_1 = """
========================================================================

EXPORTING THE JOURNAL (VIA WINDOWS ADMIN COMMAND WINDOW):

	chcp 65001 (allows UNICODE in the terminal)

	fsutil usn readjournal [drive] > [output]
	
	EX:
		chcp 65001
		fsutil usn readjournal c: > d:\\UsnJrnl_Journal

"""
	print(title_1)
	input('Press [ENTER] to continue...')

# FOR THE CREATION OF THE OUTPUT TABLE
def create_table (t_name, sql_con, sql_cur):

	# CREATE THE PROPER TABLE
	
	sqlite_mt = (f"""CREATE TABLE IF NOT EXISTS {t_name} (
	PK INTEGER PRIMARY KEY,
	TABLE_NAME VARCHAR,
	USN INTEGER,
	FILE_NAME VARCHAR,
	FILE_NAME_LENGTH VARCHAR,
	REASON VARCHAR,
	TIMESTAMP_D INTEGER,
	TIMESTAMP VARCHAR,
	FILE_ATTRIBUTES VARCHAR,
	FILE_ID VARCHAR,
	FILE_ID_SEQ_H VARCHAR,
	FILE_ID_SEQ_D INTEGER,
	FILE_ID_MFT_H VARCHAR,
	FILE_ID_MFT_D INTEGER,
	PARENT_FILE_ID VARCHAR,
	PARENT_FILE_ID_SEQ_H VARCHAR,
	PARENT_FILE_ID_SEQ_D INTEGER,
	PARENT_FILE_ID_MFT_H VARCHAR,
	PARENT_FILE_ID_MFT_D INTEGER,
	SOURCE_INFO VARCHAR,
	SECURITY_ID INTEGER,
	MAJOR_VERSION INTEGER,
	MINOR_VERSION INTEGER,
	RECORD_LENGTH INTEGER
	);""")
	
	# EXECUTE THE QUERY
	sql_cur.execute(sqlite_mt)
	
	#DON'T FORGET TO COMMIT!
	sql_con.commit() 

# DECODING THE CHANGE REASON WHEN PARSING BINARY FILES
def change_reason(hex_data, source):
# PASS 'change_reason' OR 'attributes'


	# ASSEMBLE THE DICTIONARIES OF DEFINITIONS
	
	if source == "change_reason":
		reason_dic = {
		'1_00':'',
		'1_01':'Desired Storage Class change', 
		'2_01':'UNKNOWN DATA',
		'2_02':'UNKNOWN DATA',
		'2_04':'UNKNOWN DATA',
		'2_08':'UNKNOWN DATA',
		'2_10':'UNKNOWN DATA',
		'2_20':'UNKNOWN DATA',
		'2_40':'UNKNOWN DATA',
		'1_80':'File, Directory Closed',
		'2_00':'',
		'2_01':'Hard Link Created Deleted',
		'2_02':'Changed Compression Status',
		'2_04':'Changed Encryption Status',
		'2_08':'Object ID Changed',
		'2_10':'Reparse Point Value Changed',
		'2_20':'Named Attribute Created, Deleted, Changed, AKA: Stream Changed',
		'2_40':'UNKNOWN DATA',
		'2_80':'UNKNOWN DATA',
		'3_00':'',
		'3_01':'File Created',
		'3_02':'File Deleted',
		'3_04':'Extended Attributes Changed',
		'3_08':'Security Changed',
		'3_10':'Rename: old name',
		'3_20':'Rename: new name',
		'3_40':'Content Indexed Status Changed',
		'3_80':'Basic Attributes/Information Changed',
		'4_00':'',
		'4_01':'Data Overwritten',
		'4_02':'Data Extend',
		'4_04':'Data Truncuated',
		'4_08':'UNKNOWN DATA',
		'4_10':'Named Data Overwritten',
		'4_20':'Named Data Extended',
		'4_40':'Named Data Truncuated',
		'4_80':'UNKNOWN DATA'
		}	
	
	if source == 'attributes':
		reason_dic = {
		'1_00':'',
		'1_01':'UNKNOWN DATA',
		'1_02':'UNKNOWN DATA',
		'1_04':'UNKNOWN DATA',
		'1_08':'UNKNOWN DATA',
		'1_10':'UNKNOWN DATA',
		'1_20':'UNKNOWN DATA',
		'1_40':'UNKNOWN DATA',
		'1_80':'UNKNOWN DATA',
		'2_00':'',
		'2_01':'Virtual',
		'2_02':'No scrub data',
		'2_04':'UNKNOWN DATA',
		'2_08':'UNKNOWN DATA',
		'2_10':'UNKNOWN DATA',
		'2_20':'UNKNOWN DATA',
		'2_40':'UNKNOWN DATA',
		'2_80':'UNKNOWN DATA',
		'3_00':'',
		'3_01':'Temporary',
		'3_02':'Sparse file',
		'3_04':'Reparse point',
		'3_08':'Compressed',
		'3_10':'Offline',
		'3_20':'Not content indexed',
		'3_40':'Encrypted',
		'3_80':'Integrity stream',
		'4_00':'',
		'4_01':'Readonly',
		'4_02':'Hidden',
		'4_04':'System',
		'4_10':'Directory',
		'4_20':'Archive',
		'4_40':'Device',
		'4_80':'Normal'
		}	
	
	if source == 'sourceinfo':
		reason_dic = {
		'1_00':'',
		'2_00':'',
		'3_00':'',
		'4_00':'',
		'4_01':'Data management',
		'4_02':'Auxiliary data',
		'4_04':'Replication management'
		}
	

	i_bits = 8 # SET THE BITS AT 32 WITH HIGHST VALUE OF 128
	
	# DEFINE VALUE FOR EACH BIT
	d_values = {}
	c_bit = 1 # COUNTER
	v_bit = 1 # VARIABLE
	
	# GENERATE THE VALUES FOR EACH BIT
	while c_bit < i_bits + 1:
		
		t_bit = {c_bit:str(hex(v_bit)[2:]).zfill(2)}
		d_values.update(t_bit)
		c_bit +=1
		v_bit = v_bit * 2
	
	#print(f'd_values: {d_values}') # HAVE THE VALUES THROUGH 128
	# CONVERT THE BYTES INTO INDEXED BIT SETS
	bit_dic = {}
	bit_list = []
	c_bit = 1
	
	for x in hex_data:
		bits = bin(int(x,16))[2:].zfill(8)
		
		for y in bits:
			bit_list.append(int(y)) # ADDING EACH BIT TO A LIST OF 8 BITS

		bit_list.reverse() # Reverse to align bits with generated values list

		y = None
		z = {c_bit:bit_list} # Add the items to a temp dic
		
		bit_dic.update(z) # Add the new key and list to the dictionary
		z = None
		c_bit +=1
		bit_list = [] # Set the list back to empty to use it for the next one in the loop
	
	# COMPARE THE TRUE BITS AND CORRELATE THEM WITH THE VALUES FROM THE d_values THAT HOLD THE VALUE OF EACH BIT
	c_bit = 1
	c_index = 0
	dic_values_4t = {} # Dictionary for holding the values lists to be compared with the definitions dic
	tlv = [] # Temp list values for makding the list and adding it to the dictionary
	
	for x in bit_dic.keys(): # Parse each set of 8 bits
		#print(f'x: {x}')
		for y in bit_dic[c_bit]:
			
			#print(f'y: {y}') # TESTING
			c_index +=1
			z = d_values[c_index]
			
			#print(f'TYPE: {type(y)}')
			if y == 1:
				tlv.append(z) # Add all the bits with values in hex
				
			dic_values_4t[c_bit] = tlv # Add the list to the dictionary with the c_bit as the key
			
			#print(f'z: {z}') # TESTING
		tlv = [] # Clear the temp list
		
		c_bit +=1
		c_index = 0
	
	c_bit = 0
	c_index = 0
		
	# CORRELATE dic_values_4t TO THE DEFINITIONS LIST AND BUILD THE PROPER STRING
	# TOTAL EACH LIST TO A HEX TOTAL THEN COMBINE TO A HEX STRING
	
	x = None
	y = None
	c_index
	str_list = [] # Descriptions
	hex_totals = {}
	
	
	for x in sorted(dic_values_4t.keys(), reverse=True):
		i_total = 0
		h_total = ''
		key_temp = str(x) + "_"
		 
		for y in dic_values_4t[x]:
			val_temp = key_temp + y
			dic_val_temp = reason_dic[val_temp]
			str_list.append(dic_val_temp)
			i_val = int(y, 16)
			i_total +=i_val
			h_total = hex(i_total)[2:].zfill(2).upper()

		hex_totals[x] = h_total
		s_total = str(i_total)
		
	y = None
	x = None
	c_index = 0
	hl = [] #LIST FOR HOLDING HEX STRING PARTS
	
	# FILL THE BLANK STRINGS WITH 00 SINCE THEY DIDN'T FILL PRIOR.
	# AND ASSEMBLE THE STRING FOR THE HEX
	for x in sorted(hex_totals.keys()):
		if hex_totals[x] == '':
			hex_totals[x] = '00'
		y = hex_totals.get(x)
		hl.append(y)
		
	x = None
	y = None

	reason_list = ' | '.join(str_list)
	reason_hex = '0x' + ''.join(hl)
	
	# FINALLY PUT IT ALL TOGETHER
	s_reason = (f'{reason_hex}: {reason_list}')
	
	
	# HERE FOR DECONSTRUCTION OF DATA THAT WAS USED FOR MAPPING
	# ==================================================================
	# 80 20 e3 20  Named data extend | File create | File delete | 
	# Rename: new name | Indexable change | Basic info change | Stream change | Close
	#
	# 00000020 -Named data extend 
	# 00000100 -File create
	# 00000200 -File delete
	# 00002000 -Rename: new name 
	# 00004000 -Indexable change
	# 00008000 -Basic info change
	# 00200000 -Stream change
	# 80000000 -Close
	
	# 00 00 00 20 -Named data extend 
	# 00 00 01 00 -File create
	# 00 00 02 00 -File delete
	# 00 00 20 00 -Rename: new name 
	# 00 00 40 00 -Indexable change
	# 00 00 80 00 -Basic info change
	# 00 20 00 00 -Stream change
	# 80 00 00 00 -Close
	
	# 80 20 E3 20
	
	# x80:128, x64:40, x32:20, x16:10, x8:8, x4:4, x2:2, x1:1
	
	return s_reason
	
# WORK HORSE TO PARSE EVERYTHING
def parse_file(ifn, t_name, enc, tzone, tzone_os = 0):
	
	if enc == 't':
		e = 'text file '
	elif enc == 'b':
		e = 'binary file '
	
	if tzone_os != 0:
		tz = f' using time zone offset {tzone}'
	
	else:
		tz = ''
	
	title_1 = f"""
========================================================================
============== READY TO PARSE DATA INTO WORKING DATABASE ===============
========================================================================

Proceeding will parse data from {e}{ifn} into the table {t_name} within
the working database {of_db}{tz}.  

If this is what you planned, 
press [ENTER] to proceed.  If not, enter "NO" to aport and go back to
the previous menu.

Press [ENTER] to proceed
Input "no" to abort.

"""
	print(title_1)

	resp = input('    INPUT: ').lower()
	
	if resp == 'no':
		print('Aborting...')
		return
	
	print(f'\nParsing {ifn}.  Please be patient\n')
	

	l_count = 0
	
	# logfile = open('log.txt','wa')

	# OPEN THE DATABASE CONNECTION BEFORE THE FUNCTION TO CREATE THE TABLE
	sql_con = sqlite3.connect(of_db)
	sql_con.row_factory = sqlite3.Row
	sql_cur = sql_con.cursor()
	

	# CALL THE FUNCTION TO CREATE THE TABLE
	create_table(t_name, sql_con, sql_cur)

	
	# PARSE DATA FOR THE EXPORTED TEXT FILE
	if enc == 't':

		## FORMAT OF JOURNAL ENTRY
		# Usn               : 57300484096
		# File name         : FILE_NAME
		# File name length  : 32
		# Reason            : 0x80000200: File delete | Close
		# Time stamp        : 2023-10-29 15:22:04
		# File attributes   : 0x00002020: Archive | Not content indexed
		# File ID           : 000000000000000000ba0000000d6b83
		# Parent file ID    : 000000000000000000ba0000000d6b75
		# Source info       : 0x00000000: *NONE*
		# Security ID       : 0
		# Major version     : 3
		# Minor version     : 0
		# Record length     : 112
		
		# OPENING THE FILE FOR READING AS TEXT
		s_file = open(ifn,'r', encoding='utf-8')
		line = ""
		
		# PRE-DEFINE VARIABLES TO PREVENT ERRORS FOR UNDEFINED VARIABLES IF THEY HAPPEN
		i_usn = 0
		s_filename = ""
		i_filenamelength = 0
		s_reason = ""
		s_timestamp = ''
		s_fileattributes = ''
		s_fileid = ''
		s_fileid_seq = ''
		i_fileid_seq = ''
		s_fileid_mft = ''
		i_fileid_mft = ''
		s_parentfileid = '' 
		s_parentfileid_seq = ''
		i_parentfileid_seq = ''
		s_parentfileid_mft = ''
		i_parentfileid_mft = ''
		s_sourceinfo = ''
		i_securityid = 0
		i_major_version = 0
		i_minor_version = 0
		i_record_length = 0
	
		while True:
			line = s_file.readline()
			if not line: # If the item read is NOT a new line then stop.
				break

			result = line.find('Usn               :')
			line_len = 0
			str_len = 0

			if result != -1: # Result will be position in LINE, 0 is beginning
				l_count +=1
				
				if line[0:19] == 'Usn               :':
					i_usn = int(line[20:])
					
				v_count = 0
				
				while v_count < 12: # Need to loop through to get the next line each time
					
					line = s_file.readline() # Going to the next line and read it
					
					# ASSIGN THE VARIABLES
					if line[0:19] == 'File name         :': 
						s_filename = line[20:].rstrip()
					
					if line[0:19] == 'File name length  :':
						i_filenamelength = int(line[20:].rstrip())
					
					if line[0:19] == 'Reason            :':
						s_reason = line[20:].rstrip()
						
					if line[0:19] == 'Time stamp        :':
						s_timestamp = line[20:].rstrip() + ' LT'
					
					if line[0:19] == 'File attributes   :':
						s_fileattributes = line[20:].rstrip()
					
					if line[0:19] == 'File ID           :':
						s_fileid = line[20:].rstrip()
						s_fileid_seq = s_fileid[0:20]
						s_fileid_mft = s_fileid[20:]
						i_fileid_seq = int(s_fileid_seq, 16)
						i_fileid_mft = int(s_fileid_mft, 16)
					
					if line[0:19] == 'Parent file ID    :':
						s_parentfileid = line[20:].rstrip()
						s_parentfileid_seq = s_parentfileid[0:20]
						s_parentfileid_mft = s_parentfileid[20:]
						i_parentfileid_seq = int(s_parentfileid_seq, 16)
						i_parentfileid_mft = int(s_parentfileid_mft, 16)
					
					if line[0:19] == 'Source info       :':
						s_sourceinfo = line[20:].rstrip()
					
					if line[0:19] == 'Security ID       :':
						i_securityid = int(line[20:].rstrip())
					
					if line[0:19] == 'Major version     :':
						i_major_version = int(line[20:].rstrip())
					
					if line[0:19] == 'Minor version     :':
						i_minor_version = int(line[20:].rstrip())
					
					if line[0:19] == 'Record length     :':
						i_record_length = int(line[20:].rstrip())
					
					v_count += 1
				
				# INSERT THE RECORD INTO THE DATABASE
				sql_insert = f"""
				INSERT INTO {t_name} (TABLE_NAME, USN, FILE_NAME, FILE_NAME_LENGTH,
				REASON, TIMESTAMP, FILE_ATTRIBUTES, FILE_ID, FILE_ID_SEQ_H, FILE_ID_SEQ_D, 
				FILE_ID_MFT_H, FILE_ID_MFT_D, PARENT_FILE_ID, PARENT_FILE_ID_SEQ_H, PARENT_FILE_ID_SEQ_D,
				PARENT_FILE_ID_MFT_H, PARENT_FILE_ID_MFT_D, SOURCE_INFO,
				SECURITY_ID, MAJOR_VERSION, MINOR_VERSION, RECORD_LENGTH) 
				VALUES ("{t_name}","{i_usn}","{s_filename}","{i_filenamelength}","{s_reason}","{s_timestamp}", 
				"{s_fileattributes}","{s_fileid}","{s_fileid_seq}","{i_fileid_seq}","{s_fileid_mft}", 
				"{i_fileid_mft}","{s_parentfileid}","{s_parentfileid_seq}","{i_parentfileid_seq}", 
				"{s_parentfileid_mft}","{i_parentfileid_mft}","{s_sourceinfo}","{i_securityid}",
				"{i_major_version}","{i_minor_version}","{i_record_length}")"""
				
				sql_cur.execute(sql_insert)
	
			# RESET THE VARIABLES
			i_usn = 0
			s_filename = ""
			i_filenamelength = 0
			s_reason = ""
			s_timestamp = ''
			s_fileattributes = ''
			s_fileid = ''
			s_fileid_seq = ''
			i_fileid_seq = ''
			s_fileid_mft = ''
			i_fileid_mft = ''
			s_parentfileid = ''
			s_parentfileid_seq = ''
			i_parentfileid_seq = ''
			s_parentfileid_mft = ''
			i_parentfileid_mft = ''
			s_sourceinfo = ''
			i_securityid = 0
			i_major_version = 0
			i_minor_version = 0
			i_record_length = 0
	
	# PARSE DATA FOR THE IMPORTED BIN FILE

	if enc == 'b':

		s_file = open(ifn,'rb')
		i_len = os.stat(ifn).st_size
		#print(f'I_LEN: {i_len}') # TESTING

		i_lcount = 0
		byte_list = []
		byte_list_r = []
		b_4 = []


		# PRE SET VARIABLES FOR PARSING
		# MFT RECORDS AND SEQUENCE NUMBERS GO TOGETHER FIRST (16 BYTE TOTAL)
		# FILL WITH 00s ON THE LEFT. EX: 000000000000000002eb00000006cc24
		h_entrysize = [] # Hex for size of record
		i_entrysize = 0 # Decimal for size of record
		h_version_ma = [] #Hex for major version
		s_version_ma = '' # String for major version
		h_version_mi = [] # Hex minor version
		s_version_mi = '' # String minor version
		h_mft_f = [] # Hex for the full record number read
		s_mft_f = '' # String for the full record number read in Hex
		h_mft = [] # Hex for MFT Record Number
		i_mft = 0 # Decimal for MFT Record Number
		s_mft = '' # String for MFT Record Number
		h_mft_us = [] # Hex for MFT update sequence number
		i_mft_us = 0 # Decimal for MFT update sequence number
		s_mft_us = '' # String for MFT update sequence number
		h_mft_p_f = [] # Hex for the full record number read
		s_mft_p_f = '' # String for the full record number read in Hex
		h_mft_p = [] # Hex for MFT Parent
		i_mft_p = 0 # Decimal for MFT Parent
		s_mft_p = '' # String for MFT Parent
		h_mft_p_us = [] # Hex for MFT Parent update sequence number
		i_mft_p_us = 0 # Decimal for MFT Parent update sequence number
		s_mft_p_us = '' # String for parent update sequence number
		h_usn = [] # Hex for USN number
		i_usn = 0 # USN number
		h_timestamp = [] # Hex for timestamp
		s_timestamp = '' # String for timestamp
		i_timestamp = 0 # Integer for timestamp
		h_changereason = [] # Hex for change reason
		s_changereason = '' # String for change reason
		h_sourceinfo = [] # Hex for source info
		s_sourceinfo = '' # String for source info 
		h_securityid = [] # Hex for Security ID
		s_securityid = '' # String for Security ID
		i_securityid = 0 # Integer for security ID
		h_fileattrib = [] # Hex for file attributes
		s_fileattrib = '' # String for file attributes
		h_fnsize = [] # Hex for file name size
		s_fnsize = '' # String for file name size
		i_fnsize = 0 # Integer for file name size
		h_os2fn = [] # Offset to file name (normally 0x3C)
		s_os2fn = '' # String for offset to filename
		i_os2fn = 0 # Integer to offset of file name (normally 60)
		h_filename = [] # Hex of file name
		s_filename = '' # String of file name




		# SETTING THE CURSOR BACK TO THE BEGINNING OF THE FILE
		s_file.seek(0)

		i_lcount = 0 # COUNTER TO KEEP GOING TO END OF FILE
		i_recordtstart = 0 # HOLDS THE BEGINNING OF THE RECORD
		
		loop_lock = 1
		
		while i_lcount < i_len:
		#while loop_lock == 1:
			try:
				
				# GET THE BEGINNING OF THE RECORD
				byte_check = s_file.read(1).hex()
				
				# CHECK TO SEE IF IT IS STILL PADDING.  LOOK FOR SOMETHING OTHER THAN 0x00
				if str(byte_check) != '00':
					
					
					s_file.seek(-1,1)
					i_recordstart = s_file.tell()

					ab = i_recordstart / 8 # Even number will be the result if on boundary
					
					while ab.is_integer() == False: # Check to see if ab is an even number
						
						s_file.seek(-1,1) # If false, move back 1
						ab = s_file.tell() / 8 # Re assign location and loop until it is even
					
					i_recordstart = s_file.tell() # Set the i_recordstart at the cursor at the beginning of the record
					
					# GET THE SIZE OF THE RECORD
					t_count = 0
					while t_count < 4:
						x = s_file.read(1).hex()
						h_entrysize.append(x)
						t_count +=1
					
					#print(h_entrysize)
					h_entrysize.reverse() # Reverse the bits for LE
					s_entrysize = ''.join(h_entrysize) # Make a string to allow conversion
					i_entrysize = int(s_entrysize, 16) # Convert hex to decimal
					#print(i_entrysize)

					# GET THE MAJOR VERSION
					t_count = 0
					while t_count < 2:
						x = s_file.read(1).hex()
						h_version_ma.append(x)
						t_count +=1
					h_version_ma.reverse()
					s_version_ma = str(int(''.join(h_version_ma).upper(), 16) +1)
					
					# GET THE MINOR VERSION
					t_count = 0
					while t_count < 2:
						x = s_file.read(1).hex()
						h_version_mi.append(x)
						t_count +=1
					h_version_mi.reverse()
					s_version_mi = str(int(''.join(h_version_mi).upper(), 16))
					
					# GET THE MFT RECORD NUMBER (FULL 8)
					t_count = 0
					while t_count < 8:
						x = s_file.read(1).hex()
						h_mft_f.append(x)
						t_count +=1
					h_mft_f.reverse()
					s_mft_f = ''.join(h_mft_f).zfill(32).upper() # String as it appears in exported UsnJrnl
					s_mft_us = s_mft_f[0:20] # Assign the update sequence string
					s_mft = s_mft_f[20:32] # Assign the MFT record number string
					i_mft_us = int(s_mft_us, 16) # Assign the integer for the US
					i_mft = int(s_mft, 16) # Assign the integer for the MFT RN

					# GET THE MFT PARENT RECORD NUMBER (FULL 8)
					t_count = 0
					while t_count < 8:
						x = s_file.read(1).hex()
						h_mft_p_f.append(x)
						t_count +=1
					h_mft_p_f.reverse()
					s_mft_p_f = ''.join(h_mft_p_f).zfill(32).upper() # String as it appears in exported UsnJrnl
					s_mft_p_us = s_mft_p_f[0:20] # Assign the update sequence string
					s_mft_p = s_mft_p_f[20:32] # Assign the MFT record number string
					i_mft_p_us = int(s_mft_p_us, 16) # Assign the integer for the US
					i_mft_p = int(s_mft_p, 16) # Assign the integer for the MFT RN
					
					# GET THE USN FOR THE ENTRY
					t_count = 0 # Set the count for the USN
					while t_count < 8:
						x = s_file.read(1).hex()
						h_usn.append(x)
						t_count +=1
					h_usn.reverse()
					s_usn = ''.join(h_usn).upper()
					i_usn = int(s_usn, 16)
					
					
					# GET THE TIMESTAMP
					t_count = 0
					while t_count < 8:
						x = s_file.read(1).hex()
						h_timestamp.append(x)
						t_count +=1
					h_timestamp.reverse()
					s_timestamp = ''.join(h_timestamp).upper()
					i_timestamp = int(s_timestamp, 16)
					i_ts = ((i_timestamp / 10000000 - 11644473600) - tzone_os)
					# Windows epoch starts 1601-01-01T00:00:00Z. It's 11644473600 seconds before the 
					# UNIX/Linux epoch (1970-01-01T00:00:00Z). The Windows ticks are in 100 nanoseconds. 
					# Thus, a function to get seconds from the UNIX epoch will be as follows:
					# (130305048577611542 / 10000000) - 11644473600
					x = datetime.fromtimestamp(i_ts)
					s_timestamp = str(x)[0:23]
					y = str(int(int(tzone_os / 60 / 60)))
					if y == "0":
						y = ""
					s_timestamp = s_timestamp + ' LT' + y
					y = None

								
					# GET THE CHANGE REASON
					t_count = 0
					while t_count < 4:
						x = s_file.read(1).hex()
						h_changereason.append(x)
						t_count +=1
					h_changereason.reverse()
					s_changereason = change_reason(h_changereason, "change_reason")

					# GET THE SOURCE INFORMATION
					t_count = 0
					while t_count < 4:
						x = s_file.read(1).hex()
						h_sourceinfo.append(x)
						t_count +=1
					h_sourceinfo.reverse()
					s_sourceinfo = change_reason(h_sourceinfo, 'sourceinfo')
					if s_sourceinfo == '0x00000000: ':
						s_sourceinfo = "0x00000000: *NONE*"

					# GET THE SECURITY ID
					t_count = 0
					while t_count < 4:
						x = s_file.read(1).hex()
						h_securityid.append(x)
						t_count +=1
					h_securityid.reverse()
					s_securityid = ''.join(h_securityid).upper()
					i_securityid = int(s_securityid, 16)
					
					# GET THE FILE ATTRIBUTES
					t_count = 0
					while t_count < 4:
						x = s_file.read(1).hex()
						h_fileattrib.append(x)
						t_count +=1
					h_fileattrib.reverse()
					s_fileattrib = ''.join(h_fileattrib)
					s_fileattrib = change_reason(h_fileattrib, "attributes")
					
					# GET THE SIZE OF THE FILE NAME
					t_count = 0
					while t_count < 2:
						x = s_file.read(1).hex()
						h_fnsize.append(x)
						t_count +=1
					h_fnsize.reverse()
					s_fnsize = ''.join(h_fnsize).upper()
					i_fnsize = int(s_fnsize, 16)
					
					# GET THE OFFSET TO THE FILE NAME (USUALLY 0x3C)
					t_count = 0
					while t_count < 2:
						x = s_file.read(1).hex()
						h_os2fn.append(x)
						t_count +=1
					h_os2fn.reverse()
					s_os2fn = ''.join(h_os2fn).upper()
					i_os2fn = int(s_os2fn, 16)
					x = s_file.tell()
					i_lcount = s_file.tell()
					
					# GET THE FILE NAME
					t_count = 0
					s_file.seek(i_recordstart + i_os2fn)
					while t_count < i_fnsize:
						x = s_file.read(1).hex()
						h_filename.append(x)
						t_count +=1
					x = ''.join(h_filename)
					y = bytes.fromhex(x)
					s_filename = y.decode('utf16')
					i_lcount = s_file.tell()
				
					t_count = 0
					
					# FOR CHECKING ACCURACY OF PARSING AND VARIABLES
					# NOT USED IN GENERAL CODE AND CAN BE REMOVED LATER
					print_go = False
					if print_go == True:
						print(f'Time Zone: {tzone}, {tzone_os}, {tzone_os/60/60}')
						print(f'Entry Size: {i_entrysize}')
						print(f'Major Version: {s_version_ma}')
						print(f'Minor Version: {s_version_mi}')
						print(f'MFT Number: {i_mft}')
						print(f"MFT HEX: {s_mft_f}")
						print(f'MFT Parent: {i_mft_p}')
						print(f'USN: {i_usn}')
						print(f'Timestamp i: {i_timestamp}')
						print(f'Timestamp: {s_timestamp}')
						print(f'Change Reason: {s_changereason}')
						print(f'Source Info: {s_sourceinfo}')
						print(f'Security ID: {i_securityid}')
						print(f'File Attributes: {s_fileattrib}')
						print(f'File Name Size: {i_fnsize}')
						print(f'Offset to File Name: {i_os2fn}')
						print(f'File Name: {s_filename}')
						print()
						print()
						
					# IMPORT THE THE VARIABLES INTO THE SQLITE TABLE	
					sql_go = True
					if sql_go == True:
						# INSERT THE RECORD INTO THE DATABASE
						# s_filename = 'TESTING' 	# ==================================== PROBLEMS WITH SOME FILE NAMES WITH NULL VALUES
												# ==================================== FILE NAME AT 4958635 d IN USN.BIN ERRORS
												# Should start 1 byte before it actually does.  Starts 00 69 00, should start 76 00 69 00
												
						sql_insert = f"""
						INSERT INTO {t_name} (TABLE_NAME, USN, FILE_NAME, FILE_NAME_LENGTH,
						REASON, TIMESTAMP_D, TIMESTAMP, FILE_ATTRIBUTES, FILE_ID, FILE_ID_SEQ_H, FILE_ID_SEQ_D, 
						FILE_ID_MFT_H, FILE_ID_MFT_D, PARENT_FILE_ID, PARENT_FILE_ID_SEQ_H, PARENT_FILE_ID_SEQ_D,
						PARENT_FILE_ID_MFT_H, PARENT_FILE_ID_MFT_D, SOURCE_INFO,
						SECURITY_ID, MAJOR_VERSION, MINOR_VERSION, RECORD_LENGTH) 
						VALUES ("{t_name}","{i_usn}","{s_filename}","{i_fnsize}","{s_changereason}","{i_timestamp}","{s_timestamp}", 
						"{s_fileattrib}","{s_mft_f}","{s_mft_us}","{i_mft_us}","{s_mft}", 
						"{i_mft}","{s_mft_p_f}","{s_mft_p_us}","{i_mft_p_us}", 
						"{s_mft_p}","{i_mft_p}","{s_sourceinfo}","{i_securityid}",
						"{int(s_version_ma)}","{int(s_version_mi)}","{i_entrysize}")"""
						
						sql_cur.execute(sql_insert)
					
					# ADD TO THE TOTAL COUNT OF RECORDS IMPORTED
					l_count +=1 
					

					
					# RESET ALL THE VARIABLES AFTER THEY ARE IMPORTED INTO THE SQLITE TABLE
					h_entrysize = []
					i_entrysize = 0
					h_version_ma = []
					s_version_ma = ''
					h_version_mi = []
					s_version_mi = ''
					h_mft_f = []
					s_mft_f = ''
					h_mft = []
					i_mft = 0
					s_mft = ''
					h_mft_us = []
					i_mft_us = 0
					s_mft_us = ''
					h_mft_p_f = []
					s_mft_p_f = ''
					h_mft_p = []
					i_mft_p = 0
					s_mft_p = ''
					h_mft_p_us = []
					i_mft_p_us = 0
					s_mft_p_us = ''
					h_usn = []
					i_usn = 0
					h_timestamp = []
					s_timestamp = ''
					i_timestamp = 0
					h_changereason = []
					s_changereason = ''
					h_sourceinfo = []
					s_sourceinfo = ''
					h_securityid = []
					s_securityid = ''
					i_securityid = 0
					h_fileattrib = []
					s_fileattrib = ''
					h_fnsize = []
					s_fnsize = ''
					i_fnsize = 0
					h_os2fn = []
					s_os2fn = ''
					i_os2fn = 0
					h_filename = []
					s_filename = ''
					
				i_lcount +=1
			
			
			except Exception as e:
				# print('Error...')
				# print(e)
				print(traceback.format_exc())
				print(f'Location: {s_file.tell()}')
				input('Press ENTER')
				break
			
			except ValueError as e:
				print(e)


		s_file.close()

	
	# COMMIT THE IMPORTED RECORDS TO THE DATABASE. 
	sql_con.commit()
	sql_con.close()
	
	print('If you got this far, records imported correctly')
	print(f'Total {l_count} records imported')
	print()
	input('Press [ENTER] to continue...')
	

		
		
	s_file.close()

# FOR SETTING THE TIME ZONE OFFSET
def get_timezone_offset():
	
	tzone = ''
	tzone_os = 0
	tzone_os_h = ''
	
	print()
	print()
	
	#SETTING UP THE TIME ZONE DICTIONARY
	time_zones = {
	'UTC':'-0',
	'EST':'-18000','EDT':'-14400',
	'CST':'-21600','CDT':'-18000',
	'MST':'-25200','MDT':'-21600',
	'PST':'-28800','PDT':'-25200',
	}
					
	lbl = """
If you want to adjust for local time (meaning your converted timestamps
will be stored in local time in the output database, you can specify
your timezone here.  Shown below are the timezones and offsets in hours.
   
   UTC: UTC -0
   EST: UTC -5, EDT: UTC -4 
   CST: UTC -6, CDT: UTC -5
   MST: UTC -7, MDT: UTC -6
   PST: UTC -8, PDT: UTC -7
  
Specify the timezone or ENTER to default to UTC

"""
	print(lbl)
	
	i_lock = 1
	
	while i_lock == 1:
		

		xret = input('INPUT: ').upper()
		
		if xret == '':
			tzone = 'UTC'
		else:
			tzone = xret
		
		# GET THE OFFSET VALUE IN SECONDS
		x = time_zones.get(tzone, 'ERROR')
		
		print(f'x: {x}')

		if x != 'ERROR':
			tzone_os = int(x)
			i_lock = 0
		else:
			print()
			print(f'ERROR...{tzone} is not in the list of valid zones')
			print()

	x = None
		
	return tzone, tzone_os


# SET THE OUTPUT FILES
of_db, of_tsv = set_database()

# DISPLAY THE BASIC INSTRUCTIONS
basic_instructions()

# START THE MAIN MENU
list_lock = 1
main_menu(list_lock)

print()
print(f'OUTPUT FILES: {of_db}, {of_tsv}')




