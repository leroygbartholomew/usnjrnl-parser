# usnjrnl-parser
Python script to parse the USN Journal into a SQLite database for analysis from text or binary

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
