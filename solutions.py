#!/usr/bin/python
"""Module to manage generating and printing solutions for the ctf application.

Generates a solutions file in pickled form, given a host.  The pickled form
is generated in such a way that it can be used by host.py to modify an 
exploited host for that solutions file.

pickled output looks like:

{ unique_identifier :
  { "Phasenum"  : 
     { "Flagnum" :
        { "funcname" : "flagstring" 
     { "Flagnum..." :
        { "funcname..." : "flagstring..."
     ...
  { "Phasenum..." :
  ...
}

unique_identifier is a unique identifying string that maps to a host and/or
student.

requires phases.py and settings.py

currently is fairly specific to UIC CS487 Oct 2013 ctf

randomness is not related to input unique_identifier

For copyright and license information, please see the included LICENSE file.
"""
from __future__ import with_statement
import random
import phases
import flags
import settings
import argparse
import pickle
import json

__author__ = "mt@trustdarkness.com (Michael Thompson)"

#flags_per_phase = 4
p1_flags = 4
p2_flags = 5
p3_flags = 3

def solutions_for_host(unique_identifier):
  """
  Generates a solutions datastructure forthe host given a unique identifier. 
 
  Args:
    unique_identifier - a string that is unique to a student, host, or entity

  Returns:
    a config dict object that looks like:
    { unique_identifier :
      { "Phasenum"  : 
         { "Flagnum" :
            { "funcname" : "flagstring" 
         { "Flagnum..." :
            { "funcname..." : "flagstring..."
         ...
      { "Phasenum..." :
      ...
    }
  """
  seeds = flags.possible_seeds
  num_seeds = len(flags.possible_seeds)
  our_seed_num = random.randint(0, num_seeds-1)
  our_seed = seeds[our_seed_num]
  wordlist = flags.get_wordlist(our_seed) 

  # retval will become { unique_identifier : hostconf }
  retval = {}
  hostconf = {}
  
  our_nmap = settings.nmap_flags
  our_flag_nums = settings.flag_nums
  for phase, functions in settings.phases.iteritems():
    # this should be abstracted
    phaseconf = {}
    if phase == 'Phase1':
      flags_per_phase = p1_flags
    elif phase == 'Phase2':
      flags_per_phase = p2_flags
    elif phase == 'Phase3':
      flags_per_phase = p3_flags
    for i, flag in enumerate(our_flag_nums):
      if i < flags_per_phase:
        free_phases = len(functions)
        words = len(wordlist)
        print "debug: fph: %d i: %d ws: %d" % (free_phases, i, words) 
        func_to_use = functions.pop(random.randint(0, free_phases-1))
        flag_val = wordlist.pop(random.randint(0, words))
        phaseconf[flag] = { func_to_use: flag_val }
        print "wrote %s" % phaseconf[flag]
    hostconf[phase] = phaseconf
  retval[unique_identifier] = hostconf
  return retval

def printout(filename):
  """
  Prints out in a human readable form to the console the pickled config 
  from a file generated by the above or by host.py

  Args:
    filename - a string of the filename on disk
    note: we don't error check this.
  
  Returns nothing, but prints to the console
  """
  with open(filename, "r") as f:
    conf = pickle.load(f)
    for ident, hostconf in conf.iteritems():
      print "id: %s" % ident
      for phase, phaseconf in hostconf.iteritems():
        print "phase: %s" % phase
        for flag, flag_val in phaseconf.iteritems():
          print "%s : %s" % (flag, flag_val)


if __name__ == "__main__":
  aparser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter
  )
  aparser.add_argument("-i", "--id", action="store", default=None, dest="ident",
   help="unique id for host, could be student id, hash, ip address, etc")
  aparser.add_argument("-p", "--print", action="store", default=None, 
   dest="printout", help="filename to print the contents of for easy viewing.")
  aparser.add_argument("-e", "--embed", action="store", default=None, 
   dest="embed", help="file to embedd as importable python (host.py)")

  args = aparser.parse_args()
  if not args.ident and not args.printout:
    print "Please specify -i unique_id to identify the host you're generating"
    print "a configuration for, or -p conf_file.conf to print a human readable"
    print "version of the config."
  elif args.ident and args.printout:
    print "Please choose one of -i or -p but not both."
  elif args.printout:
    printout(args.printout)    
  elif args.ident: 
    print "Saving to %s.conf if your OS doesn't support a filename with those"
    print "characters, you will likely see an error. Any existing file with"
    print "that name will be overwritten"

    conf_info = solutions_for_host(args.ident)
    if args.embed:
      with open("studentconf.py", "w") as f:
        f.write("config = ")
        json.dump(conf_info, f)        
    with open("%s.conf" % args.ident, "w") as f:
      pickle.dump(conf_info, f)

    print "%s saved to %s.conf" % (conf_info, args.ident)
