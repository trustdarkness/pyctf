#!/usr/bin/python
"""
This file is meant to be run directly on the exploitable host itself.
It takes a config file as generated by solutions.py and configures the host
its running on with those flags.  It also outputs its own solutions file
with any modifications it detected and needed to do as it was running

Requires phases.py and settings.py

also requires a local copy of argparse.py and an import statement for 
with statement using python2.5 (the default on metasploitable)

For copyright and license information, please see the included LICENSE file.
"""
from __future__ import with_statement
import phases
import settings
import subprocess
import pickle
import argparse
import getpass
import time
import sys

__author__ = "mt@trustdarkness.com (Michael Thompson)"

def configure_host(config=None):
  """TODO: output file format is missing phase locations
  Runs all the steps needed to configure a host with the provided config 
  for a ctf.

  Args:
    config - A dictionary of dictionaries formatted like:

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
  
  Does not return anything, but writes a file called "solutions.conf"
  to the cwd and prints status information to the console
  """
  if not config:
    import studentconf
    config = studentconf.config
  # we'll create a new solutions file just for comparison's sake
  solutions = {}
  for ident, hostconf in config.iteritems():
    print "configuring this host for unique id %s." % ident #This id will not be " % ident
#    print "stored anywhere on the host itself, so please record and correlate "
#    print "this unique id with this exploitable host."
    soln_hostconf = {}

    # setup initial conditions
    subprocess.call(["ssh-keygen", "-b", "2048", "-t", "rsa", "-f", "/root/.ssh/id_rsa", "-q", "-N", '"noflags"'])
    subprocess.call(["mysql", "-uroot", "-e", "create user 'dbadmin'@'localhost' identified by 'noflag'"])
    subprocess.call(["mysql", "-uroot", "-e", "flush privileges"])

    for phase, phaseconf in hostconf.iteritems():
      # these are hardcoded for now
      if phase == "Phase1":
        p = phases.NmapPhase()
      elif phase == "Phase2":
        p = phases.ExfiltrationPhase()
      elif phase == "Phase3":
        p = phases.CrackingPhase()
      soln_phaseconf = {}
      for flag, flag_data in phaseconf.iteritems():
        # this is not the most transparent thing in the world, but its
        # efficient / all purpose for now
        function = flag_data.keys()[0]
        flag_val = flag_data.values()[0]
        
        # special cases should eventually be coded out, but for time constraints
        if function == "system_password (root)":
          our_func = p.system_password 
        elif function == "system_password (msfadmin)":
          our_func = p.system_password
        elif function == "mysql_password (root)":
          our_func = p.mysql_password
        else:
          our_func = p.__getattribute__(function)
        # we need to special case a couple of functions
        if function == "samba_workgroup":
          # samba workgroups can only be 15 chars long.
          our_phase = settings.short_names[phase]
          our_flag = settings.short_names[flag]
          our_flag_val = "".join(flag_val.split())
          if (len(our_phase) + len(our_flag) + len(our_flag_val)) > 15:
            print "Warning: samba_workgroup flag value is longer than 15 chars"
            print "flag value will be truncated. %s %s" % (our_phase, our_flag)
          soln = our_func(our_phase, our_flag, our_flag_val)
        # seems like bad form to mix and match but function and our function
        # values should still be in sync and mutex within themselves
        elif function == "system_password (root)":
          our_flag_val = flag_val.split()[0]
          soln = our_func("root", phase, flag, our_flag_val)
        elif function == "system_password (msfadmin)":
          our_flag_val = flag_val.split()[0]
          soln = our_func("msfadmin", phase, flag, our_flag_val)
        elif function == "mysql_password (dbadmin)":
          our_flag_val = flag_val.split()[0]
          soln = our_func("dbadmin", phase, flag, our_flag_val)
        elif function == "mysql_password (root)":
          our_flag_val = flag_val.split()[0]
          soln = our_func("root", phase, flag, our_flag_val)
          # here we also need to make updates for the web phase
          web_phase = phases.WebPhase(our_flag_val)
        else:
          soln = our_func(phase, flag, flag_val)
        soln_phaseconf[flag] = soln
      soln_hostconf[phase] = soln_phaseconf
    solutions[ident] = soln_hostconf
    # print "Unless you saw errors on the console, the host should be ready"
    # print "after a reboot.  We'll generate a solutions.conf file in the cwd"
    # print "that you can compare with the config file you supplied."
    # print ""
    # print "They will be very similar, but not identical.  Either can be "
    # print "printed using solutions.py -p filename."
    # print ""
    # print "IMPORTANT: please delete both of these files and the ctf"
    # print "generation scripts before launching the ctf (unless you want to"
    # print "sneakily make things easier)."
    with open("solutions.conf", "w") as f:
      pickle.dump(solutions, f)


if __name__ == "__main__":
  user = getpass.getuser()
  if user != "root":
    print "Please run this script as root."
    sys.exit(0)
  aparser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter
  )
  aparser.add_argument("-c", "--config", action="store", default=None,
   dest="config", help="filename to use to configure the ctf host.")

  args = aparser.parse_args()
#  if not args.config:
#    print "Please specify -c and a config file."
  if args.config:
    with open(args.config, "r") as f:
      configure_host(pickle.load(f))
  else:
    try:
      configure_host()
      time.sleep(5)
      subprocess.call("reboot")
    except:
      print "there's something wrong with the embedded config."
      print "please contact your instructor."
