#!/usr/bin/python
"""
The methods in these classes are meant to be run on target exploitable hosts.

See docstring in Phases class for more detailed information.

For copyright and license information, please see the included LICENSE file.
"""
from __future__ import with_statement
import subprocess
import os

__author__ = "mt@trustdarkness.com (Michael Thompson)"

class Phase(object):
  """
  Phase class.  This is currently mostly a placeholder, but likely will 
  be useful for additional features.

  A "Phase" is generically described as a series of functions that generate 
  flags around a learning objective.  Though there's no reason to group them 
  this way from a programming standpoint, it will assist in organizing a ctf
  around certain objectives.

  methods in phase classes are intended to run directly on exploitable hosts 
  before the host is deployed to be exploited.  IT is assumed that the methods
  will be run as root on a metasploitable-based host.
  """
  flags_used= {}
   

class NmapPhase(Phase):
  """
  The objective of the flags in this phase is to get students familiar with 
  nmap, port scanning, and investigating a host without having anything but
  network access to it.
  """
  # num_possible_flags should be set to the number of methods in the class
  # that create flags
  num_possible_flags = 4

  def samba_workgroup(self, phase_num, flag_num, flag_val):
    """
    Sets the samba workgroup to the flag string.  Note: as mentioned below, 
    the total concatenated length of the flag string should be <= 15
  
    Args: 
      phase_num - string like "Phase2" 
      flag_num - string like "Flag1"
      flag_val - random dictionary word
 
      in cases where the full string is character limited (like samba workgroup)
      Phase2 may be abbreviated like "P2" and Flag1 like "F1".

      Deciding how to truncate the names into something sensible is the 
      responsibility of the caller, but this function will err if if can't 
      fit the flags into the string length required.

    Returns:
      False if unsuccessful, otherwise
      { __name__ : flag_string }  
      where __name__ is the funcion name and flag_string typically looks like:
      phase_num + "_" + flag_num + "_" + flag_val (though there may be some 
      variation)

    Learning Objective:
      nmap -T4 -A -v
    """
    max_str_len = 15
    flag_string = phase_num + flag_num + flag_val
    if len(flag_string) > max_str_len:
      print "Error: flag for samba string must be 15 chars or less, your" 
      print " assembled string comes out to %s" % flag_string

    sed = '/bin/sed'
    sed_string = 's/WORKGROUP/%s/' % flag_string
    p = subprocess.call([sed, '-i', sed_string, '/etc/samba/smb.conf'])
    if p != 0:
      print "Error changing workgroup to %s" % flag_string
      return False

    self.flags_used[__name__] = flag_string    
    return { __name__ : flag_string }

  def ftp_banner(self, phase_num, flag_num, flag_val):
    """
    Sets the ftp banner to a multi line string containing the flag string.
   
    Args: 
      phase_num - string like "Phase2" 
      flag_num - string like "Flag1"
      flag_val - random dictionary word

    Returns:
      False if unsuccessful, otherwise
      { __name__ : flag_string }  
      where __name__ is the funcion name and flag_string typically looks like:
      phase_num + "_" + flag_num + "_" + flag_val (though there may be some 
      variation)

    Learning Objective:
      nmap --script=banner
    """
    flag_string = phase_num + "_" + flag_num + "_" + flag_val
    conf_file = '/etc/vsftpd.conf'
    banner_string = "\nftpd_banner=Welcome to the metasploitable FTP service! %s\"" % flag_string
    with open(conf_file, 'a') as f:
      f.writelines(banner_string)

    self.flags_used[__name__] = flag_string
    return { __name__ : flag_string }

  def smtp_banner(self, phase_num, flag_num, flag_val):
    """
    Sets the smtpd hostname value to the flag string
   
    Args: 
      phase_num - string like "Phase2" 
      flag_num - string like "Flag1"
      flag_val - random dictionary word

    Returns:
      False if unsuccessful, otherwise
      { __name__ : flag_string }  
      where __name__ is the funcion name and flag_string typically looks like:
      phase_num + "_" + flag_num + "_" + flag_val (though there may be some 
      variation)

    Learning Objective:
      nmap -sC or nmap --script=smtp-commands
    """
    print "" 
    flag_string = phase_num + "_" + flag_num + "_" + "".join(flag_val.split())
    postfix = '/usr/sbin/postfix'
    maincf = '/etc/postfix/main.cf'
    postfix_string = "myhostname=%s" % flag_string

    # the below apparently doesn't work in this old version of postfix
    # p = subprocess.call([postfix, 'upgrade-configuration', \
    #   "myhostname=%s" % flag_string])
    #if p != 0:
    #  print "Error: could not change postfix hostname to %s" % flag_string
    #  return False
   
    with open(maincf, 'a') as f:
      f.writelines(postfix_string)

    self.flags_used[__name__] = flag_string
    return { __name__ : flag_string }

  def host_name(self, phase_num, flag_num, flag_val):
    """
    Sets the hostname in /etc/hostname to the flag string.

    Args: 
      phase_num - string like "Phase2" 
      flag_num - string like "Flag1"
      flag_val - random dictionary word

    Returns:
      False if unsuccessful, otherwise
      { __name__ : flag_string }  
      where __name__ is the funcion name and flag_string typically looks like:
      phase_num + "_" + flag_num + "_" + flag_val (though there may be some 
      variation)

    Learning Objective:
      nmap -sV
    """
    flag_string = phase_num + "_" + flag_num + "_" + flag_val
    hostname = '/etc/hostname'

    with open(hostname, 'w') as f:
      f.writelines(flag_string)
  
    self.flags_used[__name__] = flag_string 
    return { __name__ : flag_string }



class WebPhase(Phase):
  """
  Things will be inserted here later.
  """
  def __init__(self, mysql_root_pw):
    # once we've established the mysql root password, we need to fix the
    # webapps to work before we can use any of these properly
    
    # dvwa
    sed = '/bin/sed'
    dvwa_conf = '/var/www/dvwa/config/config.inc.php'
    sed_string = "s/''/'%s'/" % mysql_root_pw
    p = subprocess.call([sed, '-i', sed_string, dvwa_conf])
    if p != 0:
      print "couldn't modify %s" % dvwa_conf
    mutillidae_conf = '/var/www/mutillidae/config.inc'
    p = subprocess.call([sed, '-i', sed_string, mutillidae_conf])
    if p != 0:
      print "couldn't modify %s" % mutillidae_conf
    

class ExfiltrationPhase(Phase):
  """
  The Exfiltration Phase contains flags that are centered around key system
  files and utilities and currently is directed at users who are not familiar
  with Unix/Linux system administration.

  The learning goals, with that in mind, are not only to get a student exploring
  linux, but also thinking about how having root access can be used to gather
  information about a running system.

  Therefore, flags in this phase should be given with corresponding 
  comprehension questions such as: 

  what command and/or file led you to the flag?  
  did you find other information because of this file/command? 
  how would an attacker use the information found via this file/command?
  
  etc.
  """
  num_possible_flags = 5
  flags_used = {}
 
  def adduser_easteregg(self, phase_num, flag_num, flag_val):
    """
    Places an easter egg in the adduser command so that users will see the
    flag string upon trying to add a user to the system.

    Args: 
      phase_num - string like "Phase2" 
      flag_num - string like "Flag1"
      flag_val - random dictionary word

    Returns:
      False if unsuccessful, otherwise
      { __name__ : flag_string }  
      where __name__ is the funcion name and flag_string typically looks like:
      phase_num + "_" + flag_num + "_" + flag_val (though there may be some 
      variation)

    Learning Objective:
      How to add a user to the system.
    """
    flag_string = phase_num + "_" + flag_num + "_" + flag_val
    mv = '/bin/mv'
    mkdir = '/bin/mkdir'
    secret_loc = '/root/secret'
    adduser = '/usr/sbin/adduser' 
    chmod = '/bin/chmod'

    p = subprocess.call([mkdir, '-p', secret_loc])
    if p != 0:
      print "Error: could not create %s" % secret_loc
      return False
    p = subprocess.call([mv, adduser, secret_loc])
    if p != 0:
      print "Error: could not move %s to %s" % (adduser, secret_loc)
      return False
    with open(adduser, 'w') as f:
      s = "#!/bin/sh\necho \"%s\"\n%s/adduser $1;" % (flag_string, secret_loc)
      f.write(s)

    p = subprocess.call([chmod, "+x", adduser])
    if p != 0:
      print "Error: could not make adduser executable"
      return False

    self.flags_used[__name__] = flag_string
    return { __name__ : flag_string }

  def simple_http_ps_out(self, phase_num, flag_num, flag_val):
    """
    Adds a dummy process using SimpleHTTPServer to the system that will
    contain the flag string in the process name.  Future versions might want
    to serve additional flag info in the http service.

    Args: 
      phase_num - string like "Phase2" 
      flag_num - string like "Flag1"
      flag_val - random dictionary word

    Returns:
      False if unsuccessful, otherwise
      { __name__ : flag_string }  
      where __name__ is the funcion name and flag_string typically looks like:
      phase_num + "_" + flag_num + "_" + flag_val (though there may be some 
      variation)

    Learning Objective:
      Look at ps output, see running processes on the system
    """
    flag_string = phase_num + "_" + flag_num + "_" + "".join(flag_val.split())
    cp = '/bin/cp'
    shs = '/usr/lib/python2.5/SimpleHTTPServer.py'
    new_shs = '/usr/lib/python2.5/SimpleHTTPServer%s.py' % flag_string
    rclocal = '/etc/rc.local'
    rclocal_string = 'python -m SimpleHTTPServer%s 999 &' % flag_string
    p = subprocess.call([cp, shs, new_shs])
    if p != 0:
      print "Error: could not copy %s to %s" % (shs, new_shs)
      return False

    with open(rclocal, 'a') as f:
      f.writelines(rclocal_string)

    self.flags_used[__name__] = flag_string
    return { __name__ : flag_string }

  def file_in_etc(self, phase_num, flag_num, flag_val):
    """
    Places a file in /etc/ with the name and contents of the flag string

    Args: 
      phase_num - string like "Phase2" 
      flag_num - string like "Flag1"
      flag_val - random dictionary word

    Returns:
      False if unsuccessful, otherwise
      { __name__ : flag_string }  
      where __name__ is the funcion name and flag_string typically looks like:
      phase_num + "_" + flag_num + "_" + flag_val (though there may be some 
      variation)

    Learning Objective:
      Exploring the linux filesystem - looking at config files.
    """
    # for this one we'll pull any potential spaces out of the flag val
    flag_string = phase_num + "_" + flag_num + "_" + "".join(flag_val.split())
    etc = '/etc/'
    with open(os.path.join(etc, flag_string), 'w') as f:
      f.writelines(flag_string)

    self.flags_used[__name__] = flag_string
    return { __name__ : flag_string }

  def file_in_var(self, phase_num, flag_num, flag_val):
    """
    Places a file in /var/log with the name and contents of the flag string

    Args: 
      phase_num - string like "Phase2" 
      flag_num - string like "Flag1"
      flag_val - random dictionary word

    Returns:
      False if unsuccessful, otherwise
      { __name__ : flag_string }  
      where __name__ is the funcion name and flag_string typically looks like:
      phase_num + "_" + flag_num + "_" + flag_val (though there may be some 
      variation)

    Learning Objective:
      Exploring the linux filesystem - looking at log files.
    """
    # for this one we'll pull any potential spaces out of the flag val
    flag_string = phase_num + "_" + flag_num + "_" + "".join(flag_val.split())
    var = '/var/log/'
    with open(os.path.join(var, flag_string), 'w') as f:
      f.writelines(flag_string)

    self.flags_used[__name__] = flag_string
    return { __name__ : flag_string }

  def description_field_passwd_file(self, phase_num, flag_num, flag_val):
    """TODO: THIS IS BROKEN!
    Adds a flag to the description field of root's /etc/password entry

    Args: 
      phase_num - string like "Phase2" 
      flag_num - string like "Flag1"
      flag_val - random dictionary word

    Returns:
      False if unsuccessful, otherwise
      { __name__ : flag_string }  
      where __name__ is the funcion name and flag_string typically looks like:
      phase_num + "_" + flag_num + "_" + flag_val (though there may be some 
      variation)

    Learning Objective:
      Exploring important security related files on linux.
    """

    flag_string = phase_num + "_" + flag_num + "_" + flag_val
    sed = '/bin/sed'
    sed_string = 's/\:root\:/\:%s\:/'
    passwd_file = '/etc/passwd'
    p = subprocess.call([sed, '-i', sed_string, passwd_file])
    if p != 0:
      print "Error: couldn't run sed command"
      return False

    self.flags_used[__name__] = flag_string
    return { __name__ : flag_string }

  def root_private_ssh_key(self, phase_num, flag_num, flag_val):
    """
    Places a flag in root's private ssh key.

    Args: 
      phase_num - string like "Phase2" 
      flag_num - string like "Flag1"
      flag_val - random dictionary word

    Returns:
      False if unsuccessful, otherwise
      { __name__ : flag_string }  
      where __name__ is the funcion name and flag_string typically looks like:
      phase_num + "_" + flag_num + "_" + flag_val (though there may be some 
      variation)

    Learning Objective:
      Exploring important security related files on linux.
    """
    flag_string = phase_num + "_" + flag_num + "_" + flag_val
    sed = '/bin/sed'
    sed_string = 's/END RSA/END %s RSA/'
    keyfile = '/root/.ssh/id_rsa'
    p = subprocess.call([sed, '-i', sed_string, keyfile])
    if p != 0:
      print "Error: couldn't run sed command"
      return False

    self.flags_used[__name__] = flag_string
    return { __name__ : flag_string } 

  def root_public_ssh_key(self, phase_num, flag_num, flag_val):
    """
    Places a flag in root's private ssh key.

    Args:  
      phase_num - string like "Phase2" 
      flag_num - string like "Flag1"
      flag_val - random dictionary word

    Returns:
      False if unsuccessful, otherwise
      { __name__ : flag_string }  
      where __name__ is the funcion name and flag_string typically looks like:
      phase_num + "_" + flag_num + "_" + flag_val (though there may be some 
      variation)

    Learning Objective:
      Exploring important security related files on linux.
    """
    # for this one we'll pull any potential spaces out of the flag val
    flag_string = phase_num + "_" + flag_num + "_" + "".join(flag_val.split())
    flag_string = phase_num + "_" + flag_num + "_" + flag_val
    sed = '/bin/sed'
    sed_string = 's/metasploitable/%s/' % flag_string
    keyfile = '/root/.ssh/id_rsa.pub'
    p = subprocess.call([sed, '-i', sed_string, keyfile])
    if p != 0:
      print "Error: couldn't run sed command"
      return False

    self.flags_used[__name__] = flag_string
    return { __name__ : flag_string }


class CrackingPhase(Phase):
  """
  The cracking phase is different from the other phases in that flags are not
  free form text blobs, they're not randomized, and they're not hidden.  
  Instead, passwords are created using random words for system and mysql 
  accounts and students are intended to crack them.

  Passwords can be cracked by ssh dictionary attacks or by brute forcing
  or using rainbow tables on the hashes from post exploitation.
 
  This phase is not intended to be randomized other than having random 
  dictionary words as passwords.  The Phase and Flag information is provided
  for consistency and grading purposes.  Passwords should only be set using 
  the "flag_val" string.
  """
  # we'll set num possible flags to 2 here, but probably won't use it in the
  # same way as the other phases, given that you can use both system and mysql
  # passwords for multiple flags each.
  num_possible_flags = 2

  def system_password(self, login, phase_num, flag_num, flag_val):
    """
    Set the system password of the provided user login to the flag_val.

    Args:  
      login - system login name (should already exist)
      phase_num - string like "Phase2" 
      flag_num - string like "Flag1"
      flag_val - random dictionary word

    Returns:
      False if unsuccessful, otherwise
      { __name__ : flag_string }  
      where __name__ is the funcion name and flag_string typically looks like:
      phase_num + "_" + flag_num + "_" + flag_val (though there may be some 
      variation)

    Learning Objective:
      Not only how to crack passwords, but how easy simple passwords are to 
      crack.
    """
    # in order to make password cracking not *TOO* difficult, #we'll just 
    # use the dictionary word here. but still return the full flag string
    # for grading purposes.
    flag_string = phase_num + "_" + flag_num + "_" + login + "_pw_" + flag_val

    # if we're looking to make this not too difficult, we also might want to
    # make sure that password is 1 dictionary word.  For now, we'll assume 
    # that's the responsibility of the caller
    password = flag_val

    # openssl doesn't have the strongest hash functions.  We're using this 
    # intentionally
    p = subprocess.Popen(('openssl', 'passwd', '-1', password), \
      stdout=subprocess.PIPE)
   
    shadow_password = p.communicate()[0].strip()
 
    if p.returncode != 0:
      print 'Error creating hash for ' + login

    r = subprocess.call(('usermod', '-p', shadow_password, login))

    if r != 0:
      print 'Error changing password for ' + login
      return False

    self.flags_used[__name__] = flag_string
    return { __name__ : flag_string }

  def mysql_password(self, user, phase_num, flag_num, flag_val):
    """
    Set the mysql password of the provided user login to the flag_val.
    Its important that you do any other users before root, otherwise this won't
    work non-interactively.

    Args:  
      user - mysql user name (should already exist)
      phase_num - string like "Phase2" 
      flag_num - string like "Flag1"
      flag_val - random dictionary word

    Returns:
      False if unsuccessful, otherwise
      { __name__ : flag_string }  
      where __name__ is the funcion name and flag_string typically looks like:
      phase_num + "_" + flag_num + "_" + flag_val (though there may be some 
      variation)

    Learning Objective:
      Not only how to crack passwords, but how easy simple passwords are to 
      crack.
    """

    # in order to make password cracking not *TOO* difficult, #we'll just 
    # use the dictionary word here. but still return the full flag string
    # for grading purposes.
    flag_string = phase_num + "_" + flag_num + "_" + user + "_pw_" + flag_val    
    # if we're looking to make this not too difficult, we also might want to
    # make sure that password is 1 dictionary word.  For now, we'll assume 
    # that's the responsibility of the caller
    password = flag_val

    # we should probably do this with python's mysql interface but at the 
    # moment, i'd rather not assume what software is installed on the target
    # host so we'll shell out.
    p = subprocess.call(('/usr/bin/mysqladmin', '-u%s' % user, 'password', '%s' % password))
    if p != 0:
      print 'Error changing password for user %s' % user
      return False

    self.flags_used[__name__] = flag_string
    return { __name__ : flag_string }
