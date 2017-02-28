#!/usr/bin/python
"""Settings for the ctf application.

Settings module containing configuration information for the ctf application.

Requires phases.py

For copyright and license information, please see the included LICENSE file.
"""
import phases

__author__ = "mt@trustdarkness.com (Michael Thompson)"

nmap_flags = [ 
  "ftp_banner",
  "host_name", 
  "samba_workgroup",
  "smtp_banner",
]

exfiltration_flags = [
  "adduser_easteregg",
  "description_field_passwd_file",
  "file_in_etc",
  "file_in_var", 
  "root_private_ssh_key",
  "root_public_ssh_key",
  "simple_http_ps_out",
]

cracking_flags = [
  # TODO: make these generic for future ctfs
  "system_password (root)",
  "system_password (msfadmin)",
  "mysql_password (root)"
]

phase_nums = [
  "Phase1",
  "Phase2",
  "Phase3",
]

# flag nums can be separated by phase, if we want.
flag_nums = [
  "Flag1",
  "Flag2",
  "Flag3",
  "Flag4"
]

# some phases need shorter names, to facilitate this we'll make a translation
# table.  This can probably be done inline more easily, but this is easier
# to understand.
short_names = {
  "Phase1" : "P1",
  "Phase2" : "P2",
  "Phase3" : "P3",
  "Flag1" : "F1",
  "Flag2" : "F2",
  "Flag3" : "F3",
  "Flag4" : "F4",
  "Flag5" : "F5",
  "Flag6" : "F6"
}

phases = {
  "Phase1" : nmap_flags,
  "Phase2" : exfiltration_flags,
  "Phase3" : cracking_flags
}
