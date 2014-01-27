#!/usr/bin/python
"""
This code takes comma separated wordlists like you might find in a 
dictionary or thesaurus and converts them in code to be used for flags
in a ctf.  Currently the wordlists are assumed to be in a wordlists/
folder and names *_thesaurus, but that is all, obviously, configureable.

For copyright and license information, please see the included LICENSE file.
"""
import os

__author__ = "mt@trustdarkness.com (Michael Thompson)"

# this is not super elegant.  Currently, the "seeds" and wordlist locations
# are hardcoded.  
possible_seeds = [
  "fruit",
  "animal",
  "vegetable",
  "plant",
  "rock",
  "machine",
  "insect",
  "word", 
  "land",
  "home",
]


# every seed must have a file named "seed_thesaurus" in the wordlist_dir
# for this to work.  if both of those things are true, everything else
# should be agnostic to the actual values.  see earlier comment about this
# not being elegant.
wordlist_dir = "wordlists/"

def get_wordlist(seed):
  """
  Takes a seed value from possible_seeds and generates a wordlist from the
  thesaurus files.

  Args: 
    seed - a string, one of possible_seeds

  Returns:
    a list of words for flag values
  """
  word_list = []
  tmp_list = []
  word_string = ""
  with open (os.path.join(wordlist_dir, seed + "_thesaurus"), "r") as f:
    word_string = f.read()
  
  tmp_list = word_string.split(",")
  
  # the extra list isn't really necessary, i'm just doing it for clarity
  # and because java and c have poisoned my mind
  for word in tmp_list:
    word_list.append(word.strip())

  return word_list
