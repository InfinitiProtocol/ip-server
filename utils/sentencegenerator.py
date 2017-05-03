#!/usr/bin/python

import re
import random
import sys

# Markov Sentence Generator

# This program generates a sentence's worth of "real-looking" text using a Markov model and sample textual training input. 
# Given some sample text from which to build a model, the program prints out a sentence based on a Markov chain. 
# These mappings can get fairly large -- they're stored globally to save copying time. The texts of Portrait of the Artist 
# as a Young Man is taken from Project Gutenberg. The usual copyright headers had to be removed so that they could serve 
# as useful sample input, but naturally all the rights and restrictions of a Gutenberg book still apply.

# (tuple of words) -> {dict: word -> number of times the word appears following the tuple}
# Example entry:
#    ('eyes', 'turned') => {'to': 2.0, 'from': 1.0}
# Used briefly while first constructing the normalized mapping
tempMapping = {}

# (tuple of words) -> {dict: word -> *normalized* number of times the word appears following the tuple}
# Example entry:
#    ('eyes', 'turned') => {'to': 0.66666666, 'from': 0.33333333}
mapping = {}

# Contains the set of words that can start sentences
starts = []

# We want to be able to compare words independent of their capitalization.
def fixCaps(word):
	# Ex: "FOO" -> "foo"
	if word.isupper() and word != "I":
		word = word.lower()
		# Ex: "LaTeX" => "Latex"
	elif word [0].isupper():
		word = word.lower().capitalize()
		# Ex: "wOOt" -> "woot"
	else:
		word = word.lower()
	return word

# Tuples can be hashed; lists can't.  We need hashable values for dict keys.
# This looks like a hack (and it is, a little) but in practice it doesn't
# affect processing time too negatively.
def toHashKey(lst):
	return tuple(lst)

# Returns the contents of the file, split into a list of words and
# (some) punctuation.
def wordlist(filename):
	f = open(filename, 'r')
	wordlist = [fixCaps(w) for w in re.findall(r"[\w']+|[.,!?;]", f.read())]
	f.close()
	return wordlist

# Self-explanatory -- adds "word" to the "tempMapping" dict under "history".
# tempMapping (and mapping) both match each word to a list of possible next
# words.
# Given history = ["the", "rain", "in"] and word = "Spain", we add "Spain" to
# the entries for ["the", "rain", "in"], ["rain", "in"], and ["in"].
def addItemToTempMapping(history, word):
	global tempMapping
	while len(history) > 0:
		first = toHashKey(history)
		if first in tempMapping:
			if word in tempMapping[first]:
				tempMapping[first][word] += 1.0
			else:
				tempMapping[first][word] = 1.0
		else:
			tempMapping[first] = {}
			tempMapping[first][word] = 1.0
		history = history[1:]

# Building and normalizing the mapping.
def buildMapping(wordlist, markovLength):
	global tempMapping
	starts.append(wordlist [0])
	for i in range(1, len(wordlist) - 1):
		if i <= markovLength:
			history = wordlist[: i + 1]
		else:
			history = wordlist[i - markovLength + 1 : i + 1]
		follow = wordlist[i + 1]
		# if the last elt was a period, add the next word to the start list
		if history[-1] == "." and follow not in ".,!?;":
			starts.append(follow)
		addItemToTempMapping(history, follow)
	# Normalize the values in tempMapping, put them into mapping
	for first, followset in tempMapping.iteritems():
		total = sum(followset.values())
		# Normalizing here:
		mapping[first] = dict([(k, v / total) for k, v in followset.iteritems()])


# Returns the next word in the sentence (chosen randomly),
# given the previous ones.
def next(prevList):
	sum = 0.0
	retval = ""
	index = random.random()
	# Shorten prevList until it's in mapping
	while toHashKey(prevList) not in mapping:
		prevList.pop(0)
	# Get a random word from the mapping, given prevList
	for k, v in mapping[toHashKey(prevList)].iteritems():
		sum += v
		if sum >= index and retval == "":
			retval = k
	return retval

def genSentence(markovLength):
	# Start with a random "starting word"
	curr = random.choice(starts)
	sent = curr.capitalize()
	prevList = [curr]
	# Keep adding words until we hit a period
	while (curr not in ".!?"):
		curr = next(prevList)
		prevList.append(curr)
		# if the prevList has gotten too long, trim it
		if len(prevList) > markovLength:
			prevList.pop(0)
		if (curr not in ".,!?;"):
			sent += " " # Add spaces between words (but not punctuation)
		sent += curr
	return sent

def generateSentences(markovLength=5):
	# 5, because duh
	import os

	dir_path = os.path.dirname(os.path.realpath(__file__))    
	buildMapping(wordlist(dir_path+"/text.txt"), markovLength)
	sentences = ""
	x=0
	while x < 3:
		sentences += genSentence(markovLength) + '  '
		x+=1
	return sentences[0:800].strip() if len(sentences) >= 800 else sentences.strip()

