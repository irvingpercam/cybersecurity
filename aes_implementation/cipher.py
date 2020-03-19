#!/usr/bin/env python3

def transpose(text, key):
    
    return 1

def caesar(text,s): 
	result = "" 

	# traverse text 
	for i in range(len(text)): 
		char = text[i] 

		# Encrypt uppercase characters 
		if (char.isupper()): 
			result += chr((ord(char) + s-65) % 26 + 65) 

		# Encrypt lowercase characters 
		else: 
			result += chr((ord(char) + s - 97) % 26 + 97) 

	return result 
