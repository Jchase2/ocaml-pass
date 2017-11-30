# ocaml-pass (tentative name)
A simple text based password manager written in ocaml. 

This is based on the shell version: https://github.com/Jchase2/simple-pass-manager
Except theoretically more secure.

## Features

* AES stored passwords.
* Scrypt password generated key on login.
* Never writes to disk.
* Encrypts key in memory until used. Tries to keep data encrypted as well, until used.
* Can organize passwords / info by "block". (Blocks explained below.)  
* Add and remove blocks with a single or multiple lines of text within.  
* Add and Remove string(s) from blocks.
* Search for sections. Also, list all sections.
* Search for lines starting with user input. 
* Read entire contents of the "file". 

## Requirements

Ocaml, core, ocaml-scrypt-kdf, Nocrypto, ocaml-pcre.   

## How To:

When you launch it, you get a prompt. Type in a password. 
Do not forget this password, it's used to generate the AES key. 
Type "help" or "?" to get a list of commands.


Then you should add a section or sections to put pw strings between... I recommend 
formatting your username and passwords like this: 

>username:password

For additional information, like reset questions and answers, you have two options. First,
you could use really long strings like this: 

>username:password:aQuestion:answer:question2:answer2:pincode:4857489393:whatever:whatever

Which works fine. A less ugly way to do it, however, is to just insert a block of lines 
(type b or B), each beginning with the same thing, like this:  

> email:username:pass

> email:securityquestion:answer

> email:pincode:pw

When you search for a string, if you just type "email" in this example, all instances 
of email will be printed. This is generally easier to read, but it really comes down to 
personal preference. 

I'll have more searching / removing / etc implemented shortly. 
Here's the menu:

```
"Type 'read' to read the entire file.";
"Type 'stringsearch' to search for and print a string.";
"Type 'blocksearch' to search for and print a block.";
"Type 'block' to insert a new block.";
"Type 'insert' to insert new lines into a block.";
"Type 'removeblock' to remove a block.";
"Type 'removestring' to remove string(s) from a block.";
"Type 'listblocks' to list all block headers."; 
"Type 'q' to quit."
```

## How it works.

Uses the Nocrypto library, and ocaml-scrypt-kdf, to encrypt. 
Generates a key with ocaml-scrypt-kdf, runs that through Nocrypto to
generate the final AES key(s), encrypts and decrypts whatever is entered. 
Everything else is handled with (usually encrypted) references, variables, 
and buffers. 

Sections and passwords are stored like this: 

```
==== Email ====
username:password
==== END ====
```

The "END" section marks the end of a given section, and the title marks the beginning. 
When you search for a section, it will output from the title delimiter to 
"END". The first delimiter, "EMAIL" in this example, is read in by the user when 
a new section is created.  

You can also search for the string "email" and it'll output any lines beginning with "email": 
>email:pass

## Planned Changes

I'll probably keep adding features to this as time goes on. Any pull requests
are welcomed. 

* Handle variables and function passing in memory for security.
* Finish implementing adding / searching functions. 
* Improve sorting based on delimiters for lines. (Potentially?) 
* Improve header searching by allowing user to list headers during search dialogue.  
* Port to mobile / windows / build a basic GUI. Maybe? 
* Build in a password generator. 
* Maybe down the line, implement a way to sync crypted pw file across more than one machine.
