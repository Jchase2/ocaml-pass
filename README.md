# ocaml-pass (tentative name)
A simple text based password manager written in ocaml. 

## Features

* AES stored passwords.
* Key generated by password, no key storage necessary.
* Allows user to organize passwords / info by section.  
* Allows user to add and remove lines (single or multiple).  
* Allows user to search for sections or individual lines. 
* Allows user to read entire contents of the "file". 

## Requirements

Ocaml, core, ocaml-scrypt-kdf, Nocrypto.  

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

Here's the menu:

```
Type 'o' to open a password file.
Type 'r' to read the entire file.
Type 's' to search for a string.
Type 'h' to search for a section.
Type 'l' to list all sections / headers.
Type 'i' to insert a single new line. (e.g a username:password combo.)
Type 'b' to insert multiple lines at a time.
Type 'n' to create a new section.
Type 'd' to delete a section and its contents.
Type 'k' to delete a string from a section.
Type 'f' to create and open a new encrypted pw file.
Type 'q' to quit.
```

## How it works.

Uses the Nocrypto library, and ocaml-scrypt-kdf, to encrypt. 
Generates a key with ocaml-scrypt-kdf, runs that through Nocrypto to
generate the final AES key, encrypts and decrypts whatever is entered. 
Everything else is handled with references and variables. 

Sections and passwords are stored like this: 

```
==== Email ====
username:password
==== END ====
```

The "END" section marks the end of a given section, and the title marks the beginning. 
When you search for a section, it will output from the title delimiter to 
"END". The first delimiter, "EMAIL" in this example, is read in by the user when 
a new section is created. If you manually edit a PW file, make sure you use 4 
equal signs and a space between delimiters, otherwise you'll run into bugs using
this script.  

You can also search for the string "email" and it'll output any lines beginning with "email": 
>email:pass

## Planned Changes

I'll probably keep adding features to this as time goes on. Any pull requests
are welcomed. 

* Encrypt data stored in memory / handle other memory security issues. Garbage collection?
* Rewrite insert function to be slightly more structured for delimiting. (Potentially?) 
* Improve sorting based on delimiters for lines. (Potentially?) 
* Improve header searching by allowing user to list headers during search dialogue.  
* Port to mobile / windows / build a basic GUI. Maybe? 
* Make user input section when removing a line, only remove from that section. 
* Build in a password generator. 
